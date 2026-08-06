package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

// The device-token relay. The app writes the phone's APNs token into the
// user-owned rules.json (an unprivileged write that works in every escalation
// case); the agent, which holds the secret, relays it to the backend on change
// only - the same pattern as unreachable_after_s, but authenticated like the
// breach path.
//
// A device token rots (restore-from-backup, some OS updates, revoked
// permission), and a stale token means pushes fire into the void for a user who
// believes they are covered. So the token is relayed whenever it changes, and a
// CLEAR (the user revoked permission) is relayed too - distinct from ABSENT
// (the app never wrote one), or a dead token would linger for ever.

// tokenIntent is what the device_token field in rules.json is asking for.
type tokenIntent int

const (
	tokenAbsent    tokenIntent = iota // field not present: do nothing, keep backend state
	tokenClear                        // null or "": clear the backend's token
	tokenSet                          // a valid 64-hex token: relay it
	tokenMalformed                    // present but not valid: keep previous, warn
)

// parseDeviceToken decodes the device_token field, distinguishing all three
// states the design turns on. RawMessage is used precisely so ABSENT (len 0)
// can be told apart from an explicit null.
func parseDeviceToken(raw json.RawMessage) (tokenIntent, string) {
	if len(raw) == 0 {
		return tokenAbsent, ""
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return tokenClear, ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return tokenMalformed, "" // present but not even a string
	}
	if s == "" {
		return tokenClear, ""
	}
	if isHex64(s) {
		return tokenSet, s
	}
	return tokenMalformed, ""
}

// isHex64 is exactly 64 hexadecimal characters, case-insensitive (the app
// writes lowercase; the backend validates the same length).
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// tokenRelay POSTs the token to /v1/device-token on change only. The last
// successfully communicated value is held in memory and NEVER persisted: a
// restart re-sends once, which is harmless and idempotent.
type tokenRelay struct {
	endpoint string
	agentID  string
	secret   string
	client   *http.Client
	log      *slog.Logger

	desired  *string // value to communicate: a 64-hex token or "" (clear). nil = nothing to do.
	lastSent *string // last value the backend confirmed. nil = nothing sent yet.
}

// deviceTokenURL derives /v1/device-token from the beat endpoint - same host and
// scheme, so no new config field and no enrolment change.
func deviceTokenURL(beatEndpoint string) (string, error) {
	u, err := url.Parse(beatEndpoint)
	if err != nil {
		return "", err
	}
	u.Path = "/v1/device-token"
	return u.String(), nil
}

func newTokenRelay(beatEndpoint, agentID, secret string, client *http.Client, log *slog.Logger) (*tokenRelay, error) {
	endpoint, err := deviceTokenURL(beatEndpoint)
	if err != nil {
		return nil, err
	}
	return &tokenRelay{endpoint: endpoint, agentID: agentID, secret: secret, client: client, log: log}, nil
}

// setDesired updates what should be communicated from a freshly loaded rules
// file. ABSENT leaves the current desire untouched (do nothing); MALFORMED keeps
// the previous value and warns - a bad parse must never clear a live token.
// Called only when the file actually changed (mtime-gated), so it does not spam.
func (t *tokenRelay) setDesired(intent tokenIntent, value string) {
	switch intent {
	case tokenAbsent:
		return
	case tokenMalformed:
		t.log.Warn("device_token in the rules file is malformed; keeping the previous token")
		return
	case tokenSet:
		v := value
		t.desired = &v
	case tokenClear:
		empty := ""
		t.desired = &empty
	}
}

type relayOutcome int

const (
	relayDone  relayOutcome = iota // delivered, or a 4xx we will not retry: stop
	relayRetry                     // transient: try again next tick
)

// flush attempts one delivery if the desired value differs from the last sent.
// Called every sample tick, so a transient failure is retried next tick with the
// same value, until it succeeds or the value changes again.
func (t *tokenRelay) flush(ctx context.Context) {
	if t.desired == nil {
		return // nothing has ever been written
	}
	if t.lastSent != nil && *t.lastSent == *t.desired {
		return // already communicated
	}
	body, err := json.Marshal(deviceTokenBody{
		AgentID: t.agentID, Secret: t.secret, DeviceToken: *t.desired,
	})
	if err != nil {
		t.log.Error("device token marshal failed", "error", err.Error())
		return
	}
	if t.send(ctx, body) == relayDone {
		v := *t.desired
		t.lastSent = &v
	}
}

type deviceTokenBody struct {
	AgentID     string `json:"agent_id"`
	Secret      string `json:"secret"`
	DeviceToken string `json:"device_token"`
}

// send makes one delivery attempt. The token and secret are NEVER logged: on a
// transport error the request body is not in the message, and no path here logs
// the value.
func (t *tokenRelay) send(ctx context.Context, body []byte) relayOutcome {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		t.log.Error("device token request build failed", "error", err.Error())
		return relayDone // unbuildable: retrying is pointless
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		t.log.Debug("device token send failed, will retry", "error", err.Error())
		return relayRetry
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		t.log.Info("device token relayed") // never the token itself
		return relayDone
	case resp.StatusCode == http.StatusTooManyRequests:
		t.log.Debug("device token throttled, will retry")
		return relayRetry
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// This payload will never succeed (401 = revoked/wrong secret); stop.
		t.log.Warn("device token rejected, dropping", "status", resp.StatusCode)
		return relayDone
	default:
		t.log.Debug("device token send failed, will retry", "status", resp.StatusCode)
		return relayRetry
	}
}
