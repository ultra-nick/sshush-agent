package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

// The device-token relay. The app writes the phone's APNs token into its OWN
// user-owned file (/var/lib/sshush/device_token - an unprivileged write that
// works in every escalation case); the agent, which holds the secret, relays
// it to the backend on change only, authenticated like the breach path.
//
// The token deliberately does NOT live in rules.json: rules and the token have
// different writers with different lifecycles (the rules editor writes what
// the user just edited; the token sync fires on app launch and token change),
// and sharing a file forced the token writer to rewrite rules content it had
// no business owning - a device with a stale rules copy silently reverted the
// agent's rules while delivering a token. Separate files make that
// structurally impossible.
//
// A device token rots (restore-from-backup, some OS updates, revoked
// permission), and a stale token means pushes fire into the void for a user who
// believes they are covered. So the token is relayed whenever it changes, and a
// CLEAR (the user revoked permission) is relayed too - distinct from ABSENT
// (the app never wrote the file), or a dead token would linger for ever.

// tokenIntent is what the device_token file is asking for.
type tokenIntent int

const (
	tokenAbsent    tokenIntent = iota // no file: do nothing, keep backend state
	tokenClear                        // empty file: clear the backend's token
	tokenSet                          // a valid 64-hex token: relay it
	tokenMalformed                    // present but not valid: keep previous, warn
)

// parseTokenFile decodes the device_token file's CONTENT (absence of the file
// is decided by the caller's stat, not here): plain text, one value.
//
//	empty / whitespace  -> clear (the app revoked permission)
//	64 hex chars        -> relay that token
//	anything else       -> malformed: keep the previous token, warn
func parseTokenFile(content []byte) (tokenIntent, string) {
	s := string(bytes.TrimSpace(content))
	if s == "" {
		return tokenClear, ""
	}
	if isHex64(s) {
		return tokenSet, s
	}
	return tokenMalformed, ""
}

// tokenFileWatcher re-reads the device_token file when it changes and records
// the new desire on the relay (the POST itself happens on the sample tick via
// relay.flush, so transient failures retry). Same mtime gating as the rules
// watcher: a malformed file warns once per version, not once per tick.
type tokenFileWatcher struct {
	path  string
	log   *slog.Logger
	relay *tokenRelay

	present   bool
	lastMtime time.Time
}

func (w *tokenFileWatcher) check() {
	if w.relay == nil {
		return
	}
	info, err := os.Stat(w.path)
	if err != nil {
		// Absent = the app has never written one (or the dir is being torn
		// down): nothing to communicate, and NOT a clear - deleting the file
		// must never null a live token. Reset presence so re-creation re-reads.
		w.present = false
		return
	}
	if w.present && info.ModTime().Equal(w.lastMtime) {
		return // unchanged since the last read
	}
	// Record the version BEFORE parsing so a malformed file is warned once per
	// version, not every tick (same pattern as the rules watcher).
	w.present = true
	w.lastMtime = info.ModTime()

	content, err := os.ReadFile(w.path)
	if err != nil {
		w.log.Warn("device token file unreadable; keeping the previous token", "error", err.Error())
		return
	}
	intent, token := parseTokenFile(content)
	if intent == tokenMalformed {
		w.log.Warn("device token file is malformed; keeping the previous token")
		return
	}
	w.relay.setDesired(intent, token)
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

// setDesired updates what should be communicated from a freshly loaded token
// file. ABSENT leaves the current desire untouched (do nothing); MALFORMED keeps
// the previous value and warns - a bad parse must never clear a live token.
// Called only when the file actually changed (mtime-gated), so it does not spam.
func (t *tokenRelay) setDesired(intent tokenIntent, value string) {
	switch intent {
	case tokenAbsent:
		return
	case tokenMalformed:
		t.log.Warn("device token file is malformed; keeping the previous token")
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
