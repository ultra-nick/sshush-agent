package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const hexA = "1111111111111111111111111111111111111111111111111111111111111111"
const hexB = "2222222222222222222222222222222222222222222222222222222222222222"

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestParseDeviceToken(t *testing.T) {
	cases := []struct {
		name       string
		raw        string // the JSON value; "" means the field is absent
		wantIntent tokenIntent
		wantToken  string
	}{
		{"absent", "", tokenAbsent, ""},
		{"null", "null", tokenClear, ""},
		{"null padded", "  null ", tokenClear, ""},
		{"empty string", `""`, tokenClear, ""},
		{"valid", `"` + hexA + `"`, tokenSet, hexA},
		{"valid uppercase", `"` + strings.ToUpper(hexA) + `"`, tokenSet, strings.ToUpper(hexA)},
		{"too short", `"` + hexA[:63] + `"`, tokenMalformed, ""},
		{"too long", `"` + hexA + `a"`, tokenMalformed, ""},
		{"non-hex", `"` + strings.Repeat("g", 64) + `"`, tokenMalformed, ""},
		{"not a string", `12345`, tokenMalformed, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var raw json.RawMessage
			if c.raw != "" {
				raw = json.RawMessage(c.raw)
			}
			intent, token := parseDeviceToken(raw)
			if intent != c.wantIntent || token != c.wantToken {
				t.Errorf("parseDeviceToken(%q) = (%v, %q), want (%v, %q)",
					c.raw, intent, token, c.wantIntent, c.wantToken)
			}
		})
	}
}

// recorder is a test backend that captures every posted body and can be told to
// fail the first N attempts.
type recorder struct {
	mu       sync.Mutex
	bodies   []deviceTokenBody
	failNext int // return 500 for this many attempts, then 200
	status4  int // if non-zero, return this 4xx on every attempt
}

func (r *recorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var b deviceTokenBody
		_ = json.NewDecoder(req.Body).Decode(&b)
		r.mu.Lock()
		r.bodies = append(r.bodies, b)
		fail := r.failNext > 0
		if fail {
			r.failNext--
		}
		s4 := r.status4
		r.mu.Unlock()
		switch {
		case s4 != 0:
			w.WriteHeader(s4)
		case fail:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}
}

func (r *recorder) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.bodies) }
func (r *recorder) last() deviceTokenBody {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bodies[len(r.bodies)-1]
}

func newTestRelay(t *testing.T, rec *recorder) (*tokenRelay, func()) {
	t.Helper()
	srv := httptest.NewServer(rec.handler())
	relay, err := newTokenRelay(srv.URL+"/v1/beat", "agent-1", "secret-1", srv.Client(), discardLog())
	if err != nil {
		t.Fatalf("newTokenRelay: %v", err)
	}
	// The endpoint must be the derived device-token path, not the beat path.
	if !strings.HasSuffix(relay.endpoint, "/v1/device-token") {
		t.Fatalf("endpoint = %q, want .../v1/device-token", relay.endpoint)
	}
	return relay, srv.Close
}

func TestRelayValidTokenRelayedOnce(t *testing.T) {
	rec := &recorder{}
	relay, done := newTestRelay(t, rec)
	defer done()

	relay.setDesired(tokenSet, hexA)
	relay.flush(context.Background())
	relay.flush(context.Background())
	relay.flush(context.Background())

	if rec.count() != 1 {
		t.Fatalf("posts = %d, want 1", rec.count())
	}
	got := rec.last()
	if got.AgentID != "agent-1" || got.Secret != "secret-1" || got.DeviceToken != hexA {
		t.Errorf("body = %+v, want agent-1/secret-1/%s", got, hexA)
	}
}

func TestRelayUnchangedAcrossReloadsSendsOnce(t *testing.T) {
	rec := &recorder{}
	relay, done := newTestRelay(t, rec)
	defer done()

	// The file is reloaded repeatedly with the same token; the relay must send
	// exactly once, not once per reload.
	for i := 0; i < 5; i++ {
		relay.setDesired(tokenSet, hexA)
		relay.flush(context.Background())
	}
	if rec.count() != 1 {
		t.Fatalf("posts = %d, want 1", rec.count())
	}
}

func TestRelayChangedValueRelaysAgain(t *testing.T) {
	rec := &recorder{}
	relay, done := newTestRelay(t, rec)
	defer done()

	relay.setDesired(tokenSet, hexA)
	relay.flush(context.Background())
	relay.setDesired(tokenSet, hexB)
	relay.flush(context.Background())

	if rec.count() != 2 {
		t.Fatalf("posts = %d, want 2", rec.count())
	}
	if rec.last().DeviceToken != hexB {
		t.Errorf("last token = %s, want %s", rec.last().DeviceToken, hexB)
	}
}

func TestRelayAbsentDoesNothing(t *testing.T) {
	rec := &recorder{}
	relay, done := newTestRelay(t, rec)
	defer done()

	// Absent on a fresh relay: nothing to send.
	relay.setDesired(tokenAbsent, "")
	relay.flush(context.Background())
	if rec.count() != 0 {
		t.Fatalf("posts = %d, want 0 for absent", rec.count())
	}

	// After a value is sent, absent must NOT resend or clear it.
	relay.setDesired(tokenSet, hexA)
	relay.flush(context.Background())
	relay.setDesired(tokenAbsent, "")
	relay.flush(context.Background())
	if rec.count() != 1 {
		t.Fatalf("posts = %d, want 1 (absent left the prior value untouched)", rec.count())
	}
}

func TestRelayClearRelayed(t *testing.T) {
	rec := &recorder{}
	relay, done := newTestRelay(t, rec)
	defer done()

	relay.setDesired(tokenClear, "")
	relay.flush(context.Background())

	if rec.count() != 1 {
		t.Fatalf("posts = %d, want 1", rec.count())
	}
	if rec.last().DeviceToken != "" {
		t.Errorf("clear token = %q, want empty", rec.last().DeviceToken)
	}
}

func TestRelayMalformedKeepsPrevious(t *testing.T) {
	rec := &recorder{}
	relay, done := newTestRelay(t, rec)
	defer done()

	// Malformed on a fresh relay: nothing sent.
	relay.setDesired(tokenMalformed, "")
	relay.flush(context.Background())
	if rec.count() != 0 {
		t.Fatalf("posts = %d, want 0 for malformed", rec.count())
	}

	// A live token, then a malformed reload: the live token stays, nothing new.
	relay.setDesired(tokenSet, hexA)
	relay.flush(context.Background())
	relay.setDesired(tokenMalformed, "")
	relay.flush(context.Background())
	if rec.count() != 1 {
		t.Fatalf("posts = %d, want 1 (malformed kept the previous)", rec.count())
	}
}

func TestRelayFailedPostRetriedNextTick(t *testing.T) {
	rec := &recorder{failNext: 1} // first attempt 500, then 200
	relay, done := newTestRelay(t, rec)
	defer done()

	relay.setDesired(tokenSet, hexA)
	relay.flush(context.Background()) // 500 -> retry, not yet delivered
	relay.flush(context.Background()) // 200 -> delivered
	relay.flush(context.Background()) // nothing more to do

	if rec.count() != 2 {
		t.Fatalf("posts = %d, want 2 (one failure, one success, then quiet)", rec.count())
	}
}

func TestRelay4xxDropsWithoutRetryLoop(t *testing.T) {
	rec := &recorder{status4: http.StatusBadRequest}
	relay, done := newTestRelay(t, rec)
	defer done()

	relay.setDesired(tokenSet, hexA)
	relay.flush(context.Background()) // 400 -> dropped, will not retry
	relay.flush(context.Background())
	relay.flush(context.Background())

	if rec.count() != 1 {
		t.Fatalf("posts = %d, want 1 (a 4xx is dropped, not retried forever)", rec.count())
	}
}

func TestRelayRestartResendsOnce(t *testing.T) {
	rec := &recorder{}
	// A fresh relay models a restart: lastSent is nil, so the current token is
	// re-sent exactly once.
	relay, done := newTestRelay(t, rec)
	defer done()

	relay.setDesired(tokenSet, hexA)
	relay.flush(context.Background())
	relay.flush(context.Background())

	if rec.count() != 1 {
		t.Fatalf("posts = %d, want 1 on restart", rec.count())
	}
}
