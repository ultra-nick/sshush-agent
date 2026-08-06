package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const hexA = "1111111111111111111111111111111111111111111111111111111111111111"
const hexB = "2222222222222222222222222222222222222222222222222222222222222222"

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestParseTokenFile(t *testing.T) {
	cases := []struct {
		name       string
		content    string // the file's raw bytes (absence is the caller's stat, not here)
		wantIntent tokenIntent
		wantToken  string
	}{
		{"empty file", "", tokenClear, ""},
		{"whitespace only", " \n\t ", tokenClear, ""},
		{"valid", hexA, tokenSet, hexA},
		{"valid with trailing newline", hexA + "\n", tokenSet, hexA},
		{"valid uppercase", strings.ToUpper(hexA), tokenSet, strings.ToUpper(hexA)},
		{"too short", hexA[:63], tokenMalformed, ""},
		{"too long", hexA + "a", tokenMalformed, ""},
		{"non-hex", strings.Repeat("g", 64), tokenMalformed, ""},
		{"multiline garbage", hexA + "\nextra", tokenMalformed, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			intent, token := parseTokenFile([]byte(c.content))
			if intent != c.wantIntent || token != c.wantToken {
				t.Errorf("parseTokenFile(%q) = (%v, %q), want (%v, %q)",
					c.content, intent, token, c.wantIntent, c.wantToken)
			}
		})
	}
}

// The watcher end of the pipeline: file lifecycle drives the relay's desire.
func TestTokenFileWatcher(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/device_token"
	relay := &tokenRelay{log: discardLog()}
	w := &tokenFileWatcher{path: path, log: discardLog(), relay: relay}

	// Absent file: nothing to communicate.
	w.check()
	if relay.desired != nil {
		t.Fatal("absent file must not set a desire")
	}

	// A token appears (e.g. written while the agent was stopped).
	writeFile(t, path, hexA)
	w.check()
	if relay.desired == nil || *relay.desired != hexA {
		t.Fatalf("desired = %v, want %q", relay.desired, hexA)
	}

	// Malformed rewrite: keep the previous token, do not clear.
	writeFile(t, path, "not-a-token")
	w.check()
	if relay.desired == nil || *relay.desired != hexA {
		t.Fatal("malformed file must keep the previous desire")
	}

	// Emptied file: an explicit clear.
	writeFile(t, path, "")
	w.check()
	if relay.desired == nil || *relay.desired != "" {
		t.Fatal("empty file must set an explicit clear")
	}

	// Deleting the file is ABSENT, not clear: the desire stays as it was.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.check()
	if relay.desired == nil || *relay.desired != "" {
		t.Fatal("removing the file must not change the desire")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	// A fresh mtime each write: some filesystems have coarse mtime granularity,
	// and the watcher is mtime-gated. Chtimes makes the change unmissable.
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mtimeBump = mtimeBump + time.Second
	if err := os.Chtimes(path, now, now.Add(mtimeBump)); err != nil {
		t.Fatal(err)
	}
}

var mtimeBump time.Duration

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
