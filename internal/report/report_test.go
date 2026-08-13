package report

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ultra-nick/sshush-agent/internal/rules"
)

const testSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func testEvent(direction string) []rules.Event {
	return []rules.Event{{
		Rule: rules.Rule{
			ID:        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			Metric:    "disk",
			Threshold: 85,
			Label:     "/",
		},
		Direction: direction,
		Value:     91.5,
	}}
}

// script is a controllable backend: each request appends its body and pops
// the next status from the queue (repeating the last one).
type script struct {
	mu       sync.Mutex
	statuses []int
	bodies   [][]byte
}

func (s *script) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	s.bodies = append(s.bodies, body)
	status := s.statuses[0]
	if len(s.statuses) > 1 {
		s.statuses = s.statuses[1:]
	}
	w.WriteHeader(status)
	if status == http.StatusOK {
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}
}

func (s *script) seqs(t *testing.T) []int64 {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []int64
	for _, b := range s.bodies {
		var req struct {
			Seq int64 `json:"seq"`
		}
		if err := json.Unmarshal(b, &req); err != nil {
			t.Fatalf("request body not json: %v", err)
		}
		out = append(out, req.Seq)
	}
	return out
}

func newTestReporter(url string, clock *time.Time) *Reporter {
	r := New(url, "6ba7b810-9dad-11d1-80b4-00c04fd430c8", testSecret,
		&http.Client{Timeout: 2 * time.Second},
		slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	r.now = func() time.Time { return *clock }
	return r
}

// The adopted high-water is clamped to plausibility: MaxInt64 from a hostile
// or corrupt backend would wrap the next increment negative and persist the
// garbage; non-positive values are noise. Plausible values still adopt.
func TestAdoptSeqClampsImplausible(t *testing.T) {
	clock := time.Unix(5000, 0)
	r := newTestReporter("http://unused.invalid", &clock)
	r.lastSeq = 5000

	r.adoptSeq(math.MaxInt64)
	r.adoptSeq(-3)
	r.adoptSeq(0)
	if r.lastSeq != 5000 {
		t.Fatalf("implausible backend seq adopted: lastSeq = %d", r.lastSeq)
	}
	r.adoptSeq(6000)
	if r.lastSeq != 6000 {
		t.Fatalf("plausible backend seq not adopted: lastSeq = %d", r.lastSeq)
	}
}

func TestSeqStrictlyIncreasing(t *testing.T) {
	clock := time.Unix(5000, 0)
	r := newTestReporter("http://unused.invalid", &clock)

	// Three builds in the same second: 5000, 5001, 5002.
	a, b, c := r.nextSeq(), r.nextSeq(), r.nextSeq()
	if a != 5000 || b != 5001 || c != 5002 {
		t.Fatalf("same-second seqs = %d,%d,%d, want 5000,5001,5002", a, b, c)
	}

	// Clock steps backwards (NTP): never at or below the last sent.
	clock = time.Unix(4000, 0)
	d := r.nextSeq()
	if d != 5003 {
		t.Fatalf("seq after backward clock step = %d, want 5003", d)
	}

	// Clock ahead again: back to timestamp-derived.
	clock = time.Unix(6000, 0)
	if e := r.nextSeq(); e != 6000 {
		t.Fatalf("seq after clock recovers = %d, want 6000", e)
	}
}

func TestRetryReusesOriginalSeqAndBytes(t *testing.T) {
	sc := &script{statuses: []int{500, 500, 200}}
	srv := httptest.NewServer(http.HandlerFunc(sc.handler))
	defer srv.Close()

	clock := time.Unix(5000, 0)
	r := newTestReporter(srv.URL, &clock)
	r.Enqueue(testEvent("breach"), nil)

	for i := 0; i < 3; i++ {
		clock = clock.Add(31 * time.Second) // time passes between ticks
		r.Flush(context.Background())
	}
	if r.Pending() != 0 {
		t.Fatalf("pending = %d after success, want 0", r.Pending())
	}
	if len(sc.bodies) != 3 {
		t.Fatalf("attempts = %d, want 3", len(sc.bodies))
	}
	// Same seq AND byte-identical body on every attempt, despite the clock
	// having moved: the request was frozen at build time.
	for i := 1; i < 3; i++ {
		if string(sc.bodies[i]) != string(sc.bodies[0]) {
			t.Fatalf("attempt %d body differs from the original", i)
		}
	}
	if seqs := sc.seqs(t); seqs[0] != 5000 {
		t.Fatalf("seq = %d, want 5000 (build-time, not send-time)", seqs[0])
	}
}

func TestNewTransitionGetsNewSeqOldKeepsOld(t *testing.T) {
	sc := &script{statuses: []int{500}} // backend down throughout
	srv := httptest.NewServer(http.HandlerFunc(sc.handler))
	defer srv.Close()

	clock := time.Unix(5000, 0)
	r := newTestReporter(srv.URL, &clock)
	r.Enqueue(testEvent("breach"), nil)
	r.Flush(context.Background()) // fails, stays queued

	clock = time.Unix(5060, 0)
	r.Enqueue(testEvent("clear"), nil) // separate request, its own seq
	if r.Pending() != 2 {
		t.Fatalf("pending = %d, want 2 (never merged into the committed request)", r.Pending())
	}

	// Backend returns: both deliver, oldest first.
	sc.mu.Lock()
	sc.statuses = []int{200}
	sc.mu.Unlock()
	r.Flush(context.Background())
	if r.Pending() != 0 {
		t.Fatalf("pending = %d after recovery, want 0", r.Pending())
	}
	seqs := sc.seqs(t)
	last2 := seqs[len(seqs)-2:]
	if !(last2[0] == 5000 && last2[1] == 5060) {
		t.Fatalf("delivery order = %v, want oldest first [5000 5060]", last2)
	}
}

func TestFlushStopsAtFirstRetryableFailure(t *testing.T) {
	// Two queued; backend down. Exactly ONE attempt per flush: delivering
	// (or even attempting) the newer past the older would invert seq order,
	// and a later-delivered older request would be swallowed as stale.
	sc := &script{statuses: []int{500}}
	srv := httptest.NewServer(http.HandlerFunc(sc.handler))
	defer srv.Close()

	clock := time.Unix(5000, 0)
	r := newTestReporter(srv.URL, &clock)
	r.Enqueue(testEvent("breach"), nil)
	clock = time.Unix(5030, 0)
	r.Enqueue(testEvent("clear"), nil)

	r.Flush(context.Background())
	if len(sc.bodies) != 1 {
		t.Fatalf("attempts in one failed flush = %d, want 1 (FIFO must hold)", len(sc.bodies))
	}
	if r.Pending() != 2 {
		t.Fatalf("pending = %d, want 2", r.Pending())
	}
}

func TestPermanent4xxDropsOnlyThatRequest(t *testing.T) {
	sc := &script{statuses: []int{401, 200}}
	srv := httptest.NewServer(http.HandlerFunc(sc.handler))
	defer srv.Close()

	clock := time.Unix(5000, 0)
	r := newTestReporter(srv.URL, &clock)
	r.Enqueue(testEvent("breach"), nil)
	clock = time.Unix(5030, 0)
	r.Enqueue(testEvent("clear"), nil)

	r.Flush(context.Background())
	if r.Pending() != 0 {
		t.Fatalf("pending = %d, want 0 (401 dropped, next delivered)", r.Pending())
	}
	if len(sc.bodies) != 2 {
		t.Fatalf("attempts = %d, want 2", len(sc.bodies))
	}
}

func Test429IsRetryableNotADrop(t *testing.T) {
	sc := &script{statuses: []int{429}}
	srv := httptest.NewServer(http.HandlerFunc(sc.handler))
	defer srv.Close()

	clock := time.Unix(5000, 0)
	r := newTestReporter(srv.URL, &clock)
	r.Enqueue(testEvent("breach"), nil)
	r.Flush(context.Background())
	if r.Pending() != 1 {
		t.Fatalf("pending = %d after 429, want 1 (throttled is not rejected)", r.Pending())
	}
}

// (TestStaleBodyCountsAsDelivered is deliberately GONE: stale no longer
// counts as delivered. A stale verdict means the backend refused the events
// and never will accept them at that seq - counting it as delivered silently
// lost every post-restart report on a clock-regressed host. See
// TestStaleResponseAdoptsAndResends / TestStaleTwiceDrops for the current
// contract.)

func TestQueueCapDropsOldest(t *testing.T) {
	clock := time.Unix(5000, 0)
	r := newTestReporter("http://unused.invalid", &clock)

	for i := 0; i < maxQueue+4; i++ {
		r.Enqueue(testEvent("breach"), nil)
	}
	if r.Pending() != maxQueue {
		t.Fatalf("pending = %d, want %d", r.Pending(), maxQueue)
	}
	// The survivors are the NEWEST 16: seqs 5004..5019, oldest 4 dropped.
	if r.queue[0].seq != 5004 {
		t.Fatalf("oldest surviving seq = %d, want 5004 (drop the oldest, keep the newest)", r.queue[0].seq)
	}
	if r.queue[len(r.queue)-1].seq != 5019 {
		t.Fatalf("newest surviving seq = %d, want 5019", r.queue[len(r.queue)-1].seq)
	}
}

// The wire request names the agent's full current rule set - the backend's
// rule-removal signal.
func TestEnqueueCarriesRuleIDs(t *testing.T) {
	var got wireRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()
	clock := time.Unix(3_000_000_000, 0)
	r := newTestReporter(srv.URL, &clock)
	r.Enqueue(testEvent("breach"), []string{"6ba7b810-9dad-11d1-80b4-00c04fd430c8", "00000000-0000-4000-8000-00000000000c"})
	r.Flush(context.Background())
	if len(got.RuleIDs) != 2 {
		t.Fatalf("rule_ids = %v, want the 2 current rules", got.RuleIDs)
	}
}

// The stale self-heal: a clock regressed across a restart produces a seq at
// or below the backend's high-water mark. The old behaviour counted the
// stale 2xx as delivered and silently lost the events; now the backend's
// last_seq is adopted and the SAME events are re-sent under a fresh seq.
func TestStaleResponseAdoptsAndResends(t *testing.T) {
	type gotReq struct {
		seq    int64
		events int
	}
	var reqs []gotReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var wire wireRequest
		_ = json.Unmarshal(body, &wire)
		reqs = append(reqs, gotReq{wire.Seq, len(wire.Events)})
		if wire.Seq <= 5000 { // the backend's high-water mark
			_, _ = w.Write([]byte(`{"stale":true,"last_seq":5000}`))
			return
		}
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()

	clock := time.Unix(1000, 0) // regressed WAY behind the mark
	r := newTestReporter(srv.URL, &clock)
	r.Enqueue(testEvent("breach"), nil)
	r.Flush(context.Background())

	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want stale then re-send", len(reqs))
	}
	if reqs[0].seq != 1000 {
		t.Errorf("first seq = %d, want the clock's 1000", reqs[0].seq)
	}
	if reqs[1].seq != 5001 {
		t.Errorf("re-sent seq = %d, want 5001 (adopted mark + 1)", reqs[1].seq)
	}
	if reqs[1].events != reqs[0].events {
		t.Errorf("re-send changed the events: %d vs %d", reqs[1].events, reqs[0].events)
	}
	if r.Pending() != 0 {
		t.Errorf("queue = %d, want drained", r.Pending())
	}
}

// One rebuild per request, so a backend that answers stale for ever cannot
// wedge the queue.
func TestStaleTwiceDrops(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"stale":true}`)) // old backend: no last_seq either
	}))
	defer srv.Close()
	clock := time.Unix(1000, 0)
	r := newTestReporter(srv.URL, &clock)
	r.Enqueue(testEvent("breach"), nil)
	r.Flush(context.Background())
	if calls != 2 {
		t.Errorf("attempts = %d, want exactly 2 (original + one rebuild)", calls)
	}
	if r.Pending() != 0 {
		t.Errorf("queue = %d, want the wedged request dropped", r.Pending())
	}
}

// The durable high-water mark: a new Reporter over the same seqPath resumes
// past the previous process's last seq even when the clock regressed.
func TestSeqPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last_seq")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()

	clock := time.Unix(9_000, 0)
	r1 := New(srv.URL, "6ba7b810-9dad-11d1-80b4-00c04fd430c8", testSecret,
		&http.Client{Timeout: 2 * time.Second},
		slog.New(slog.NewTextHandler(io.Discard, nil)), path)
	r1.now = func() time.Time { return clock }
	r1.Enqueue(testEvent("breach"), nil) // seq 9000, persisted
	r1.Flush(context.Background())

	// "Restart" with the clock regressed to 100.
	regressed := time.Unix(100, 0)
	r2 := New(srv.URL, "6ba7b810-9dad-11d1-80b4-00c04fd430c8", testSecret,
		&http.Client{Timeout: 2 * time.Second},
		slog.New(slog.NewTextHandler(io.Discard, nil)), path)
	r2.now = func() time.Time { return regressed }
	if got := r2.nextSeq(); got != 9001 {
		t.Errorf("post-restart seq = %d, want 9001 (stored mark + 1, not the regressed clock)", got)
	}
}

// A reconcile (rule removal with nothing else to say) freezes an events-EMPTY
// request that still carries rule_ids - "events":[] on the wire, never null,
// so the backend's reconcile branch (empty events + rule_ids present) matches.
func TestEnqueueReconcileFreezesEmptyEvents(t *testing.T) {
	clock := time.Unix(5000, 0)
	r := newTestReporter("http://unused.invalid", &clock)

	r.EnqueueReconcile([]string{"6ba7b810-9dad-11d1-80b4-00c04fd430c8"})
	if r.Pending() != 1 {
		t.Fatalf("pending = %d, want the reconcile queued", r.Pending())
	}
	var wire struct {
		Events  []json.RawMessage `json:"events"`
		RuleIDs []string          `json:"rule_ids"`
	}
	if err := json.Unmarshal(r.queue[0].body, &wire); err != nil {
		t.Fatalf("frozen body not json: %v", err)
	}
	if wire.Events == nil || len(wire.Events) != 0 {
		t.Fatalf("events = %v, want present-and-empty", wire.Events)
	}
	if len(wire.RuleIDs) != 1 {
		t.Fatalf("rule_ids = %v, want the current set", wire.RuleIDs)
	}
}
