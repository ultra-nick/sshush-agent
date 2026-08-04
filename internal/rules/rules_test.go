package rules

import (
	"testing"
	"time"
)

const ruleID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

// harness drives one rule through a scripted series of ticks.
type harness struct {
	engine *Engine
	clock  time.Time
	tick   time.Duration
}

func newHarness(threshold float64, duration time.Duration) *harness {
	h := &harness{
		clock: time.Unix(1_700_000_000, 0),
		tick:  30 * time.Second,
	}
	r := Rule{ID: ruleID, Metric: "cpu", Threshold: threshold, Duration: duration}
	h.engine = New([]Rule{r}, func() time.Time { return h.clock })
	return h
}

// step advances one tick and evaluates with the given sample. ok=false
// models an unreadable metric.
func (h *harness) step(v float64, ok bool) []Event {
	events := h.engine.Evaluate(func(string, string) (float64, bool) { return v, ok })
	h.clock = h.clock.Add(h.tick)
	return events
}

// settle consumes the one-time startup report (first determination) so the
// steady-state cases can assert on transitions alone.
func (h *harness) settle(v float64) {
	h.step(v, true)
}

func count(events []Event, direction string) int {
	n := 0
	for _, e := range events {
		if e.Direction == direction {
			n++
		}
	}
	return n
}

func TestBelowThresholdNeverFires(t *testing.T) {
	h := newHarness(90, 0)
	h.settle(10)
	for i := 0; i < 10; i++ {
		if evs := h.step(10, true); len(evs) != 0 {
			t.Fatalf("tick %d: events %v from a value below threshold", i, evs)
		}
	}
}

func TestDurationGatesTheBreach(t *testing.T) {
	// duration 120s, tick 30s: above at t0, fires when elapsed >= 120.
	h := newHarness(90, 120*time.Second)
	h.settle(10)

	fired := 0
	for i := 0; i < 4; i++ { // t=+0,+30,+60,+90: elapsed < 120 on entry
		fired += count(h.step(95, true), "breach")
	}
	if fired != 0 {
		t.Fatalf("breach fired %d times before duration elapsed", fired)
	}
	if got := count(h.step(95, true), "breach"); got != 1 { // elapsed 120
		t.Fatalf("breach after duration = %d events, want exactly 1", got)
	}
	// Still above: no repeats.
	for i := 0; i < 5; i++ {
		if evs := h.step(96, true); len(evs) != 0 {
			t.Fatalf("repeat transition while state unchanged: %v", evs)
		}
	}
}

func TestDipBelowResetsTheTimer(t *testing.T) {
	h := newHarness(90, 120*time.Second)
	h.settle(10)

	h.step(95, true) // above, timer starts
	h.step(95, true)
	h.step(50, true) // dips below: timer must fully reset
	fired := 0
	for i := 0; i < 4; i++ { // above again for 90s of elapsed time on entry
		fired += count(h.step(95, true), "breach")
	}
	if fired != 0 {
		t.Fatalf("breach fired %d times; the dip must reset the window completely", fired)
	}
	if got := count(h.step(95, true), "breach"); got != 1 {
		t.Fatalf("breach after full fresh window = %d, want 1", got)
	}
}

func TestClearFiresOnFirstSampleBelow(t *testing.T) {
	h := newHarness(90, 0)
	h.settle(10)

	if got := count(h.step(95, true), "breach"); got != 1 {
		t.Fatalf("duration 0 must fire on first breach, got %d", got)
	}
	// One sample below is enough - no clear-side duration.
	evs := h.step(89.9, true)
	if got := count(evs, "clear"); got != 1 {
		t.Fatalf("clear on first sample below = %d events, want 1 (%v)", got, evs)
	}
	// And no repeats while it stays below.
	for i := 0; i < 5; i++ {
		if evs := h.step(10, true); len(evs) != 0 {
			t.Fatalf("repeat clear while state unchanged: %v", evs)
		}
	}
}

func TestDurationZeroFiresImmediately(t *testing.T) {
	h := newHarness(90, 0)
	h.settle(10)
	if got := count(h.step(90.1, true), "breach"); got != 1 {
		t.Fatalf("duration_s=0 first breach = %d events, want 1", got)
	}
}

func TestExactlyAtThresholdIsNotAbove(t *testing.T) {
	h := newHarness(90, 0)
	h.settle(10)
	if evs := h.step(90.0, true); len(evs) != 0 {
		t.Fatalf("value exactly at threshold produced %v; above means strictly greater", evs)
	}
}

func TestUnreadableMetricIsNoEvidence(t *testing.T) {
	h := newHarness(90, 120*time.Second)
	h.settle(10)

	h.step(95, true)        // above, timer starts
	h.step(0, false)        // unreadable: must not reset the timer...
	h.step(95, true)        // ...and must not have advanced state either
	h.step(95, true)        // elapsed 90s... timer started at first above
	evs := h.step(95, true) // elapsed 120s from first above
	if got := count(evs, "breach"); got != 1 {
		t.Fatalf("breach after duration with an unreadable gap = %d, want 1", got)
	}

	// Unreadable while breached: no clear. No information is not good news.
	if evs := h.step(0, false); len(evs) != 0 {
		t.Fatalf("unreadable metric produced events while breached: %v", evs)
	}
}

func TestStartupFirstDeterminationIsReportedOnce(t *testing.T) {
	// Below threshold at startup: exactly one clear (the startup report),
	// then silence. This is what reconciles the backend after a restart
	// changed the rules out from under a recorded breach.
	h := newHarness(90, 0)
	evs := h.step(10, true)
	if got := count(evs, "clear"); got != 1 {
		t.Fatalf("first determination = %d clear events, want exactly 1", got)
	}
	for i := 0; i < 5; i++ {
		if evs := h.step(10, true); len(evs) != 0 {
			t.Fatalf("startup report repeated: %v", evs)
		}
	}

	// Above at startup with a duration: no startup clear, and the breach
	// (when duration elapses) is the first report. Timer runs from the
	// first sample, so an already-breached condition at boot fires
	// duration_s after startup - deliberately not special-cased.
	h2 := newHarness(90, 60*time.Second)
	if evs := h2.step(95, true); len(evs) != 0 {
		t.Fatalf("above-at-boot produced early events: %v", evs)
	}
	h2.step(95, true)       // elapsed 30
	evs = h2.step(95, true) // elapsed 60
	if got := count(evs, "breach"); got != 1 {
		t.Fatalf("boot-breached rule after duration = %d breach events, want 1", got)
	}

	// Above at startup but dropping below before duration: the clear that
	// follows is the (single) first report.
	h3 := newHarness(90, 120*time.Second)
	h3.step(95, true)
	evs = h3.step(10, true)
	if got := count(evs, "clear"); got != 1 {
		t.Fatalf("drop-below before first report = %d clear events, want 1", got)
	}
	if evs := h3.step(10, true); len(evs) != 0 {
		t.Fatalf("startup report repeated after drop-below: %v", evs)
	}
}

func TestBreachClearBreachIsThreeTransitions(t *testing.T) {
	h := newHarness(90, 0)
	h.settle(10)
	total := 0
	total += len(h.step(95, true)) // breach
	total += len(h.step(10, true)) // clear
	total += len(h.step(95, true)) // breach again
	if total != 3 {
		t.Fatalf("breach/clear/breach = %d transitions, want 3", total)
	}
}
