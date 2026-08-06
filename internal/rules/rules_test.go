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

// --- interfaceDown: the state rule shares all the engine machinery ---

// newInterfaceHarness drives an interfaceDown rule. The sampled value is the
// display value: 1 = up, 0 = down. Threshold is ignored for state rules.
func newInterfaceHarness(duration time.Duration) *harness {
	h := &harness{clock: time.Unix(1_700_000_000, 0), tick: 30 * time.Second}
	r := Rule{ID: ruleID, Metric: InterfaceDownMetric, Threshold: 0, Duration: duration}
	h.engine = New([]Rule{r}, func() time.Time { return h.clock })
	return h
}

func TestInterfaceDownStatePolarity(t *testing.T) {
	// duration 0: down fires immediately, up clears on first sample. The
	// polarity is the whole point - a naive v>threshold with threshold 0
	// would breach when UP (value 1), which is backwards.
	h := newInterfaceHarness(0)

	// Startup while up: one clear (the first determination), then quiet.
	if got := count(h.step(1, true), "clear"); got != 1 {
		t.Fatalf("up at startup = %d clear events, want 1", got)
	}
	// Interface goes down: breach.
	if got := count(h.step(0, true), "breach"); got != 1 {
		t.Fatalf("down = %d breach events, want 1", got)
	}
	// Comes back up: clear.
	if got := count(h.step(1, true), "clear"); got != 1 {
		t.Fatalf("back up = %d clear events, want 1", got)
	}
	// Stays up: nothing.
	for i := 0; i < 3; i++ {
		if evs := h.step(1, true); len(evs) != 0 {
			t.Fatalf("staying up produced %v", evs)
		}
	}
}

func TestInterfaceDownRespectsDuration(t *testing.T) {
	// duration 120s, tick 30s: a NIC must be continuously down for the full
	// window before it fires - exactly as a threshold rule gates.
	h := newInterfaceHarness(120 * time.Second)
	h.settle(1) // start up, consume the first-determination clear

	fired := 0
	for i := 0; i < 4; i++ { // down at t=+0,+30,+60,+90: elapsed < 120 on entry
		fired += count(h.step(0, true), "breach")
	}
	if fired != 0 {
		t.Fatalf("breach fired %d times before the down-duration elapsed", fired)
	}
	if got := count(h.step(0, true), "breach"); got != 1 { // elapsed 120
		t.Fatalf("breach after duration = %d, want 1", got)
	}
}

func TestInterfaceDownFlapResetsTheTimer(t *testing.T) {
	// A flapping NIC with a duration reports nothing: one sample back up
	// resets the down excursion completely.
	h := newInterfaceHarness(120 * time.Second)
	h.settle(1)

	h.step(0, true) // down, timer starts
	h.step(0, true)
	h.step(1, true) // flaps up: timer must fully reset
	fired := 0
	for i := 0; i < 4; i++ {
		fired += count(h.step(0, true), "breach")
	}
	if fired != 0 {
		t.Fatalf("flap did not reset the down timer; breach fired %d times", fired)
	}
}

func TestInterfaceDownMissingIsNoEvidence(t *testing.T) {
	// ok=false (interface absent) must neither start nor reset the excursion,
	// same as any unreadable metric.
	h := newInterfaceHarness(120 * time.Second)
	h.settle(1)

	h.step(0, true)  // down, timer starts
	h.step(0, false) // absent: no information, must not reset
	h.step(0, true)  // still down
	h.step(0, true)  // elapsed toward 120 from the first down
	if got := count(h.step(0, true), "breach"); got != 1 {
		t.Fatalf("breach after duration with an absent gap = %d, want 1", got)
	}
}

// interfaceDown participates in startup reconciliation exactly like a
// threshold rule: the first settled determination is emitted once, in
// whichever direction it lands.
func TestInterfaceDownStartupReconciliation(t *testing.T) {
	// Down at startup, duration 0: first determination is a breach.
	down := newInterfaceHarness(0)
	if got := count(down.step(0, true), "breach"); got != 1 {
		t.Fatalf("down at startup = %d breach events, want 1 (first determination)", got)
	}
	if evs := down.step(0, true); len(evs) != 0 {
		t.Fatalf("startup breach repeated: %v", evs)
	}

	// Up at startup: first determination is a clear, then silence.
	up := newInterfaceHarness(0)
	if got := count(up.step(1, true), "clear"); got != 1 {
		t.Fatalf("up at startup = %d clear events, want 1", got)
	}
	if evs := up.step(1, true); len(evs) != 0 {
		t.Fatalf("startup clear repeated: %v", evs)
	}
}
