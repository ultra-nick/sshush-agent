// Package rules evaluates alert rules against sampled metrics and emits
// state transitions. Duration is held entirely here, agent-side; the backend
// knows nothing about it and only ever hears that a rule transitioned.
package rules

import "time"

// InterfaceDownMetric is the one STATE rule: it breaches when the named
// interface is not up. Its sampled value is a display value (1 = up, 0 = down),
// not a magnitude, so its breach condition is "value is down", never a
// threshold comparison. This constant is what keeps that polarity in one place
// instead of scattered "interfaceDown" string checks.
const InterfaceDownMetric = "interfaceDown"

// Rule is one validated alert rule from config.json. The agent never
// interprets RuleID beyond relaying it; it is the phone's identifier.
type Rule struct {
	ID        string
	Metric    string
	Threshold float64
	Duration  time.Duration
	Label     string
}

// breaching reports whether a sampled value is in this rule's breach
// condition. Threshold rules breach strictly above their threshold; the
// interfaceDown state rule breaches when the interface is down (sampled as 0),
// with the threshold ignored entirely. Extracting this predicate is what lets
// the state rule share every other part of the engine - duration, reporting,
// transitions - without being forced into the threshold shape.
func (r Rule) breaching(v float64) bool {
	if r.Metric == InterfaceDownMetric {
		return v < 1 // 0 = down = breach; 1 = up (or unknown) = clear
	}
	return v > r.Threshold
}

// Event is one state transition to report.
type Event struct {
	Rule      Rule
	Direction string // "breach" or "clear"
	Value     float64
}

// Sampler returns the current value of a metric, or ok=false when there is
// no information this tick.
type Sampler func(metric, label string) (float64, bool)

// Engine tracks per-rule state across ticks. Not safe for concurrent use;
// the tick loop is the only caller.
type Engine struct {
	rules []Rule
	now   func() time.Time
	state map[string]*ruleState
}

type ruleState struct {
	// breached is the last state this process reported (or would report).
	breached bool
	// reported records whether ANY state has been sent for this rule since
	// startup. Rules start unreported, not silently "clear": the agent
	// cannot know what the backend last recorded (a previous process may
	// have reported breach, and the config that caused it may since have
	// changed), so the first settled determination of each rule is always
	// emitted once. The backend's state-change guard makes that free when
	// it is a duplicate and a genuine correction when it is not - without
	// it, raising a threshold over a breached value and restarting would
	// leave the backend claiming breach forever.
	reported bool
	// aboveSince is when the value first went above threshold in the
	// current excursion; zero when at or below.
	aboveSince time.Time
	// blindSince marks the start of the CURRENT unreadable stretch (zero =
	// the last evaluation had information). It bounds how much blind time an
	// excursion may credit (see maxBlindGap): aboveSince anchors to the wall
	// clock, so without a bound one breaching sample, an hours-long
	// unreadable stretch (a hung NFS mount), and one recovery-edge sample
	// would fire a "sustained" breach observed for only two ticks.
	blindSince time.Time
}

// maxBlindGap is the longest unreadable stretch an in-flight excursion may
// absorb before its timer restarts on the next reading. Short gaps (a couple
// of missed ticks) stay credited - decision 6's test pins a 30s blind step
// counting toward the duration - but a gap this long means nobody measured
// anything for most of the window, and "sustained" would be a claim about
// time the agent never observed.
const maxBlindGap = 60 * time.Second

// New builds an engine. Every rule starts unreported with no excursion.
func New(rules []Rule, now func() time.Time) *Engine {
	st := make(map[string]*ruleState, len(rules))
	for _, r := range rules {
		st[r.ID] = &ruleState{}
	}
	return &Engine{rules: rules, now: now, state: st}
}

// UpdateRules swaps in a new rule set, carrying per-rule state forward only
// where the excursion being measured is unchanged.
//
// A rule is carried over intact - keeping its breached/reported state AND its
// in-flight duration timer - exactly when a rule of the same id already in
// force has the same metric, threshold and label. Then a reload mid-excursion
// (say, the user changed an unrelated rule) does not reset a timer that is
// still measuring the same thing. Any change to what is measured or the bar it
// is measured against, and any genuinely new id, starts fresh: unreported with
// no excursion, exactly as at startup, so the reconciliation behaviour applies
// and the backend's guarded upsert makes a re-emitted duplicate free. Rules
// absent from the new set are dropped and stop being evaluated.
//
// Single-caller like the rest of the engine: the sample goroutine is the only
// thing that reloads and evaluates.
func (e *Engine) UpdateRules(newRules []Rule) {
	oldByID := make(map[string]Rule, len(e.rules))
	for _, r := range e.rules {
		oldByID[r.ID] = r
	}
	newState := make(map[string]*ruleState, len(newRules))
	for _, r := range newRules {
		if old, ok := oldByID[r.ID]; ok && sameExcursion(old, r) {
			newState[r.ID] = e.state[r.ID] // carry the existing state pointer
		} else {
			newState[r.ID] = &ruleState{}
		}
	}
	e.rules = newRules
	e.state = newState
}

// sameExcursion reports whether two rules with the same id measure the same
// thing against the same bar, so a mid-flight duration timer is still valid.
// Duration is deliberately excluded: changing only the required length does
// not change which excursion is being measured.
func sameExcursion(a, b Rule) bool {
	return a.Metric == b.Metric && a.Threshold == b.Threshold && a.Label == b.Label
}

// Rules returns the rule set currently in force. A read-only view for the
// reload path and tests; callers must not mutate it.
func (e *Engine) Rules() []Rule { return e.rules }

// Evaluate samples every rule's metric once and returns the transitions to
// report, in rule order. Rules whose metric yields no information this tick
// are untouched: their duration timers neither advance toward firing nor
// reset, because an unreadable metric is not evidence in either direction.
func (e *Engine) Evaluate(sample Sampler) []Event {
	var events []Event
	now := e.now()

	// One reading per distinct (metric, label) per tick, shared by every rule
	// on that metric. Delta-based samplers (cpu) keep previous-reading state
	// and are NOT idempotent within a tick: two cpu rules each calling the
	// sampler gave the first a proper ~10s window and the second a
	// microseconds window that the regression guard rejected almost every
	// tick - so the second rule silently never evaluated, never advanced its
	// duration, and never emitted its first determination. Memoizing also
	// makes multi-rule evaluation self-consistent: every rule on a metric
	// judges the SAME number.
	type sampled struct {
		v  float64
		ok bool
	}
	memo := make(map[[2]string]sampled, len(e.rules))
	sampleOnce := func(metric, label string) (float64, bool) {
		key := [2]string{metric, label}
		if m, done := memo[key]; done {
			return m.v, m.ok
		}
		v, ok := sample(metric, label)
		memo[key] = sampled{v, ok}
		return v, ok
	}

	for _, r := range e.rules {
		s := e.state[r.ID]
		v, ok := sampleOnce(r.Metric, r.Label)
		if !ok {
			// Record when this blind stretch began (first unreadable tick
			// after information), then leave everything else untouched.
			if s.blindSince.IsZero() {
				s.blindSince = now
			}
			continue
		}
		// Information again after a LONG blind stretch: invalidate the
		// in-flight excursion timer rather than crediting the unobserved
		// span (decision 6 - bounded crediting; see maxBlindGap). Short
		// stretches stay credited exactly as before.
		if !s.aboveSince.IsZero() && !s.blindSince.IsZero() &&
			now.Sub(s.blindSince) > maxBlindGap {
			s.aboveSince = time.Time{}
		}
		s.blindSince = time.Time{}

		if r.breaching(v) {
			// Slow to alarm: the value must stay in breach for the full
			// duration, measured from the start of this excursion. A single
			// non-breaching sample resets the excursion entirely - so a
			// flapping NIC with a 60s duration reports nothing, exactly as a
			// flapping threshold does.
			if s.aboveSince.IsZero() {
				s.aboveSince = now
			}
			if !s.breached && now.Sub(s.aboveSince) >= r.Duration {
				s.breached = true
				s.reported = true
				events = append(events, Event{Rule: r, Direction: "breach", Value: v})
			}
			continue
		}

		// Fast to reassure: one non-breaching sample ends a breach.
		s.aboveSince = time.Time{}
		if s.breached {
			s.breached = false
			s.reported = true
			events = append(events, Event{Rule: r, Direction: "clear", Value: v})
		} else if !s.reported {
			s.reported = true
			events = append(events, Event{Rule: r, Direction: "clear", Value: v})
		}
	}
	return events
}
