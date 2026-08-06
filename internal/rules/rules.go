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
}

// New builds an engine. Every rule starts unreported with no excursion.
func New(rules []Rule, now func() time.Time) *Engine {
	st := make(map[string]*ruleState, len(rules))
	for _, r := range rules {
		st[r.ID] = &ruleState{}
	}
	return &Engine{rules: rules, now: now, state: st}
}

// Evaluate samples every rule's metric once and returns the transitions to
// report, in rule order. Rules whose metric yields no information this tick
// are untouched: their duration timers neither advance toward firing nor
// reset, because an unreadable metric is not evidence in either direction.
func (e *Engine) Evaluate(sample Sampler) []Event {
	var events []Event
	now := e.now()

	for _, r := range e.rules {
		s := e.state[r.ID]
		v, ok := sample(r.Metric, r.Label)
		if !ok {
			continue
		}

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
