package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultra-nick/sshush-agent/internal/rules"
)

const goodRule = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

func TestValidateRules(t *testing.T) {
	valid := func() ruleConfig {
		return ruleConfig{RuleID: goodRule, Metric: "cpu", Threshold: 90, DurationS: 300}
	}

	tests := []struct {
		name     string
		mutate   func(*ruleConfig)
		extra    []ruleConfig
		wantHint string // must appear in the problem text, "" = valid
	}{
		{name: "valid rule", mutate: func(r *ruleConfig) {}},
		{name: "valid disk rule with label", mutate: func(r *ruleConfig) { r.Metric = "disk"; r.Label = "/" }},
		{name: "valid swap rule", mutate: func(r *ruleConfig) { r.Metric = "swap"; r.Threshold = 80 }},
		{name: "valid interfaceDown rule", mutate: func(r *ruleConfig) { r.Metric = "interfaceDown"; r.Label = "eth0"; r.Threshold = 0 }},
		{name: "bad uuid", mutate: func(r *ruleConfig) { r.RuleID = "nope" }, wantHint: "canonical hyphenated uuid"},
		{name: "bad metric", mutate: func(r *ruleConfig) { r.Metric = "uptime" }, wantHint: "not one of"},
		// net was removed: a config still carrying it must now fail validation.
		{name: "net metric removed", mutate: func(r *ruleConfig) { r.Metric = "net"; r.Label = "eth0" }, wantHint: "not one of"},
		{name: "negative duration", mutate: func(r *ruleConfig) { r.DurationS = -1 }, wantHint: "duration_s"},
		{name: "disk without label", mutate: func(r *ruleConfig) { r.Metric = "disk" }, wantHint: "label is required"},
		{name: "interfaceDown without label", mutate: func(r *ruleConfig) { r.Metric = "interfaceDown" }, wantHint: "label is required"},
		{name: "label too long", mutate: func(r *ruleConfig) { r.Label = strings.Repeat("x", 129) }, wantHint: "max 128"},
		{name: "label with control characters", mutate: func(r *ruleConfig) { r.Label = "bad\x01label" }, wantHint: "control characters"},
		// 30 raw bytes but 180 escaped (& -> \u0026): passes the raw cap,
		// must fail the escaped-length mirror of the backend's body cap.
		{name: "label too long JSON-escaped", mutate: func(r *ruleConfig) { r.Label = strings.Repeat("&", 30) }, wantHint: "JSON-escaped"},
		{
			name:     "duplicate rule_id",
			mutate:   func(r *ruleConfig) {},
			extra:    []ruleConfig{{RuleID: goodRule, Metric: "mem", Threshold: 80}},
			wantHint: "duplicate rule_id",
		},
		// The backend mirrors (audit round): each turns a silent 4xx-and-drop
		// on every future report into a loud reload-time refusal.
		{name: "duration overflow", mutate: func(r *ruleConfig) { r.DurationS = 10_000_000_000 }, wantHint: "duration_s"},
		{name: "threshold past backend bound", mutate: func(r *ruleConfig) { r.Threshold = 2e6 }, wantHint: "backend's bound"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := valid()
			tc.mutate(&r)
			problems := validateRules(append([]ruleConfig{r}, tc.extra...))

			if tc.wantHint == "" {
				if len(problems) != 0 {
					t.Fatalf("valid rule rejected: %v", problems)
				}
				return
			}
			if len(problems) == 0 {
				t.Fatal("invalid rule accepted; startup must fail non-zero")
			}
			joined := strings.Join(problems, "\n")
			if !strings.Contains(joined, tc.wantHint) {
				t.Errorf("problems %q do not mention %q", joined, tc.wantHint)
			}
			// Attributable to the specific rule: index and rule_id present.
			if !strings.Contains(joined, "rules[") || !strings.Contains(joined, "rule_id") {
				t.Errorf("problem not attributable to a rule: %q", joined)
			}
		})
	}
}

// Every problem is reported at once, not one per restart cycle.
func TestValidateRulesReportsAllProblems(t *testing.T) {
	problems := validateRules([]ruleConfig{
		{RuleID: "bad", Metric: "cpu", Threshold: 1},
		{RuleID: goodRule, Metric: "wrong", Threshold: 1},
	})
	if len(problems) != 2 {
		t.Fatalf("problems = %d, want 2 (all reported at once): %v", len(problems), problems)
	}
}

// An oversized rules.json must be refused BEFORE the read (keep-previous, one
// warning) - reading it whole used to OOM-kill the process pre-beat into an
// indefinite crash loop and a false absence alert.
func TestOversizedRulesFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rules.json"
	big := make([]byte, maxRulesFileBytes+1)
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatal(err)
	}
	var intervalNanos, unreachable atomic.Int64
	intervalNanos.Store(int64(60 * time.Second))
	w := &ruleWatcher{
		path: path, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		engine:   rules.New(nil, time.Now),
		interval: &intervalNanos, unreachable: &unreachable,
	}
	w.check(true)
	if got := len(w.engine.Rules()); got != 0 {
		t.Fatalf("rules loaded from an oversized file: %d", got)
	}
	if !w.present {
		t.Fatal("the oversized file must be recorded as seen (no re-warn every tick)")
	}
}
