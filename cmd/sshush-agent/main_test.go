package main

import (
	"strings"
	"testing"
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
		{
			name:     "duplicate rule_id",
			mutate:   func(r *ruleConfig) {},
			extra:    []ruleConfig{{RuleID: goodRule, Metric: "mem", Threshold: 80}},
			wantHint: "duplicate rule_id",
		},
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
