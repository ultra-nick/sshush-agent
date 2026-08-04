// Command sshush-agent is the SSHush server-side agent.
//
// It reads its identity from /etc/sshush/config.json once at startup, then
// does exactly one thing forever: POST a heartbeat to the backend every
// interval. It ignores every response and every error - no retry, no backoff,
// no state machine, no reaction to any status code. The next beat is always
// one interval away.
//
// That rule is the single most important one in this program. The backend
// infers presence from beats arriving and absence from beats stopping, so any
// intelligence added here - retries, buffering, response handling - would only
// blur the one signal the agent exists to send, and would turn the easiest
// component to audit into one that needs auditing. Resist it.
//
// On SIGTERM or SIGINT it exits 0, mid-beat or not. The unit uses
// Restart=on-failure, so a clean stop stays stopped.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ultra-nick/sshush-agent/internal/metrics"
	"github.com/ultra-nick/sshush-agent/internal/report"
	"github.com/ultra-nick/sshush-agent/internal/rules"
)

const (
	configPath = "/etc/sshush/config.json"

	// beatTimeout bounds one POST. Config validation keeps every interval at
	// or above minIntervalS, so a request that runs to the full timeout still
	// completes well before the next beat is due - beats can never stack.
	beatTimeout  = 10 * time.Second
	minIntervalS = 30

	secretLen = 32
)

// config is the agent's identity and rule set, read once. It is never
// reloaded: when anything changes - a rule edit included - the app rewrites
// this file and restarts the agent over SSH. No file watching.
type config struct {
	AgentID        string       `json:"agent_id"`
	Secret         string       `json:"secret"`
	IntervalS      int          `json:"interval_s"`
	Endpoint       string       `json:"endpoint"`
	BreachEndpoint string       `json:"breach_endpoint"`
	Rules          []ruleConfig `json:"rules"`
}

// ruleConfig is one alert rule as written by the app. rules may be absent or
// empty, in which case the agent only beats.
type ruleConfig struct {
	RuleID    string  `json:"rule_id"`
	Metric    string  `json:"metric"`
	Threshold float64 `json:"threshold"`
	DurationS int     `json:"duration_s"`
	Label     string  `json:"label"`
}

var validMetrics = map[string]bool{
	"cpu": true, "mem": true, "disk": true, "load": true, "net": true, "temp": true,
}

// labelRequired: disk needs a mount point, net an interface name. For every
// other metric the label is carried but ignored.
var labelRequired = map[string]bool{"disk": true, "net": true}

// maxLabelBytes mirrors the backend's cap. Enforcing it here turns a
// too-long label into a loud startup failure instead of a silent 400 on
// every future breach report.
const maxLabelBytes = 128

func main() {
	insecure := flag.Bool("insecure", false,
		"permit a plain-http endpoint (testing only: the secret crosses the network unencrypted)")
	flag.Parse()

	log := newLogger()

	cfg, err := loadConfig(*insecure)
	if err != nil {
		// An agent with no identity has nothing useful to do. Exit non-zero
		// and let systemd retry; the message names what is wrong and where.
		log.Error("configuration rejected", "error", err.Error())
		os.Exit(1)
	}

	if strings.HasPrefix(cfg.Endpoint, "http:") {
		log.Warn("--insecure: the beat secret crosses the network unencrypted",
			"endpoint", cfg.Endpoint)
	}

	// The body never changes, so it is built exactly once. This is the only
	// place the secret leaves the process, and it leaves only toward the
	// endpoint - never toward a log, on any path.
	body, err := json.Marshal(map[string]string{
		"agent_id": cfg.AgentID,
		"secret":   cfg.Secret,
	})
	if err != nil {
		log.Error("building beat body failed", "error", err.Error())
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	client := &http.Client{Timeout: beatTimeout}
	interval := time.Duration(cfg.IntervalS) * time.Second

	log.Info("sshush-agent starting",
		"agent_id", cfg.AgentID, "endpoint", cfg.Endpoint,
		"interval", interval, "rules", len(cfg.Rules))

	// Rule machinery exists only when rules do; with none configured the
	// agent only beats, exactly as before this slice.
	var (
		engine   *rules.Engine
		reporter *report.Reporter
		sample   rules.Sampler
	)
	if len(cfg.Rules) > 0 {
		collector := metrics.New(log, runtime.NumCPU())
		rs := make([]rules.Rule, 0, len(cfg.Rules))
		hasTemp := false
		for _, rc := range cfg.Rules {
			if rc.Metric == "temp" {
				hasTemp = true
			}
			rs = append(rs, rules.Rule{
				ID:        rc.RuleID,
				Metric:    rc.Metric,
				Threshold: rc.Threshold,
				Duration:  time.Duration(rc.DurationS) * time.Second,
				Label:     rc.Label,
			})
		}
		// Absent sensor is not an error, but a rule that will never evaluate
		// deserves one loud line now rather than eternal silence.
		if hasTemp && !collector.TempAvailable() {
			log.Warn("a temp rule is configured but no thermal zone is readable; that rule will never evaluate")
		}
		engine = rules.New(rs, time.Now)
		reporter = report.New(cfg.BreachEndpoint, cfg.AgentID, cfg.Secret, client, log)
		sample = collector.Sample
	}

	// One tick: beat first - liveness must never wait behind metric reads -
	// then evaluate rules, queue any transitions, and attempt delivery of
	// everything undelivered (retries included).
	tick := func() {
		beat(ctx, client, cfg.Endpoint, body, log)
		if engine != nil {
			if events := engine.Evaluate(sample); len(events) > 0 {
				for _, ev := range events {
					log.Info("rule transition",
						"rule_id", ev.Rule.ID, "metric", ev.Rule.Metric,
						"direction", ev.Direction, "value", ev.Value)
				}
				reporter.Enqueue(events)
			}
			reporter.Flush(ctx)
		}
	}

	// First tick immediately rather than one interval from now: a restarted
	// agent should announce itself at once, and the first metric samples
	// double as the baselines for the delta metrics.
	tick()

	for {
		select {
		case <-ctx.Done():
			log.Info("sshush-agent stopping")
			return
		case <-time.After(jitter(interval)):
		}
		// The wait above starts only after the previous tick has returned
		// (every network call in it is timeout-bounded), so the interval is
		// measured from last completion and beats can never stack.
		tick()
	}
}

// beat sends one heartbeat and deliberately discards the outcome.
//
// The status code is logged at debug and acted on by no one. The request
// context is the process context, so SIGTERM mid-beat aborts the request and
// the loop exits cleanly.
func beat(ctx context.Context, client *http.Client, endpoint string, body []byte, log *slog.Logger) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Debug("beat", "outcome", "request_build_failed", "error", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Transport errors name the endpoint and the network condition; they
		// never contain the request body, so the secret stays out of the
		// journal here too.
		log.Debug("beat", "outcome", "send_failed", "error", err.Error())
		return
	}
	// Drain a bounded amount so the connection can be reused, then move on.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	log.Debug("beat", "outcome", resp.StatusCode)
}

// loadConfig reads and validates the identity file.
//
// Every error message names the offending field but never echoes its value:
// the secret must not reach a terminal or the journal on any path, and that
// includes configuration failures.
func loadConfig(insecureOK bool) (config, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return config{}, fmt.Errorf("read %s: %w (enrolment or the installer places this file)", configPath, err)
	}

	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return config{}, fmt.Errorf("parse %s: %w", configPath, err)
	}

	if !validUUID(cfg.AgentID) {
		return config{}, fmt.Errorf("%s: agent_id is not a canonical hyphenated uuid", configPath)
	}
	if !validSecret(cfg.Secret) {
		return config{}, fmt.Errorf("%s: secret does not decode to exactly %d bytes of base64url", configPath, secretLen)
	}
	if cfg.IntervalS < minIntervalS {
		// The floor keeps the fixed request timeout well under every
		// interval, which is what makes overlapping beats impossible.
		return config{}, fmt.Errorf("%s: interval_s must be at least %d, got %d", configPath, minIntervalS, cfg.IntervalS)
	}

	if err := checkEndpoint("endpoint", cfg.Endpoint, insecureOK); err != nil {
		return config{}, err
	}
	// breach_endpoint is required only when there are rules to report on.
	if len(cfg.Rules) > 0 || cfg.BreachEndpoint != "" {
		if cfg.BreachEndpoint == "" {
			return config{}, fmt.Errorf("%s: rules are configured but breach_endpoint is missing", configPath)
		}
		if err := checkEndpoint("breach_endpoint", cfg.BreachEndpoint, insecureOK); err != nil {
			return config{}, err
		}
	}

	if problems := validateRules(cfg.Rules); len(problems) > 0 {
		// Any invalid rule stops the agent outright - no starting with
		// partial rules. The app is mid-restart over SSH when this fires
		// and needs a failure it can attribute to the exact rule.
		return config{}, fmt.Errorf("%s: invalid rules:\n  - %s", configPath, strings.Join(problems, "\n  - "))
	}

	return cfg, nil
}

func checkEndpoint(name, raw string, insecureOK bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s: %s is not a valid url", configPath, name)
	}
	switch u.Scheme {
	case "https":
		// The only acceptable production transport.
		return nil
	case "http":
		if !insecureOK {
			return fmt.Errorf("%s: %s is plain http, which would send the secret unencrypted; use https, or pass --insecure to accept that on a test network", configPath, name)
		}
		return nil
	default:
		return fmt.Errorf("%s: %s scheme must be https (or http with --insecure)", configPath, name)
	}
}

// validateRules checks every rule and reports every problem at once, each
// attributable to its rule by index and id.
func validateRules(rs []ruleConfig) []string {
	var problems []string
	bad := func(i int, r ruleConfig, msg string) {
		problems = append(problems, fmt.Sprintf("rules[%d] (rule_id %q): %s", i, r.RuleID, msg))
	}
	seen := make(map[string]bool)
	for i, r := range rs {
		if !validUUID(r.RuleID) {
			bad(i, r, "rule_id is not a canonical hyphenated uuid")
		} else if seen[r.RuleID] {
			// Two rules sharing an id would fight over one backend state
			// row, flapping it forever.
			bad(i, r, "duplicate rule_id")
		} else {
			seen[r.RuleID] = true
		}
		if !validMetrics[r.Metric] {
			bad(i, r, fmt.Sprintf("metric %q is not one of cpu|mem|disk|load|net|temp", r.Metric))
		}
		if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) {
			bad(i, r, "threshold is not a finite number")
		}
		if r.DurationS < 0 {
			bad(i, r, fmt.Sprintf("duration_s must be >= 0, got %d", r.DurationS))
		}
		if labelRequired[r.Metric] && r.Label == "" {
			bad(i, r, fmt.Sprintf("label is required for metric %q (mount point or interface name)", r.Metric))
		}
		if len(r.Label) > maxLabelBytes {
			bad(i, r, fmt.Sprintf("label is %d bytes, max %d", len(r.Label), maxLabelBytes))
		}
	}
	return problems
}

// validUUID accepts the canonical 8-4-4-4-12 hyphenated form only, matching
// what the backend's parser accepts. No braces, no urn: prefix.
func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	compact := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	_, err := hex.DecodeString(compact)
	return err == nil
}

// validSecret accepts base64url with or without padding, exactly secretLen
// decoded bytes. The decoded value is discarded - the agent sends the string
// as received and never needs the raw bytes.
func validSecret(s string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return false
		}
	}
	return len(raw) == secretLen
}

// newLogger builds a stdout slog with the level taken from SSHUSH_LOG_LEVEL
// (default info). Per-beat outcomes log at debug, so a normally-configured
// agent journals only lifecycle events. The time attribute is dropped -
// journald stamps every line already.
func newLogger() *slog.Logger {
	var level slog.Level
	switch strings.ToLower(os.Getenv("SSHUSH_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}

// jitter spreads beats by +-10% so a fleet of agents installed at the same
// moment does not hit the backend in lockstep forever.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	delta := (mrand.Float64()*2 - 1) * 0.1 * float64(d)
	out := time.Duration(float64(d) + delta)
	if out <= 0 {
		return d
	}
	return out
}
