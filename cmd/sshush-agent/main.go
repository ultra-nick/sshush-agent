// Command sshush-agent is the SSHush server-side agent.
//
// Its configuration is split across two files so that rules can be edited
// without root:
//
//	/etc/sshush/config.json    root:sshush 0640   the IDENTITY: agent_id,
//	                                               secret, endpoint,
//	                                               breach_endpoint. Read once
//	                                               at startup; missing or
//	                                               malformed is fatal.
//	/var/lib/sshush/rules.json <user>:sshush 0644 the SETTINGS: interval_s and
//	                                               rules[]. Owned by the user
//	                                               who ran the install, re-read
//	                                               on change, and never fatal.
//
// Credentials need root; settings do not. That split is the whole point: on a
// server where sudo needs a password, root exists only during the interactive
// install, so rule editing must not need it afterwards.
//
// The agent POSTs a heartbeat every interval and, when rules are configured,
// samples metrics on a fixed tick and reports state transitions. It ignores
// every beat response and error - no retry, no backoff, no reaction to any
// status code. The backend infers presence from beats arriving and absence
// from beats stopping; any intelligence here would only blur that one signal.
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ultra-nick/sshush-agent/internal/metrics"
	"github.com/ultra-nick/sshush-agent/internal/report"
	"github.com/ultra-nick/sshush-agent/internal/rules"
)

const (
	configPath = "/etc/sshush/config.json"
	rulesPath  = "/var/lib/sshush/rules.json"

	// beatTimeout bounds one POST. Interval validation keeps every interval at
	// or above minIntervalS, so a request that runs to the full timeout still
	// completes well before the next beat is due - beats can never stack.
	beatTimeout  = 10 * time.Second
	minIntervalS = 30

	// defaultIntervalS is the beat cadence when no rules file is present. The
	// heartbeat must keep working regardless of the settings file, so a missing
	// rules.json falls back to this rather than stopping.
	defaultIntervalS = 60

	// unreachable_after_s bounds. It is the single number the app computes and
	// the agent relays to the backend on every beat: how long of silence
	// should count as down. The agent never interprets it, only carries it.
	minUnreachableS     = 60
	maxUnreachableS     = 3600
	defaultUnreachableS = 180

	// sampleInterval is the FIXED metric-sampling, rule-evaluation, and
	// rules-file-stat rate, independent of the beat interval and deliberately
	// not configurable. At 10s the shortest offered duration (60s) is six
	// consecutive readings, so "sustained" means something regardless of what
	// beat interval the user chose.
	sampleInterval = 10 * time.Second

	secretLen = 32
)

// identity is the credential file (/etc/sshush/config.json), read once at
// startup and never reloaded - the secret needs root and does not change on a
// rule edit. Extra fields (a stale interval_s or rules from before the split)
// are ignored.
type identity struct {
	AgentID        string `json:"agent_id"`
	Secret         string `json:"secret"`
	Endpoint       string `json:"endpoint"`
	BreachEndpoint string `json:"breach_endpoint"`
}

// rulesFileJSON is the settings file (/var/lib/sshush/rules.json), user-owned
// and re-read on change. interval_s and unreachable_after_s live here, not in
// the identity, so a password-sudo user can change the timing without root.
//
// unreachable_after_s is a pointer so an absent field (nil -> defaulted with a
// warning) is distinguishable from a present-but-out-of-range value (which
// keeps the previous settings, like any malformed field).
type rulesFileJSON struct {
	IntervalS         int             `json:"interval_s"`
	UnreachableAfterS *int            `json:"unreachable_after_s"`
	DeviceToken       json.RawMessage `json:"device_token"`
	Rules             []ruleConfig    `json:"rules"`
}

// ruleSettings is one successfully loaded settings file.
type ruleSettings struct {
	intervalS            int
	unreachableAfterS    int
	tokenIntent          tokenIntent // what the device_token field is asking for
	deviceToken          string      // the token value when tokenIntent == tokenSet
	rules                []rules.Rule
	unreachableDefaulted bool // the field was absent and fell back to the default
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
	"cpu": true, "mem": true, "swap": true, "disk": true,
	"load": true, "temp": true, "interfaceDown": true,
}

// validMetricList is the human-readable enum for error messages, in the same
// order the product presents the alert types.
const validMetricList = "cpu|mem|swap|disk|load|temp|interfaceDown"

// labelRequired: disk needs a mount point, interfaceDown an interface name.
// For every other metric the label is carried but ignored.
var labelRequired = map[string]bool{"disk": true, "interfaceDown": true}

// maxLabelBytes mirrors the backend's cap. Enforcing it here turns a
// too-long label into a loud startup failure instead of a silent 400 on
// every future breach report.
const maxLabelBytes = 128

func main() {
	insecure := flag.Bool("insecure", false,
		"permit a plain-http endpoint (testing only: the secret crosses the network unencrypted)")
	flag.Parse()

	log := newLogger()

	id, err := loadIdentity(*insecure)
	if err != nil {
		// An agent with no identity has nothing useful to do. Exit non-zero
		// and let systemd retry; the message names what is wrong and where.
		log.Error("configuration rejected", "error", err.Error())
		os.Exit(1)
	}

	if strings.HasPrefix(id.Endpoint, "http:") {
		log.Warn("--insecure: the beat secret crosses the network unencrypted",
			"endpoint", id.Endpoint)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	client := &http.Client{Timeout: beatTimeout}

	// The beat interval and the reported unreachable_after_s both live in
	// shared atomic state because a rules-file reload on the sample goroutine
	// changes them, and the beat goroutine reads the current values on its next
	// tick - no restart. interval in nanoseconds, unreachable in seconds.
	var intervalNanos atomic.Int64
	intervalNanos.Store(int64(defaultIntervalS) * int64(time.Second))
	var unreachableS atomic.Int64
	unreachableS.Store(int64(defaultUnreachableS))

	// The engine and reporter exist even when there are no rules yet: rules can
	// APPEAR at runtime when the settings file is written, so the sample loop
	// always runs and the machinery is always ready. Only the sample goroutine
	// ever touches the engine and reporter, so the engine stays single-caller
	// with no mutex.
	collector := metrics.New(log, runtime.NumCPU())
	engine := rules.New(nil, time.Now)
	var reporter *report.Reporter
	if id.BreachEndpoint != "" {
		reporter = report.New(id.BreachEndpoint, id.AgentID, id.Secret, client, log)
	}
	sample := collector.Sample

	// The device-token relay reports the phone's APNs token to /v1/device-token
	// (agent_id + secret auth, like the breach path) whenever the app changes it
	// in rules.json - on change only, never on every reload.
	relay, err := newTokenRelay(id.Endpoint, id.AgentID, id.Secret, client, log)
	if err != nil {
		// The endpoint already parsed as a URL at identity load, so this is not
		// expected; disable the relay rather than take the agent down over it.
		log.Error("device-token relay disabled: cannot derive endpoint", "error", err.Error())
	}

	watcher := &ruleWatcher{
		path: rulesPath, log: log, engine: engine, collector: collector,
		interval: &intervalNanos, unreachable: &unreachableS, relay: relay,
	}
	watcher.check(true) // startup load: applies rules.json if present, else no rules

	log.Info("sshush-agent starting",
		"agent_id", id.AgentID, "endpoint", id.Endpoint,
		"interval", time.Duration(intervalNanos.Load()),
		"unreachable_after_s", unreachableS.Load())

	// Two independent timers that share no timing. The beat reads the current
	// interval each tick; the sample loop re-reads the rules file and evaluates.
	var wg sync.WaitGroup

	// Beat: immediate first (announce on restart at once), then every current
	// interval jittered +-10%, measured from last completion.
	//
	// procStart anchors uptime_s: seconds since THIS process began, so the
	// backend can spot a crash loop (see beatBody.UptimeS). Process start, not
	// host boot - a rebooting host is the host's business; a restarting process
	// is ours.
	procStart := time.Now()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runTickLoop(ctx, func() time.Duration {
			return jitter(time.Duration(intervalNanos.Load()))
		}, func() {
			// The body is rebuilt each beat so it carries the CURRENT
			// unreachable_after_s (a reload may have changed it) and uptime.
			beat(ctx, client, id.Endpoint,
				buildBeatBody(id.AgentID, id.Secret, unreachableS.Load(),
					int64(time.Since(procStart).Seconds())), log)
		})
	}()

	// Sample: immediate first (also seeds the delta-metric baselines), then
	// every fixed sampleInterval. Always runs: it re-reads rules.json (one
	// cheap stat) before evaluating, so a rule or interval change takes effect
	// within one tick without a restart.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runTickLoop(ctx, func() time.Duration { return sampleInterval }, func() {
			watcher.check(false)
			evaluateAndReport(ctx, engine, sample, reporter, log)
			// Relay the device token if it changed. Runs every tick (not
			// mtime-gated) so a failed post is retried next tick with the same
			// value; a no-op when nothing changed.
			if watcher.relay != nil {
				watcher.relay.flush(ctx)
			}
		})
	}()

	<-ctx.Done()
	log.Info("sshush-agent stopping")
	wg.Wait()
}

// ruleWatcher re-reads the settings file when it changes and swaps the new
// rules and interval into the running agent. Every field is touched only from
// the sample goroutine (and once from main at startup, before that goroutine
// starts), except interval, which is atomic and shared with the beat loop.
type ruleWatcher struct {
	path        string
	log         *slog.Logger
	engine      *rules.Engine
	collector   *metrics.Collector
	interval    *atomic.Int64 // nanoseconds, read by the beat loop
	unreachable *atomic.Int64 // seconds, read by the beat loop and reported on every beat
	relay       *tokenRelay   // device-token relay; nil disables it (e.g. bad endpoint)

	lastMtime time.Time
	present   bool
}

// check stats the settings file and, on an mtime change, re-reads it. The
// three rules that matter most:
//
//  1. A file that fails to parse or validate is IGNORED - the rules already in
//     force stay, and it logs at warn. A malformed file must never silently
//     stop monitoring.
//  2. A missing file is not fatal - the previous rules stay in force (which at
//     startup is none), and the heartbeat keeps running regardless.
//  3. An interval change takes effect on the beat loop with no restart.
//
// startup only affects the wording, so a first-run message reads sensibly.
func (w *ruleWatcher) check(startup bool) {
	info, err := os.Stat(w.path)
	if err != nil {
		if w.present {
			w.log.Warn("rules file is gone; keeping the rules already in force", "path", w.path)
		} else if startup {
			w.log.Warn("no rules file; starting with no rules - the heartbeat and absence detection still run", "path", w.path)
		}
		w.present = false
		return
	}
	if w.present && info.ModTime().Equal(w.lastMtime) {
		return // unchanged since the last read
	}
	// Record the version we are about to read BEFORE parsing, so a file that
	// fails to parse is not re-read (and re-warned) every tick - only when it
	// changes again, e.g. when the user fixes it.
	w.present = true
	w.lastMtime = info.ModTime()

	s, perr := loadRulesFile(w.path)
	if perr != nil {
		if startup {
			w.log.Warn("rules file could not be loaded; starting with no rules", "error", perr.Error())
		} else {
			w.log.Warn("rules file ignored; keeping the rules already in force", "error", perr.Error())
		}
		return
	}

	w.interval.Store(int64(time.Duration(s.intervalS) * time.Second))
	w.unreachable.Store(int64(s.unreachableAfterS))
	// Update the token to communicate from this load. The actual POST happens on
	// the sample tick (relay.flush), so a transient failure retries; here we only
	// record what the file now wants sent.
	if w.relay != nil {
		w.relay.setDesired(s.tokenIntent, s.deviceToken)
	}
	w.engine.UpdateRules(s.rules)
	w.warnUnevaluable(s.rules)
	if s.unreachableDefaulted {
		w.log.Warn("rules file has no unreachable_after_s; using the default",
			"default_s", defaultUnreachableS)
	}
	if startup {
		w.log.Info("rules loaded", "rules", len(s.rules),
			"interval_s", s.intervalS, "unreachable_after_s", s.unreachableAfterS)
	} else {
		w.log.Info("rules reloaded", "rules", len(s.rules),
			"interval_s", s.intervalS, "unreachable_after_s", s.unreachableAfterS)
	}
}

// warnUnevaluable logs the one-line "this rule will never evaluate" warnings on
// the current rule set: a temp rule with no thermal zone, or a swap rule on a
// machine without swap. Runs on every applied load (startup and each reload),
// which is infrequent (user-initiated) so it does not spam.
func (w *ruleWatcher) warnUnevaluable(rs []rules.Rule) {
	hasTemp, hasSwap := false, false
	for _, r := range rs {
		switch r.Metric {
		case "temp":
			hasTemp = true
		case "swap":
			hasSwap = true
		}
	}
	if hasTemp && !w.collector.TempAvailable() {
		w.log.Warn("a temp rule is configured but no thermal zone is readable; that rule will never evaluate")
	}
	if hasSwap && !w.collector.SwapAvailable() {
		w.log.Warn("a swap rule is configured but this machine has no swap; that rule will never evaluate")
	}
}

// runTickLoop runs work once immediately, then before every subsequent tick
// waits nextInterval() - jittered for the beat, fixed for the sample. It is
// the single tested loop shape both timers use; each call captures its own
// interval and work, so two loops share nothing. The wait starts only after
// work returns, so a slow tick delays its own next tick and never stacks -
// and never touches the other loop.
func runTickLoop(ctx context.Context, nextInterval func() time.Duration, work func()) {
	work()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextInterval()):
		}
		work()
	}
}

// evaluateAndReport is one sample tick: evaluate every rule's metric, log and
// queue any transitions, and attempt delivery of everything undelivered
// (retries included). Called only from the sample goroutine.
//
// reporter is nil only when the identity carried no breach_endpoint - a
// degraded state, since transitions cannot be sent. Evaluation still runs (the
// engine keeps correct per-rule state) and one warning is enough to surface it.
func evaluateAndReport(ctx context.Context, engine *rules.Engine, sample rules.Sampler, reporter *report.Reporter, log *slog.Logger) {
	events := engine.Evaluate(sample)
	for _, ev := range events {
		log.Info("rule transition",
			"rule_id", ev.Rule.ID, "metric", ev.Rule.Metric,
			"direction", ev.Direction, "value", ev.Value)
	}
	if reporter == nil {
		if len(events) > 0 {
			log.Warn("rule transitions detected but no breach_endpoint is configured; not reporting", "count", len(events))
		}
		return
	}
	if len(events) > 0 {
		reporter.Enqueue(events)
	}
	reporter.Flush(ctx)
}

// beatBody is the heartbeat payload. unreachable_after_s rides every beat so
// the backend always has the current threshold from the most recent beat -
// there is no separately stored value to fall out of step. interval_s is NOT
// reported: the backend does not care how often beats arrive, only how long of
// silence counts.
type beatBody struct {
	AgentID           string `json:"agent_id"`
	Secret            string `json:"secret"`
	UnreachableAfterS int64  `json:"unreachable_after_s"`
	// UptimeS is how long this PROCESS has been alive, in whole seconds. The
	// backend uses it to spot a crash-looping agent: a process that keeps
	// dying and restarting beats on time (systemd brings it back), so liveness
	// alone can never see the problem - but every one of its beats reports a
	// young uptime, and a run of those is the fingerprint. Additive and
	// optional: an old backend ignores it.
	UptimeS int64 `json:"uptime_s"`
}

// buildBeatBody marshals one beat payload. Kept separate so the payload shape
// is unit-testable without a network. The secret is a value here and goes only
// toward the endpoint - never toward a log, on any path.
func buildBeatBody(agentID, secret string, unreachableS, uptimeS int64) []byte {
	b, _ := json.Marshal(beatBody{
		AgentID: agentID, Secret: secret,
		UnreachableAfterS: unreachableS, UptimeS: uptimeS,
	})
	return b
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

// loadIdentity reads and validates the credential file. Missing or malformed
// is fatal to the caller: an agent with no identity has nothing useful to do.
//
// Every error message names the offending field but never echoes its value:
// the secret must not reach a terminal or the journal on any path, and that
// includes configuration failures. Extra fields (a stale interval_s or rules
// left in this file from before the config split) are ignored by the struct.
func loadIdentity(insecureOK bool) (identity, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return identity{}, fmt.Errorf("read %s: %w (enrolment or the installer places this file)", configPath, err)
	}

	var id identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return identity{}, fmt.Errorf("parse %s: %w", configPath, err)
	}

	if !validUUID(id.AgentID) {
		return identity{}, fmt.Errorf("%s: agent_id is not a canonical hyphenated uuid", configPath)
	}
	if !validSecret(id.Secret) {
		return identity{}, fmt.Errorf("%s: secret does not decode to exactly %d bytes of base64url", configPath, secretLen)
	}
	if err := checkEndpoint("endpoint", id.Endpoint, insecureOK); err != nil {
		return identity{}, err
	}
	// breach_endpoint is validated when present; rules can appear at runtime,
	// so it belongs in this file even before any rule exists.
	if id.BreachEndpoint != "" {
		if err := checkEndpoint("breach_endpoint", id.BreachEndpoint, insecureOK); err != nil {
			return identity{}, err
		}
	}

	return id, nil
}

// loadRulesFile reads, parses and validates the settings file. Any error -
// missing file, bad JSON, out-of-range interval or unreachable, an invalid
// rule - is returned for the caller to handle by keeping whatever is already
// in force. Nothing here is fatal.
//
// A missing unreachable_after_s is NOT an error: it defaults to
// defaultUnreachableS and the returned settings flag it so the caller can warn.
// A present but out-of-range value IS an error, like any malformed field.
func loadRulesFile(path string) (ruleSettings, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ruleSettings{}, err
	}
	var rf rulesFileJSON
	if err := json.Unmarshal(raw, &rf); err != nil {
		return ruleSettings{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if rf.IntervalS < minIntervalS {
		// The floor keeps the request timeout well under every interval, so
		// beats can never stack. Out of range keeps the previous value.
		return ruleSettings{}, fmt.Errorf("%s: interval_s must be at least %d, got %d", path, minIntervalS, rf.IntervalS)
	}

	unreachable := defaultUnreachableS
	defaulted := false
	if rf.UnreachableAfterS == nil {
		defaulted = true
	} else if *rf.UnreachableAfterS < minUnreachableS || *rf.UnreachableAfterS > maxUnreachableS {
		return ruleSettings{}, fmt.Errorf("%s: unreachable_after_s must be between %d and %d, got %d",
			path, minUnreachableS, maxUnreachableS, *rf.UnreachableAfterS)
	} else {
		unreachable = *rf.UnreachableAfterS
	}

	if problems := validateRules(rf.Rules); len(problems) > 0 {
		return ruleSettings{}, fmt.Errorf("%s: invalid rules:\n  - %s", path, strings.Join(problems, "\n  - "))
	}
	out := make([]rules.Rule, 0, len(rf.Rules))
	for _, rc := range rf.Rules {
		out = append(out, rules.Rule{
			ID:        rc.RuleID,
			Metric:    rc.Metric,
			Threshold: rc.Threshold,
			Duration:  time.Duration(rc.DurationS) * time.Second,
			Label:     rc.Label,
		})
	}
	// device_token is parsed leniently: a malformed value keeps the previous
	// token and warns, it does NOT fail the whole load (the rest of the file is
	// still valid). ABSENT/CLEAR/SET are told apart by the relay.
	intent, token := parseDeviceToken(rf.DeviceToken)

	return ruleSettings{
		intervalS:            rf.IntervalS,
		unreachableAfterS:    unreachable,
		tokenIntent:          intent,
		deviceToken:          token,
		rules:                out,
		unreachableDefaulted: defaulted,
	}, nil
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
			bad(i, r, fmt.Sprintf("metric %q is not one of %s", r.Metric, validMetricList))
		}
		// interfaceDown is a state rule: its threshold is ignored, so the app
		// may send any placeholder (0) for a uniform rule shape. Every other
		// metric's threshold must be a real number.
		if r.Metric != "interfaceDown" && (math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0)) {
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
