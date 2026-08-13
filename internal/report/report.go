// Package report builds, queues and delivers breach requests.
//
// Unlike the beat, a breach report matters individually: it is retried on
// every tick, with its ORIGINAL seq, until the backend confirms it. The
// backend's seq guard makes a retry idempotent only if the seq is unchanged,
// which is why a queued request is frozen bytes - never rebuilt, never
// merged with newer transitions.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ultra-nick/sshush-agent/internal/rules"
)

// maxQueue caps undelivered requests. Beyond it the OLDEST is dropped: a
// server generating more than 16 unacknowledged batches has bigger problems,
// and unbounded memory in the agent is not a fix for them.
const maxQueue = 16

// Reporter owns the seq counter and the undelivered queue. Not safe for
// concurrent use; the tick loop is the only caller.
type Reporter struct {
	endpoint string
	agentID  string
	secret   string
	client   *http.Client
	log      *slog.Logger
	now      func() time.Time

	lastSeq int64
	queue   []pending

	// seqPath is the durable high-water file ("" disables). Best-effort in
	// both directions: an unreadable file at start falls back to the clock,
	// and a failed write costs nothing that the stale-adoption path below
	// cannot recover.
	seqPath string
}

// pending is one frozen request. body already contains seq; a retry sends
// exactly these bytes. events and ruleIDs are kept ONLY for the stale-rebuild
// path, which re-freezes the same events under a fresh seq; they are never
// merged with newer transitions.
type pending struct {
	seq     int64
	body    []byte
	events  []wireEvent
	ruleIDs []string
	rebuilt bool
}

type wireEvent struct {
	RuleID    string  `json:"rule_id"`
	Metric    string  `json:"metric"`
	Direction string  `json:"direction"`
	Value     float64 `json:"value"`
	Threshold float64 `json:"threshold"`
	Label     string  `json:"label,omitempty"`
}

type wireRequest struct {
	AgentID string      `json:"agent_id"`
	Secret  string      `json:"secret"`
	Seq     int64       `json:"seq"`
	Events  []wireEvent `json:"events"`
	// RuleIDs is the agent's FULL current rule set at freeze time - the
	// backend's rule-removal signal: alert_state rows for ids not listed are
	// pruned in the same transaction, so retired rules stop counting toward
	// the backend's rule cap. Older backends ignore the field.
	RuleIDs []string `json:"rule_ids"`
}

// New builds a Reporter. client's timeout bounds each delivery attempt.
// seqPath, when non-empty, is the durable seq high-water file; see nextSeq.
func New(endpoint, agentID, secret string, client *http.Client, log *slog.Logger, seqPath string) *Reporter {
	r := &Reporter{
		endpoint: endpoint,
		agentID:  agentID,
		secret:   secret,
		client:   client,
		log:      log,
		now:      time.Now,
		seqPath:  seqPath,
	}
	if seqPath != "" {
		if raw, err := os.ReadFile(seqPath); err == nil {
			if v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && v > 0 {
				r.lastSeq = v
			}
		}
	}
	return r
}

// nextSeq derives a seq: unix seconds at the moment the request is built, or
// one past the high-water mark, whichever is greater.
//
// The clock alone is NOT monotonic across restarts, despite what an earlier
// version of this comment claimed: an RTC-less host (a Raspberry Pi) that
// crashes and reboots restores a clock minutes behind via fake-hwclock, and
// every report until the clock caught up came back {"stale":true} - which
// counted as delivered and was silently dropped. Two defences, layered:
//
//  1. The high-water mark is PERSISTED (seqPath, best-effort) and reloaded at
//     start, so a restart resumes past the previous process's last seq even
//     with a regressed clock. File loss is safe: the clock usually leads, and
//     when it does not, defence 2 catches it.
//  2. A stale response now carries the backend's last_seq, which Flush adopts
//     and re-sends under (see sendStale) - so even a lost or stale file
//     self-heals on the first rejected report instead of losing it.
//
// Within the process the sequence is strictly increasing regardless of clock
// steps. (The backend's last_seq column is BIGINT - migration 010 - and its
// handler bound is MaxInt64, so unix-seconds seqs never hit a ceiling.)
func (r *Reporter) nextSeq() int64 {
	v := r.now().Unix()
	if v <= r.lastSeq {
		v = r.lastSeq + 1
	}
	r.lastSeq = v
	r.persistSeq()
	return v
}

// persistSeq writes the high-water mark, best effort. Called on every advance
// - advances happen only when a batch is frozen or a stale is adopted, both
// rare. A failed write is logged at debug only: the stale-adoption path makes
// the file an optimisation, not a correctness requirement.
func (r *Reporter) persistSeq() {
	if r.seqPath == "" {
		return
	}
	if err := os.WriteFile(r.seqPath, []byte(strconv.FormatInt(r.lastSeq, 10)), 0o644); err != nil {
		r.log.Debug("seq high-water not persisted", "error", err.Error())
	}
}

// adoptSeq raises the high-water mark to the backend's, from a stale
// response. The next nextSeq then starts past it.
//
// The adopted value is clamped to plausibility - this is the one place a
// parsed response value feeds arithmetic and persisted state. Legitimate
// seqs are unix-timestamp-scale (nextSeq starts at now); a hostile or
// corrupt counterparty sending MaxInt64 would wrap the next increment
// negative and persist the garbage high-water. Anything non-positive or
// further than a year past now is ignored: the batch still follows the
// normal stale path, just without adopting the number.
func (r *Reporter) adoptSeq(backendSeq int64) {
	if backendSeq <= 0 || backendSeq > r.now().Unix()+365*24*3600 {
		return
	}
	if backendSeq > r.lastSeq {
		r.lastSeq = backendSeq
		r.persistSeq()
	}
}

// Enqueue freezes one batch of transitions into a request with a fresh seq.
// ruleIDs is the agent's full current rule set, captured at freeze time.
//
// Transitions from one tick always share one request; transitions that occur
// while older requests are undelivered get their own request with their own
// seq - the pending ones are committed to theirs.
func (r *Reporter) Enqueue(events []rules.Event, ruleIDs []string) {
	if len(events) == 0 {
		return
	}
	wireEvents := make([]wireEvent, 0, len(events))
	for _, ev := range events {
		wireEvents = append(wireEvents, wireEvent{
			RuleID:    ev.Rule.ID,
			Metric:    ev.Rule.Metric,
			Direction: ev.Direction,
			Value:     ev.Value,
			Threshold: ev.Rule.Threshold,
			Label:     ev.Rule.Label,
		})
	}
	p, ok := r.freeze(wireEvents, ruleIDs)
	if !ok {
		return
	}
	r.queue = append(r.queue, p)
	if len(r.queue) > maxQueue {
		dropped := len(r.queue) - maxQueue
		r.log.Warn("breach queue full, dropping oldest", "dropped", dropped, "seq", r.queue[0].seq)
		r.queue = r.queue[dropped:]
	}
}

// EnqueueReconcile freezes an events-EMPTY request carrying only the current
// rule set - the rule-REMOVAL signal. The prune otherwise only travelled on
// some other rule's transition, so deleting a rule while it was breached left
// the backend's alert_state row wedged at 'breach': the eventual re-enable's
// first-determination breach was then swallowed by the backend's state-change
// guard during a genuinely live breach. The backend treats an events-empty
// body with rule_ids as a reconcile (seq advance + prune, nothing upserted).
func (r *Reporter) EnqueueReconcile(ruleIDs []string) {
	p, ok := r.freeze(nil, ruleIDs)
	if !ok {
		return
	}
	r.queue = append(r.queue, p)
	if len(r.queue) > maxQueue {
		dropped := len(r.queue) - maxQueue
		r.log.Warn("breach queue full, dropping oldest", "dropped", dropped, "seq", r.queue[0].seq)
		r.queue = r.queue[dropped:]
	}
}

// freeze builds one pending request under a fresh seq. Shared by Enqueue and
// the stale-rebuild path so both produce identical bytes for the same events.
func (r *Reporter) freeze(events []wireEvent, ruleIDs []string) (pending, bool) {
	wire := wireRequest{
		AgentID: r.agentID,
		Secret:  r.secret,
		Seq:     r.nextSeq(),
		Events:  events,
		RuleIDs: ruleIDs,
	}
	if wire.Events == nil {
		wire.Events = []wireEvent{} // a reconcile marshals "events":[], never null
	}
	if wire.RuleIDs == nil {
		wire.RuleIDs = []string{}
	}
	body, err := json.Marshal(wire)
	if err != nil {
		// Cannot happen with these types; losing the batch beats crashing.
		r.log.Error("breach request marshal failed", "error", err.Error())
		return pending{}, false
	}
	return pending{seq: wire.Seq, body: body, events: events, ruleIDs: ruleIDs}, true
}

// Pending reports the undelivered count, for logging and tests.
func (r *Reporter) Pending() int { return len(r.queue) }

// Flush attempts delivery, strictly oldest-first, stopping at the first
// retryable failure.
//
// The FIFO order is load-bearing, not tidiness: seqs increase with age, and
// the backend treats anything at or below its high-water mark as stale. If a
// newer request were delivered past an undelivered older one, the older
// would come back {"stale":true} - which counts as delivered - and its
// events would be lost silently. Stopping on the first retryable failure is
// what preserves that ordering, and it also bounds a backend-down tick to a
// single timeout rather than one per queued request.
func (r *Reporter) Flush(ctx context.Context) {
	for len(r.queue) > 0 {
		p := r.queue[0]
		outcome, backendSeq := r.send(ctx, p)
		switch outcome {
		case sendDelivered, sendDropped:
			r.queue = r.queue[1:]
		case sendRetry:
			return
		case sendStale:
			// The backend's high-water mark is past this seq: a clock
			// regression across a restart, or a lost seq file. The events were
			// NOT processed and never will be at this seq, so dropping them
			// (the old behaviour) silently lost the post-restart state
			// re-assertion - including the clear for a pre-crash breach.
			// Adopt the mark and re-freeze the same events under a fresh seq;
			// alert_state's own state-compare keeps the resend replay-safe.
			// One rebuild per request: adoption guarantees the second attempt
			// is past the mark, so a second stale means something else is
			// wrong and retrying forever would wedge the queue.
			if p.rebuilt {
				r.log.Warn("breach report stale twice, dropping", "seq", p.seq)
				r.queue = r.queue[1:]
				continue
			}
			r.adoptSeq(backendSeq)
			rebuilt, ok := r.freeze(p.events, p.ruleIDs)
			if !ok {
				r.queue = r.queue[1:]
				continue
			}
			rebuilt.rebuilt = true
			r.log.Info("breach seq behind backend, re-sending under fresh seq",
				"stale_seq", p.seq, "new_seq", rebuilt.seq)
			r.queue[0] = rebuilt
		}
	}
}

type sendOutcome int

const (
	sendDelivered sendOutcome = iota
	sendDropped
	sendRetry
	// sendStale: the backend answered 2xx {"stale":true} - it has NOT
	// processed these events and never will at this seq.
	sendStale
)

// staleResponse is the one 2xx body shape that is NOT "delivered": the seq
// guard rejected the request. last_seq is the backend's high-water mark
// (0 from older backends, which omit it - adoption then no-ops and the
// rebuild still runs under clock-vs-lastSeq+1).
type staleResponse struct {
	Stale   bool  `json:"stale"`
	LastSeq int64 `json:"last_seq"`
}

// send makes one delivery attempt. A 2xx body is parsed just far enough to
// distinguish {"stale":true} - the backend REFUSED these events - from every
// other success shape; stale used to count as delivered, which silently
// discarded the post-restart re-assertion whenever the clock regressed.
func (r *Reporter) send(ctx context.Context, p pending) (sendOutcome, int64) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(p.body))
	if err != nil {
		r.log.Error("breach request build failed", "seq", p.seq, "error", err.Error())
		return sendDropped, 0
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		// Transport errors never contain the request body, so the secret
		// stays out of the journal here, as everywhere.
		r.log.Debug("breach send failed, will retry", "seq", p.seq, "error", err.Error())
		return sendRetry, 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		var stale staleResponse
		if err := json.Unmarshal(body, &stale); err == nil && stale.Stale {
			r.log.Debug("breach seq stale", "seq", p.seq, "backend_last_seq", stale.LastSeq)
			return sendStale, stale.LastSeq
		}
		r.log.Debug("breach delivered", "seq", p.seq, "status", resp.StatusCode)
		return sendDelivered, 0
	case resp.StatusCode == http.StatusTooManyRequests:
		r.log.Debug("breach send throttled, will retry", "seq", p.seq)
		return sendRetry, 0
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// This payload will never succeed; retrying forever is pointless.
		// 401 in particular means revoked or wrong secret - keep beating,
		// keep evaluating, just stop retrying this payload.
		r.log.Warn("breach report rejected, dropping", "seq", p.seq, "status", resp.StatusCode)
		return sendDropped, 0
	default:
		r.log.Debug("breach send failed, will retry", "seq", p.seq, "status", resp.StatusCode)
		return sendRetry, 0
	}
}
