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
}

// pending is one frozen request. body already contains seq; a retry sends
// exactly these bytes.
type pending struct {
	seq  int64
	body []byte
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
}

// New builds a Reporter. client's timeout bounds each delivery attempt.
func New(endpoint, agentID, secret string, client *http.Client, log *slog.Logger) *Reporter {
	return &Reporter{
		endpoint: endpoint,
		agentID:  agentID,
		secret:   secret,
		client:   client,
		log:      log,
		now:      time.Now,
	}
}

// nextSeq derives a seq from the clock: unix seconds at the moment the
// request is built.
//
// Timestamp-derived, deliberately not persisted. Restarts are frequent by
// design (every rule edit is one), and a persisted counter that reset to 1
// on file loss would have every subsequent breach silently swallowed as
// stale forever - an invisible, permanent failure. The clock is monotonic
// across restarts with no file to lose. Within the process: a same-second
// build increments, and a backward clock step (NTP) falls back to last+1,
// so the sequence is strictly increasing for the process lifetime.
// (Unix seconds stay inside the backend's INT32 column until 2038.)
func (r *Reporter) nextSeq() int64 {
	v := r.now().Unix()
	if v <= r.lastSeq {
		v = r.lastSeq + 1
	}
	r.lastSeq = v
	return v
}

// Enqueue freezes one batch of transitions into a request with a fresh seq.
//
// Transitions from one tick always share one request; transitions that occur
// while older requests are undelivered get their own request with their own
// seq - the pending ones are committed to theirs.
func (r *Reporter) Enqueue(events []rules.Event) {
	if len(events) == 0 {
		return
	}
	wire := wireRequest{
		AgentID: r.agentID,
		Secret:  r.secret,
		Seq:     r.nextSeq(),
		Events:  make([]wireEvent, 0, len(events)),
	}
	for _, ev := range events {
		wire.Events = append(wire.Events, wireEvent{
			RuleID:    ev.Rule.ID,
			Metric:    ev.Rule.Metric,
			Direction: ev.Direction,
			Value:     ev.Value,
			Threshold: ev.Rule.Threshold,
			Label:     ev.Rule.Label,
		})
	}
	body, err := json.Marshal(wire)
	if err != nil {
		// Cannot happen with these types; losing the batch beats crashing.
		r.log.Error("breach request marshal failed", "error", err.Error())
		return
	}
	r.queue = append(r.queue, pending{seq: wire.Seq, body: body})
	if len(r.queue) > maxQueue {
		dropped := len(r.queue) - maxQueue
		r.log.Warn("breach queue full, dropping oldest", "dropped", dropped, "seq", r.queue[0].seq)
		r.queue = r.queue[dropped:]
	}
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
		switch r.send(ctx, p) {
		case sendDelivered, sendDropped:
			r.queue = r.queue[1:]
		case sendRetry:
			return
		}
	}
}

type sendOutcome int

const (
	sendDelivered sendOutcome = iota
	sendDropped
	sendRetry
)

// send makes one delivery attempt. The response body is never parsed:
// {"stale":true} and {"accepted":0} both mean the backend has the
// information, so any 2xx is delivered.
func (r *Reporter) send(ctx context.Context, p pending) sendOutcome {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(p.body))
	if err != nil {
		r.log.Error("breach request build failed", "seq", p.seq, "error", err.Error())
		return sendDropped
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		// Transport errors never contain the request body, so the secret
		// stays out of the journal here, as everywhere.
		r.log.Debug("breach send failed, will retry", "seq", p.seq, "error", err.Error())
		return sendRetry
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		r.log.Debug("breach delivered", "seq", p.seq, "status", resp.StatusCode)
		return sendDelivered
	case resp.StatusCode == http.StatusTooManyRequests:
		r.log.Debug("breach send throttled, will retry", "seq", p.seq)
		return sendRetry
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// This payload will never succeed; retrying forever is pointless.
		// 401 in particular means revoked or wrong secret - keep beating,
		// keep evaluating, just stop retrying this payload.
		r.log.Warn("breach report rejected, dropping", "seq", p.seq, "status", resp.StatusCode)
		return sendDropped
	default:
		r.log.Debug("breach send failed, will retry", "seq", p.seq, "status", resp.StatusCode)
		return sendRetry
	}
}
