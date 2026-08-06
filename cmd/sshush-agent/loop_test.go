package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// runTickLoop must run work once immediately, then once per interval, and stop
// promptly when the context is cancelled.
func TestRunTickLoopImmediateThenPeriodicThenStops(t *testing.T) {
	var calls int32
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runTickLoop(ctx, func() time.Duration { return 20 * time.Millisecond }, func() {
			atomic.AddInt32(&calls, 1)
		})
		close(done)
	}()

	// Immediate first call happens with no wait.
	time.Sleep(10 * time.Millisecond)
	if atomic.LoadInt32(&calls) < 1 {
		t.Fatal("work was not run immediately")
	}

	time.Sleep(100 * time.Millisecond) // ~5 more ticks at 20ms
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runTickLoop did not stop within a second of cancel")
	}

	if got := atomic.LoadInt32(&calls); got < 3 {
		t.Errorf("calls = %d, want several ticks over ~110ms at 20ms", got)
	}
	// No further calls after it has returned.
	final := atomic.LoadInt32(&calls)
	time.Sleep(60 * time.Millisecond)
	if atomic.LoadInt32(&calls) != final {
		t.Error("work ran after the loop returned")
	}
}

// The beat and sample loops are fully independent: a slow sample tick must not
// drag the beat's cadence. Both run as separate runTickLoop instances sharing
// no state, so a sample that blocks far longer than its interval leaves the
// beat ticking at its own rate.
func TestBeatUnaffectedBySlowSample(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var beats, samples int32

	// Beat: 20ms interval, trivial work.
	go runTickLoop(ctx, func() time.Duration { return 20 * time.Millisecond }, func() {
		atomic.AddInt32(&beats, 1)
	})
	// Sample: 20ms interval, but each tick blocks 60ms - like a slow disk.
	go runTickLoop(ctx, func() time.Duration { return 20 * time.Millisecond }, func() {
		atomic.AddInt32(&samples, 1)
		time.Sleep(60 * time.Millisecond)
	})

	time.Sleep(300 * time.Millisecond)
	cancel()

	b := atomic.LoadInt32(&beats)
	s := atomic.LoadInt32(&samples)

	// The beat, unimpeded, ticks ~15 times over 300ms; the slow sample far
	// fewer. If they were coupled the beat would be dragged down toward the
	// sample's rate. Loose bounds keep this robust on a loaded machine.
	if b < 8 {
		t.Errorf("beats = %d, want the beat to keep its own fast cadence (>=8)", b)
	}
	if int(b) <= int(s)*2 {
		t.Errorf("beats=%d samples=%d: the beat did not run independently of the slow sample", b, s)
	}
}
