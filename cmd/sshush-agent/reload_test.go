package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultra-nick/sshush-agent/internal/metrics"
	"github.com/ultra-nick/sshush-agent/internal/rules"
)

const (
	oneRule = `{"interval_s":45,"rules":[{"rule_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","metric":"cpu","threshold":80,"duration_s":300,"label":""}]}`
	twoRule = `{"interval_s":60,"rules":[
	  {"rule_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","metric":"cpu","threshold":80,"duration_s":300,"label":""},
	  {"rule_id":"00000000-0000-4000-8000-00000000000c","metric":"mem","threshold":90,"duration_s":60,"label":""}]}`
)

// Returns the watcher (its .unreachable atomic is reachable via the field for
// the tests that check it), a log buffer, the interval atomic, and the engine.
func newTestWatcher(t *testing.T, path string) (*ruleWatcher, *bytes.Buffer, *atomic.Int64, *rules.Engine) {
	t.Helper()
	iv := new(atomic.Int64)
	iv.Store(int64(defaultIntervalS) * int64(time.Second))
	unr := new(atomic.Int64)
	unr.Store(int64(defaultUnreachableS))
	eng := rules.New(nil, time.Now)
	var buf bytes.Buffer
	w := &ruleWatcher{
		path:        path,
		log:         slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		engine:      eng,
		collector:   metrics.New(slog.New(slog.NewTextHandler(io.Discard, nil)), 4),
		interval:    iv,
		unreachable: unr,
	}
	return w, &buf, iv, eng
}

func writeFileMtime(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func nanos(seconds int) int64 { return int64(seconds) * int64(time.Second) }

func TestWatcherStartupMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json") // never created
	w, buf, iv, eng := newTestWatcher(t, path)

	w.check(true)

	if len(eng.Rules()) != 0 {
		t.Errorf("rules present with no file: %v", eng.Rules())
	}
	if iv.Load() != nanos(defaultIntervalS) {
		t.Errorf("interval changed with no file: %d", iv.Load())
	}
	if !strings.Contains(buf.String(), "no rules file") {
		t.Errorf("missing startup warning, log:\n%s", buf.String())
	}
}

func TestWatcherLoadsValidFileAtStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeFileMtime(t, path, oneRule, time.Unix(1000, 0))
	w, _, iv, eng := newTestWatcher(t, path)

	w.check(true)

	if len(eng.Rules()) != 1 {
		t.Fatalf("rules = %d, want 1", len(eng.Rules()))
	}
	if iv.Load() != nanos(45) {
		t.Errorf("interval = %d, want 45s", iv.Load())
	}
}

func TestWatcherUnchangedMtimeIsNotReRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	mtime := time.Unix(1000, 0)
	writeFileMtime(t, path, oneRule, mtime)
	w, _, _, eng := newTestWatcher(t, path)
	w.check(true) // one rule

	// Corrupt the CONTENT but keep the SAME mtime. If the agent re-read, the
	// parse would fail; the mtime gate must skip the read entirely.
	writeFileMtime(t, path, "{ broken", mtime)
	w.check(false)

	if len(eng.Rules()) != 1 {
		t.Errorf("re-read despite unchanged mtime; rules = %v", eng.Rules())
	}
}

func TestWatcherReloadsOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeFileMtime(t, path, oneRule, time.Unix(1000, 0))
	w, _, iv, eng := newTestWatcher(t, path)
	w.check(true)

	writeFileMtime(t, path, twoRule, time.Unix(2000, 0))
	w.check(false)

	if len(eng.Rules()) != 2 {
		t.Errorf("rules = %d, want 2 after reload", len(eng.Rules()))
	}
	if iv.Load() != nanos(60) {
		t.Errorf("interval = %d, want 60s after reload", iv.Load())
	}
}

func TestWatcherMalformedKeepsPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeFileMtime(t, path, oneRule, time.Unix(1000, 0))
	w, buf, iv, eng := newTestWatcher(t, path)
	w.check(true)

	// A truncated file, with a newer mtime so the read is attempted.
	writeFileMtime(t, path, `{"interval_s":60,"rules":[{"rule_`, time.Unix(2000, 0))
	w.check(false)

	if len(eng.Rules()) != 1 {
		t.Error("a malformed file cleared the rules in force")
	}
	if iv.Load() != nanos(45) {
		t.Error("a malformed file changed the interval")
	}
	if !strings.Contains(buf.String(), "ignored") {
		t.Errorf("no warning on a malformed reload, log:\n%s", buf.String())
	}

	// Fixing the file (new mtime) recovers.
	writeFileMtime(t, path, twoRule, time.Unix(3000, 0))
	w.check(false)
	if len(eng.Rules()) != 2 {
		t.Error("did not recover after the file was fixed")
	}
}

func TestWatcherMissingAtRuntimeKeepsPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeFileMtime(t, path, oneRule, time.Unix(1000, 0))
	w, buf, iv, eng := newTestWatcher(t, path)
	w.check(true)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.check(false)

	if len(eng.Rules()) != 1 {
		t.Error("removing the file cleared the rules in force")
	}
	if iv.Load() != nanos(45) {
		t.Error("removing the file changed the interval")
	}
	if !strings.Contains(buf.String(), "gone") {
		t.Errorf("no warning when the file vanished, log:\n%s", buf.String())
	}
}

func TestWatcherIntervalBelow30Rejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeFileMtime(t, path, oneRule, time.Unix(1000, 0))
	w, _, iv, eng := newTestWatcher(t, path)
	w.check(true) // interval 45, one rule

	// interval_s below the floor invalidates the whole file, so the previous
	// interval AND the previous rules are kept.
	writeFileMtime(t, path, `{"interval_s":10,"rules":[]}`, time.Unix(2000, 0))
	w.check(false)

	if iv.Load() != nanos(45) {
		t.Errorf("out-of-range interval was applied: %d", iv.Load())
	}
	if len(eng.Rules()) != 1 {
		t.Error("an invalid file dropped the rules in force")
	}
}

func TestLoadRulesFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("valid with unreachable", func(t *testing.T) {
		s, err := loadRulesFile(write("ok.json", `{"interval_s":45,"unreachable_after_s":300,"rules":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		if s.intervalS != 45 || s.unreachableAfterS != 300 || s.unreachableDefaulted {
			t.Errorf("parsed = %+v", s)
		}
	})
	t.Run("missing unreachable defaults with flag", func(t *testing.T) {
		s, err := loadRulesFile(write("noun.json", oneRule)) // oneRule has no unreachable field
		if err != nil {
			t.Fatal(err)
		}
		if s.unreachableAfterS != defaultUnreachableS || !s.unreachableDefaulted {
			t.Errorf("missing unreachable = %d, defaulted %v; want %d, true", s.unreachableAfterS, s.unreachableDefaulted, defaultUnreachableS)
		}
	})
	t.Run("unreachable below 60 rejected", func(t *testing.T) {
		if _, err := loadRulesFile(write("low_u.json", `{"interval_s":60,"unreachable_after_s":59,"rules":[]}`)); err == nil {
			t.Error("unreachable 59 accepted")
		}
	})
	t.Run("unreachable above 3600 rejected", func(t *testing.T) {
		if _, err := loadRulesFile(write("high_u.json", `{"interval_s":60,"unreachable_after_s":3601,"rules":[]}`)); err == nil {
			t.Error("unreachable 3601 accepted")
		}
	})
	t.Run("interval below 30", func(t *testing.T) {
		if _, err := loadRulesFile(write("low.json", `{"interval_s":29,"rules":[]}`)); err == nil {
			t.Error("interval 29 accepted")
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		if _, err := loadRulesFile(write("bad.json", `{"interval_s":`)); err == nil {
			t.Error("malformed json accepted")
		}
	})
	t.Run("invalid rule", func(t *testing.T) {
		bad := `{"interval_s":60,"rules":[{"rule_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","metric":"uptime","threshold":1,"duration_s":0,"label":""}]}`
		if _, err := loadRulesFile(write("badrule.json", bad)); err == nil {
			t.Error("invalid metric accepted")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if _, err := loadRulesFile(filepath.Join(dir, "nope.json")); err == nil {
			t.Error("missing file accepted")
		}
	})
}

// buildBeatBody must carry unreachable_after_s on every beat, and the current
// value from the atomic - not interval_s.
func TestBuildBeatBody(t *testing.T) {
	body := buildBeatBody("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "sekret", 240)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["agent_id"] != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" || got["secret"] != "sekret" {
		t.Errorf("identity fields wrong: %v", got)
	}
	if got["unreachable_after_s"].(float64) != 240 {
		t.Errorf("unreachable_after_s = %v, want 240", got["unreachable_after_s"])
	}
	if _, present := got["interval_s"]; present {
		t.Error("interval_s must NOT be in the beat body")
	}
}

// unreachable_after_s and interval_s change independently on reload, and both
// atomics reflect the new file.
func TestWatcherUpdatesUnreachableIndependently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeFileMtime(t, path, `{"interval_s":60,"unreachable_after_s":180,"rules":[]}`, time.Unix(1000, 0))
	w, _, iv, _ := newTestWatcher(t, path)
	w.check(true)
	if iv.Load() != nanos(60) || w.unreachable.Load() != 180 {
		t.Fatalf("startup: interval %d, unreachable %d", iv.Load(), w.unreachable.Load())
	}

	// Change ONLY unreachable_after_s.
	writeFileMtime(t, path, `{"interval_s":60,"unreachable_after_s":600,"rules":[]}`, time.Unix(2000, 0))
	w.check(false)
	if iv.Load() != nanos(60) || w.unreachable.Load() != 600 {
		t.Errorf("after unreachable change: interval %d (want 60s), unreachable %d (want 600)", iv.Load(), w.unreachable.Load())
	}

	// Change ONLY interval_s.
	writeFileMtime(t, path, `{"interval_s":120,"unreachable_after_s":600,"rules":[]}`, time.Unix(3000, 0))
	w.check(false)
	if iv.Load() != nanos(120) || w.unreachable.Load() != 600 {
		t.Errorf("after interval change: interval %d (want 120s), unreachable %d (want 600)", iv.Load(), w.unreachable.Load())
	}
}

// An out-of-range unreachable_after_s keeps the previous value (and rules).
func TestWatcherUnreachableOutOfRangeKeepsPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeFileMtime(t, path, `{"interval_s":60,"unreachable_after_s":300,"rules":[]}`, time.Unix(1000, 0))
	w, _, _, _ := newTestWatcher(t, path)
	w.check(true)

	writeFileMtime(t, path, `{"interval_s":60,"unreachable_after_s":10,"rules":[]}`, time.Unix(2000, 0))
	w.check(false)
	if w.unreachable.Load() != 300 {
		t.Errorf("out-of-range unreachable applied: %d, want 300 kept", w.unreachable.Load())
	}
}
