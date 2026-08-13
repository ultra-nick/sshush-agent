package metrics

import (
	"errors"
	"io"
	"log/slog"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

// Fixtures captured from real systems. procStat1/2 include non-zero steal -
// the cloud-VM case the busy calculation must not ignore.
const (
	procStat1 = `cpu  84650 210 34761 8492104 12047 0 2601 1830 0 0
cpu0 42325 105 17380 4246052 6023 0 1300 915 0 0
intr 123456
ctxt 654321
`
	// +900 busy (user), +100 idle over procStat1: exactly 90% busy.
	procStat2 = `cpu  85550 210 34761 8492204 12047 0 2601 1830 0 0
cpu0 42775 105 17380 4246102 6023 0 1300 915 0 0
`
	// Swap present: 2097148 total, 1048574 free -> 50% used.
	procMeminfo = `MemTotal:        8062924 kB
MemFree:          234256 kB
MemAvailable:    4048572 kB
Buffers:          401232 kB
Cached:          3121400 kB
SwapTotal:       2097148 kB
SwapFree:        1048574 kB
`
	// A machine with no swap configured.
	procMeminfoNoSwap = `MemTotal:        8062924 kB
MemFree:          234256 kB
MemAvailable:    4048572 kB
SwapTotal:             0 kB
SwapFree:              0 kB
`
	procLoadavg = `2.48 1.90 1.55 2/1024 12345
`
)

func approx(t *testing.T, got, want, tol float64, what string) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s = %v, want %v (tolerance %v)", what, got, want, tol)
	}
}

func TestParseCPUWithSteal(t *testing.T) {
	c, err := ParseCPU([]byte(procStat1))
	if err != nil {
		t.Fatal(err)
	}
	// busy = 84650+210+34761+0+2601+1830 = 124052 (guest excluded).
	if c.Busy != 124052 {
		t.Errorf("Busy = %d, want 124052 (steal must be included, guest must not)", c.Busy)
	}
	if c.Total != 124052+8492104+12047 {
		t.Errorf("Total = %d, want %d", c.Total, 124052+8492104+12047)
	}
}

func TestCPUPercentDelta(t *testing.T) {
	c1, _ := ParseCPU([]byte(procStat1))
	c2, _ := ParseCPU([]byte(procStat2))
	v, ok := CPUPercent(c1, c2)
	if !ok {
		t.Fatal("no value from a genuine delta")
	}
	approx(t, v, 90.0, 0.01, "cpu percent")

	if _, ok := CPUPercent(c1, c1); ok {
		t.Error("zero delta must yield ok=false, not a number")
	}
}

func TestParseMemPercentUsesAvailable(t *testing.T) {
	v, err := ParseMemPercent([]byte(procMeminfo))
	if err != nil {
		t.Fatal(err)
	}
	// (8062924-4048572)/8062924 - the MemFree figure would give ~97%.
	approx(t, v, 49.79, 0.01, "mem percent")
	if v > 90 {
		t.Error("looks like MemFree was used instead of MemAvailable")
	}
}

func TestParseSwapPercent(t *testing.T) {
	v, hasSwap, err := ParseSwapPercent([]byte(procMeminfo))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSwap {
		t.Fatal("swap should be reported present")
	}
	// (2097148-1048574)/2097148 = 50%.
	approx(t, v, 50.0, 0.01, "swap percent")
}

func TestParseSwapPercentNoSwap(t *testing.T) {
	_, hasSwap, err := ParseSwapPercent([]byte(procMeminfoNoSwap))
	if err != nil {
		t.Fatalf("SwapTotal 0 must not be an error: %v", err)
	}
	if hasSwap {
		t.Error("SwapTotal 0 must report hasSwap=false, not a breach")
	}
}

func TestParseLoad1(t *testing.T) {
	v, err := ParseLoad1([]byte(procLoadavg))
	if err != nil {
		t.Fatal(err)
	}
	approx(t, v, 2.48, 0.0001, "load1")
}

// testCollector wires a Collector to scripted file contents. A path present in
// files reads its value; anything else is a read failure.
func testCollector(files map[string]string, zones []string) *Collector {
	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 4)
	c.readFile = func(path string) ([]byte, error) {
		if data, ok := files[path]; ok {
			return []byte(data), nil
		}
		return nil, errors.New("no such file")
	}
	c.zones = func() []string { return zones }
	return c
}

func TestCollectorCPUFirstSampleIsBaseline(t *testing.T) {
	files := map[string]string{"/proc/stat": procStat1}
	c := testCollector(files, nil)

	if _, ok := c.Sample("cpu", ""); ok {
		t.Fatal("first cpu sample must produce nothing")
	}
	files["/proc/stat"] = procStat2
	v, ok := c.Sample("cpu", "")
	if !ok {
		t.Fatal("second cpu sample must produce a value")
	}
	approx(t, v, 90.0, 0.01, "cpu percent via collector")
}

func TestCollectorSwap(t *testing.T) {
	c := testCollector(map[string]string{"/proc/meminfo": procMeminfo}, nil)
	v, ok := c.Sample("swap", "")
	if !ok {
		t.Fatal("no swap value from a machine with swap")
	}
	approx(t, v, 50.0, 0.01, "swap percent via collector")
	if !c.SwapAvailable() {
		t.Error("SwapAvailable = false with swap configured")
	}

	// No swap configured: not an error, just no information, and no breach.
	none := testCollector(map[string]string{"/proc/meminfo": procMeminfoNoSwap}, nil)
	if _, ok := none.Sample("swap", ""); ok {
		t.Error("swap sample on a swapless machine must yield ok=false")
	}
	if none.SwapAvailable() {
		t.Error("SwapAvailable = true with no swap")
	}
}

func TestCollectorLoadPerCore(t *testing.T) {
	c := testCollector(map[string]string{"/proc/loadavg": procLoadavg}, nil)
	v, ok := c.Sample("load", "")
	if !ok {
		t.Fatal("no load value")
	}
	approx(t, v, 0.62, 0.0001, "load per core (2.48 / 4)")
}

func TestCollectorTempHighestZoneAndAbsence(t *testing.T) {
	files := map[string]string{
		"/sys/class/thermal/thermal_zone0/temp": "48500\n",
		"/sys/class/thermal/thermal_zone1/temp": "61000\n",
	}
	c := testCollector(files, []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/class/thermal/thermal_zone1/temp",
	})
	v, ok := c.Sample("temp", "")
	if !ok {
		t.Fatal("no temp value")
	}
	approx(t, v, 61.0, 0.0001, "temp (highest zone)")
	if !c.TempAvailable() {
		t.Error("TempAvailable = false with readable zones")
	}

	// No zones at all: not an error, just no information.
	none := testCollector(map[string]string{}, nil)
	if _, ok := none.Sample("temp", ""); ok {
		t.Error("absent sensor must yield ok=false")
	}
	if none.TempAvailable() {
		t.Error("TempAvailable = true with no zones")
	}
}

// interfaceDown is a state metric: 1 for up, 0 for down, and NO INFORMATION
// (ok=false) when the interface is absent. "unknown" counts as up.
func TestCollectorInterfaceState(t *testing.T) {
	cases := map[string]struct {
		operstate string
		wantVal   float64
		wantOK    bool
	}{
		"up":             {"up\n", 1, true},
		"down":           {"down\n", 0, true},
		"unknown":        {"unknown\n", 1, true}, // working virtual/wireless NIC
		"lowerlayerdown": {"lowerlayerdown\n", 0, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := testCollector(map[string]string{
				"/sys/class/net/eth0/operstate": tc.operstate,
			}, nil)
			v, ok := c.Sample("interfaceDown", "eth0")
			if ok != tc.wantOK || v != tc.wantVal {
				t.Errorf("operstate %q -> (%v, %v), want (%v, %v)", tc.operstate, v, ok, tc.wantVal, tc.wantOK)
			}
		})
	}
}

func TestCollectorInterfaceMissingIsNoInformation(t *testing.T) {
	// No operstate file at all: the interface was removed or renamed. Must be
	// no information, never a breach in either direction.
	c := testCollector(map[string]string{}, nil)
	if _, ok := c.Sample("interfaceDown", "eth9"); ok {
		t.Error("missing interface must yield ok=false")
	}
	// A label with a slash must not escape sysfs into an arbitrary read.
	if _, ok := c.Sample("interfaceDown", "../../etc/hostname"); ok {
		t.Error("a slashed label must be rejected as no information")
	}
}

func TestCollectorReadFailureIsNoInformation(t *testing.T) {
	c := testCollector(map[string]string{}, nil)
	for _, m := range []string{"cpu", "mem", "swap", "load"} {
		if _, ok := c.Sample(m, ""); ok {
			t.Errorf("%s: read failure must yield ok=false", m)
		}
	}
}

// A statfs that blocks past the deadline must yield no information within the
// timeout, never stall the caller, and never be mistaken for a breach.
func TestCollectorDiskTimeout(t *testing.T) {
	release := make(chan struct{})
	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 4)
	c.diskTimeout = 40 * time.Millisecond
	c.statfs = func(string) (uint64, uint64, uint64, error) {
		<-release // hang until the test lets go
		return 0, 0, 0, nil
	}

	start := time.Now()
	_, ok := c.Sample("disk", "/mnt/hung")
	elapsed := time.Since(start)
	if ok {
		t.Error("a hung statfs must yield ok=false (no information)")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("disk sample blocked %v, must return near the %v timeout", elapsed, c.diskTimeout)
	}
	close(release) // let the leaked goroutine finish so the test is clean
}

// While one disk mount is hung, every other metric - and other disk mounts -
// must still sample normally.
func TestCollectorDiskTimeoutDoesNotStallOthers(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 4)
	c.diskTimeout = 40 * time.Millisecond
	c.readFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/stat":
			return []byte(procStat2), nil
		case "/proc/meminfo":
			return []byte(procMeminfo), nil
		default:
			return nil, errors.New("no such file")
		}
	}
	c.statfs = func(mount string) (uint64, uint64, uint64, error) {
		if mount == "/mnt/hung" {
			<-release
		}
		// A healthy mount: 100 blocks, 50 free/avail -> 50% used.
		return 100, 50, 50, nil
	}

	// The hung mount times out...
	if _, ok := c.Sample("disk", "/mnt/hung"); ok {
		t.Fatal("hung mount must time out to ok=false")
	}
	// ...and a healthy mount still reads.
	if v, ok := c.Sample("disk", "/"); !ok || v != 50 {
		t.Errorf("healthy disk after a hung one = (%v, %v), want (50, true)", v, ok)
	}
	// ...and non-disk metrics are unaffected.
	if _, ok := c.Sample("mem", ""); !ok {
		t.Error("mem sample must work while a disk mount is hung")
	}
}

// A mount that stays blocked must not spawn a fresh statfs goroutine every
// tick: while one is in flight the next tick skips immediately.
func TestCollectorDiskInflightGuard(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	var calls int32
	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 4)
	c.diskTimeout = 20 * time.Millisecond
	c.statfs = func(string) (uint64, uint64, uint64, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		return 0, 0, 0, nil
	}

	// First tick spawns the (hung) statfs and times out.
	c.Sample("disk", "/mnt/hung")
	// Several more ticks while it is still blocked: none spawns another.
	for i := 0; i < 5; i++ {
		if _, ok := c.Sample("disk", "/mnt/hung"); ok {
			t.Fatal("still-blocked mount must yield ok=false")
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("statfs spawned %d times for a stuck mount, want exactly 1", got)
	}
}

// Busy regression (a hypervisor resetting the steal counter across a live
// migration) must invalidate the sample, exactly as a Total regression does -
// unguarded, the uint64 subtraction wrapped to a quintillion-percent CPU.
func TestCPUPercentRejectsBusyRegression(t *testing.T) {
	prev := CPUCounters{Busy: 1000, Total: 10000}
	cur := CPUCounters{Busy: 990, Total: 10500} // Busy fell, Total still climbed
	if v, ok := CPUPercent(prev, cur); ok {
		t.Errorf("busy regression accepted as %v%%, want rejected", v)
	}
}

// MARK: audit-round fixtures - hostile/malformed inputs and the new guards.

func TestSampleTempRejectsGarbageZone(t *testing.T) {
	// One flaky zone reporting INT_MAX millidegrees must be NO INFORMATION,
	// not a "valid" ~2,147,483 C sample (which breached the temp rule AND
	// 400ed the whole breach batch at the backend's +-1e6 bound).
	c := testCollector(map[string]string{
		"/z/broken": "9223372036854775807",
		"/z/real":   "48250",
	}, []string{"/z/broken", "/z/real"})
	v, ok := c.Sample("temp", "")
	if !ok || v != 48.25 {
		t.Fatalf("temp = %v ok=%v, want the real zone's 48.25 with the garbage zone ignored", v, ok)
	}
	// ALL zones garbage: no information at all.
	c = testCollector(map[string]string{"/z/broken": "2147483647000"}, []string{"/z/broken"})
	if _, ok := c.Sample("temp", ""); ok {
		t.Fatal("a garbage-only zone set must yield no information")
	}
}

func TestSampleTempNegativeIsInformation(t *testing.T) {
	// The outdoor Pi: hottest zone below 0 C is a real reading, not "no
	// sensor" (the old -1.0 sentinel conflated the two).
	c := testCollector(map[string]string{"/z/cold": "-12500"}, []string{"/z/cold"})
	v, ok := c.Sample("temp", "")
	if !ok || v != -12.5 {
		t.Fatalf("temp = %v ok=%v, want -12.5 true", v, ok)
	}
	if !c.TempAvailable() {
		t.Fatal("TempAvailable must be true for a working-but-cold sensor")
	}
}

func TestDiskPercentInconsistentStatfsIsNoInformation(t *testing.T) {
	// bfree > blocks wrapped the uint64 subtraction and latched a false
	// ~100% page. Inconsistent numbers are no information.
	if _, ok := DiskPercent(100, 150, 40); ok {
		t.Fatal("bfree > blocks must be no information")
	}
	if _, ok := DiskPercent(100, 40, 150); ok {
		t.Fatal("bavail > blocks must be no information")
	}
	// Sane numbers still compute df's formula.
	v, ok := DiskPercent(100, 40, 30)
	if !ok || v < 66.66 || v > 66.67 {
		t.Fatalf("DiskPercent = %v ok=%v, want ~66.67 true", v, ok)
	}
}

func TestCPUPercentIowaitRegressionIsNoInformation(t *testing.T) {
	// iowait is in Total but not Busy and is non-monotonic on SMP: a partial
	// regression that leaves Total climbing shrinks dTotal below dBusy and
	// used to yield >100% "valid" samples.
	prev := CPUCounters{Busy: 100, Total: 200}
	cur := CPUCounters{Busy: 110, Total: 202} // dBusy 10 > dTotal 2
	if _, ok := CPUPercent(prev, cur); ok {
		t.Fatal("dBusy > dTotal must be no information")
	}
}

func TestParsersRejectMalformedInput(t *testing.T) {
	// Every parse-error branch reachable by a fixture, so a refactor turning
	// an error into a zero-value success (a false 0% / false clear) fails
	// the suite instead of shipping.
	if _, err := ParseCPU([]byte("cpu 1 2 3\n")); err == nil {
		t.Error("short cpu line must error")
	}
	if _, err := ParseCPU([]byte("intr 0 0 0\n")); err == nil {
		t.Error("missing aggregate cpu line must error")
	}
	if _, err := ParseMemPercent([]byte("MemTotal: 1000 kB\n")); err == nil {
		t.Error("meminfo without MemAvailable must error")
	}
	if _, _, err := ParseSwapPercent([]byte("SwapTotal: abc kB\n")); err == nil {
		t.Error("non-numeric SwapTotal must error")
	}
	if _, err := ParseLoad1([]byte("")); err == nil {
		t.Error("empty loadavg must error")
	}
	if _, err := ParseLoad1([]byte("not-a-number 0.2 0.3")); err == nil {
		t.Error("garbage load1 must error")
	}
}
