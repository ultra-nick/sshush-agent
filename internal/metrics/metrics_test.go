package metrics

import (
	"errors"
	"io"
	"log/slog"
	"math"
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
	procMeminfo = `MemTotal:        8062924 kB
MemFree:          234256 kB
MemAvailable:    4048572 kB
Buffers:          401232 kB
Cached:          3121400 kB
`
	procLoadavg = `2.48 1.90 1.55 2/1024 12345
`
	procNetDev1 = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    2000    0    0    0     0          0         0  1234567    2000    0    0    0     0       0          0
  eth0: 1000000    2000    0    0    0     0          0         0  2000000    3000    0    0    0     0       0          0
`
	// eth0 +900000 rx, +350000 tx = +1250000 bytes; over 1s = 10 Mbit/s.
	procNetDev2 = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 1900000    2500    0    0    0     0          0         0  2350000    3400    0    0    0     0       0          0
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

func TestParseLoad1(t *testing.T) {
	v, err := ParseLoad1([]byte(procLoadavg))
	if err != nil {
		t.Fatal(err)
	}
	approx(t, v, 2.48, 0.0001, "load1")
}

func TestParseNetBytes(t *testing.T) {
	b, err := ParseNetBytes([]byte(procNetDev1), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if b != 3000000 {
		t.Errorf("eth0 bytes = %d, want 3000000 (rx+tx)", b)
	}
	if _, err := ParseNetBytes([]byte(procNetDev1), "wg0"); err == nil {
		t.Error("missing interface must be an error")
	}
}

// testCollector wires a Collector to scripted file contents and a fake clock.
func testCollector(files map[string]string, zones []string, clock *time.Time) *Collector {
	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 4)
	c.readFile = func(path string) ([]byte, error) {
		if data, ok := files[path]; ok {
			return []byte(data), nil
		}
		return nil, errors.New("no such file")
	}
	c.zones = func() []string { return zones }
	c.now = func() time.Time { return *clock }
	return c
}

func TestCollectorCPUFirstSampleIsBaseline(t *testing.T) {
	files := map[string]string{"/proc/stat": procStat1}
	clock := time.Unix(1000, 0)
	c := testCollector(files, nil, &clock)

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

func TestCollectorNetFirstSampleIsBaseline(t *testing.T) {
	files := map[string]string{"/proc/net/dev": procNetDev1}
	clock := time.Unix(1000, 0)
	c := testCollector(files, nil, &clock)

	if _, ok := c.Sample("net", "eth0"); ok {
		t.Fatal("first net sample must produce nothing")
	}
	files["/proc/net/dev"] = procNetDev2
	clock = clock.Add(time.Second)
	v, ok := c.Sample("net", "eth0")
	if !ok {
		t.Fatal("second net sample must produce a value")
	}
	approx(t, v, 10.0, 0.01, "net Mbit/s")
}

func TestCollectorLoadPerCore(t *testing.T) {
	clock := time.Unix(1000, 0)
	c := testCollector(map[string]string{"/proc/loadavg": procLoadavg}, nil, &clock)
	v, ok := c.Sample("load", "")
	if !ok {
		t.Fatal("no load value")
	}
	approx(t, v, 0.62, 0.0001, "load per core (2.48 / 4)")
}

func TestCollectorTempHighestZoneAndAbsence(t *testing.T) {
	clock := time.Unix(1000, 0)
	files := map[string]string{
		"/sys/class/thermal/thermal_zone0/temp": "48500\n",
		"/sys/class/thermal/thermal_zone1/temp": "61000\n",
	}
	c := testCollector(files, []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/class/thermal/thermal_zone1/temp",
	}, &clock)
	v, ok := c.Sample("temp", "")
	if !ok {
		t.Fatal("no temp value")
	}
	approx(t, v, 61.0, 0.0001, "temp (highest zone)")
	if !c.TempAvailable() {
		t.Error("TempAvailable = false with readable zones")
	}

	// No zones at all: not an error, just no information.
	none := testCollector(map[string]string{}, nil, &clock)
	if _, ok := none.Sample("temp", ""); ok {
		t.Error("absent sensor must yield ok=false")
	}
	if none.TempAvailable() {
		t.Error("TempAvailable = true with no zones")
	}
}

func TestCollectorReadFailureIsNoInformation(t *testing.T) {
	clock := time.Unix(1000, 0)
	c := testCollector(map[string]string{}, nil, &clock)
	for _, m := range []string{"cpu", "mem", "load", "net"} {
		if _, ok := c.Sample(m, "eth0"); ok {
			t.Errorf("%s: read failure must yield ok=false", m)
		}
	}
}
