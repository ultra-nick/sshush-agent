// Package metrics samples system metrics from /proc and /sys.
//
// Every source is world-readable: the agent needs no capabilities and no
// root, and adding a metric that would require either is a design change,
// not an extension.
//
// A failed read means NO INFORMATION - never a breach, never a clear. The
// sampler reports ok=false and the rule is simply not evaluated this tick.
package metrics

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Collector holds the state that delta-based metrics (cpu, net) need between
// samples. Not safe for concurrent use; the agent's single tick loop is the
// only caller.
type Collector struct {
	log *slog.Logger

	// Injectable for tests; defaults read the live system.
	readFile func(string) ([]byte, error)
	statfs   func(path string) (blocks, bfree, bavail uint64, err error)
	zones    func() []string
	now      func() time.Time
	numCPU   float64

	prevCPU *CPUCounters
	prevNet map[string]netPoint
}

type netPoint struct {
	bytes uint64
	at    time.Time
}

// New returns a Collector reading the live system.
func New(log *slog.Logger, numCPU int) *Collector {
	return &Collector{
		log:      log,
		readFile: os.ReadFile,
		statfs:   statfsUsage,
		zones:    thermalZones,
		now:      time.Now,
		numCPU:   float64(numCPU),
		prevNet:  make(map[string]netPoint),
	}
}

// Sample returns the current value for a metric, or ok=false when there is no
// information this tick: a read failure, a missing sensor, or the first
// sample of a delta-based metric.
func (c *Collector) Sample(metric, label string) (float64, bool) {
	switch metric {
	case "cpu":
		return c.sampleCPU()
	case "mem":
		return c.sampleMem()
	case "load":
		return c.sampleLoad()
	case "disk":
		return c.sampleDisk(label)
	case "net":
		return c.sampleNet(label)
	case "temp":
		return c.sampleTemp()
	default:
		return 0, false
	}
}

// TempAvailable reports whether any thermal zone is readable. Used once at
// startup so a temp rule on sensorless hardware is called out loudly rather
// than silently never evaluating.
func (c *Collector) TempAvailable() bool {
	_, ok := c.sampleTemp()
	return ok
}

func (c *Collector) sampleCPU() (float64, bool) {
	data, err := c.readFile("/proc/stat")
	if err != nil {
		c.log.Debug("metric read failed", "metric", "cpu", "error", err.Error())
		return 0, false
	}
	cur, err := ParseCPU(data)
	if err != nil {
		c.log.Debug("metric parse failed", "metric", "cpu", "error", err.Error())
		return 0, false
	}
	prev := c.prevCPU
	c.prevCPU = &cur
	if prev == nil {
		// First sample is the baseline. Not a breach, not an error.
		return 0, false
	}
	return CPUPercent(*prev, cur)
}

func (c *Collector) sampleMem() (float64, bool) {
	data, err := c.readFile("/proc/meminfo")
	if err != nil {
		c.log.Debug("metric read failed", "metric", "mem", "error", err.Error())
		return 0, false
	}
	v, err := ParseMemPercent(data)
	if err != nil {
		c.log.Debug("metric parse failed", "metric", "mem", "error", err.Error())
		return 0, false
	}
	return v, true
}

func (c *Collector) sampleLoad() (float64, bool) {
	data, err := c.readFile("/proc/loadavg")
	if err != nil {
		c.log.Debug("metric read failed", "metric", "load", "error", err.Error())
		return 0, false
	}
	v, err := ParseLoad1(data)
	if err != nil {
		c.log.Debug("metric parse failed", "metric", "load", "error", err.Error())
		return 0, false
	}
	if c.numCPU <= 0 {
		return 0, false
	}
	// Per-core load, so the same threshold means the same thing on a
	// 1-core VPS and a 16-core box.
	return v / c.numCPU, true
}

func (c *Collector) sampleDisk(mount string) (float64, bool) {
	blocks, bfree, bavail, err := c.statfs(mount)
	if err != nil {
		c.log.Debug("metric read failed", "metric", "disk", "label", mount, "error", err.Error())
		return 0, false
	}
	// df's formula: used never counts the root-reserved blocks as available,
	// so the percentage matches what an operator sees in df output.
	used := float64(blocks - bfree)
	denom := used + float64(bavail)
	if denom <= 0 {
		return 0, false
	}
	return used / denom * 100, true
}

func (c *Collector) sampleNet(iface string) (float64, bool) {
	data, err := c.readFile("/proc/net/dev")
	if err != nil {
		c.log.Debug("metric read failed", "metric", "net", "error", err.Error())
		return 0, false
	}
	bytes, err := ParseNetBytes(data, iface)
	if err != nil {
		c.log.Debug("metric parse failed", "metric", "net", "label", iface, "error", err.Error())
		return 0, false
	}
	now := c.now()
	prev, had := c.prevNet[iface]
	c.prevNet[iface] = netPoint{bytes: bytes, at: now}
	if !had {
		return 0, false
	}
	dt := now.Sub(prev.at).Seconds()
	if dt <= 0 || bytes < prev.bytes {
		// Counter reset (interface bounce) or no elapsed time: baseline again.
		return 0, false
	}
	return float64(bytes-prev.bytes) * 8 / dt / 1e6, true
}

func (c *Collector) sampleTemp() (float64, bool) {
	best := -1.0
	for _, zone := range c.zones() {
		data, err := c.readFile(zone)
		if err != nil {
			continue
		}
		milli, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			continue
		}
		if v := float64(milli) / 1000; v > best {
			best = v
		}
	}
	if best < 0 {
		// Absent sensor is not an error; the rule is simply never evaluated.
		return 0, false
	}
	return best, true
}

// --- pure parsers, fixture-testable ---

// CPUCounters is one reading of the aggregate cpu line.
type CPUCounters struct {
	Busy  uint64
	Total uint64
}

// ParseCPU reads the aggregate "cpu " line of /proc/stat.
//
// Busy includes irq, softirq and steal, matching what top and htop show -
// on cloud VMs steal is real lost time and excluding it under-reports a
// contended host. guest/guest_nice are excluded because the kernel already
// folds them into user/nice; adding them would double-count.
func ParseCPU(data []byte) (CPUCounters, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 9 {
			return CPUCounters{}, fmt.Errorf("cpu line has %d fields, want at least 9", len(f))
		}
		var v [8]uint64
		for i := 0; i < 8; i++ {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return CPUCounters{}, fmt.Errorf("cpu field %d: %w", i+1, err)
			}
			v[i] = n
		}
		user, nice, system, idle, iowait, irq, softirq, steal := v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]
		busy := user + nice + system + irq + softirq + steal
		return CPUCounters{Busy: busy, Total: busy + idle + iowait}, nil
	}
	return CPUCounters{}, fmt.Errorf("no aggregate cpu line in /proc/stat")
}

// CPUPercent computes percent busy across the interval between two readings.
func CPUPercent(prev, cur CPUCounters) (float64, bool) {
	if cur.Total <= prev.Total {
		return 0, false
	}
	dBusy := float64(cur.Busy - prev.Busy)
	dTotal := float64(cur.Total - prev.Total)
	return dBusy / dTotal * 100, true
}

// ParseMemPercent computes used memory percent from /proc/meminfo.
//
// MemAvailable, not MemFree: free excludes reclaimable page cache, so a
// healthy Linux box always looks nearly out of memory by MemFree. Available
// is the kernel's own estimate of what could be allocated without swapping,
// which matches what an operator means by "used".
func ParseMemPercent(data []byte) (float64, error) {
	var total, avail float64
	var haveTotal, haveAvail bool
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			v, err := strconv.ParseFloat(f[1], 64)
			if err != nil {
				return 0, fmt.Errorf("MemTotal: %w", err)
			}
			total, haveTotal = v, true
		case "MemAvailable:":
			v, err := strconv.ParseFloat(f[1], 64)
			if err != nil {
				return 0, fmt.Errorf("MemAvailable: %w", err)
			}
			avail, haveAvail = v, true
		}
	}
	if !haveTotal || !haveAvail || total <= 0 {
		return 0, fmt.Errorf("meminfo missing MemTotal or MemAvailable")
	}
	return (total - avail) / total * 100, nil
}

// ParseLoad1 reads the 1-minute average from /proc/loadavg. The caller
// divides by core count.
func ParseLoad1(data []byte) (float64, error) {
	f := strings.Fields(string(data))
	if len(f) < 1 {
		return 0, fmt.Errorf("empty loadavg")
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, fmt.Errorf("loadavg: %w", err)
	}
	return v, nil
}

// ParseNetBytes returns rx+tx bytes for one interface from /proc/net/dev.
func ParseNetBytes(data []byte, iface string) (uint64, error) {
	for _, line := range strings.Split(string(data), "\n") {
		idx := strings.IndexByte(line, ':')
		if idx < 0 || strings.TrimSpace(line[:idx]) != iface {
			continue
		}
		f := strings.Fields(line[idx+1:])
		// Receive bytes is field 0; transmit bytes is field 8.
		if len(f) < 9 {
			return 0, fmt.Errorf("interface %s: %d fields, want at least 9", iface, len(f))
		}
		rx, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("interface %s rx: %w", iface, err)
		}
		tx, err := strconv.ParseUint(f[8], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("interface %s tx: %w", iface, err)
		}
		return rx + tx, nil
	}
	return 0, fmt.Errorf("interface %s not present in /proc/net/dev", iface)
}

// --- live-system defaults ---

func statfsUsage(path string) (blocks, bfree, bavail uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, err
	}
	return uint64(st.Blocks), uint64(st.Bfree), uint64(st.Bavail), nil
}

func thermalZones() []string {
	zones, err := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	if err != nil {
		return nil
	}
	return zones
}
