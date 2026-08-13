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
	"sync"
	"syscall"
	"time"
)

// diskTimeout bounds one statfs. Every other metric source is a kernel
// pseudo-file that cannot block; statfs hits the filesystem and, on an
// unresponsive NFS or CIFS mount, can block for seconds or indefinitely.
// Left unbounded it would stall the sample tick and silently stop ALL rule
// evaluation on the machine - one flaky mount taking out monitoring entirely.
const diskTimeout = 2 * time.Second

// Collector holds the state that delta-based metrics (cpu) need between
// samples. Not safe for concurrent use; the agent's single tick loop is the
// only caller.
type Collector struct {
	log *slog.Logger

	// Injectable for tests; defaults read the live system.
	readFile    func(string) ([]byte, error)
	statfs      func(path string) (blocks, bfree, bavail uint64, err error)
	zones       func() []string
	numCPU      float64
	diskTimeout time.Duration

	prevCPU *CPUCounters

	// diskInflight guards against piling up statfs goroutines on a hung
	// mount: while a mount's statfs is still blocked from a previous tick, the
	// next tick skips it instead of spawning another, bounding the leak to one
	// goroutine per stuck mount. Written by the sample goroutine (set) and the
	// statfs goroutines (clear), so it needs the mutex.
	diskMu       sync.Mutex
	diskInflight map[string]bool
}

// New returns a Collector reading the live system.
func New(log *slog.Logger, numCPU int) *Collector {
	return &Collector{
		log:          log,
		readFile:     os.ReadFile,
		statfs:       statfsUsage,
		zones:        thermalZones,
		numCPU:       float64(numCPU),
		diskTimeout:  diskTimeout,
		diskInflight: make(map[string]bool),
	}
}

// Sample returns the current value for a metric, or ok=false when there is no
// information this tick: a read failure, a missing sensor, an unconfigured
// resource, or the first sample of a delta-based metric.
//
// For the state metric interfaceDown the value is the DISPLAY value - 1 for
// up, 0 for down - not a magnitude. The rules engine knows to compare it as a
// state, not against a threshold.
func (c *Collector) Sample(metric, label string) (float64, bool) {
	switch metric {
	case "cpu":
		return c.sampleCPU()
	case "mem":
		return c.sampleMem()
	case "swap":
		return c.sampleSwap()
	case "load":
		return c.sampleLoad()
	case "disk":
		return c.sampleDisk(label)
	case "temp":
		return c.sampleTemp()
	case "interfaceDown":
		return c.sampleInterface(label)
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

// SwapAvailable reports whether the machine has swap configured. Used once at
// startup so a swap rule on a swapless machine is called out, exactly as a
// missing thermal zone is for temp.
func (c *Collector) SwapAvailable() bool {
	data, err := c.readFile("/proc/meminfo")
	if err != nil {
		return false
	}
	_, hasSwap, err := ParseSwapPercent(data)
	return err == nil && hasSwap
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

func (c *Collector) sampleSwap() (float64, bool) {
	data, err := c.readFile("/proc/meminfo")
	if err != nil {
		c.log.Debug("metric read failed", "metric", "swap", "error", err.Error())
		return 0, false
	}
	v, hasSwap, err := ParseSwapPercent(data)
	if err != nil {
		c.log.Debug("metric parse failed", "metric", "swap", "error", err.Error())
		return 0, false
	}
	if !hasSwap {
		// SwapTotal == 0: swap is not configured. Not an error and not a
		// breach - the rule is simply never evaluated, exactly as a missing
		// thermal zone is handled.
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
	perCore := v / c.numCPU
	// Plausibility bound, mirroring the temp sampler's: the backend 400s any
	// event value beyond +-1e6 and a 4xx drops the whole batch, so an
	// implausible reading must become no-information here rather than poison
	// co-batched events. Genuine loadavg cannot approach this (millions of
	// runnable tasks per core); only corrupt input can.
	if perCore < 0 || perCore > 1e6 {
		c.log.Debug("metric implausible", "metric", "load", "per_core", perCore)
		return 0, false
	}
	return perCore, true
}

func (c *Collector) sampleDisk(mount string) (float64, bool) {
	blocks, bfree, bavail, ok := c.statfsBounded(mount)
	if !ok {
		// Timed out, still-blocked from a prior tick, or a real error - all
		// NO INFORMATION, which the engine handles by neither advancing nor
		// resetting the duration timer.
		return 0, false
	}
	return DiskPercent(blocks, bfree, bavail)
}

// DiskPercent computes df's used percentage from raw statfs numbers.
//
// Inconsistent statfs (bfree or bavail exceeding blocks - driver- or
// FUSE-supplied numbers are not guaranteed coherent) is NO INFORMATION,
// exactly like CPUPercent's regression guard: without this, the uint64
// subtraction below wrapped to ~1.8e19, dominated the denominator, and
// returned a "valid" ~100% sample - a false disk page that then LATCHED,
// because clear needs one below-threshold sample that never arrives while
// the inconsistency persists.
func DiskPercent(blocks, bfree, bavail uint64) (float64, bool) {
	if bfree > blocks || bavail > blocks {
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

// statfsBounded runs statfs with a deadline so a hung mount cannot stall the
// tick. On timeout it returns no information and leaves the syscall running in
// the background; while that syscall is still blocked, later ticks for the
// same mount skip immediately rather than spawning another goroutine.
func (c *Collector) statfsBounded(mount string) (blocks, bfree, bavail uint64, ok bool) {
	c.diskMu.Lock()
	if c.diskInflight[mount] {
		c.diskMu.Unlock()
		c.log.Debug("metric read skipped: previous disk statfs still blocked", "metric", "disk", "label", mount)
		return 0, 0, 0, false
	}
	c.diskInflight[mount] = true
	c.diskMu.Unlock()

	type result struct {
		blocks, bfree, bavail uint64
		err                   error
	}
	// Buffered so a late syscall never blocks trying to send after we have
	// already given up on it.
	ch := make(chan result, 1)
	go func() {
		b, f, a, err := c.statfs(mount)
		c.diskMu.Lock()
		c.diskInflight[mount] = false
		c.diskMu.Unlock()
		ch <- result{b, f, a, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			c.log.Debug("metric read failed", "metric", "disk", "label", mount, "error", r.err.Error())
			return 0, 0, 0, false
		}
		return r.blocks, r.bfree, r.bavail, true
	case <-time.After(c.diskTimeout):
		c.log.Debug("metric read timed out", "metric", "disk", "label", mount, "timeout", c.diskTimeout.String())
		return 0, 0, 0, false
	}
}

func (c *Collector) sampleTemp() (float64, bool) {
	// Presence is tracked EXPLICITLY, not via a sentinel: the old best=-1.0
	// scheme conflated "no sensor" with "hottest zone below 0 C", so an
	// outdoor Pi in winter silently produced no samples (and the sensorless-
	// hardware startup warning fired on working-but-cold hardware).
	found := false
	best := 0.0
	for _, zone := range c.zones() {
		data, err := c.readFile(zone)
		if err != nil {
			continue
		}
		milli, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			continue
		}
		v := float64(milli) / 1000
		// A reading outside any physically plausible range is a broken zone,
		// and NO INFORMATION (decision 6) - never a sample. Without this, one
		// flaky sensor reporting INT_MAX millidegrees produced a "valid"
		// ~2,147,483 C reading that breached the temp rule AND, exceeding the
		// backend's +-1e6 value bound, 400ed the whole breach batch - dropping
		// every co-batched legitimate alert, permanently.
		if v < -50 || v > 250 {
			continue
		}
		if !found || v > best {
			best = v
			found = true
		}
	}
	if !found {
		// Absent sensor is not an error; the rule is simply never evaluated.
		return 0, false
	}
	return best, true
}

// sampleInterface reads an interface's operstate and returns the display
// value: 1 for up, 0 for down. A missing interface is NO INFORMATION.
//
// This is the sample side of the one STATE rule. It returns a value, not a
// magnitude; the rules engine turns "0 = down" into a breach, never a
// threshold comparison.
func (c *Collector) sampleInterface(iface string) (float64, bool) {
	// Interface names never contain a slash. Rejecting one keeps a malformed
	// label from escaping the sysfs directory into an arbitrary read.
	if iface == "" || strings.ContainsRune(iface, '/') {
		return 0, false
	}
	data, err := c.readFile("/sys/class/net/" + iface + "/operstate")
	if err != nil {
		// The interface has been removed or renamed: NO INFORMATION. A
		// renamed NIC must not fire a false alert, and a genuinely absent
		// interface is indistinguishable from a typo in the config.
		c.log.Debug("metric read failed", "metric", "interfaceDown", "label", iface, "error", err.Error())
		return 0, false
	}
	state := strings.TrimSpace(string(data))
	// "unknown" is what many virtual and wireless interfaces report while
	// working normally; treating it as anything but up would be a permanent
	// false breach on those machines.
	if state == "up" || state == "unknown" {
		return 1, true
	}
	return 0, true
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
//
// THREE guards. Busy includes steal, and hypervisors can regress the steal
// counter across a live migration (observed on KVM cloud hosts); a Busy
// regression small enough to leave Total climbing would otherwise wrap the
// uint64 subtraction to ~1.8e19 and report a quintillion-percent CPU sample
// as valid. The third guard is the invariant that actually matters:
// dBusy <= dTotal. iowait is in Total but not Busy and proc(5) documents it
// as non-monotonic on SMP, so a partial iowait regression that leaves Total
// climbing can shrink dTotal below dBusy and yield >100% "valid" samples -
// inconsistent interval accounting is NO INFORMATION.
func CPUPercent(prev, cur CPUCounters) (float64, bool) {
	if cur.Total <= prev.Total || cur.Busy < prev.Busy {
		return 0, false
	}
	dBusy := float64(cur.Busy - prev.Busy)
	dTotal := float64(cur.Total - prev.Total)
	if dBusy > dTotal {
		return 0, false
	}
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
	if avail > total {
		// Incoherent kernel numbers are no information, not a reading
		// (decision 6): a negative percent here is one below-threshold
		// sample, and decision 7's one-sample clear would fire a false
		// "back to normal" mid-breach. Same guard as DiskPercent's
		// bfree > blocks and CPUPercent's regression check.
		return 0, fmt.Errorf("meminfo inconsistent: MemAvailable %.0f > MemTotal %.0f", avail, total)
	}
	return (total - avail) / total * 100, nil
}

// ParseSwapPercent computes used swap percent from /proc/meminfo.
//
// The bool is false when SwapTotal is 0: swap is not configured, which is not
// an error and not a breach - the caller skips the rule, exactly as for a
// missing thermal zone. An error is returned only for genuinely malformed
// input.
func ParseSwapPercent(data []byte) (float64, bool, error) {
	var total, free float64
	var haveTotal, haveFree bool
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "SwapTotal:":
			v, err := strconv.ParseFloat(f[1], 64)
			if err != nil {
				return 0, false, fmt.Errorf("SwapTotal: %w", err)
			}
			total, haveTotal = v, true
		case "SwapFree:":
			v, err := strconv.ParseFloat(f[1], 64)
			if err != nil {
				return 0, false, fmt.Errorf("SwapFree: %w", err)
			}
			free, haveFree = v, true
		}
	}
	if !haveTotal || !haveFree {
		return 0, false, fmt.Errorf("meminfo missing SwapTotal or SwapFree")
	}
	if total == 0 {
		return 0, false, nil // swap not configured
	}
	if free > total {
		// Same no-information guard as ParseMemPercent: a negative percent
		// would read as one below-threshold sample and fire a false clear.
		return 0, false, fmt.Errorf("meminfo inconsistent: SwapFree %.0f > SwapTotal %.0f", free, total)
	}
	return (total - free) / total * 100, true, nil
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
