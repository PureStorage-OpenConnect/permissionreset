package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
	"golang.org/x/sys/unix"
)

// Platform-specific cache control (dropCaches, newCacheController) lives in
// cache_linux.go and cache_other.go.

// runOnce is the seam over the real repair path. Every trial goes through
// run.Run, so a candidate pays exactly the transport setup, enumeration and
// apply work an operator's own run pays. Tests replace it; nothing else does.
var runOnce = run.Run

// cacheController removes client-side warmth before a trial. It is one method
// because that is all cache handling is allowed to be: something done before a
// trial starts, never something that adjusts the number afterwards.
type cacheController interface {
	BeforeTrial(context.Context) error
}

type cacheFunc func(context.Context) error

func (f cacheFunc) BeforeTrial(ctx context.Context) error { return f(ctx) }

// noCacheControl is the controller for every case where there is nothing this
// client can usefully drop.
func noCacheControl() cacheController {
	return cacheFunc(func(context.Context) error { return nil })
}

// clientBoundCPUPct is the busy share at or above which the client, not the
// array, is the thing being measured. A trial at this level is reported as
// client-bound so nobody reads its rate as a property of the storage.
//
// PROVISIONAL: 90% is a guess, not a measurement. It is pinned by
// TestRecordClientMarksBoundAtTheThreshold so it cannot drift silently, but the
// number itself is pending a live run I will do on a lab array.
const clientBoundCPUPct = 90.0

// runTrialRunner turns one parameter set into one measured rate.
type runTrialRunner struct {
	base          run.Config
	cache         cacheController
	out           io.Writer
	expectedPaths int64

	// readCPU and readNofile are injectable only so a test can exercise the
	// sampling arithmetic; production leaves them nil and reads the real host.
	readCPU    func() (cpuTimes, error)
	readNofile func() (uint64, error)

	last     tuning.ClientMeasurement
	haveLast bool
}

func newRunTrialRunner(base run.Config, cache cacheController, out io.Writer) TrialRunner {
	return &runTrialRunner{base: base, cache: cache, out: out}
}

func (r *runTrialRunner) SetExpectedPaths(n int64) { r.expectedPaths = n }

func setExpectedPaths(runner TrialRunner, n int64) {
	if sized, ok := runner.(interface{ SetExpectedPaths(int64) }); ok {
		sized.SetExpectedPaths(n)
	}
}

// Trial measures one candidate.
//
// The rate is applied objects over the run's own elapsed time and nothing else.
// No child run is summed, and connection or session setup is never subtracted:
// an operator pays that setup once per run, so a tuning that wins only after it
// is discounted is not a tuning that wins.
func (r *runTrialRunner) Trial(ctx context.Context, params tuning.Params) (float64, error) {
	if r.cache != nil {
		if err := r.cache.BeforeTrial(ctx); err != nil {
			return 0, fmt.Errorf("cache control: %w", err)
		}
	}

	cfg := r.base
	cfg.Connections = params.Connections
	cfg.Slots = params.Slots
	cfg.Workers = params.Workers
	cfg.BatchSize = params.BatchSize
	cfg.MaxOpsPerCompound = params.MaxOpsPerCompound
	// A trial must be the repair, not a rehearsal of it. --compare would skip
	// objects that already match and measure a shrinking tree; --pfind is a
	// separate enumerator that cannot be fused with the fix.
	cfg.Apply = true
	cfg.DryRun = false
	cfg.Compare = false
	cfg.Validate = false
	cfg.Pfind = false
	cfg.Quiet = true

	out := r.out
	if out == nil {
		out = io.Discard
	}

	before, cpuErr := r.sampleCPU()
	result, err := runOnce(ctx, cfg, out)
	if err != nil {
		return 0, err
	}
	if result.Elapsed <= 0 {
		return 0, fmt.Errorf("trial reported %s elapsed, so it measured nothing", result.Elapsed)
	}
	if result.Stats.Applied <= 0 {
		return 0, fmt.Errorf("trial applied %d objects, so it measured nothing", result.Stats.Applied)
	}
	// A trial that walks materially less of the tree than the manifest says
	// exists must not be ranked: a descriptor-starved run is fast precisely
	// because it is short, so without this it can win. The observed starvation
	// shapes walked 63%, 29% and 20% of the tree (lab measurements at soft 512,
	// 256 and 128 respectively).
	//
	// 95% rather than exact equality. total_paths is a path count -- it excludes
	// the root, symlinks and acl_manifest.json, while a repair walks the manifest
	// file and the root -- so a complete trial lands at or just above 1.00, and
	// the remaining 5 points absorb a benign shortfall such as an object
	// disappearing mid-walk. There is little else to absorb: trials force
	// --compare off so Skipped is always 0, and any walk error already fails the
	// run through errRunFailed.
	//
	// This floor was 75% while the generator double-counted outlier files and
	// counted neither department directories nor subtree roots, which inflated
	// total_paths by ~19% and put a complete trial at 0.83 (measured: 573,058
	// applied against a manifest claiming 688,141). Issue #14 fixed the count on
	// main; carrying 75% across that merge would have left 25 points of slack and
	// re-admitted the very shape this rejects.
	if r.expectedPaths > 0 {
		minimum := (r.expectedPaths*19 + 19) / 20
		if result.Stats.Applied < minimum {
			return 0, fmt.Errorf("trial applied %d paths, below the minimum %d of %d expected paths", result.Stats.Applied, minimum, r.expectedPaths)
		}
	}
	rate := float64(result.Stats.Applied) / result.Elapsed.Seconds()

	if cpuErr == nil {
		r.recordClient(before)
	}
	return rate, nil
}

// LastMeasurement reports the client sample from the most recent successful
// trial. After a complete search that is a winner confirmation; after an
// interrupted search it may describe the last successful candidate instead.
func (r *runTrialRunner) LastMeasurement() (tuning.ClientMeasurement, bool) {
	return r.last, r.haveLast
}

// measuringRunner is the optional half of TrialRunner: a runner that can say
// what the client was doing while it measured.
type measuringRunner interface {
	LastMeasurement() (tuning.ClientMeasurement, bool)
}

type cpuTimes struct {
	total, idle, user, sys, softirq float64
}

func (r *runTrialRunner) sampleCPU() (cpuTimes, error) {
	if r.readCPU != nil {
		return r.readCPU()
	}
	return readProcStat("/proc/stat")
}

func (r *runTrialRunner) nofile() (uint64, error) {
	if r.readNofile != nil {
		return r.readNofile()
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return 0, err
	}
	return limit.Cur, nil
}

// recordClient stores the CPU share this trial consumed. A sampling failure
// leaves the previous record alone rather than writing zeros, because a zeroed
// record reads as an idle client, which is the opposite of an unknown one.
func (r *runTrialRunner) recordClient(before cpuTimes) {
	after, err := r.sampleCPU()
	if err != nil {
		return
	}
	span := after.total - before.total
	if span <= 0 {
		return
	}
	busy := span - (after.idle - before.idle)
	measurement := tuning.ClientMeasurement{
		CPUPct:        pct(busy, span),
		CPUUserPct:    pct(after.user-before.user, span),
		CPUSysPct:     pct(after.sys-before.sys, span),
		CPUSoftirqPct: pct(after.softirq-before.softirq, span),
	}
	if nofile, err := r.nofile(); err == nil {
		measurement.RlimitNofile = nofile
	}
	measurement.Bound = measurement.CPUPct >= clientBoundCPUPct
	r.last = measurement
	r.haveLast = true
}

func pct(part, whole float64) float64 {
	if whole <= 0 {
		return 0
	}
	value := part / whole * 100
	if value < 0 {
		return 0
	}
	return value
}

// readProcStat reads the aggregate "cpu" line from path.
func readProcStat(path string) (cpuTimes, error) {
	f, err := os.Open(path)
	if err != nil {
		return cpuTimes{}, err
	}
	defer f.Close()
	return parseProcStat(f, path)
}

// parseProcStat reads the aggregate "cpu" line out of /proc/stat content.
//
// idle here is idle plus iowait: a client blocked on the array is not the
// bottleneck, and counting iowait as busy would report every well-tuned run as
// client-bound. PROVISIONAL: this is a reasoned choice, not a measured one, and
// is pending a live run on a lab array.
//
// The length guard is derived from the highest index this function reads
// without its own guard, which is values[4] (iowait). values[4] is fields[5],
// so a usable line needs len(fields) >= 6. The only higher index read,
// values[6] (softirq), carries its own length check below.
func parseProcStat(r io.Reader, label string) (cpuTimes, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] != "cpu" {
			continue
		}
		values := make([]float64, 0, len(fields)-1)
		for _, field := range fields[1:] {
			ticks, err := strconv.ParseFloat(field, 64)
			if err != nil {
				return cpuTimes{}, fmt.Errorf("parse %s: %w", label, err)
			}
			values = append(values, ticks)
		}
		times := cpuTimes{user: values[0] + values[1], sys: values[2], idle: values[3] + values[4]}
		if len(values) > 6 {
			times.softirq = values[6]
		}
		for _, v := range values {
			times.total += v
		}
		return times, nil
	}
	if err := scanner.Err(); err != nil {
		return cpuTimes{}, err
	}
	return cpuTimes{}, fmt.Errorf("%s has no aggregate cpu line", label)
}
