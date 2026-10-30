package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/stats"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

func cmpStrings(got, want []string) string {
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Sprintf("sequence = %v, want %v", got, want)
	}
	return ""
}

// stubRun replaces the seam over run.Run for the duration of one test.
func stubRun(t *testing.T, fn func(context.Context, run.Config, io.Writer) (run.Result, error)) {
	t.Helper()
	old := runOnce
	runOnce = fn
	t.Cleanup(func() { runOnce = old })
}

func TestRunTrialCallsCacheThenRunOnceOverTheWholeRoot(t *testing.T) {
	var order []string
	cache := cacheFunc(func(context.Context) error { order = append(order, "cache"); return nil })
	stubRun(t, func(_ context.Context, cfg run.Config, _ io.Writer) (run.Result, error) {
		order = append(order, "run:"+cfg.Root)
		return run.Result{Stats: stats.Snapshot{Applied: 3000}, Elapsed: 3 * time.Second}, nil
	})

	r := &runTrialRunner{base: run.Config{Root: "/export/sweep", Spec: &spec.Spec{}}, cache: cache, out: io.Discard}
	rate, err := r.Trial(context.Background(), tuning.Params{Workers: 256, BatchSize: 50})
	if err != nil {
		t.Fatal(err)
	}
	if rate != 1000 {
		t.Fatalf("rate = %v, want 1000", rate)
	}
	if diff := cmpStrings(order, []string{"cache", "run:/export/sweep"}); diff != "" {
		t.Fatal(diff)
	}
}

// Every candidate must pay exactly the work an operator's own repair pays: the
// real apply path over the whole root, with no dry run, no compare shortcut and
// no pfind enumerator.
func TestRunTrialMapsEveryTunedFieldAndForcesTheRealRepairPath(t *testing.T) {
	var got run.Config
	stubRun(t, func(_ context.Context, cfg run.Config, _ io.Writer) (run.Result, error) {
		got = cfg
		return run.Result{Stats: stats.Snapshot{Applied: 100}, Elapsed: time.Second}, nil
	})

	base := run.Config{
		Root: "/export/sweep", Spec: &spec.Spec{}, Transport: "userspace",
		// A base that already carries the wrong answers, so a runner that merely
		// leaves them alone fails this test.
		DryRun: true, Compare: true, Pfind: true, Apply: false, Quiet: false,
	}
	r := &runTrialRunner{base: base, cache: noCacheControl(), out: io.Discard}
	params := tuning.Params{Connections: 64, Slots: 32, Workers: 512, BatchSize: 100, MaxOpsPerCompound: 16}
	if _, err := r.Trial(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	if got.Connections != 64 || got.Slots != 32 || got.Workers != 512 ||
		got.BatchSize != 100 || got.MaxOpsPerCompound != 16 {
		t.Fatalf("tuned fields = %+v", got)
	}
	if !got.Apply || got.DryRun || got.Compare || got.Pfind || !got.Quiet {
		t.Fatalf("run mode = apply %v dry-run %v compare %v pfind %v quiet %v",
			got.Apply, got.DryRun, got.Compare, got.Pfind, got.Quiet)
	}
	if got.Root != "/export/sweep" || got.Spec == nil {
		t.Fatalf("root = %q, spec = %v", got.Root, got.Spec)
	}
}

// A run that applied nothing measured nothing. Reporting its elapsed time as a
// rate would rank a broken trial as the fastest one in the ladder.
func TestRunTrialRejectsAnEmptyOrInstantRun(t *testing.T) {
	cases := []struct {
		name   string
		result run.Result
		want   string
	}{
		{"nothing applied", run.Result{Stats: stats.Snapshot{Applied: 0}, Elapsed: time.Second}, "applied 0"},
		{"no elapsed time", run.Result{Stats: stats.Snapshot{Applied: 10}, Elapsed: 0}, "elapsed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubRun(t, func(context.Context, run.Config, io.Writer) (run.Result, error) {
				return tc.result, nil
			})
			r := &runTrialRunner{base: run.Config{Root: "/export/sweep", Spec: &spec.Spec{}}, cache: noCacheControl(), out: io.Discard}
			rate, err := r.Trial(context.Background(), tuning.Params{Workers: 1, BatchSize: 1})
			if err == nil {
				t.Fatalf("rate = %v, err = nil, want a failed point", rate)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestRunTrialRejectsMateriallyIncompleteRun(t *testing.T) {
	cases := []struct {
		name    string
		applied int64
		wantErr bool
	}{
		{name: "one below the completeness floor", applied: 949, wantErr: true},
		{name: "exactly at the completeness floor", applied: 950},
		// A complete trial exceeds total_paths: a repair walks the manifest file
		// and the root, which the manifest's own count excludes.
		{name: "slightly above the expected count", applied: 1002},
		// The shapes the floor exists to reject, from the lab measurements at
		// soft 512, 256 and 128.
		{name: "the 63% starvation shape", applied: 630, wantErr: true},
		{name: "the 29% starvation shape", applied: 290, wantErr: true},
		{name: "the 20% starvation shape", applied: 200, wantErr: true},
		// The old 75% floor sat here. It must now be rejected -- carrying it
		// across the issue #14 merge would have re-admitted a short walk.
		{name: "the retired 75% floor", applied: 750, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubRun(t, func(context.Context, run.Config, io.Writer) (run.Result, error) {
				return run.Result{Stats: stats.Snapshot{Applied: tc.applied}, Elapsed: time.Second}, nil
			})
			r := &runTrialRunner{
				base:  run.Config{Root: "/export/sweep", Spec: &spec.Spec{}},
				cache: noCacheControl(), out: io.Discard, expectedPaths: 1000,
			}
			rate, err := r.Trial(context.Background(), tuning.Params{Workers: 1, BatchSize: 1})
			if (err != nil) != tc.wantErr {
				t.Fatalf("rate = %v, error = %v, wantErr %v", rate, err, tc.wantErr)
			}
			// The message must carry both counts, and the minimum is spelled out
			// rather than derived so that moving the floor breaks this test.
			if tc.wantErr && (!strings.Contains(err.Error(), fmt.Sprint(tc.applied)) || !strings.Contains(err.Error(), "950")) {
				t.Fatalf("error = %v, want applied count %d and minimum 950", err, tc.applied)
			}
		})
	}
}

// A failed repair is a failed point, never a zero-throughput one: sweepKnob
// ranks zero and never ranks an error.
func TestRunTrialReturnsARunErrorAsAFailedPoint(t *testing.T) {
	boom := errors.New("transport exploded")
	stubRun(t, func(context.Context, run.Config, io.Writer) (run.Result, error) {
		return run.Result{Stats: stats.Snapshot{Applied: 5}, Elapsed: time.Second}, boom
	})
	r := &runTrialRunner{base: run.Config{Root: "/export/sweep", Spec: &spec.Spec{}}, cache: noCacheControl(), out: io.Discard}
	_, err := r.Trial(context.Background(), tuning.Params{Workers: 1, BatchSize: 1})
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the run error", err)
	}
}

// A root cache or remount failure fails the point rather than yielding a number
// measured against a cache the sweeper meant to have dropped.
func TestRunTrialFailsThePointWhenCacheControlFails(t *testing.T) {
	stubRun(t, func(context.Context, run.Config, io.Writer) (run.Result, error) {
		t.Fatal("run started after cache control failed")
		return run.Result{}, nil
	})
	cache := cacheFunc(func(context.Context) error { return errors.New("remount refused") })
	r := &runTrialRunner{base: run.Config{Root: "/export/sweep", Spec: &spec.Spec{}}, cache: cache, out: io.Discard}
	if _, err := r.Trial(context.Background(), tuning.Params{Workers: 1, BatchSize: 1}); err == nil {
		t.Fatal("a cache-control failure produced a usable point")
	}
}

// Nonroot on the kernel transport cannot drop caches, so it must say so rather
// than report warmed numbers as if they were cold.
func TestNewCacheControllerWarnsWhenItCannotDropCaches(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can drop caches")
	}
	var buf strings.Builder
	if c := newCacheController("kernel", "/mnt/sweep", &buf); c == nil {
		t.Fatal("no cache controller")
	}
	if !strings.Contains(buf.String(), "cache") {
		t.Fatalf("warning = %q, want the cache warmth named", buf.String())
	}

	var quiet strings.Builder
	if c := newCacheController("userspace", "", &quiet); c == nil {
		t.Fatal("no cache controller")
	}
	if quiet.String() != "" {
		t.Fatalf("userspace warned about caches it does not use: %q", quiet.String())
	}
}

// The client sample is what tells an operator whether the number they are about
// to act on describes their array or their own CPU, so the threshold it turns on
// is pinned here rather than left to whatever the constant happens to say.
func TestRecordClientMarksBoundAtTheThreshold(t *testing.T) {
	cases := []struct {
		name      string
		busyTicks float64
		wantPct   float64
		wantBound bool
	}{
		// span is 1000 ticks throughout, so busy ticks are tenths of a percent.
		{"just below the threshold", 899, 89.9, false},
		{"exactly at the threshold", 900, 90.0, true},
		{"above the threshold", 970, 97.0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			after := cpuTimes{
				total:   1000,
				idle:    1000 - tc.busyTicks,
				user:    tc.busyTicks - 100,
				sys:     90,
				softirq: 10,
			}
			r := &runTrialRunner{
				readCPU:    func() (cpuTimes, error) { return after, nil },
				readNofile: func() (uint64, error) { return 4096, nil },
			}
			r.recordClient(cpuTimes{})

			m, ok := r.LastMeasurement()
			if !ok {
				t.Fatal("no measurement recorded")
			}
			if diff := m.CPUPct - tc.wantPct; diff > 0.001 || diff < -0.001 {
				t.Fatalf("cpu = %v, want %v", m.CPUPct, tc.wantPct)
			}
			if m.Bound != tc.wantBound {
				t.Fatalf("bound = %v at %v%% busy, want %v (threshold %v)", m.Bound, m.CPUPct, tc.wantBound, clientBoundCPUPct)
			}
			if m.RlimitNofile != 4096 {
				t.Fatalf("rlimit_nofile = %d, want the sampled 4096", m.RlimitNofile)
			}
			if m.CPUSysPct != 9 || m.CPUSoftirqPct != 1 {
				t.Fatalf("breakdown = %+v, want sys 9%% and softirq 1%%", m)
			}
		})
	}
}

// A sampling failure must leave the previous record alone: zeros would read as
// an idle client, which is the opposite of an unknown one.
func TestRecordClientKeepsSilentWhenSamplingFails(t *testing.T) {
	r := &runTrialRunner{readCPU: func() (cpuTimes, error) { return cpuTimes{}, errors.New("no /proc") }}
	r.recordClient(cpuTimes{})
	if _, ok := r.LastMeasurement(); ok {
		t.Fatal("a failed sample was recorded as a measurement")
	}

	// A span of zero is the same situation: two samples taken inside one tick say
	// nothing about the client.
	same := cpuTimes{total: 500, idle: 250}
	r = &runTrialRunner{readCPU: func() (cpuTimes, error) { return same, nil }}
	r.recordClient(same)
	if _, ok := r.LastMeasurement(); ok {
		t.Fatal("a zero-length sample window was recorded as a measurement")
	}
}

// iowait counts as idle. A client blocked on the array is not the bottleneck,
// and counting iowait as busy would report every well-tuned run as client-bound.
func TestParseProcStatCountsIowaitAsIdle(t *testing.T) {
	// user nice system idle iowait irq softirq
	times, err := parseProcStat(strings.NewReader("cpu  100 0 100 100 700 0 0\ncpu0 1 1 1 1 1 1 1\n"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if times.total != 1000 {
		t.Fatalf("total = %v, want every field summed", times.total)
	}
	if times.idle != 800 {
		t.Fatalf("idle = %v, want idle plus iowait (100+700)", times.idle)
	}

	r := &runTrialRunner{readCPU: func() (cpuTimes, error) { return times, nil }}
	r.recordClient(cpuTimes{})
	m, ok := r.LastMeasurement()
	if !ok {
		t.Fatal("no measurement recorded")
	}
	if m.CPUPct != 20 {
		t.Fatalf("cpu = %v, want 20%% -- a client 70%% blocked on the array is not busy", m.CPUPct)
	}
	if m.Bound {
		t.Fatal("a client mostly waiting on the array was reported as the bound one")
	}
}

// The length guard is derived from the highest index parseProcStat reads without
// its own check, values[4] (iowait), which is fields[5]. A shorter aggregate line
// is unusable and must be skipped rather than indexed into.
func TestParseProcStatSkipsATruncatedAggregateLine(t *testing.T) {
	if _, err := parseProcStat(strings.NewReader("cpu 1 2 3 4\n"), "fixture"); err == nil {
		t.Fatal("a four-value cpu line was accepted")
	} else if !strings.Contains(err.Error(), "no aggregate cpu line") {
		t.Fatalf("err = %v, want the line reported as absent", err)
	}

	// Five values is the shortest usable line: it reaches iowait.
	times, err := parseProcStat(strings.NewReader("cpu 10 0 10 10 20\n"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if times.idle != 30 || times.softirq != 0 || times.total != 50 {
		t.Fatalf("times = %+v, want idle 30, no softirq and total 50", times)
	}

	if _, err := parseProcStat(strings.NewReader("cpu 1 2 3 4 nonsense 6\n"), "fixture"); err == nil {
		t.Fatal("an unparseable tick count was accepted")
	}
}
