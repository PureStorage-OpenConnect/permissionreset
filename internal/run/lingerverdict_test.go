package run

import (
	"math"
	"strings"
	"testing"
	"time"
)

// s200Run reproduces the measured S200 baseline: 1,135,009 objects at c32/w1024,
// 1,220,832 write(2) carrying 1,270,043 records, on a client that was not CPU
// saturated. This is the run the verdict has to say "no" to, and it is the only
// hardware measurement the report has ever been checked against.
func s200Run() lingerInputs {
	return lingerInputs{
		Batches:  1220832,
		Records:  1270043,
		Conns:    32,
		Workers:  1024,
		Wall:     18 * time.Second,
		CPU:      time.Duration(0.78 * 18 * 8 * float64(time.Second)),
		CPUKnown: true,
		Cores:    8,
	}
}

// TestTheMeasuredS200RunSaysNo is the regression that matters most. If a future
// change to the thresholds or the arithmetic makes this run recommend a linger,
// the report is recommending a change that measurement already showed cannot
// help: at 470us of interarrival per connection, no linger short enough to
// afford gathers anything.
func TestTheMeasuredS200RunSaysNo(t *testing.T) {
	lines := lingerVerdict(s200Run())
	if len(lines) == 0 {
		t.Fatal("no report for a run with write statistics")
	}
	verdict := lines[len(lines)-1]
	if !strings.Contains(verdict, "NO") {
		t.Fatalf("verdict for the measured S200 run = %q, want NO", verdict)
	}
	// And for the documented reason: sparse arrivals, not saturation. Getting
	// the right answer from the wrong half of the test would pass a bare
	// substring check while inverting on the next array.
	if !strings.Contains(verdict, "gathers usefully") {
		t.Errorf("verdict %q does not name sparse arrivals as the reason", verdict)
	}
}

// TestReportIsEmptyWithoutAWriteToDescribe covers the kernel-transport path and
// any run that made no RPCs. Dividing records by zero batches yields NaN, which
// would print "depth NaN" in a summary a human is meant to trust.
func TestReportIsEmptyWithoutAWriteToDescribe(t *testing.T) {
	for name, in := range map[string]lingerInputs{
		"no batches": {Records: 10, Conns: 16, Wall: time.Second},
		"no records": {Batches: 10, Conns: 16, Wall: time.Second},
		"no wall":    {Batches: 10, Records: 10, Conns: 16},
		"no conns":   {Batches: 10, Records: 10, Wall: time.Second},
	} {
		if lines := lingerVerdict(in); lines != nil {
			t.Errorf("%s: got %d lines, want none", name, len(lines))
		}
	}
}

// TestSaturationIsRequiredEvenWhenGatheringWouldWork pins the half of the test
// most likely to be dropped as an over-complication. An affordable linger that
// reaches a useful depth is still a loss on a client with idle cores: the
// throughput cost of the added latency is real, and the CPU it frees is CPU
// nothing was waiting for.
func TestSaturationIsRequiredEvenWhenGatheringWouldWork(t *testing.T) {
	const bestDepth = 8.0
	idle := lingerDecision(1.02, bestDepth, 100*time.Microsecond, 0.50)
	if !strings.Contains(idle, "NO") {
		t.Errorf("decision at 50%% saturation = %q, want NO", idle)
	}
	if !strings.Contains(idle, "nothing to do") {
		t.Errorf("decision %q does not explain that the freed CPU is idle", idle)
	}
	busy := lingerDecision(1.02, bestDepth, 100*time.Microsecond, 0.97)
	if !strings.Contains(busy, "BUILD IT") {
		t.Errorf("decision at 97%% saturation with depth %.0f = %q, want BUILD IT", bestDepth, busy)
	}
}

// TestAlreadyGatheringOutranksSaturation covers the ordering inside the switch.
// A client that is both saturated AND already gathering must not be told to add
// a linger: the drain is finding parked senders on its own, and waiting would
// add latency to a path that already has its syscall reduction.
func TestAlreadyGatheringOutranksSaturation(t *testing.T) {
	got := lingerDecision(11.0, 20.0, 200*time.Microsecond, 0.99)
	if !strings.Contains(got, "NO") {
		t.Fatalf("decision at achieved depth 11 = %q, want NO", got)
	}
	if !strings.Contains(got, "already") {
		t.Errorf("decision %q does not say the drain already gathers", got)
	}
}

// TestMissingCPUIsInconclusiveNotAnEndorsement covers the non-unix build. The
// dangerous failure is a report that omits saturation and then recommends the
// change anyway, since the omitted half is the half that says no.
func TestMissingCPUIsInconclusiveNotAnEndorsement(t *testing.T) {
	got := lingerDecision(1.02, 8.0, 100*time.Microsecond, math.NaN())
	if strings.Contains(got, "BUILD IT") {
		t.Fatalf("decision without client CPU = %q, want no recommendation", got)
	}
	if !strings.Contains(got, "INCONCLUSIVE") {
		t.Errorf("decision %q does not mark itself inconclusive", got)
	}
	in := s200Run()
	in.CPUKnown = false
	report := strings.Join(lingerVerdict(in), "\n")
	if !strings.Contains(report, "unavailable on this platform") {
		t.Errorf("report without client CPU does not say so:\n%s", report)
	}
}

// TestProjectedDepthFollowsTheArrivalRate is the arithmetic itself. Depth is
// 1 + lambda*L, so a connection taking 100us between records reaches depth 3 at
// a 200us linger. Pinning it here means the numbers quoted from a customer run
// can be re-derived by hand.
func TestProjectedDepthFollowsTheArrivalRate(t *testing.T) {
	// 10,000 RPC/sec on one connection = 100us interarrival.
	in := lingerInputs{
		Batches:  10000,
		Records:  10000,
		Conns:    1,
		Workers:  4,
		Wall:     time.Second,
		CPU:      time.Second,
		CPUKnown: true,
		Cores:    1,
	}
	report := strings.Join(lingerVerdict(in), "\n")
	if !strings.Contains(report, "L=200µs  depth ~3.0") {
		t.Errorf("report does not project depth 3.0 at L=200us for a 100us interarrival:\n%s", report)
	}
	// Mean RTT by Little's law: 4 workers / 10,000 RPC/sec = 400us. A 200us
	// linger costs 100us of that, which is 25% -- far past affordable.
	if !strings.Contains(report, "Mean RTT:   ~400µs") {
		t.Errorf("report does not derive a 400us mean RTT:\n%s", report)
	}
	if !strings.Contains(report, "too expensive") {
		t.Errorf("report does not mark the unaffordable candidates:\n%s", report)
	}
}

// TestDepthCannotBeProjectedPastTheBound stops the report promising a depth the
// gather loop would never reach: writeBatchMax caps a batch at 32 regardless of
// how long the linger waits.
func TestDepthCannotBeProjectedPastTheBound(t *testing.T) {
	in := lingerInputs{
		Batches:  1,
		Records:  1, // depth 1, so the "already gathering" arm does not fire
		Conns:    1,
		Workers:  4096,
		Wall:     time.Second,
		CPU:      time.Second,
		CPUKnown: true,
		Cores:    1,
	}
	// One connection at a million RPC/sec: L=50us would nominally project depth 51.
	in.Batches, in.Records = 1000000, 1000000
	report := strings.Join(lingerVerdict(in), "\n")
	if strings.Contains(report, "depth ~51") {
		t.Errorf("report projects a depth past the %d-record bound:\n%s", 32, report)
	}
	if !strings.Contains(report, "depth ~32.0") {
		t.Errorf("report does not clamp the projection to the bound:\n%s", report)
	}
}
