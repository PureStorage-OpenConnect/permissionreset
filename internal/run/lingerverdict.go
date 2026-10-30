package run

import (
	"fmt"
	"math"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
)

// A deliberate linger in writeLoop -- blocking briefly for more records instead
// of writing the first one immediately -- is the only remaining way to raise the
// write-gather depth, and it is only ever worth building in one regime. This
// file computes the verdict from numbers a run already produces, so the question
// is settled by a measurement rather than by argument.
//
// The trade is explicit. Throughput is outstanding-ops over latency, so adding L/2
// of mean latency costs that same fraction of throughput unless the CPU the
// linger frees was the actual constraint. On a client with idle cores the freed
// syscall time has nothing to do, and the latency is paid for nothing: the linger
// is strictly negative there. It pays only when the client is CPU-saturated.
//
// Two facts have to hold together, which is why neither number alone is the
// signal:
//
//  1. The client is CPU-saturated. Below saturation, spare cores mean the
//     syscall reduction buys no throughput and the latency is pure loss.
//  2. Some affordable linger actually gathers. Depth follows 1 + lambda*L for a
//     per-connection arrival rate lambda, so a slow-arriving connection needs a
//     linger measured in milliseconds to gather anything -- absurd against any
//     round trip. Whether an affordable L exists is a property of the run, not
//     of the code.
//
// Measured on the S200 at c32/w1024: depth 1.02 against a ceiling of 32, because
// the non-blocking drain in writeLoop only catches senders parked at that exact
// instant, and ~470 microseconds of interarrival against a ~7 microsecond write
// syscall leaves that window empty.

// lingerCandidates are the linger durations priced in the report. The range is
// bounded by the two failure modes: below ~50us the wait is comparable to the
// syscall it is meant to amortise, and above ~500us it is a visible fraction of
// even a slow array's round trip.
var lingerCandidates = []time.Duration{
	50 * time.Microsecond,
	100 * time.Microsecond,
	200 * time.Microsecond,
	500 * time.Microsecond,
}

const (
	// lingerAffordableCost caps how much mean latency a candidate may add before
	// it stops counting as affordable. 5% of the round trip is roughly the point
	// at which the throughput it costs starts to rival the CPU it frees.
	lingerAffordableCost = 0.05

	// lingerUsefulDepth is the gather depth below which the syscall reduction is
	// not worth any added latency at all. At depth 4 three write(2) in four are
	// gone; below that the arithmetic stops clearing the noise on a repair run.
	lingerUsefulDepth = 4.0

	// lingerSaturated is where the client counts as CPU-bound. A run at 78% has
	// idle cores, and freeing syscall time on an idle core buys nothing.
	lingerSaturated = 0.85

	// lingerAlreadyGathering is the depth above which the question is moot: the
	// non-blocking drain is already finding senders parked, and a linger would
	// add latency to a path that does not need it.
	lingerAlreadyGathering = 4.0
)

// lingerInputs is everything the verdict needs, all of it already measured by a
// --rpc-stats run.
type lingerInputs struct {
	Batches  uint64        // write(2) calls the gather loop made
	Records  uint64        // RPC records those calls carried
	Conns    int           // TCP connections in the pool
	Workers  int           // apply concurrency; stands in for outstanding ops
	Wall     time.Duration // wall clock of the run
	CPU      time.Duration // process CPU time, user + system
	CPUKnown bool          // false where the platform has no getrusage
	Cores    int           // runtime.NumCPU()
}

// lingerVerdict renders the report. It returns nil when there is nothing
// meaningful to say, so the caller can print it unconditionally.
//
// Pure by construction: every input is a plain number, so the whole decision is
// testable without an array, and the arithmetic that will be quoted in a Slack
// thread is the arithmetic the tests pin.
func lingerVerdict(in lingerInputs) []string {
	if in.Batches == 0 || in.Records == 0 || in.Wall <= 0 || in.Conns <= 0 {
		return nil
	}

	depth := float64(in.Records) / float64(in.Batches)
	wallSec := in.Wall.Seconds()
	rpcRate := float64(in.Records) / wallSec
	arrivalPerConn := rpcRate / float64(in.Conns)

	lines := []string{
		fmt.Sprintf("  Writes:     %d write(2) carrying %d records, mean gather depth %.2f (max %d)",
			in.Batches, in.Records, depth, nfs41.WriteBatchMax),
		fmt.Sprintf("  Arrivals:   %.0f RPC/sec over %d connections = %.0f/sec/conn, mean interarrival %s",
			rpcRate, in.Conns, arrivalPerConn, roundedMicros(secondsToDuration(1/arrivalPerConn))),
	}

	// Little's law. Outstanding ops is the worker count, since a worker is
	// blocked on exactly one RPC at a time, so mean latency is workers over
	// throughput. This is what prices a linger as a fraction of a round trip
	// without instrumenting every call with two time.Now.
	var meanLatency time.Duration
	if in.Workers > 0 {
		meanLatency = secondsToDuration(float64(in.Workers) / rpcRate)
		lines = append(lines, fmt.Sprintf("  Mean RTT:   ~%s (Little's law: %d workers / %.0f RPC/sec)",
			roundedMicros(meanLatency), in.Workers, rpcRate))
	}

	saturation := math.NaN()
	if in.CPUKnown && in.Cores > 0 && wallSec > 0 {
		saturation = in.CPU.Seconds() / (wallSec * float64(in.Cores))
		lines = append(lines, fmt.Sprintf("  Client CPU: %.1fs over %.1fs wall on %d cores = %.0f%% saturated",
			in.CPU.Seconds(), wallSec, in.Cores, saturation*100))
	} else {
		lines = append(lines, "  Client CPU: unavailable on this platform; the verdict below is incomplete")
	}

	// Price each candidate. Depth follows 1 + lambda*L: the first record starts
	// the timer, and arrivals accumulate for its duration. Mean added latency is
	// L/2, since a record arriving uniformly within the window waits for the
	// remainder of it.
	lines = append(lines, "  Linger:     projected depth and latency cost if writeLoop waited")
	best := time.Duration(0)
	bestDepth := 0.0
	for _, l := range lingerCandidates {
		projected := math.Min(float64(nfs41.WriteBatchMax), 1+arrivalPerConn*l.Seconds())
		cost := math.NaN()
		costText := "cost unknown"
		if meanLatency > 0 {
			cost = (l.Seconds() / 2) / meanLatency.Seconds()
			costText = fmt.Sprintf("+%.1f%% latency", cost*100)
		}
		affordable := !math.IsNaN(cost) && cost <= lingerAffordableCost
		note := ""
		if !affordable && !math.IsNaN(cost) {
			note = "  (too expensive)"
		}
		lines = append(lines, fmt.Sprintf("                L=%-6s depth ~%.1f, %s%s",
			roundedMicros(l), projected, costText, note))
		if affordable && projected > bestDepth {
			best, bestDepth = l, projected
		}
	}

	lines = append(lines, "  Verdict:    "+lingerDecision(depth, bestDepth, best, saturation))
	return lines
}

// lingerDecision is the one sentence the report exists to produce. Split out so
// the decision boundaries are testable independently of the formatting.
func lingerDecision(depth, bestDepth float64, best time.Duration, saturation float64) string {
	switch {
	case depth >= lingerAlreadyGathering:
		return fmt.Sprintf("NO -- the non-blocking drain already reaches depth %.1f; a linger would add latency to a path that does not need it", depth)

	case bestDepth < lingerUsefulDepth:
		return fmt.Sprintf("NO -- no affordable linger gathers usefully (best is depth ~%.1f, under the %.0f needed); arrivals are too sparse per connection, and fewer connections would concentrate them more cheaply than waiting", bestDepth, lingerUsefulDepth)

	case math.IsNaN(saturation):
		return fmt.Sprintf("INCONCLUSIVE -- L=%s would reach depth ~%.1f affordably, but without client CPU the saturation half of the test is missing", roundedMicros(best), bestDepth)

	case saturation < lingerSaturated:
		return fmt.Sprintf("NO -- L=%s would reach depth ~%.1f affordably, but the client is only %.0f%% saturated, so the freed syscall CPU has nothing to do and the latency is paid for nothing", roundedMicros(best), bestDepth, saturation*100)

	default:
		return fmt.Sprintf("BUILD IT -- client is %.0f%% saturated and L=%s reaches depth ~%.1f, cutting write(2) by ~%.0f%% for under %.0f%% latency",
			saturation*100, roundedMicros(best), bestDepth, (1-1/bestDepth)*100, lingerAffordableCost*100)
	}
}

// secondsToDuration converts without losing sub-microsecond values to integer
// truncation, which matters because an interarrival can be tens of nanoseconds
// on a fast connection.
func secondsToDuration(s float64) time.Duration {
	if math.IsNaN(s) || math.IsInf(s, 0) || s <= 0 {
		return 0
	}
	return time.Duration(s * float64(time.Second))
}

// roundedMicros keeps the report readable: nobody reading a linger report needs
// nanosecond precision, and "196.083us" is harder to compare across rows than
// "196us".
func roundedMicros(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Microsecond {
		return d.String()
	}
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(10 * time.Microsecond).String()
}
