package tuning

import (
	"fmt"
	"math"
	"os"
	"strings"
)

const (
	MaxSlots          int64 = math.MaxUint32
	MaxConnections          = 4096
	MaxWorkers              = 8192
	MaxBatchSize            = 65536
	MaxOpsPerCompound       = 4096

	// DescriptorReserve covers every descriptor a run holds that the budget does
	// not charge per worker or per connection.
	//
	// Measured 2026-08-24, kernel transport, NFSv4.1, 4-vCPU client, fd counts
	// polled at 500us across 30 trials: the non-budgeted floor is 5 -- /dev/null,
	// stdout, stderr, an eventfd, an eventpoll -- and it is CONSTANT from workers
	// 1 through 2048. With --log and --checkpoint both active it is 7. So 64 is
	// roughly 13x the worst case it has to cover.
	//
	// It is deliberately not tightened to fit. This value is chosen on the sweep
	// host and then replayed on hosts nobody has measured, and the two errors are
	// not symmetric: refusing a workable entry warns loudly and falls back to
	// built-in defaults, while accepting an unworkable one exhausts descriptors
	// mid-run -- which truncates the walk SILENTLY and misreports EMFILE as fix
	// errors (issue #16). Erring toward the recoverable failure is the point.
	//
	// The cost is real and bounded, so it is recorded rather than hidden: on the
	// kernel transport workers=1024 peaks at 982 descriptors and first fails at
	// 992, but the budget demands 1088. Soft limits in [992, 1087] therefore
	// refuse a setting that works, and the stock ulimit -n of 1024 sits inside
	// that band. An operator there sees a measured workers=1024 entry silently
	// downgraded to the 128 default.
	//
	// Deriving the floor at startup instead of hardcoding it would remove the
	// band entirely and is the better long-term shape; it is deferred rather than
	// forgotten.
	DescriptorReserve uint64 = 64
)

// ValidateParams is the shared reader/writer contract for a persisted tuning.
// explicit names command-line values that replaced entry fields; the writer
// passes nil because every value it persists came from the sweep.
func ValidateParams(params Params, transport string, explicit map[string]bool, softNofile uint64) error {
	var missingOrZero []string
	if transport == "userspace" && params.Connections == 0 {
		missingOrZero = append(missingOrZero, "connections")
	}
	if params.Workers == 0 {
		missingOrZero = append(missingOrZero, "workers")
	}
	if params.BatchSize == 0 {
		missingOrZero = append(missingOrZero, "batch_size")
	}
	if len(missingOrZero) > 0 {
		return fmt.Errorf("%s absent or zero; entire tuning entry discarded", strings.Join(missingOrZero, " and "))
	}
	if params.Connections < 0 || params.Connections > MaxConnections {
		return fmt.Errorf("connections must be between 0 and %d: %d", MaxConnections, params.Connections)
	}
	if params.Slots < 0 || int64(params.Slots) > MaxSlots {
		return fmt.Errorf("slots must be between 0 and %d: %d", MaxSlots, params.Slots)
	}
	if params.Workers < 0 || params.Workers > MaxWorkers {
		return fmt.Errorf("workers must be between 1 and %d: %d", MaxWorkers, params.Workers)
	}
	if params.BatchSize < 0 || params.BatchSize > MaxBatchSize {
		return fmt.Errorf("batch-size must be between 1 and %d: %d", MaxBatchSize, params.BatchSize)
	}
	if params.MaxOpsPerCompound < 0 || params.MaxOpsPerCompound > MaxOpsPerCompound {
		return fmt.Errorf("max-ops-per-compound must be between 0 and %d: %d", MaxOpsPerCompound, params.MaxOpsPerCompound)
	}
	name := DescriptorField(transport)
	if name == "" || explicit[name] {
		return nil
	}
	value := params.Workers
	if name == "connections" {
		value = params.Connections
	}
	return FitsDescriptorLimit(name, value, softNofile)
}

// DescriptorField names the one tuning value that opens local descriptors for
// a transport. Userspace workers reuse the connection pool; kernel connections
// are inert.
func DescriptorField(transport string) string {
	switch transport {
	case "userspace":
		return "connections"
	case "kernel":
		return "workers"
	default:
		return ""
	}
}

// DescriptorReserveMargin is added to the live open-fd count to cover
// descriptors opened between the check and the work.
const DescriptorReserveMargin = 10

// OpenDescriptorCount returns the number of currently open file descriptors
// by reading /proc/self/fd. Returns 0 if the count cannot be determined.
func OpenDescriptorCount() uint64 {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return uint64(len(entries))
}

// LiveDescriptorReserve returns a reserve derived from the actual open fd
// count plus a margin for descriptors opened between the check and the work.
// Falls back to DescriptorReserve if the live count cannot be read.
func LiveDescriptorReserve() uint64 {
	live := OpenDescriptorCount()
	if live == 0 {
		return DescriptorReserve
	}
	return live + DescriptorReserveMargin
}

// FitsDescriptorLimit charges value plus the live non-tuning reserve against
// the soft limit. Uses the actual open fd count when available, falling back
// to the hardcoded reserve. Equality fits: descriptors are numbered from
// zero through soft-1.
func FitsDescriptorLimit(name string, value int, soft uint64) error {
	return FitsDescriptorLimitWithReserve(name, value, soft, LiveDescriptorReserve())
}

// FitsDescriptorLimitWithReserve is the testable core: same check with an
// explicit reserve so tests can inject a known value.
func FitsDescriptorLimitWithReserve(name string, value int, soft, reserve uint64) error {
	if value < 0 {
		return fmt.Errorf("%s must not be negative: %d", name, value)
	}
	needed := uint64(value) + reserve
	if needed > soft {
		return fmt.Errorf("%s %d need %d file descriptors but soft RLIMIT_NOFILE is %d", name, value, needed, soft)
	}
	return nil
}
