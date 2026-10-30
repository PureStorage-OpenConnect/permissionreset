package nfs41

import (
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// This file exists because Task 7's Step 1 froze ops_test.go as the task's
// specification while Step 5 asks for a benchmark. Rather than edit the frozen
// file, the benchmark is additive here -- the same split rpc_notsent_test.go
// uses against rpc_test.go.
//
// Why measure at all: goxdr's -B output marshals through an interface, so every
// field goes through a dynamic dispatch and the escape analysis that would
// normally keep small values on the stack cannot see through it. At this
// client's target rate -- 2048 COMPOUNDs in flight, one SETATTR per file, a
// million files -- a per-COMPOUND allocation count in the hundreds would show up
// as GC pressure rather than as CPU in the profile, which is the hard kind to
// diagnose later.
//
// Measured on linux/amd64, go1.25, AMD Ryzen AI 5 PRO 340, 12 threads:
//
//	BenchmarkSetACLCompound-12     797.4 ns/op   1032 B/op   51 allocs/op
//	BenchmarkReadDirCompound-12    773.1 ns/op    992 B/op   49 allocs/op
//
// Read against the target workload -- one SETATTR per file at the 109K ops/sec
// the kernel transport already reaches -- 51 allocs/op is 5.6M allocations and
// ~107 MB of garbage per second, and 797 ns/op is about 0.7% of total CPU across
// twelve cores. So it is real GC pressure and not a bottleneck.
//
// Per the plan: do NOT hand-optimize the generated marshaling on this number.
// It exists so a future decision to optimize has a baseline, and so the hot ops
// have a correct reference to be optimized against. TestMarshalingAllocationsHaveNotRegressed
// guards it loosely -- the ceiling is set well above the measurement so a Go
// version bump does not fail the build, while a structural regression does.
//
// SUPERSEDED, deliberately kept. That future decision arrived: BuildCompound now
// takes fastencode.go's hand-written path for the operations this client sends,
// so these two benchmarks measure the fast encoder and read far below the
// figures above. The figures are left as the recorded baseline the fast encoder
// is measured against; fastencode_test.go carries the current pair, which runs
// the generated encoder explicitly rather than through the toggle.
//
// TestMarshalingAllocationsHaveNotRegressed below is NOT superseded -- it was
// repointed. It now guards both encoders separately, because a single guard at
// the generated encoder's loose ceiling would have gone quiet exactly when it
// became load-bearing: the fast path allocates once, so a ceiling of 100 passes
// whether the encoder is working, regressed to per-field allocation, or
// silently declining every COMPOUND and falling back.

// benchACL is 5 bytes so that marshaling has to run the outer attrlist4
// opaque's padding branch rather than the aligned fast path.
//
// It is deliberately NOT a valid fattr4_acl -- its first word would be ACE count
// 0x01020304 -- and that is fine here, because BuildCompound only marshals the
// bytes and never interprets them. Do not read this as a claim about the
// attrlist4 tests in ops_test.go: those use a real 28-byte ACL and explicitly
// assert len(raw)%4 == 0, noting that there is no such thing as a 5-byte
// fattr4_acl. An earlier version of this comment and of ed48ab8's commit
// message both got that backwards.
//
// Do not change the value: the figures recorded above were measured with it.
var benchACL = []byte{1, 2, 3, 4, 5}

func BenchmarkSetACLCompound(b *testing.B) {
	fh := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, err := BuildCompound("bench", []xdr.Nfs_argop4{
			OpPutFH(fh),
			OpSetACL(benchACL),
		})
		if err != nil {
			b.Fatal(err)
		}
		if len(buf) == 0 {
			b.Fatal("empty COMPOUND")
		}
	}
}

// TestMarshalingAllocationsHaveNotRegressed turns the recorded figure into a
// guard rather than a comment that rots. The ceiling is deliberately loose: the
// measurement is 51, and 51 is a property of goxdr's interface-dispatch
// marshaling rather than of anything this package chose, so a Go or goxdr
// version bump could move it a little without anything being wrong. Doubling it
// could not happen without a structural change, which is exactly what should
// fail here.
func TestMarshalingAllocationsHaveNotRegressed(t *testing.T) {
	fh := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	// The operations are built ONCE, outside the measured closure, so this
	// measures encoding and nothing else. OpPutFH and OpSetACL together
	// allocate 4 times, which is invisible against the generated encoder's
	// ceiling of 100 but would be five sixths of the fast path's budget --
	// enough to make the tight guard below fail on a working encoder.
	ops := []xdr.Nfs_argop4{
		OpPutFH(fh),
		OpSetACL(benchACL),
	}

	// The length check in each case is not decoration: without it an encoder
	// that returned (nil, nil) would allocate nothing and pass with flying
	// colours.
	build := func(t *testing.T, encode func(string, []xdr.Nfs_argop4) ([]byte, error)) float64 {
		t.Helper()
		return testing.AllocsPerRun(200, func() {
			b, err := encode("guard", ops)
			if err != nil {
				t.Fatal(err)
			}
			if len(b) == 0 {
				t.Fatal("encoder returned no bytes")
			}
		})
	}

	// The generated encoder is still the fallback for every operation the fast
	// path declines, so it keeps its own guard at the original loose ceiling.
	// 51 is a property of goxdr's interface-dispatch marshaling rather than of
	// anything this package chose, so a Go or goxdr version bump could move it
	// a little without anything being wrong. Doubling it could not happen
	// without a structural change, which is what should fail here.
	t.Run("generated", func(t *testing.T) {
		const ceiling = 100
		if n := build(t, buildCompoundGenerated); n > ceiling {
			t.Errorf("buildCompoundGenerated allocates %.0f times per SETACL COMPOUND, ceiling %d "+
				"(recorded baseline 51); a jump this size means the marshaling path changed "+
				"structurally, so re-measure with -benchmem and update the comment above", n, ceiling)
		}
	})

	// BuildCompound takes the hand-written path for SETACL, so guarding it at
	// the generated encoder's ceiling would assert nothing -- it would pass at
	// 1 allocation and pass just as happily at 99, including in the case that
	// matters most, a silent fall back to the generated encoder. The tight
	// ceiling is the whole point: 1 is the measurement (the returned slice),
	// and 3 leaves room for a caller-supplied buffer growing without letting a
	// regression to per-field allocation through.
	t.Run("fast", func(t *testing.T) {
		const ceiling = 3
		if n := build(t, BuildCompound); n > ceiling {
			t.Errorf("BuildCompound allocates %.0f times per SETACL COMPOUND, ceiling %d "+
				"(measured 1); either the fast encoder regressed or it silently declined "+
				"this COMPOUND and fell back to the generated encoder -- check which before "+
				"raising this number", n, ceiling)
		}
	})
}

// BenchmarkReadDirCompound covers the other steady-state op. READDIR is issued
// once per directory where SETATTR is once per file, so it matters less, but it
// carries the attribute bitmap and is the op whose reply is parsed.
func BenchmarkReadDirCompound(b *testing.B) {
	fh := []byte{0xde, 0xad, 0xbe, 0xef}
	var verf [8]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, err := BuildCompound("bench", []xdr.Nfs_argop4{
			OpPutFH(fh),
			OpReadDir(0, verf, 8192, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		})
		if err != nil {
			b.Fatal(err)
		}
		if len(buf) == 0 {
			b.Fatal("empty COMPOUND")
		}
	}
}
