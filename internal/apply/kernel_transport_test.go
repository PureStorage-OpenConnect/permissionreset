package apply

import (
	"os"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// kernelTransport returns a kernel transport for the tests that predate the
// Transport seam. They operate on real tmpdir paths and assert on the resulting
// on-disk state, so they need the syscall implementation rather than the
// recording double.
//
// The root only feeds Kernel.Root(), which apply never calls; every method these
// tests reach takes an absolute path in the Ref. It is os.TempDir() rather than
// "/" for two reasons: "/" is the one target main explicitly refuses, so a
// fixture built on it tests the production-forbidden case, and constructing this
// in a package-level var made a failure surface as an opaque init panic instead
// of a named test failure.
func kernelTransport(t *testing.T) transport.Transport {
	t.Helper()
	k, err := transport.NewKernel(os.TempDir())
	if err != nil {
		t.Fatalf("kernel transport over %s: %v", os.TempDir(), err)
	}
	return k
}
