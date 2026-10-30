//go:build windows

package session

import (
	"context"
	"errors"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
)

// newKernelBackend is the Windows stub Connect calls for Transport Kernel.
func newKernelBackend(_ context.Context, _ ConnectRequest) (backend, string, error) {
	return nil, "", errors.New("kernel transport unavailable on Windows; use --transport=userspace")
}

// NewKernelReader is a stub on Windows. The kernel transport requires the
// Linux NFS client; Connect refuses Transport Kernel before this would ever
// be called.
func NewKernelReader(_ string) (speccapture.Reader, error) {
	return nil, errors.New("kernel transport unavailable on Windows; use --transport=userspace")
}

// NewKernelVerifier is a stub on Windows. The kernel transport (and its
// verifier) are unavailable on this platform.
func NewKernelVerifier() speccapture.ReplayVerifier {
	return nil
}
