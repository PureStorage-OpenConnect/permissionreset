//go:build !windows

package main

import (
	"github.com/PureStorage-OpenConnect/permissionreset/internal/session"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
)

// newKernelFromMount builds a kernel transport rooted at mountRoot.
// It is gated behind !windows because transport.NewKernel only exists there.
func newKernelFromMount(mountRoot string) (speccapture.Reader, error) {
	return session.NewKernelReader(mountRoot)
}

// newKernelVerifier returns the ReplayVerifier used by --verify-write on the
// kernel transport. KernelVerifier is only available on non-Windows platforms.
func newKernelVerifier() speccapture.ReplayVerifier {
	return session.NewKernelVerifier()
}
