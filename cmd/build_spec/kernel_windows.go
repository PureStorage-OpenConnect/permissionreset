//go:build windows

package main

import (
	"github.com/PureStorage-OpenConnect/permissionreset/internal/session"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
)

// newKernelFromMount is a stub on Windows. The kernel transport requires the
// Linux NFS client; the gate in registerFlags refuses --transport=kernel before
// this path is ever reached, so this function should never be called.
func newKernelFromMount(mountRoot string) (speccapture.Reader, error) {
	return session.NewKernelReader(mountRoot)
}

// newKernelVerifier is a stub on Windows. The kernel transport (and its
// verifier) are unavailable; the gate refuses --transport=kernel before this
// path is ever reached.
func newKernelVerifier() speccapture.ReplayVerifier {
	return session.NewKernelVerifier()
}
