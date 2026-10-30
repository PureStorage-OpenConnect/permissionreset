package main

import (
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
)

// caps is this command's view of the platform matrix. Production never assigns
// it; tests swap it through cmdflagstest.With so one Linux test binary
// exercises both branches of every gate. See internal/cmdflags for the Gate
// helper itself -- it is shared, not copied, because the refusal it emits is an
// operator-visible contract and a contract with two owners drifts.
var caps = platform.Current()

// defaultSweepTransport mirrors cmd/permissionreset: where the kernel transport
// cannot work, userspace is not a choice but the only mode, so it is the default.
func defaultSweepTransport() string {
	if caps.KernelTransport {
		return "kernel"
	}
	return "userspace"
}
