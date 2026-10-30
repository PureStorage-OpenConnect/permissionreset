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

// defaultGenTreeTransport puts the default where it can actually work. Gating
// the flag alone would not be enough: the common invocation names no transport
// at all, and a kernel default sends it straight into setxattr on a platform
// with no system.nfs4_acl -- after the whole directory tree has been built.
func defaultGenTreeTransport() string {
	if caps.KernelTransport {
		return "kernel"
	}
	return "userspace"
}
