package main

import (
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
)

// caps is this command's platform matrix.
//
// internal/platform exports constants and stays the source of truth; nothing in
// production assigns caps. The variable exists so that one test binary on Linux
// can exercise both branches of every gate, which real build tags cannot do: a
// darwin binary is not runnable on the runner that runs the tests. Tests swap it
// through cmdflagstest.With(t, &caps, platform.Darwin()).
var caps = platform.Current()

// defaultTransport is "kernel" where the kernel transport works and "userspace"
// where it does not.
//
// The default MOVES rather than the flag merely being discouraged, because on a
// platform with no system.nfs4_acl the kernel backend compiles, runs a real
// setxattr, and fails ENOTSUP once per object. A default that lands there would
// make the failure the normal experience. The flag itself stays visible and
// usable -- only the value "kernel" is refused; see Task 4.
func defaultTransport() string {
	if caps.KernelTransport {
		return "kernel"
	}
	return "userspace"
}

// userspaceDefaultNote explains the userspace worker default. On a build with
// two transports it has to say WHICH transport it is talking about; on a build
// with one it must not, both because the qualifier is noise and because naming
// "--transport=userspace" inside a usage string is indistinguishable, to any
// reader scanning --help, from offering a choice.
func userspaceDefaultNote() string {
	if caps.KernelTransport {
		return " (--transport=userspace defaults to 1024 against a FlashBlade and 64 against a FlashArray)"
	}
	return " (defaults to 1024 against a FlashBlade and 64 against a FlashArray)"
}

// userspaceOnly appends the qualifier that only means something where a second
// transport exists. Where the kernel transport is unavailable, userspace is the
// only mode and the qualifier implies a choice the operator does not have.
func userspaceOnly(usage string) string {
	if !caps.KernelTransport {
		return usage
	}
	return usage + " (--transport=userspace only)"
}
