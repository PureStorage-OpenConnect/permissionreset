package main

import "github.com/PureStorage-OpenConnect/permissionreset/internal/platform"

var caps = platform.Current()

// defaultTransport returns "kernel" on Linux (where the NFS client exposes
// system.nfs4_acl) and "userspace" everywhere else.
func defaultTransport() string {
	if caps.KernelTransport {
		return "kernel"
	}
	return "userspace"
}
