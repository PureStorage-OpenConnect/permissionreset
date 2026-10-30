//go:build !linux

package main

import (
	"fmt"
	"io"
)

// newCacheController on non-Linux platforms always returns a no-op controller.
// Cache drop and remount require Linux-specific syscalls (/proc/sys/vm/drop_caches,
// MS_REMOUNT). Userspace transport is unaffected — it starts cold by construction.
// Kernel transport on a non-Linux host is unlikely in practice, but if reached the
// warning matches the existing "not root" degradation path.
func newCacheController(transportName, mountPoint string, out io.Writer) cacheController {
	if transportName == "kernel" {
		fmt.Fprintf(out, "warning: cache drop and remount are only available on Linux; "+
			"kernel transport trials will run with warm caches and the measured ladder "+
			"may be flatter than the real one\n")
	}
	return noCacheControl()
}
