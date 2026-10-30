//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// dropCachesPath is the kernel's whole-system cache release. It is a variable
// only so the root path is addressable in a test on a machine that has one.
var dropCachesPath = "/proc/sys/vm/drop_caches"

// dropCaches drops the page, dentry and inode caches and remounts the target,
// which is what makes an NFS trial start from the same cold state every time.
// A failure here fails the point: a warm trial reported as a cold one is worse
// than no data, because it ranks against cold trials in the same ladder.
type dropCaches struct{ mountPoint string }

func (d dropCaches) BeforeTrial(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.mountPoint == "" {
		return fmt.Errorf("cannot remount: no mount point resolved for the trial root")
	}
	// Sync first: dirty pages the drop cannot discard would otherwise be written
	// back during the trial and charged to it.
	unix.Sync()
	if err := os.WriteFile(dropCachesPath, []byte("3\n"), 0o200); err != nil {
		return fmt.Errorf("drop caches: %w", err)
	}
	// The remount is what clears the NFS client's own attribute and directory
	// caches for this mount; drop_caches alone leaves them.
	if err := unix.Mount("", d.mountPoint, "", unix.MS_REMOUNT, ""); err != nil {
		return fmt.Errorf("remount %s: %w", d.mountPoint, err)
	}
	return nil
}

// newCacheController picks the cache handling this transport and this identity
// can perform.
//
// Userspace needs none: run.Run constructs and closes a fresh userspace
// transport on every call, so no session, filehandle or attribute cache
// survives a trial, and the tree is never in this client's page cache at all.
//
// Kernel without root cannot drop anything, and the sweep still runs — refusing
// would make the tool unusable for the common case. What it must not do is stay
// silent, because the first trial of a ladder pays for a cold cache and every
// later one does not, which flattens the ladder and can crown the wrong knob
// value purely by ordering.
func newCacheController(transportName, mountPoint string, out io.Writer) cacheController {
	if transportName != "kernel" {
		return noCacheControl()
	}
	if os.Geteuid() != 0 {
		fmt.Fprintf(out, "warning: not running as root, so the page, dentry and inode caches "+
			"cannot be dropped between trials; later trials inherit cache warmth from earlier "+
			"ones and the measured ladder may be flatter than the real one\n")
		return noCacheControl()
	}
	return dropCaches{mountPoint: mountPoint}
}
