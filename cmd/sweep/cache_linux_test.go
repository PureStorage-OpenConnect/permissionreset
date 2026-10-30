//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dropCaches is exercised through the dropCachesPath seam, because the real path
// is root-only and system-wide.
func TestDropCachesRefusesWhatItCannotDoHonestly(t *testing.T) {
	t.Run("no mount point resolved", func(t *testing.T) {
		err := dropCaches{}.BeforeTrial(context.Background())
		if err == nil || !strings.Contains(err.Error(), "no mount point") {
			t.Fatalf("err = %v, want a refusal naming the missing mount point", err)
		}
	})

	t.Run("already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// A cancelled sweep must not drop the whole machine's caches on its way out,
		// so the context is checked before anything is written.
		old := dropCachesPath
		dropCachesPath = filepath.Join(t.TempDir(), "must-not-be-written")
		t.Cleanup(func() { dropCachesPath = old })

		if err := (dropCaches{mountPoint: "/mnt/sweep"}).BeforeTrial(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if _, err := os.Stat(dropCachesPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a cancelled trial still wrote to drop_caches")
		}
	})

	t.Run("drop_caches unwritable", func(t *testing.T) {
		old := dropCachesPath
		dropCachesPath = filepath.Join(t.TempDir(), "missing-dir", "drop_caches")
		t.Cleanup(func() { dropCachesPath = old })

		err := dropCaches{mountPoint: "/mnt/sweep"}.BeforeTrial(context.Background())
		if err == nil || !strings.Contains(err.Error(), "drop caches") {
			t.Fatalf("err = %v, want the failed drop reported", err)
		}
	})

	t.Run("remount fails", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root may actually be able to remount an ordinary directory")
		}
		old := dropCachesPath
		dropCachesPath = filepath.Join(t.TempDir(), "drop_caches")
		t.Cleanup(func() { dropCachesPath = old })

		// A warm trial reported as a cold one is worse than no data, so a failed
		// remount fails the point even though the drop itself succeeded.
		err := dropCaches{mountPoint: t.TempDir()}.BeforeTrial(context.Background())
		if err == nil || !strings.Contains(err.Error(), "remount") {
			t.Fatalf("err = %v, want the failed remount reported", err)
		}
	})
}
