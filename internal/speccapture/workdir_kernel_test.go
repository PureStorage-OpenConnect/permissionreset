//go:build !windows

package speccapture_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestCheckWorkDirWithTheKernelTransport runs the check through the real
// kernel transport's lstat, so its ENOENT is the error being recognized, and
// confirms nothing is created at the missing path.
func TestCheckWorkDirWithTheKernelTransport(t *testing.T) {
	root := t.TempDir()
	k, err := transport.NewKernel(root)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file.txt")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "scratch")

	if err := speccapture.CheckWorkDir(k, root, "probe directory"); err != nil {
		t.Errorf("directory: err = %v, want nil", err)
	}
	if err := speccapture.CheckWorkDir(k, missing, "probe directory"); !errors.Is(err, speccapture.ErrDirMissing) {
		t.Errorf("missing: err = %v, want ErrDirMissing", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Errorf("missing path exists after the check (lstat err = %v); the check must not create it", err)
	}
	if err := speccapture.CheckWorkDir(k, file, "probe directory"); !errors.Is(err, speccapture.ErrNotDir) {
		t.Errorf("file: err = %v, want ErrNotDir", err)
	}
	if err := speccapture.CheckWorkDir(k, link, "probe directory"); !errors.Is(err, speccapture.ErrNotDir) {
		t.Errorf("symlink: err = %v, want ErrNotDir", err)
	}
}
