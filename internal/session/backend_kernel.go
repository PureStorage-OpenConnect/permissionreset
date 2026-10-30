//go:build !windows

package session

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// newKernelBackend constructs the kernel backend for Connect. It is a plain
// function (not a method) so session.go can reference it from a build-tag-free
// file while backend_kernel_windows.go supplies the Windows stub under the
// same name.
func newKernelBackend(_ context.Context, req ConnectRequest) (backend, string, error) {
	root, err := absPath(req.MountPath)
	if err != nil {
		return nil, "", err
	}
	k, err := transport.NewKernel(root)
	if err != nil {
		return nil, "", err
	}
	return &kernelBackend{k: k}, root, nil
}

// NewKernelReader builds a speccapture.Reader backed by the kernel transport,
// rooted at mountRoot. It is the same construction cmd/build_spec used
// directly before the session package existed.
func NewKernelReader(mountRoot string) (speccapture.Reader, error) {
	return transport.NewKernel(mountRoot)
}

// NewKernelVerifier returns the ReplayVerifier used by --verify-write (and the
// session package's Verify) on the kernel transport.
func NewKernelVerifier() speccapture.ReplayVerifier {
	return speccapture.KernelVerifier{}
}

// kernelBackend adapts *transport.Kernel to the session package's backend
// interface.
type kernelBackend struct {
	k *transport.Kernel
}

var _ backend = (*kernelBackend)(nil)

func (k *kernelBackend) Stat(ref transport.Ref) (transport.Attr, error) {
	return k.k.Stat(ref)
}

func (k *kernelBackend) GetACL(ref transport.Ref) ([]byte, error) {
	return k.k.GetACL(ref)
}

// ReadDirLimited lists ref's children like the kernel transport's ReadDir,
// but stops after limit entries. The kernel transport has no readdir cursor
// cheap enough to expose here, so this reads the full directory via
// os.ReadDir and truncates in memory; that is acceptable for the interactive
// browsing this exists for, and unlike the userspace transport there is no
// per-entry RPC being saved.
func (k *kernelBackend) ReadDirLimited(ref transport.Ref, limit int) ([]transport.Dirent, bool, error) {
	entries, err := os.ReadDir(ref.Path)
	if err != nil {
		return nil, false, err
	}
	truncated := false
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
		truncated = true
	}
	out := make([]transport.Dirent, 0, len(entries))
	for _, e := range entries {
		d := transport.Dirent{Name: e.Name(), Ref: transport.Ref{Path: filepath.Join(ref.Path, e.Name())}}
		if e.Type()&fs.ModeSymlink != 0 {
			d.IsSymlink = true
		} else {
			d.IsDir = e.Type().IsDir()
		}
		out = append(out, d)
	}
	return out, truncated, nil
}

func (k *kernelBackend) Verifier() speccapture.ReplayVerifier {
	return speccapture.KernelVerifier{}
}

func (k *kernelBackend) Close() error {
	return k.k.Close()
}
