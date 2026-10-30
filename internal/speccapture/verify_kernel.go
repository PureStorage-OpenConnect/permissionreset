//go:build !windows

package speccapture

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// KernelVerifier implements ReplayVerifier using kernel-mount operations:
// exclusive os.Mkdir / os.OpenFile for creates, nfs4acl.SetACL / GetACL for
// xattr operations, and os.Remove for cleanup.
type KernelVerifier struct{}

var _ ReplayVerifier = KernelVerifier{}

func (KernelVerifier) CreateProbeDirectory(parent transport.Ref, name string) (transport.Ref, error) {
	p := filepath.Join(parent.Path, name)
	if err := os.Mkdir(p, 0o700); err != nil {
		return transport.Ref{}, fmt.Errorf("kernel: mkdir %q: %w", p, err)
	}
	return transport.Ref{Path: p}, nil
}

func (KernelVerifier) CreateProbeFile(parent transport.Ref, name string) (transport.Ref, error) {
	p := filepath.Join(parent.Path, name)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return transport.Ref{}, fmt.Errorf("kernel: create %q: %w", p, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(p)
		return transport.Ref{}, fmt.Errorf("kernel: close %q: %w", p, err)
	}
	return transport.Ref{Path: p}, nil
}

func (KernelVerifier) SetACL(ref transport.Ref, acl []byte) error {
	return nfs4acl.SetACL(ref.Path, acl)
}

func (KernelVerifier) GetACL(ref transport.Ref) ([]byte, error) {
	return nfs4acl.GetACL(ref.Path)
}

func (KernelVerifier) Remove(parent transport.Ref, name string) error {
	return os.Remove(filepath.Join(parent.Path, name))
}
