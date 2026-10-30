package speccapture

import (
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// UserspaceVerifier implements ReplayVerifier using the userspace NFSv4.1
// client. Probes are created with a safe default mode (0700/0600) and no
// initial ACL; SetACL is then exercised explicitly so verification tests the
// same code path that repair uses.
type UserspaceVerifier struct {
	Client *nfs41.Client
}

var _ ReplayVerifier = (*UserspaceVerifier)(nil)

func (u *UserspaceVerifier) CreateProbeDirectory(parent transport.Ref, name string) (transport.Ref, error) {
	return u.Client.Mkdir(parent, name, nil, 0o700)
}

func (u *UserspaceVerifier) CreateProbeFile(parent transport.Ref, name string) (transport.Ref, error) {
	return u.Client.CreateFile(parent, name, nil, 0o600)
}

func (u *UserspaceVerifier) SetACL(ref transport.Ref, acl []byte) error {
	return u.Client.SetACL(ref, acl)
}

func (u *UserspaceVerifier) GetACL(ref transport.Ref) ([]byte, error) {
	return u.Client.GetACL(ref)
}

func (u *UserspaceVerifier) Remove(parent transport.Ref, name string) error {
	return u.Client.Remove(parent, name)
}
