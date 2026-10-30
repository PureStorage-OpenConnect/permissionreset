package session

import (
	"context"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// NewUserspace opens a userspace NFSv4.1 connection and returns the pieces
// build-spec and the session package both need: a speccapture.Reader, a
// speccapture.ReplayVerifier bound to the same client, and a closer that
// sends DESTROY_SESSION. This is the same construction cmd/build_spec used
// directly before the session package existed; it now lives here so both
// callers share one code path.
func NewUserspace(ctx context.Context, cfg nfs41.Config) (speccapture.Reader, speccapture.ReplayVerifier, func() error, error) {
	c, err := nfs41.New(ctx, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	return c, &speccapture.UserspaceVerifier{Client: c}, c.Close, nil
}

// userspaceBackend adapts *nfs41.Client to the session package's backend
// interface.
type userspaceBackend struct {
	client *nfs41.Client
}

var _ backend = (*userspaceBackend)(nil)

func (u *userspaceBackend) Stat(ref transport.Ref) (transport.Attr, error) {
	return u.client.Stat(ref)
}

func (u *userspaceBackend) GetACL(ref transport.Ref) ([]byte, error) {
	return u.client.GetACL(ref)
}

func (u *userspaceBackend) ReadDirLimited(ref transport.Ref, limit int) ([]transport.Dirent, bool, error) {
	return u.client.ReadDirLimited(ref, limit)
}

func (u *userspaceBackend) Verifier() speccapture.ReplayVerifier {
	return &speccapture.UserspaceVerifier{Client: u.client}
}

func (u *userspaceBackend) Close() error {
	return u.client.Close()
}
