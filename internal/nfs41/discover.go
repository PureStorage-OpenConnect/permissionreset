package nfs41

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// ErrDiscoveryUnsupported is returned when the server does not list its exports
// under the NFSv4 pseudo-root (NFS4ERR_NOTSUPP, or an empty listing).
var ErrDiscoveryUnsupported = errors.New("nfs41: export discovery is not supported by this server")

// DiscoverExports connects to cfg.Server, enumerates the NFSv4 pseudo-root and
// returns each directory child as "/name", sorted. It uses one connection,
// ignores cfg.Export and cfg.Target, and sets AllowNonPureServer so a
// pseudo-root whose FATTR4_MAXFILESIZE is outside the Pure table does not
// refuse discovery (the gate exists to protect writes; discovery is read-only
// and never descends into an export). The client is closed before return.
func DiscoverExports(ctx context.Context, cfg Config) ([]string, error) {
	cfg.Export = "/"
	cfg.Target = ""
	cfg.Connections = 1
	cfg.AllowNonPureServer = true

	c, err := New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("nfs41: discover exports: connect: %w", err)
	}
	defer c.Close()

	root, err := c.Root()
	if err != nil {
		return nil, fmt.Errorf("nfs41: discover exports: resolve pseudo-root: %w", err)
	}

	entries, err := c.ReadDir(root)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == NFS4ERR_NOTSUPP {
			return nil, ErrDiscoveryUnsupported
		}
		return nil, fmt.Errorf("nfs41: discover exports: read pseudo-root: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir && !e.IsSymlink {
			names = append(names, "/"+e.Name)
		}
	}
	if len(names) == 0 {
		return nil, ErrDiscoveryUnsupported
	}
	sort.Strings(names)
	return names, nil
}
