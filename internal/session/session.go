// Package session wraps one live connection -- kernel or userspace -- behind
// a transport-agnostic API meant for a long-lived caller such as a desktop
// GUI. The CLI tools (build-spec, permissionreset) each open a connection, do one
// piece of work, and exit; a GUI instead holds a session open across many
// user actions, so this package adds the things that situation needs and the
// CLI never did: idle expiry, a single-flight lock so concurrent UI actions
// serialize instead of racing the same connection, and a session-lost error
// distinct from an ordinary operation failure.
//
// It owns no new protocol logic. Every operation is delegated to the same
// pieces the CLI already uses -- internal/nfs41, internal/transport,
// internal/speccapture -- through a small unexported backend interface, so a
// test can inject a fake and exercise locking, expiry, and path validation
// without a network or a mount.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// Transport selects which backend Connect builds.
type Transport string

const (
	Userspace Transport = "userspace"
	Kernel    Transport = "kernel"
)

// ConnectRequest carries every parameter Connect needs for either transport.
// Only the fields for the chosen Transport are read; the others are ignored.
type ConnectRequest struct {
	Transport Transport

	// Userspace fields.
	Server, Export string
	Auth           *nfs41.AuthSys // nil means "build one from the running process"
	RPCTimeout     time.Duration
	RetryBudget    int
	RetryBaseDelay time.Duration

	// Kernel fields.
	MountPath string

	// Log receives progress and warning messages from the backend. A nil Log
	// is replaced with a no-op.
	Log func(string)
}

// Entry is one child returned by Session.ListDir.
type Entry struct {
	Name      string
	IsDir     bool
	IsSymlink bool
}

// ErrSessionLost reports that the underlying connection to the server dropped.
// It is distinct from ErrExpired: this is unwrapped-by-us but caused by the
// network, and a caller should offer to reconnect rather than retry in place.
var ErrSessionLost = errors.New("session: connection to the server was lost")

// ErrExpired reports that the session outlived its idle timeout, or was
// already closed, before this call was made.
var ErrExpired = errors.New("session: expired after idle timeout")

// backend is the narrow surface Session needs from either transport. It
// embeds speccapture.Reader so Session.Capture can pass it straight through.
type backend interface {
	speccapture.Reader
	ReadDirLimited(ref transport.Ref, limit int) ([]transport.Dirent, bool, error)
	Verifier() speccapture.ReplayVerifier
	Close() error
}

// newBackend constructs the backend for a ConnectRequest. It is a package
// variable so tests can inject a fake backend without a network or a mount;
// production code never reassigns it outside init.
var newBackend = defaultNewBackend

func defaultNewBackend(ctx context.Context, req ConnectRequest) (backend, string, error) {
	switch req.Transport {
	case Userspace:
		if req.Server == "" {
			return nil, "", errors.New("session: server is required for the userspace transport")
		}
		if req.Export == "" {
			return nil, "", errors.New("session: export is required for the userspace transport")
		}
		cfg := nfs41.Config{
			Server:         req.Server,
			Export:         req.Export,
			Target:         "",
			Connections:    1,
			RPCTimeout:     req.RPCTimeout,
			RetryBudget:    req.RetryBudget,
			RetryBaseDelay: req.RetryBaseDelay,
			Auth:           req.Auth,
			Log:            req.Log,
		}
		c, err := nfs41.New(ctx, cfg)
		if err != nil {
			return nil, "", err
		}
		return &userspaceBackend{client: c}, path.Clean(req.Export), nil
	case Kernel:
		if req.MountPath == "" {
			return nil, "", errors.New("session: mount path is required for the kernel transport")
		}
		return newKernelBackend(ctx, req)
	default:
		return nil, "", fmt.Errorf("session: unknown transport %q", req.Transport)
	}
}

// absPath resolves p to an absolute path. It exists so both kernel backend
// constructors (Unix and the Windows stub, which never calls it) share one
// implementation.
func absPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("session: resolve mount path %q: %w", p, err)
	}
	return abs, nil
}

// Session is one live connection to a server, shared across many calls from
// a long-lived caller. All exported methods except Expired and Close take an
// internal lock, so calls from different goroutines serialize rather than
// race the underlying connection.
type Session struct {
	mu        sync.Mutex
	backend   backend
	root      string
	transport Transport
	cfg       ConnectRequest // copy, used by Exports to rebuild an nfs41.Config
	lastUsed  time.Time
	idle      time.Duration
	now       func() time.Time
	closed    bool
}

// Connect opens a session for req.Transport. idle <= 0 means the session
// never expires from inactivity. now is the clock Session uses to measure
// idleness; pass time.Now in production and an injectable fake in tests.
func Connect(ctx context.Context, req ConnectRequest, idle time.Duration, now func() time.Time) (*Session, error) {
	if req.Log == nil {
		req.Log = func(string) {}
	}
	if now == nil {
		now = time.Now
	}
	b, root, err := newBackend(ctx, req)
	if err != nil {
		return nil, err
	}
	return &Session{
		backend:   b,
		root:      root,
		transport: req.Transport,
		cfg:       req,
		lastUsed:  now(),
		idle:      idle,
		now:       now,
	}, nil
}

// Transport reports which transport this session was opened with.
func (s *Session) Transport() Transport { return s.transport }

// Root returns the export path (userspace) or mount path (kernel) this
// session is rooted at.
func (s *Session) Root() string { return s.root }

// Expired reports whether the session is closed or has been idle longer than
// its configured timeout. It takes no lock and touches no state, so it is
// safe to poll from a UI thread without contending with in-flight calls.
func (s *Session) Expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiredLocked()
}

func (s *Session) expiredLocked() bool {
	if s.closed {
		return true
	}
	if s.idle <= 0 {
		return false
	}
	return s.now().Sub(s.lastUsed) > s.idle
}

// enter locks the session, checks expiry, and touches lastUsed. Callers must
// call the returned unlock function (always, even on error) exactly once.
func (s *Session) enter() (func(), error) {
	s.mu.Lock()
	if s.expiredLocked() {
		s.mu.Unlock()
		return func() {}, ErrExpired
	}
	s.lastUsed = s.now()
	return s.mu.Unlock, nil
}

// underRoot checks that p is an absolute forward-slash path under root.
// allowRoot permits p == root (used by ListDir); Capture/Verify exemplars and
// the Verify scratch directory must all be strictly inside root, so they
// pass allowRoot=false.
func underRoot(p, root string, allowRoot bool) error {
	if strings.Contains(p, `\`) {
		return fmt.Errorf("path %q contains backslashes; use forward slashes", p)
	}
	if !path.IsAbs(p) {
		return fmt.Errorf("path %q must be an absolute path (start with /)", p)
	}
	clean := path.Clean(p)
	rootClean := path.Clean(root)
	if clean == rootClean {
		if allowRoot {
			return nil
		}
		return fmt.Errorf("path %q is the session root %q; give a path inside it", p, root)
	}
	if !strings.HasPrefix(clean, rootClean+"/") {
		return fmt.Errorf("path %q is not inside %q", p, root)
	}
	rel := strings.TrimPrefix(clean, rootClean+"/")
	if rel == ".." || strings.Contains(rel, "/../") || strings.HasSuffix(rel, "/..") || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("path %q contains a '..' component that escapes %q", p, root)
	}
	return nil
}

// checkPath validates p against the session's root for the appropriate
// transport: userspace paths are forward-slash server paths (path.Clean
// semantics); kernel paths are resolved with filepath.Abs and must have root
// as a prefix.
func (s *Session) checkPath(p string, allowRoot bool) error {
	if s.transport == Kernel {
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("resolve path %q: %w", p, err)
		}
		rootClean := filepath.Clean(s.root)
		if abs == rootClean {
			if allowRoot {
				return nil
			}
			return fmt.Errorf("path %q is the session root %q; give a path inside it", p, s.root)
		}
		if !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) {
			return fmt.Errorf("path %q is not inside %q", p, s.root)
		}
		return nil
	}
	return underRoot(p, s.root, allowRoot)
}

// classifyLost wraps err with ErrSessionLost when it looks like a dropped
// connection rather than an ordinary operation failure (a bad path, a
// permissions error, an argument-order mistake). Everything else passes
// through unchanged.
func classifyLost(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrSessionLost, err)
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return fmt.Errorf("%w: %v", ErrSessionLost, err)
	}
	return err
}

const (
	defaultListLimit = 2000
	maxListLimit     = 5000
)

// ListDir lists the children of p, which must be s.Root() itself or a path
// under it. limit <= 0 defaults to 2000 entries; any limit above 5000 is
// clamped to it, so an interactive browser can never pull an unbounded
// directory into memory in one call.
func (s *Session) ListDir(p string, limit int) ([]Entry, bool, error) {
	unlock, err := s.enter()
	defer unlock()
	if err != nil {
		return nil, false, err
	}
	if err := s.checkPath(p, true); err != nil {
		return nil, false, err
	}
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	dirents, truncated, err := s.backend.ReadDirLimited(transport.Ref{Path: p}, limit)
	if err != nil {
		return nil, false, classifyLost(err)
	}
	out := make([]Entry, len(dirents))
	for i, d := range dirents {
		out[i] = Entry{Name: d.Name, IsDir: d.IsDir, IsSymlink: d.IsSymlink}
	}
	return out, truncated, nil
}

// discover is a package variable wrapping nfs41.DiscoverExports so tests can
// stub it without a network.
var discover = nfs41.DiscoverExports

// Exports lists the exports visible from the pseudo-root. It is only
// meaningful for the userspace transport; on the kernel transport it returns
// supported=false, since a kernel mount is already bound to one export and
// has no pseudo-root to enumerate. supported is also false when the server
// itself does not support discovery (nfs41.ErrDiscoveryUnsupported).
func (s *Session) Exports(ctx context.Context) ([]string, bool, error) {
	unlock, err := s.enter()
	defer unlock()
	if err != nil {
		return nil, false, err
	}
	if s.transport != Userspace {
		return nil, false, nil
	}
	cfg := nfs41.Config{
		Server:         s.cfg.Server,
		Export:         s.cfg.Export,
		Connections:    1,
		RPCTimeout:     s.cfg.RPCTimeout,
		RetryBudget:    s.cfg.RetryBudget,
		RetryBaseDelay: s.cfg.RetryBaseDelay,
		Auth:           s.cfg.Auth,
		Log:            s.cfg.Log,
	}
	names, err := discover(ctx, cfg)
	if err != nil {
		if errors.Is(err, nfs41.ErrDiscoveryUnsupported) {
			return nil, false, nil
		}
		return nil, false, classifyLost(err)
	}
	sort.Strings(names)
	return names, true, nil
}

// Capture reads the ACLs from dir and file, which must both be paths under
// s.Root(), and returns the same speccapture.Result the build-spec CLI
// produces for the same opts. Argument-order and validation errors from
// speccapture.Capture pass through unchanged; only a dropped connection is
// classified as ErrSessionLost.
func (s *Session) Capture(dir, file string, opts speccapture.Options) (*speccapture.Result, error) {
	unlock, err := s.enter()
	defer unlock()
	if err != nil {
		return nil, err
	}
	if err := s.checkPath(dir, false); err != nil {
		return nil, err
	}
	if err := s.checkPath(file, false); err != nil {
		return nil, err
	}
	res, err := speccapture.CaptureWithOptions(s.backend, transport.Ref{Path: dir}, transport.Ref{Path: file}, opts)
	if err != nil {
		return nil, classifyLost(err)
	}
	return res, nil
}

// Verify captures dir and file, then replays the resulting ACLs through
// scratch to confirm the server accepts them. scratch, dir, and file must
// each be under s.Root(), and scratch must differ from both exemplars (the
// same rule speccapture.Verify enforces).
func (s *Session) Verify(scratch, dir, file string, opts speccapture.Options) (*speccapture.Result, error) {
	unlock, err := s.enter()
	defer unlock()
	if err != nil {
		return nil, err
	}
	if err := s.checkPath(scratch, false); err != nil {
		return nil, err
	}
	if err := s.checkPath(dir, false); err != nil {
		return nil, err
	}
	if err := s.checkPath(file, false); err != nil {
		return nil, err
	}
	dirRef := transport.Ref{Path: dir}
	fileRef := transport.Ref{Path: file}
	res, err := speccapture.CaptureWithOptions(s.backend, dirRef, fileRef, opts)
	if err != nil {
		return nil, classifyLost(err)
	}
	verified, err := speccapture.Verify(s.backend.Verifier(), transport.Ref{Path: scratch}, dirRef, fileRef, res)
	if err != nil {
		return nil, classifyLost(err)
	}
	return verified, nil
}

// Close releases the underlying backend. It is idempotent: a second call
// returns nil without touching the backend again.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.backend.Close()
}
