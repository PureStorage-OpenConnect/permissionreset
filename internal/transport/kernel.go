//go:build !windows

package transport

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
)

// Kernel performs every operation with a syscall against a mounted path. It is
// the default transport and preserves the behavior permissionreset had before the
// Transport interface existed.
//
// It holds no state beyond the root path, so every method is trivially safe for
// concurrent use.
type Kernel struct {
	root string
}

// NewKernel returns a kernel transport rooted at an existing directory.
func NewKernel(root string) (*Kernel, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", root, err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", abs, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", abs)
	}
	return &Kernel{root: abs}, nil
}

func (k *Kernel) Root() (Ref, error) { return Ref{Path: k.root}, nil }

// ReadDir lists children. os.ReadDir already sorts by name, which is the order
// the Transport contract requires.
//
// It performs NO per-entry stat, and so leaves AttrsKnown false. On Linux,
// getdents supplies d_type and nothing more, so Mode and FSID would each cost an
// lstat per entry — and CLAUDE.md's design rules forbid exactly that: "Stat in
// apply workers, never in enumerator." The cost is not hypothetical. The primary
// workload is protocol: nfsv4, applyNFSv4 takes no cached mode, and Prepass has
// never stat'ed files at all, so stat'ing here would add one round trip per
// object on a million-object run and consume none of them.
//
// A caller that genuinely needs an attribute calls Stat and pays for it visibly.
func (k *Kernel) ReadDir(r Ref) ([]Dirent, error) {
	entries, err := os.ReadDir(r.Path)
	if err != nil {
		return nil, err
	}
	out := make([]Dirent, 0, len(entries))
	for _, e := range entries {
		out = append(out, kernelDirent(r.Path, e))
	}
	return out, nil
}

func kernelDirent(dir string, e os.DirEntry) Dirent {
	d := Dirent{Name: e.Name(), Ref: Ref{Path: dir + "/" + e.Name()}}

	// Symlinks are tested before IsDir: a symlink to a directory reports
	// IsDir() false but must still be tagged, never followed.
	if e.Type()&os.ModeSymlink != 0 {
		d.IsSymlink = true
	} else {
		d.IsDir = e.IsDir()
	}
	return d
}

// ReadDirBatches lists r n children at a time through one open directory
// handle (File.ReadDir(n), one or more getdents calls per batch), so the
// listing never holds more than n entries. It is the DirBatcher the walk uses
// on this transport; see that interface for the ordering and reuse contract.
//
// The handle stays open until the listing ends, including while fn blocks on
// a slow consumer. The walk keeps at most one listing open per goroutine, so
// open handles are bounded by its worker count.
func (k *Kernel) ReadDirBatches(r Ref, n int, fn func([]Dirent) error) (bool, error) {
	if n < 1 {
		n = 1
	}
	f, err := os.Open(r.Path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// The buffer grows to what the listing actually returns rather than being
	// sized to n up front: most directories are far smaller than n, and
	// allocating n Dirents for each of them cost measurable CPU and RSS on a
	// tree of many small directories.
	delivered := false
	var batch []Dirent
	for {
		entries, err := f.ReadDir(n)
		if len(entries) > 0 {
			batch = batch[:0]
			for _, e := range entries {
				batch = append(batch, kernelDirent(r.Path, e))
			}
			delivered = true
			if ferr := fn(batch); ferr != nil {
				return delivered, ferr
			}
		}
		if err == io.EOF {
			return delivered, nil
		}
		if err != nil {
			return delivered, err
		}
	}
}

// ReadDirSetACL on the kernel transport is ReadDir followed by SetACL. There is
// no COMPOUND to fold into, so it saves no round trips — it exists so the walk
// can use one code path regardless of transport.
func (k *Kernel) ReadDirSetACL(ref Ref, acl []byte) ([]Dirent, bool, error) {
	entries, err := k.ReadDir(ref)
	if err != nil {
		return nil, false, err
	}
	if len(acl) == 0 {
		return entries, false, nil
	}
	if err := k.SetACL(ref, acl); err != nil {
		return entries, false, nil
	}
	return entries, true, nil
}

// Stat returns one object's attributes. It does not follow symlinks, so a
// symlink reports its own attributes rather than its target's.
//
// The error is returned rather than swallowed. A caller deciding a filesystem
// boundary needs to distinguish "different FSID" from "could not tell", because
// treating the second as the first silently skips a subtree and exits zero.
func (k *Kernel) Stat(r Ref) (Attr, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(r.Path, &st); err != nil {
		return Attr{}, fmt.Errorf("lstat %s: %w", r.Path, err)
	}
	isDir := st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	isSymlink := st.Mode&syscall.S_IFMT == syscall.S_IFLNK
	return Attr{
		Mode:      uint32(st.Mode) & 07777,
		FSID:      uint64(st.Dev),
		IsDir:     isDir,
		IsSymlink: isSymlink,
		Kind:      kindFromMode(uint32(st.Mode)),
	}, nil
}

func (k *Kernel) SetACL(r Ref, acl []byte) error { return nfs4acl.SetACL(r.Path, acl) }
func (k *Kernel) GetACL(r Ref) ([]byte, error)   { return nfs4acl.GetACL(r.Path) }

func (k *Kernel) GetACLBatch(refs []Ref) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, r := range refs {
		acl, err := k.GetACL(r)
		if err != nil {
			return nil, err
		}
		out[i] = acl
	}
	return out, nil
}

// Chmod follows symlinks. Relocated from apply.applyPosix, which used
// syscall.Chmod; Linux has no lchmod, so this is the only available behavior.
func (k *Kernel) Chmod(r Ref, mode uint32) error { return syscall.Chmod(r.Path, mode) }

// Chown does not follow symlinks. Relocated from apply.applyOwnership, which
// used syscall.Lchown. The asymmetry with Chmod is inherited, not accidental.
func (k *Kernel) Chown(r Ref, uid, gid int) error { return syscall.Lchown(r.Path, uid, gid) }

// ProbeTarget creates a temporary file under the given directory and returns it
// for the caller to apply the spec to, with a cleanup that removes it.
//
// The removal is the cleanup's job and its error is discarded there, matching
// the deferred os.Remove this replaced. Returning an unlink failure as the
// probe's verdict would report "cannot write here" on a delete-restricted export
// where writing in fact succeeded.
func (k *Kernel) ProbeTarget(r Ref) (Ref, bool, func() error, error) {
	f, err := os.CreateTemp(r.Path, ".permissionreset-probe-")
	if err != nil {
		return Ref{}, false, nil, fmt.Errorf("create probe file in %s: %w", r.Path, err)
	}
	name := f.Name()
	// The handle is not needed: the spec is applied by path. Closing it here
	// keeps the descriptor from outliving this call.
	f.Close()
	// isDir false: this is a regular file, so the caller applies the spec's file
	// rules to it. The userspace transport returns a directory and says so.
	return Ref{Path: name}, false, func() error {
		os.Remove(name)
		return nil
	}, nil
}

func (k *Kernel) Close() error { return nil }

// kindFromMode derives a Kind from the file type bits of an st_mode value.
func kindFromMode(mode uint32) Kind {
	switch mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		return KindRegular
	case syscall.S_IFDIR:
		return KindDirectory
	case syscall.S_IFLNK:
		return KindSymlink
	default:
		return KindOther
	}
}

// compile-time check that Kernel satisfies the interface.
var (
	_ Transport  = (*Kernel)(nil)
	_ DirBatcher = (*Kernel)(nil)
)
