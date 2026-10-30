package treegen

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

// procMounts is the only mount table this tool knows how to read. It is a
// Linux path on purpose: tuning.ResolveMount parses the /proc/mounts format,
// so a host without this file has no mount table we can consult rather than
// one in a different place.
const procMounts = "/proc/mounts"

// errNoMountTable reports that this host has no mount table to consult. It is
// distinct from tuning.ErrNoMountForTarget -- "there is no table" and "the
// table has no answer" arrive by different routes -- but both mean the same
// thing to a caller, which is that TARGET was never a local path.
var errNoMountTable = errors.New("no mount table on this host")

// openMountTable returns the host's NFS mount table, or a nil reader when the
// host has none.
//
// macOS is the case that needs the nil: it has no /proc, and Apple's mount_nfs
// tops out at NFSv4.0, so there was never going to be a 4.1 mount to find. A
// missing file is therefore an answer, not a failure. Any other open error is
// a real one -- /proc exists but is unreadable -- and is reported.
func openMountTable() (io.ReadCloser, error) {
	f, err := os.Open(procMounts)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", procMounts, err)
	}
	return f, nil
}

// resolveExportRelTarget turns TARGET into a path relative to the export root,
// which is what the userspace client addresses objects by.
//
// A local mount path and a path on the server are both absolute and there is
// no way to tell them apart by looking, so the mount table decides. If TARGET
// sits under an NFS mount of --export it is local and is translated:
// /mnt/fb-perms/bigdata on a mount of /fb-perms becomes bigdata: the
// client is already rooted at the export, so the export's own name is not part
// of the path (it would create <export>/<export>/bigdata). If there is no mount table, or TARGET is under no NFS
// mount, it is already a path on the server and is taken as typed.
//
// Both branches run on both platforms. A Linux host that has not mounted the
// export is mount-free in exactly the way a Mac is, and gets exactly the same
// answer -- the userspace transport needs no mount on either one, so making
// the behaviour depend on GOOS would invent a difference the transport does
// not have. What differs between platforms is only which branch is reachable.
//
// The fallback returns a note rather than staying quiet. Taking TARGET as
// server-side is an inference, and the case it is wrong in is a mistyped mount
// path: /mnt/fb-perm is under no mount, so the tree lands at
// <export>/mnt/fb-perm. That is a legal request -- refusing it would break
// every genuine mount-free run -- but the operator has to be able to see that
// no translation happened before a million objects arrive somewhere unexpected.
//
// One case stays fatal, because it is a contradiction and not an absence:
// TARGET under an NFS mount of a DIFFERENT export. There the operator named a
// path this invocation cannot mean, and both readings of it are wrong.
func resolveExportRelTarget(localTarget, export string, mounts io.Reader) (relTarget, note string, err error) {
	asServerSide := serverSideRel(localTarget)

	if mounts == nil {
		return asServerSide, mountFreeNote(localTarget, asServerSide, export,
			"this host has no NFS mount table"), nil
	}
	// A relative TARGET is under no mount by construction -- there is no
	// working directory on the server to resolve it against -- and
	// tuning.ResolveMount rejects it with an error that is not
	// ErrNoMountForTarget. Routing it here keeps the mount-free answer the same
	// on a host that happens to have a mount table and one that does not.
	if !filepath.IsAbs(localTarget) {
		return asServerSide, mountFreeNote(localTarget, asServerSide, export,
			"it is not an absolute path"), nil
	}

	mount, err := tuning.ResolveMount(localTarget, mounts)
	if errors.Is(err, tuning.ErrNoMountForTarget) {
		return asServerSide, mountFreeNote(localTarget, asServerSide, export,
			"it is under no NFS mount"), nil
	}
	if err != nil {
		return "", "", err
	}
	if mount.Export != filepath.Clean(export) {
		return "", "", fmt.Errorf(
			"%s is on a mount of export %q, but --export says %q; "+
				"name a path under a mount of %s, or a path on the server",
			localTarget, mount.Export, filepath.Clean(export), filepath.Clean(export))
	}

	serverPath, err := tuning.ServerPath(localTarget, mount)
	if err != nil {
		return "", "", err
	}
	// ServerPath is export-qualified; the client's root is the export itself.
	// Rel works on path components, so an export that is a name prefix of a
	// sibling, or "/", is not mangled the way a string trim would.
	rel, err := filepath.Rel(mount.Export, serverPath)
	if err != nil {
		return "", "", fmt.Errorf("make %s relative to export %s: %w", serverPath, mount.Export, err)
	}
	return rel, "", nil
}

// serverSideRel is the one normalisation the mount-free path uses, rooted so
// that a leading ".." collapses rather than surviving as a component. It has to
// match what userspaceTargetIsEmpty inspects and what the fan-out creates: all
// three read the same string, and three normalisations produced three
// directories with the note naming a fourth. Server paths are forward-slashed
// whatever the client's OS, so path, not filepath, does the cleaning.
func serverSideRel(localTarget string) string {
	return strings.Trim(path.Clean("/"+filepath.ToSlash(localTarget)), "/")
}

// mountFreeNote states the inference and, more usefully, where the tree will
// actually be created if it is wrong.
func mountFreeNote(localTarget, relTarget, export, because string) string {
	return fmt.Sprintf(
		"note: %s was not translated because %s; taking it as a path on the server. "+
			"The tree will be created at %s",
		localTarget, because, filepath.Join("/"+strings.TrimPrefix(filepath.Clean(export), "/"), relTarget))
}
