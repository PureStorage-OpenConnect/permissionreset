// Package transport abstracts the filesystem operations permissionreset performs, so
// the same walk and apply logic can run either through the kernel NFS client on a
// mounted export or through a userspace NFSv4.1 client speaking to the array
// directly.
//
// The kernel implementation is the default and is a relocation of code that
// previously lived in internal/apply and internal/nfs4acl, not a reimplementation.
package transport

// Ref identifies an object to the transport.
//
// Path is always set. It is not redundant with FH: it drives spec matching,
// checkpoint keys, and log output, and it is what makes recovery from a stale
// filehandle possible, since the object can be looked up again from the root.
//
// FH is set only by the userspace transport and is nil on the kernel transport.
type Ref struct {
	Path string
	FH   []byte
}

// Kind is the type of a filesystem object.
//
// Both transports populate Kind on every Stat call. The kernel transport derives
// it from the st_mode bits returned by Lstat; the userspace transport derives it
// from FATTR4_TYPE in the GETATTR reply. IsDir and IsSymlink remain for
// backward compatibility with existing call sites — they carry the same
// information as KindDirectory and KindSymlink respectively.
type Kind uint8

const (
	KindOther     Kind = iota // unknown or unsupported object type
	KindRegular               // regular file
	KindDirectory             // directory
	KindSymlink               // symbolic link
)

// Attr is the subset of an object's metadata permissionreset uses.
//
// Mode carries permission bits only (the low 12).
//
// FSID identifies the filesystem the object lives on, for --one-filesystem. The
// kernel transport reports st_dev; the userspace transport reports FATTR4_FSID,
// which is what the kernel derives st_dev from on an NFS mount.
type Attr struct {
	Mode      uint32
	FSID      uint64
	IsDir     bool
	IsSymlink bool
	Kind      Kind
}

// Dirent is one child discovered by ReadDir.
//
// IsDir and IsSymlink are always populated: every transport learns an entry's
// type as part of reading the directory.
//
// Mode and FSID are populated only when AttrsKnown is true, and a consumer MUST
// check that flag before reading them. They are not merely optional data — they
// are the difference between a free answer and a per-entry round trip:
//
//   - the kernel transport leaves AttrsKnown false. On Linux, getdents supplies
//     d_type and nothing else, so mode and FSID would each cost an lstat per
//     entry. CLAUDE.md's design rules forbid that: "Stat in apply workers, never
//     in enumerator — setxattr invalidates NFS attr cache, serial lstat becomes a
//     round-trip bottleneck." A caller that needs them calls Stat explicitly, and
//     pays for it knowingly.
//
//   - the userspace transport sets AttrsKnown true. FATTR4_MODE and FATTR4_FSID
//     ride along in the READDIR bitmask at no extra cost, so withholding them
//     would throw away information already on the wire.
//
// AttrsKnown false therefore means "not asked", never "lookup failed".
type Dirent struct {
	Name       string
	Ref        Ref
	IsDir      bool
	IsSymlink  bool
	AttrsKnown bool
	Mode       uint32
	FSID       uint64
}

// DirBatcher is implemented by a transport that can list a directory in
// bounded batches instead of materializing every child at once (PS-11). The
// walk prefers it when present, so one very wide directory costs at most n
// Dirents of memory per directory in flight rather than its whole listing.
//
// ReadDirBatches calls fn with successive batches of at most n children, in the
// order the filesystem returns them: NOT sorted by name, since sorting needs
// the whole listing, which is the memory this exists to avoid. Nothing that
// consumes the walk depends on per-directory order — the checkpoint counts
// children, it does not sequence them — and output from parallel workers is
// interleaved regardless.
//
// The slice passed to fn is reused for the next batch, so fn must copy what it
// keeps. A non-nil error from fn stops the listing and is returned. delivered
// reports whether fn was called at least once, which is what tells a caller
// whether a failure happened before any child was seen (the directory is
// unreadable: fix it and retry) or partway through (children were already
// handed on, and a retry would hand them on twice).
type DirBatcher interface {
	ReadDirBatches(ref Ref, n int, fn func([]Dirent) error) (delivered bool, err error)
}

// Transport is the complete set of filesystem operations permissionreset performs.
//
// Implementations must be safe for concurrent use by many goroutines: the walk
// runs directories in parallel and the apply workers run alongside it.
//
// ReadDir must return entries sorted by name. The kernel transport gets this
// free from os.ReadDir; the userspace transport must sort explicitly, because
// server order is arbitrary and a differing order between transports would show
// up as nondeterministic log and checkpoint output.
//
// Traversal never follows symlinks: ReadDir tags them and the walk skips them,
// and no implementation may resolve one to descend into it. That rule governs
// traversal only — it is not a blanket statement about every method. Chmod and
// Chown differ from each other on this point, deliberately, and each documents
// its own behavior below.
type Transport interface {
	// Root returns a Ref for the tree being operated on.
	Root() (Ref, error)

	// ReadDir lists the children of a directory, sorted by name.
	ReadDir(Ref) ([]Dirent, error)

	// ReadDirSetACL lists children and folds a SETATTR(ACL) into the READDIR
	// COMPOUND, saving one round-trip per directory. On the userspace transport
	// the SETATTR rides along in the same COMPOUND as READDIR; on the kernel
	// transport it is a separate syscall after the readdir (no savings, same
	// semantics). acl is raw NFSv4 ACL bytes as produced by nfs4acl.Encode.
	//
	// Returns the directory entries, whether the ACL was applied, and any
	// readdir error. A false aclApplied with a nil error means the readdir
	// succeeded but the ACL set failed; the caller should fall back to the
	// normal apply path.
	ReadDirSetACL(ref Ref, acl []byte) (dirents []Dirent, aclApplied bool, err error)

	// Stat returns one object's attributes, at the cost of a round trip on
	// either transport. Call it only where the attributes are actually needed:
	// see the Dirent.AttrsKnown comment for why they are not free.
	Stat(Ref) (Attr, error)

	// SetACL writes raw NFSv4 ACL bytes as produced by nfs4acl.Encode.
	//
	// acl must be non-empty. The kernel implementation passes it to a setxattr
	// that takes the address of the first byte, so an empty slice panics rather
	// than failing. Callers already return early when a spec names no ACEs.
	SetACL(Ref, []byte) error

	// GetACL reads raw NFSv4 ACL bytes in the same encoding SetACL accepts.
	GetACL(Ref) ([]byte, error)

	// GetACLBatch reads ACLs for multiple refs, batching RPCs where the
	// transport supports it. Results are positional: acls[i] corresponds
	// to refs[i]. An error on any single ref fails the entire batch.
	GetACLBatch(refs []Ref) ([][]byte, error)

	// Chmod sets POSIX permission bits.
	//
	// This FOLLOWS symlinks, matching the syscall.Chmod the kernel path has
	// always used. There is no lchmod on Linux, so the alternative does not
	// exist; the userspace transport must resolve the final component to match.
	Chmod(Ref, uint32) error

	// Chown sets owner and group. A value of -1 leaves that field unchanged.
	//
	// This does NOT follow symlinks, matching the syscall.Lchown the kernel path
	// has always used. The asymmetry with Chmod is inherited behavior, not an
	// oversight, and both transports must reproduce it.
	Chown(ref Ref, uid, gid int) error

	// ProbeTarget returns a disposable object the caller may safely apply the
	// spec to as a preflight check, whether that object is a directory, and a
	// cleanup func to call when finished. Neither transport may return an
	// existing, live object here -- see PS-01 (#70): restoring an NFS ACL
	// cannot reconstruct SMB inheritance metadata lost in translation, so a
	// probe target that cannot be disposed of is not a safe probe target.
	//
	// isDir is not a convenience. Spec rules differ for files and directories, so
	// a caller that assumes one applies the wrong rule set to the other: the
	// kernel probe is a file and the userspace probe is a directory. Getting it
	// wrong writes a file ACL onto a real directory.
	//
	// It exists because preflight has to do more than prove the tree is
	// writable: applying the real spec to a throwaway target is what catches
	// idmapd misconfiguration, an unresolvable principal, and an export with no
	// NFSv4 ACL support. Those are the failures worth finding before touching a
	// million objects, and none of them shows up in a create-and-unlink.
	//
	// The two transports differ in what they can offer, which is why this returns
	// a target rather than performing the check itself:
	//
	//   - kernel: a temporary file it created under the given directory, isDir
	//     false. The cleanup removes it.
	//   - userspace: a disposable directory it created under the resolved target
	//     directory (or the export root, when the given path does not resolve),
	//     isDir true, using the same Mkdir/Remove this client already uses to
	//     seed test trees. The cleanup removes it. If disposable probing is
	//     unsupported or denied, ProbeTarget fails before any live-object ACL
	//     mutation rather than falling back to a real object.
	//
	// The cleanup func's error must not be discarded: a probe object that fails
	// to clean itself up is a real failure the caller should fold into its own
	// returned error, not a silent leftover.
	//
	// Passing the spec in here instead would have been simpler, and was rejected:
	// it would make this package depend on internal/spec, which is the layering
	// the seam exists to avoid.
	ProbeTarget(Ref) (target Ref, isDir bool, cleanup func() error, err error)

	// Close releases any resources. Safe to call more than once.
	Close() error
}
