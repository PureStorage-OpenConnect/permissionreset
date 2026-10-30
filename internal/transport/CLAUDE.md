# internal/transport

Filesystem operation abstraction layer. Lets walk and apply work identically on kernel mounts or userspace NFSv4.1.

## Files

- `transport.go` — Transport interface, Ref, Attr, Dirent types
- `kernel.go` — Kernel implementation (syscalls on mounted paths)

The userspace implementation lives in `internal/nfs41/client.go` (nfs41.Client implements Transport).

## Key types

- `Ref` — Path (always set) + FH (filehandle, userspace only, nil on kernel). Path drives spec matching, logging, stale-FH recovery.
- `Attr` — Mode (low 12 bits), FSID, IsDir, IsSymlink
- `Dirent` — child from ReadDir. AttrsKnown flag gates Mode/FSID access.
- `Transport` — interface: Root, ReadDir, Stat, SetACL, GetACL, GetACLBatch, Chmod, Chown, ProbeTarget, Close

## Transport interface contract

- Concurrency-safe (walk + apply workers run in parallel)
- ReadDir returns entries sorted by name
- Optional `DirBatcher.ReadDirBatches(ref, n, fn)`: batches of <= n, filesystem order (unsorted), slice reused between calls, `delivered` says whether fn ran before an error. Kernel implements it (`File.ReadDir(n)`, handle open until done); userspace does not.
- Symlinks: never followed during traversal. Chmod follows (no lchmod on Linux). Chown does NOT follow (lchown).
- GetACLBatch: positional results, error on any ref fails entire batch

## Kernel implementation

- Stateless (root path only), trivially concurrent
- ReadDir: `os.ReadDir` (pre-sorted), NO per-entry stat (AttrsKnown=false)
- SetACL/GetACL: delegates to `nfs4acl.SetACL/GetACL` (setxattr/getxattr)
- GetACLBatch: simple loop over GetACL (no batching benefit on kernel)
- ProbeTarget: creates a temp file under target (`os.CreateTemp`), cleanup removes it
- Chmod: `syscall.Chmod` (follows symlinks)
- Chown: `syscall.Lchown` (does NOT follow symlinks)

## Dirent.AttrsKnown (critical)

- Kernel: always false. Mode/FSID would cost one lstat per entry; design rules forbid stat in enumerator.
- Userspace: always true. FATTR4_MODE and FATTR4_FSID ride along in READDIR bitmask for free.
- Consumer MUST check AttrsKnown before reading Mode/FSID. Zero mode with AttrsKnown=false means "not asked", not "mode is 0000".

## ProbeTarget asymmetry

- Kernel: returns a temp file (isDir=false) it created under the target, cleanup removes it
- Userspace: returns a disposable directory (isDir=true) it created (Mkdir) under the resolved
  target directory (or export root, if the given path does not resolve), cleanup removes it
  (Remove). Neither transport may fall back to a live, existing object (PS-01, #70): if disposable
  probing is unsupported or denied, ProbeTarget fails before any live-object ACL mutation.
- isDir matters because spec rules differ for files vs directories
- Cleanup's error is not discarded by callers — it is folded into the caller's own returned error

## Gotchas

- `var _ Transport = (*Kernel)(nil)` compile-time interface check at bottom of kernel.go
- No dependency on internal/spec — layering boundary. ProbeTarget returns a target for the caller to apply to.
- Ref.FH nil is normal on kernel — everything resolves by path. On userspace, nil FH triggers LOOKUP.
