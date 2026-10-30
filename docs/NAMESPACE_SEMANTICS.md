# Namespace semantics

What permissionreset does when the tree it is walking is not a plain forest of
directories and regular files: nested mounts, special files, hard links,
symlinks, and a namespace that changes underneath the walk. Every statement here
describes the behavior of the current implementation and names the code that
produces it, so a reader can check it rather than trust it.

## Scope: include/exclude

There is no include list. The unit of inclusion is the target: permissionreset walks
everything under `TARGET` unless an exclude pattern removes it.

Exclusions come from two places and are unioned, spec first, then command line
(`spec.MergeExcludes`, `internal/spec/exclude.go`):

```yaml
protocol: posix
exclude:
  - .snapshot
  - "*.tmp"
```

```bash
permissionreset --spec permspec.yaml --exclude .snapshot --exclude 'logs/*.gz' /mnt/fb/data
```

Matching is `filepath.Match` glob syntax, the same syntax as a rule's
`match.pattern`, and there are exactly two forms:

- **No slash in the pattern** — matched against the object's **base name**, at
  any depth. `.snapshot` excludes every `.snapshot` in the tree; `*.tmp`
  excludes every temp file.
- **A slash in the pattern** — matched against the path **relative to
  `TARGET`**. `logs/*.gz` matches `TARGET/logs/old.gz`. `filepath.Match`
  wildcards never cross a separator and there is no `**`, so a slash pattern is
  anchored at the target and matches at one fixed depth. Anything deeper needs
  its own pattern, or a base-name pattern instead.

A matched **directory is pruned**: it is not fixed, not descended, and nothing
beneath it is enumerated, so one pattern removes a whole subtree at no traversal
cost (`walk.Prepass`, `internal/walk/walk.go`). A matched **file** is dropped
before it is emitted. The target itself is never excluded, even by a pattern that
matches its name — excluding the target would make the whole run a no-op reported
as success.

Patterns are compiled and validated before the transport is constructed, so a
malformed glob is refused before anything is read, whether it came from the spec
(`exclude[0]: invalid glob pattern`) or from the flag.

Excluded objects are counted and reported: an `Excluded:` line in the stdout
counts block, `objects.excluded` in the JSON summary, one `EXCLUDE: <path>` line
per object in the `--evidence-dir` records, and the effective pattern list in the plan block,
the `Excluding:` line, and `options.exclude`. An excluded **directory counts
once, for itself** — its subtree is never enumerated, so there is nothing else to
count. That is why `excluded` is a count of exclusion decisions, not an estimate
of objects skipped.

Two interactions are worth stating explicitly:

- **`--pfind` prunes nothing.** pfind is an external process that has already
  walked the tree by the time its output is read, so excluded paths are filtered
  out of its stream and the apply work is saved, but the excluded subtree is
  still enumerated. The run prints a note saying so. The built-in walk is the
  only enumerator that gets the pruning benefit.
- **The exclude list is part of the checkpoint's run binding**
  (`checkpoint.RunHash`). A directory recorded complete under one exclude set was
  walked with part of its subtree pruned; resuming with a different set would
  skip that directory outright and report the newly in-scope objects as done. So
  changing `--exclude` or the spec's `exclude:` between runs invalidates the
  checkpoint and `--resume` is refused, exactly as changing the spec is.

## Nested mounts

**Default (no `--one-filesystem`): mount boundaries are invisible and are
crossed.** Nothing in the walk consults the filesystem identity unless asked, so
a mount point under `TARGET` is an ordinary directory and its contents are
enumerated and repaired like any other.

`--one-filesystem` stops the walk at a boundary. The implementation stats the
target once, requires a nonzero filesystem ID (a target reporting 0 is a hard
error — the flag cannot be enforced and silently ignoring it would repair the
nested filesystem anyway), and compares each subdirectory against it
(`walk.sameFilesystem`, `run.Run`). Which number is compared depends on the
transport, and the two are **not** interchangeable:

| Transport | Identity | Source |
| --- | --- | --- |
| `kernel` | `st_dev` | one `lstat` per subdirectory, because `ReadDir` deliberately does not stat |
| `userspace` | `FATTR4_FSID` | already carried in the `READDIR` attribute bitmask, so the check is a field compare and free |

A skipped nested mount is **not** counted as an exclusion; it is simply not
enumerated. The filesystem that answered is recorded in the run detail block and
in `transport.filesystem_id` / `filesystem_id_source`, so two runs against the
same path across a remount can be told apart.

If the stat needed for the boundary check fails, the subdirectory is skipped and
the walk error counter is incremented, so the run exits nonzero rather than
reporting success over a subtree it never read.

## Special files: FIFOs, sockets, device nodes

**They are treated as ordinary non-directory objects and the spec is applied to
them.** There is no special-file test anywhere in the walk or the apply path: the
enumerator classifies an entry as symlink, directory, or "everything else"
(`transport.Kernel.ReadDir`, `walk.Prepass`), and "everything else" goes to
`apply.ProcessPath` as a file. A FIFO, a unix socket, or a device node therefore
matches `match.type: file` rules and receives `chmod` (posix) or the NFSv4 ACL
`setxattr` (nfsv4) like a regular file.

This is verified behavior, not inference. A `posix` run over a directory
containing a FIFO and a unix socket produces:

```
OK: chmod 0644 .../pipe  (was 0600)
OK: chmod 0644 .../sock  (was 0755)
```

Consequences worth knowing:

- `chmod` on a FIFO or socket succeeds on Linux and changes who may open it. If a
  spec's file rule is more permissive than the special file's original mode, the
  run widens access to a running service's socket. Exclude them by name if that
  matters (`--exclude '*.sock'`), or match them with a narrower rule.
- Device nodes are repaired if they are under `TARGET`. On a FlashBlade export
  this is a non-issue — device nodes are not a normal inhabitant of a data share
  — but it is the reason `TARGET` may not be `/`.
- Nothing is ever opened. permissionreset only stats and sets permissions, so a FIFO
  with no reader cannot block the run.

## Hard links

A hard link is two names for one inode, and permissionreset works in names: both names
are enumerated by `readdir` and both are applied to. The **inode is therefore
stamped twice**, and the operation is idempotent — the second apply writes the
same mode or the same ACL that the first one wrote.

In practice the second name is usually not written at all, because `applyPosix`
stats the object when the enumerator did not supply a mode and skips when the
current value already equals the target. So a two-name file typically reports one
`Applied` and one `Skipped`:

```
OK: chmod 0644 .../f1  (was 0600)     # f1 and f2 are one inode
                                       # f2 -> Skipped (already 0644)
```

`--compare` makes that skip explicit and extends it to the `nfsv4` path, where
the ACL is read and structurally compared before writing. Without `--compare`,
the `nfsv4` backend writes unconditionally, so an N-name inode receives N
`setxattr` calls with identical content — correct, but N times the round trips.

The counts follow the names, not the inodes: a tree of one million files reachable
under two million names reports two million enumerated objects. There is no
inode-level deduplication, and adding one would require a `st_ino` set the size of
the tree.

## Symlinks

Detected at enumeration and **never followed**. `readdir`'s `d_type` tags them
before any type dispatch (the symlink test deliberately precedes the `IsDir`
test, because a symlink to a directory reports `IsDir() == false` and would
otherwise fall through untagged), and the apply worker counts them under
`Symlinks:` and logs `SKIP: symlink <path>` without touching them. `TARGET`
itself is resolved through `EvalSymlinks` before the walk begins, on the kernel
transport.

The residual race — a regular file replaced by a symlink between the enumerator's
`lstat` and the apply worker's `chmod` — is bounded by the trusted-tree model
below, and by the fact that on NFS the apply is addressed by a server-side
filehandle from `READDIR`/`LOOKUP` rather than by re-resolving the local path
(package doc, `internal/walk/walk.go`; RISKS.md item 4).

## Renames and concurrent namespace changes

**The operating model is a trusted tree: permissionreset assumes it has exclusive
write access to `TARGET` for the duration of a run** (package doc,
`internal/walk/walk.go`). That is an assumption about the deployment, not a
guarantee the tool enforces, so this section says what actually happens when it
is violated.

- **An object renamed or unlinked between enumeration and apply** fails at the
  apply with `ENOENT`. The failure is counted in `objects.failed` /
  `errors.apply`, written to `--log` as an `ERR:` line naming the path, and the
  run exits nonzero. Nothing is retried and nothing is silently dropped: the
  exit code is the signal that the run does not describe the tree.
- **An object created after its parent's `readdir`** is not seen at all. There is
  no second sweep and no re-read, by design — the fused walk reads each directory
  exactly once. The new object simply keeps whatever permissions it was created
  with, and the run reports success. This is the failure mode the trusted-tree
  assumption exists to exclude, and the reason a FlashBlade snapshot before a run
  is the recommended practice: a snapshot is instantaneous and free, and it turns
  "the tree changed under me" into a question you can answer afterwards.
- **A directory renamed between its own `readdir` and its subtree's walk** leaves
  the walk holding paths that no longer resolve; on the kernel transport those
  become `ENOENT` at the next `readdir` or apply and are counted as errors. On the
  userspace transport the operations are addressed by filehandle, which survives
  a rename, so the objects are repaired at their new location — the same inodes,
  a different path than the log records.
- **`readdir` racing a directory being modified** is a POSIX/NFS-level race, not
  one permissionreset mediates: a concurrent create or unlink during a directory
  listing may or may not appear in it. There is no ordering guarantee to recover
  here, which is why the model is exclusivity rather than retry.
- **An unreadable directory** (permissions, not a race) is fixed and re-read
  once; a directory that still cannot be read after the fix is counted in
  `prepass.errors`, and the run warns explicitly that subtrees under unfixed
  directories were not walked.

The two conditions that make a run's counts untrustworthy for reasons of the
tool's own — interruption by a signal, and duplicate checkpoint completion
signals — are reported separately (`interrupted`, `errors.duplicate_completions`)
and are documented with the checkpoint, not here.

## Partitioned runs

A partition manifest (`--partitions`, `docs/partitions.md`) divides `TARGET`
into disjoint subtrees **by path**. Everything above stays as described here,
with these partition-specific rules:

- **Hard links across partitions** are stamped once per name, as within one run.
  Each partition stamps its own names.
- **Aliased partition roots** (a bind mount, or a second mount of one export)
  are refused on the kernel transport when two roots share a device and inode,
  and so is a partition root that is a symlink. An alias deeper inside a
  partition is not detected.
- **Nested mounts**: under `--one-filesystem`, a partition root on another
  filesystem is refused. The residual partition records every partition root
  it hands off, and a root it never reached makes the run incomplete.
- **A partition root replaced between attempts** (renamed away and recreated)
  is caught on the kernel transport by its device and inode, and the resume is
  refused.

## Summary table

| Object / event | Behavior | Counted as |
| --- | --- | --- |
| Regular file, directory | Spec applied | `applied` / `skipped` |
| Excluded file | Not emitted | `excluded` |
| Excluded directory | Pruned, subtree never read | `excluded` (once) |
| Nested mount, no `--one-filesystem` | Crossed and repaired | ordinary objects |
| Nested mount, `--one-filesystem` | Not descended | nothing |
| Partition root, in the residual walk | Handed off: pruned, owned by its partition | `handed_off` (not `excluded`) |
| FIFO, socket, device node | Spec applied as a file | `applied` / `skipped` |
| Hard link, second name | Applied again (idempotent), usually skipped | `enumerated` per name |
| Symlink | Detected, never followed | `symlinks` |
| Object removed or renamed mid-run | `ENOENT` at apply, run exits nonzero | `failed` |
| Object created mid-run | Never seen | nothing |
| Unreadable directory after fix | Subtree not walked, explicit warning | `prepass.errors` |
