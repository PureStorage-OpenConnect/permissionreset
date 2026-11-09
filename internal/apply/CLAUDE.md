# internal/apply

Permission application and validation for all protocols (posix, nfsv4, smb).

## Key types

- `Result` — applied/skipped/error outcome from `ProcessPath`
- `ValidateResult` — matches/mismatch/error from `ValidatePath`
- `Options` — DryRun, Compare, SetOwner flags

## Key functions

- `ProcessPath(t, ref, isDir, spec, opts, cachedMode)` — dispatches to protocol-specific apply. ref.FH carries the filehandle from READDIR so the transport skips LOOKUP.
- `ValidatePath(t, ref, isDir, spec, cachedMode, cachedACL)` — read-only check. `cachedACL` (non-nil) skips the per-file GetACL call, enabling batch pre-fetch.
- `FixDirPerms(t, ref, spec, opts) FixOutcome` — single directory fix for prepass. Falls back to chmod 755 on posix if the spec apply fails. Returns a `FixOutcome{OK, Msg, Applied, RealApply}` rather than a bare `(bool, string)`: `RealApply` tells `internal/walk`'s `Prepass` (via `run.go`'s `Fix` closure, which translates this into `walk.FixResult`) whether the real spec apply already ran to completion, so the directory is not reprocessed a second time by the ordinary apply path. `RealApply` is false only for the posix chmod-755 fallback (traversability restored, final mode still pending) and for an outright failure (`OK` false).
- `ProbePreflight(t, ref, spec)` — applies real spec to a throwaway target, catching idmapd/principal failures before traversal. `ProbeTarget`'s target is a disposable object on both transports now (PS-01, #70: userspace creates it with `Mkdir`/removes it with `Remove`, never falling back to a live object); for an nfsv4 spec this still reads the target's current ACL (`orig`) before writing anything and restores it with a deferred `SetACL` once done, success or failure alike, before the disposable target's own cleanup removes it. A failed read of `orig` leaves the target untouched, and a failed restore replaces (or is appended to) the returned error rather than being swallowed. A failed cleanup (the probe object could not be removed) is likewise folded into the returned error, not discarded. Posix specs skip all of this (chmod, no ACL to read back). When the matched rule (or any rule, as a fallback) carries `sacl:`, it also proves the audit-ACE write privilege (a spec whose only `sacl:` keys are `sacl: []` is probed with `placeholderAuditACE`, because such a rule still reads every object): `ErrAuditPrivilege` on EACCES/EPERM/NFS4ERR_ACCESS, `ErrAuditNotRetained` when the read-back has no `U` entries. A DACL-keeping rule (`sacl:` with no `acl:`) is `applyKeepDACL` now (plan v3 commit 4): the ordinary `ProcessPath` call below already performs the real write, so this needs a second, separate probe write (`orig`'s own ALLOW/DENY entries plus a file-shaped copy of a borrowed `sacl:`, via `nfs4acl.JoinACL`) only for the one gap `applyKeepDACL` cannot cover itself -- the spec's only `sacl:` living on a rule that does not match the probe target (a directory-only `sacl:` probed against a file, or vice versa).
- `ProbeUnmappedPrincipals(t, ref, spec)` — writes the probe target's own DACL plus one read-attributes ALLOW per `spec.NamedPrincipals()` entry (SACL kept at the tail), reads it back, restores the original, and returns the spec principals the array rendered as nobody. Entries are matched by position after the target's own; a read-back with a different A/D count and extra nobody entries is an error, not a guess. `run` turns the result into a WARNING (FA stores the SID of a principal with no RFC 2307 id but shows `65534` over NFS, #50).
- `CheckKeepDACLTarget(t, root)` — reads root's ACL and returns `ErrUnmappedPrincipal` if its DACL names an unmapped principal (`nfs4acl.IsUnmappedWho`: 65534, nobody, …). `run`'s preflight calls it before `ProbePreflight` for DACL-keeping specs. `applyKeepDACL` and `ProbePreflight` run the same check (`checkMappedDACL`) before any write, because FA turns such a who into its local nobody SID on write (RISKS.md #11).
- `ProveAuditBypass(t, ref) (auditproof.Proof, error)` (PS-02, #71) — proves the audit bypass entirely on a disposable probe target (never root or any other live object): writes `placeholderAuditACE`, reads it back, confirms retention. On success the `Proof` names the probe; `run` prints it as a NOTE before the first live read (#31). `run`'s preflight calls this FIRST, before `CheckKeepDACLTarget` or a DACL reset that keeps auditing (`applyPreserveSACL`) reads any live ACL -- and an unprivileged read has been observed on at least one array to empty inherited auditing, so reading root to decide whether it is safe to touch its auditing can itself destroy that state. A failure here (including `ErrAuditPrivilege`/`ErrAuditNotRetained`) must fail the run closed without ever reading root. Reuses `buildSaclProbe`/`placeholderAuditACE`/`isAuditAccessDenied`/`hasAuditACE` from `ProbePreflight`'s own audit-ACE probing -- same mechanics, applied before any live read rather than interleaved with the real spec write.
- `applyPreserveSACL` (PS-04, #73) — an `acl:` rule with no `sacl:` key (`RulePerms.PreserveSACL()`):
  read the object (or use `CachedACL`), `nfs4acl.SplitRaw` it, write `EncodedACL()` ++ the object's
  existing audit/alarm region byte for byte (`nfs4acl.JoinRaw`). Read or parse failure → error,
  no write. An object with any audit ACEs → `ErrAuditedObject`, no write, unless
  `Options.AllowAuditedDACLReset` (`--allow-audited-dacl-reset`; `ProbePreflight` sets it for its
  disposable target). Audit ACEs naming nobody or id >= 1e9 → `ErrUnpreservableAudit`, no write. Dry run neither
  reads nor writes. `Result.AuditKept` counts the entries carried. `validateNFSv4` checks only the
  DACL region for such a rule.
- `CheckTraversePreserved(spec)` — rejects specs that would lock the walker out of child directories (no execute). A no-op for a DACL-keeping rule: `perms.ACL` is empty for one by definition, so there is no spec-defined DACL to inspect, and correctly so -- `applyKeepDACL` never changes an object's existing ALLOW/DENY entries, so it can never be the thing that locks the walk out.

### DACL-keeping apply (`applyKeepDACL`, plan v3 commit 4)

For a rule with `sacl:` and no `acl:` (`RulePerms.KeepDACL()`), `applyNFSv4` branches to `applyKeepDACL`:
`GetACL` the object, `nfs4acl.SplitACL` it into its DACL region (copied byte-for-byte, never
decoded and re-encoded) and whatever audit/alarm entries it already has (discarded, wherever they
were), then `nfs4acl.JoinACL` the kept DACL with the rule's own `SaclACEs()` at the tail. A read
error fails the object with no write attempted. An object whose DACL region has zero ALLOW/DENY
entries fails with `ErrNoDACLToKeep`, also before any write -- writing a SACL-only ACL would strip
all access. `--compare` runs `nfs4acl.ACLEqualIdent` on the whole reassembled ACL against what was
read: byte-identical by construction for the kept DACL, identity-aware for the SACL tail, so a
second run against an already-converged object is a no-op. `--dry-run` neither reads nor writes
(review item 7): it returns WOULD before the `GetACL`, because a dry run has no preflight and before
Purity//FA 6.12.1 a read without the audit bypass empties inheriting SACLs. The cost is that a dry run
cannot report converged or `ErrNoDACLToKeep` objects; `--validate` (which runs the preflight) can.

`validateNFSv4` mirrors this for `--validate`: a `KeepDACL()` rule is checked by splitting the
object's current ACL and comparing only the SACL tail (`nfs4acl.ACEsEqualIdent`) against the rule's
`SaclACEs()`; the DACL is never compared; because the spec defines none for this rule.

**Directories need no special handling here or in `internal/run`/`internal/walk`.** A KeepDACL
rule's `perms.ACL` is empty by definition, so `run.go`'s `popts.DirACL` (which only returns
non-nil when `len(perms.ACL) > 0`) already returns `nil` for one -- the fused `ReadDirSetACL`
path never fires, and the directory's own `Entry` flows into `entryCh` like any other object and
reaches `ProcessPath` -> `applyNFSv4` -> `applyKeepDACL` exactly once, same as a file. `isDir` only
changes which rule `EffectivePerms` matches; the apply logic itself does not look at it.

**Userspace batching:** `ProcessPath` takes an `Options.CachedACL []byte` field. When non-nil,
`applyKeepDACL` uses it instead of calling `t.GetACL` -- the caller (`run.go`'s `processBatch`) is
the one that calls `tr.GetACLBatch` for every pending entry whose effective rule is `KeepDACL()`,
the same batching `runValidate` already does for `--validate` (4 per COMPOUND on the userspace
transport). `CachedACL` being a plain `Options` field rather than a new `ProcessPath`/`applyNFSv4`
parameter keeps every other call site (every other apply, every existing test) unchanged -- the
zero value (nil) means "no cache," and `applyKeepDACL` falls back to its own per-object `GetACL`
exactly as it always has. A batch-read error never reaches a write: `run.go` leaves `CachedACL`
unset for every entry in a failed batch and lets `applyKeepDACL`'s own per-object `GetACL` run (and
fail the same way, for the same reason, if the transport itself is the problem) -- there is no path
from a missing or failed read to a SetACL call.
- `PreResolveIdentities(spec)` — validates owner/group names resolve before traversal.

## Invariants

- ACL bytes are encoded once at spec load time (`RulePerms.encodedACL`), never per-object. `EncodedACL()` falls back to on-demand encode for struct-literal specs (tests).
- `--compare` uses `nfs4acl.ACLEqual` (structural), not `bytes.Equal` — arrays normalize stored ACLs.
- A matching rule REPLACES the default entirely. Fields the rule omits are zero, not inherited.
- ref.Path must always be set (spec matching, logging, stale-FH recovery). ref.FH may be nil.
- Ownership validation uses `syscall.Lstat` (kernel mount authority), not the transport.

## Test seam

- `recordingTransport` — records SetACL/Chmod/Chown/Stat calls without touching filesystem. Implements full Transport interface including GetACLBatch.
- `kernelTransport(t)` — real syscall transport over `os.TempDir()`.
- `loadSpec(t, yamlString)` — helper to build specs from inline YAML.

## Gotchas

- `uidGidCache` is package-level `sync.Map` — survives across calls, caches nsswitch lookups.
- SMB backend exists but is broken (RISKS.md #8: passes local paths, smbcacls expects share-relative). Protocol "smb" is rejected at spec validation.
- `cachedMode == 0` means "unknown" (stat again), not "mode is 0000".
- `validateOwnership` bypasses the transport and calls `syscall.Lstat` directly — correct under userspace because the kernel mount is the uid/gid authority.
- `ProbePreflight` builds its fallback probe ACL with `nfs4acl.SplitACL`/`JoinACL` now, the same
  raw-split functions `applyKeepDACL` uses for the real write — there is no separate
  `keepAllowDeny` helper anymore; one split/join implementation means the probe's prediction of
  what `applyKeepDACL` will do (`attemptsWrite` in `ProbePreflight`) and what it actually does agree
  by construction.
