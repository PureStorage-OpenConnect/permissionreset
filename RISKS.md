# Risks and Gaps

Known risks and gaps, with their status. Fixed items stay listed so the reasoning behind each guard
is on record.

> Issue and pull request numbers (`#50`, `PR #67`) written before the public launch refer to the
> project's earlier private repository. They do not match issues or pull requests here.

## Important Risks

### ~~1. Incomplete walks reported as successful~~ — FIXED
Walk errors (readdir failures, pfind exit code, scanner errors) are now tracked via `walk.WalkErrors` and reported in the summary with a breakdown (fix / walk / apply). A directory that could not be fixed, or could not be read after being fixed, counts once against `fix` rather than twice. Summary prints `WARNING` when walk or fix errors occur, explaining that subtrees may have been skipped.

### ~~2. Process exits 0 after operational errors~~ — FIXED
Process exits 1 if any errors occurred (directory fix, walk, or apply). Error summary breaks down the count by phase. Automation can now detect partial repairs via exit code.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | the repair failed, or `--validate` found mismatches |
| 2 | flag parsing failed (emitted by the `flag` package) |
| 3 | the repair succeeded, but the checkpoint could not be flushed — **do not `--resume` from it** |

On exit 3 the command also prints the advice to stderr, naming the `--checkpoint` path and saying that the repair succeeded but the file must not be resumed from — an operator should not have to know the exit code to be told the one thing they must not do next. That line appears on no other exit code.

3 is deliberately distinct from 1. A failed repair leaves a good checkpoint and is worth retrying with `--resume`; an unflushed checkpoint means the file on disk does not describe the work that was done, so resuming from it would skip directories that were never completed. `internal/run` returns `run.ErrCheckpointUnflushed` for that case, matchable with `errors.Is`, and only ever when the repair itself succeeded — 3 never masks a failure that should have been 1.

The transport close is the opposite case and stays non-fatal: a failed `DESTROY_SESSION` leaves a session the server expires on its own, so it prints `WARNING` and the run still exits 0.

### ~~3. POSIX dry-run can make changes~~ — FIXED
`FixDirPerms` now checks `opts.DryRun` before the fallback chmod and returns a "WOULD FALLBACK" log message instead of modifying the directory.

### ~~4. Symlinks can modify objects outside target tree~~ — FIXED (TOCTOU caveat below)
Symlinks are now detected by all three walkers (ParallelWalk via `DirEntry.Type()`, Pfind/sequential via `Lstat`, Prepass skips symlink dirs) and skipped before reaching the apply stage. Each skipped symlink is logged (`SKIP: symlink <path>`) and counted in the summary (`Symlinks: N (not followed)`). The `applyPosix` stat fallback was also changed from `Stat` to `Lstat` as defense-in-depth.

**Remaining TOCTOU window**: a regular file can be replaced with a symlink between the walker's Lstat and the apply worker's Chmod/setxattr. `syscall.Chmod` follows symlinks; `setxattr` operates on the path. Descriptor-relative operations (`fchmod` on an O_NOFOLLOW fd) would close this gap but add one `open` syscall per file. The current design operates under a **trusted-tree model**: the target namespace is assumed stable during the run. If concurrent renames or symlink creation are expected, the operator should snapshot the filesystem first (FlashBlade snapshots are instantaneous and free).

### ~~5. Specs receive minimal validation~~ — FIXED
Spec validation now runs at load time before any traversal begins. Checks: protocol must be one of posix/nfsv4/smb; POSIX modes must be valid octal; NFSv4 ACE lines are parsed and rejected on bad type/flags/permissions; glob patterns are validated; match types must be "file" or "directory"; SMB protocol requires server and share. A typo in the spec is now a fatal error on startup, not a per-object failure mid-run.

### ~~6. Owner/group fields silently ignored~~ — FIXED
`--set-owner` flag applies owner/group from spec via `Lchown` syscall. Requires root or CAP_CHOWN. Name-to-uid/gid resolution cached per unique owner:group pair. Without `--set-owner`, spec fields are noted at load time but not applied.

### ~~7. Worker arguments unchecked~~ — FIXED
`--workers` and `--batch-size` are validated to be >= 1 before any work begins. Zero or negative values produce a clear error and exit 1.

### ~~8. SMB support incomplete~~ — RESCOPED: out of scope by design
An SMB repair backend will not be implemented. FlashBlade translates NFSv4 ACLs to NTFS security descriptors at evaluation time, so NFSv4-written ACLs are authoritative for SMB clients; and SMB on FlashBlade has no multichannel, so an SMB-side repair could never approach NFS-side throughput. The Windows tree generator's role was to prove ACL fidelity parity between SMB-written and NFSv4-written ACLs, not to enable an SMB repair path. The vestigial `applySMB`/`smbcacls` code is unreachable (`protocol: smb` rejected at spec load).

**Residual task**: verify from a Windows SMB client that NFSv4-written ACLs render and enforce as intended across the generator scenarios.

### ~~9. NFSv4 ACL identity mapping affects --compare and --validate~~ — FIXED
The `who` field in ACEs is id-mapped by the kernel on both write and read. `--compare` and `--validate` now decode both ACLs (`nfs4acl.DecodeACL`) and compare per-ACE via `nfs4acl.ACLEqual` (`internal/nfs4acl/nfs4acl.go`), which normalizes identity casing rather than doing a raw `bytes.Equal` on the wire encoding. Byte differences from idmapd domain casing no longer cause false mismatches (verified in code and matches README.md "Known Limitations"). Not independently re-verified against a live idmapd misconfiguration in this pass — flagging that as unverified rather than assuming full coverage of every identity-mapping edge case (e.g. numeric-ID specs where the server has no reverse mapping at all).

### 10. A DACL-only spec wipes existing audit ACEs on FlashArray and FlashBlade — MITIGATED (fixed under `--sacl`; kept per object without it, PS-04)
`applyNFSv4` writes the spec's ACL as the whole `system.nfs4_acl`. FlashArray returns audit (`U`)
ACEs in that same attribute, so a write without them deletes the object's SACL and ends dynamic SACL
inheritance on that object (`benchmarks/sacl-phase0-20261014/SACL-MODEL.md`). Measured on FA 6.10.6
(4 of 4 objects lost every audit ACE, run reported success) and again on 6.12.1.

**Fixed in SACL mode.** With `--sacl`, an `acl:` rule with no `sacl:` key is refused before
anything is touched, and DACL-keeping rules (`sacl:` with no `acl:`) keep each object's DACL byte
for byte and replace only its SACL, behind a preflight that proves the audit bypass. Lab:
1,135,009 objects on 6.12.1 with 0 DACLs changed (`benchmarks/sacl-fa-20261015/`).

**FlashBlade too (#51).** On Purity//FB 4.8.0, multiprotocol FS, access-control style `shared`, no
audit policy: a SACL set over SMB is returned in `system.nfs4_acl`, and a plain `acl:` reset over NFS
deleted it on 10/10 objects. The run reported success (`benchmarks/sacl-unmapped-sid-20261020/`,
`out-fb-sacl51/`, `verify-fbs51.txt`).

**Kept without `--sacl` (PS-04, #73).** An `acl:` rule with no `sacl:` key now keeps auditing: each
object's ACL is read, and the spec DACL is written with that object's existing audit/alarm entries
appended, byte for byte. `sacl:` entries replace them and `sacl: []` clears them, both under
`--sacl` as before. This replaces the v0.9.4-sacl guard (`ErrWouldDeleteAudit`), which read only the
root and so missed audited objects below a clean one unless `--compare` was on. No platform test
gates it. An unreadable or unparseable ACL is not written, and neither is one whose audit entries
name nobody or an id ≥ 1e9 (`ErrUnpreservableAudit`), since writing those back would change the
SID. The audit-bypass proof runs first. Cost: one ACL read per object (batched on userspace), and
directories leave the fused READDIR+SETATTR path.

What is kept is the audit entries the NFS view shows, not SMB inheritance state: an inherited audit
ACE written back over NFS may be stored as explicit (compare #11). The run reports `Audit kept: N`,
meaning what was written, not a read-back.

**Still open:**
- **Live evidence for PS-04.** The kept-auditing path is covered offline only. FA and FB runs, plus
  RPC counts and runtime for all-change and all-match trees, are still needed.
- **The 6.10.6 read freeze.** On Purity//FA before 6.12.1, an ACL read by an identity without the
  audit bypass empties an inheriting object's SACL. permissionreset' own reads are covered by the
  preflight, but objects created after the run are exposed to any unprivileged reader (spec guide
  limit 1). 6.12.1 fixed this.
- **Copy-then-rename.** A file copied and renamed over the original carries only the parent's
  inherited SACL, not its stamped one (spec guide limit 6, `benchmarks/sacl-tamper/`).

### 11. Keeping an SMB-written DACL over NFS rewrites it on FlashArray — GUARDED (refused for unmapped principals; flattening needs an ack)
A DACL-keeping rule sends back exactly the DACL bytes it read, but FlashArray re-translates every
`who` to a SID on write. On Purity//FA 6.10.6, with a tree written over SMB and verified from SMB
afterwards (`benchmarks/sacl-unmapped-sid-20261020/RESULTS.md`):
- every SID with no RFC 2307 id (users, groups, `Domain Users`) reads as `65534`, and comes back
  as the array's local nobody SID (`…-501`); `BUILTIN\Administrators` came back as local `…-500`;
- inherited flags were dropped and the DACL was marked protected (`D:P`), on mapped principals too.
  ACE order and count are kept: a raw `GetFileSecurityW` read shows every ACE where it was written,
  with none merged. The reorder and merge reported earlier came from `Get-Acl`, which sorts and
  merges an already-canonical DACL (`benchmarks/dacl-reset-fidelity-20261020/raw-recheck-fa-20261021.md`
  on `test/sacl-unmapped-sid`);
- the run reported 0 errors, `--compare` reported converged, and the NFS view was unchanged.
The earlier 0-DACLs-changed result (#10) compared the NFS view only, on NFS-written data.

**Guarded:** a DACL-keeping rule refuses any object whose DACL names `65534`, `4294967294`, `-2`,
`nobody`, `nfsnobody` or `nobody@…` (`ErrUnmappedPrincipal`) and writes nothing to it. The same
check runs on the root and on the preflight probe before either is written, so such a tree is
refused whole. There is no override.

**A plain `acl:` reset is not affected, and only warns.** When the spec itself names a principal with
no RFC 2307 id (`name@domain`), FA stores its SID and SMB shows the right account on every object
(#50, `benchmarks/dacl-reset-fidelity-20261020/RESULTS-fa.md`, cells 4–5). Over NFS it still reads
back as `65534`, so the preflight writes every spec principal to its probe, reads it back, and
prints a WARNING naming the ones that come back as nobody. The run continues. FlashBlade refuses
such a principal at the write (EINVAL), so the objects naming it fail instead.

**Still open:**
- **Mapped principals: inheritance is flattened. Guarded by an acknowledgement.** With every SID
  mapped, SIDs, owner and group survived, but FA cleared the inherited flag on every inherited ACE
  (8 of 10 objects; the 2 with only explicit ACEs kept every ACE). Effective access was unchanged. FA's NFS view never carries `ACE4_INHERITED_ACE`,
  so the client cannot detect or preserve it. An `--sacl` apply with a DACL-keeping rule is now
  refused unless `--accept-dacl-flattening` is passed (`ErrDACLFlattening`). Dry run and
  `--validate` are not refused.
- **FlashBlade.** FB renders an unmapped SID as `1000000000 + RID`, so the guard does not fire
  there. Writing that number back restores a domain SID (#12). FB also clears inherited flags and
  marks the DACL `D:P`, and keeps ACE order and count (raw read,
  `benchmarks/dacl-reset-fidelity-20261020/raw-recheck-fb-20261021.md` on `test/sacl-unmapped-sid`).
- **SMB-side SACL pass.** `tools/set-saclonly/Set-SaclOnly.ps1` writes only the SACL over SMB and
  checks each object's owner/group/DACL before and after. On FA 6.10.6 it kept 20/20 DACLs identical,
  mapped and unmapped principals alike, with inherited flags intact. Its parallel version was timed at
  t200k on both arrays (HANDOFF). v1 (backup-intent handle
  I/O, `-Spec`, the root audit-bypass preflight, SACL `P` kept) passed live on FA and FB on 2026-10-21:
  owner/group/DACL unchanged on every object (45,409 on t40k), raw before/after.
- **No SMB-side verification in the tool.** permissionreset reads only the NFS view, which hides this
  damage.

### 12. FlashBlade rewrites ids ≥ 1,000,000,000 on any NFS ACL write — GUARDED (refused unless `--allow-high-ids`)
FlashBlade renders a SID with no RFC 2307 id as `1000000000 + RID`, and on an NFS ACL write it decodes
**every** numeric `who` ≥ 1e9 that way, whatever the number meant (Purity//FB 4.8.0, #52):
- a real uidNumber 2000000003 comes back as `<domain>-1000000003`, unresolvable;
- `BUILTIN\Administrators` (read as `1000000544`) comes back as `<domain>-544`, and `S-1-22-2-10001` as `<domain>-10001`;
- domain SIDs with no id (`1000002776`) round-trip correctly;
- ids below 1e9 round-trip correctly. Inheritance metadata is still flattened, and the DACL marked
  `D:P`, as in #11; ACE order and count are kept.
Nothing is reported, and the NFS view shows the same identities, as names after the first write.

**Guarded:** a DACL-keeping object whose DACL names an id ≥ 1e9 is refused
(`ErrSyntheticRangePrincipal`). This covers numeric ids and named principals NSS resolves to one;
the root and the preflight probe are checked first. FlashArray is refused too, because the kernel
transport cannot tell the platforms apart.

**A plain `acl:` reset hits the same decode** (#50, `benchmarks/dacl-reset-fidelity-20261020/RESULTS-fb.md`
on `test/sacl-unmapped-sid`): on FB, uid 2000000003 and gid 1880600173 came back as
`<domain>-1000000003` and `<domain>-880600173` on all 10 objects, exit 0. Ids below 1e9 came back
exact. **Guarded:** an apply whose spec names an id ≥ 1e9 in `acl:` or `sacl:`, numerically or by a
name NSS resolves to one, is refused before anything is touched (`ErrHighIDPrincipal`) unless
`--allow-high-ids` is passed. Dry runs and `--validate` print a WARNING. The flag is for FlashArray,
and for FB ids that are already the array's own `1000000000 + RID` form of a domain SID (those
round-trip). It does not lift the DACL-keeping refusal above.

**Still open:** a named principal this host cannot resolve is not checked; FB's form for other
well-known SIDs (NT AUTHORITY, CREATOR OWNER) is unmeasured.

## Project Health Gaps

- [x] ~~No unit tests~~ — `Test*` functions across cmd/permissionreset and internal packages (run `grep -rc '^func Test' --include='*_test.go' .` for current count). A subset of internal/nfs41 tests are `_live_test.go` and require a real FlashBlade/NFS server.
- [x] ~~No CI pipeline~~ — `.github/workflows/ci.yml`: gofmt, go vet, staticcheck, go test -race with per-package coverage floor. Runs on `small-baremetal` ISS self-hosted runners.
- [x] ~~No release packaging~~ — `make release` cross-compiles static `linux/amd64` and `linux/arm64` binaries for both `permissionreset` and `generate-tree` into `dist/`. No goreleaser, no published/signed releases, no versioned artifact distribution beyond the local `dist/` output.
- [x] ~~No standalone validate mode~~ — `--validate` reads tree and reports mismatches without writing. Measured 98,403 overall ops/sec on 1,104,409 objects, FlashBlade S500, 12-core client, `vers=4.1,nconnect=16` (see benchmarks/PERFORMANCE.md); cache state not recorded for this specific run.
- [x] ~~No resume/checkpoint~~ — `--checkpoint` / `--resume` tracks completed directories, skips subtrees on resume (landed via PR #2 / `checkpoint-resume` branch, merged into `main`)
- [x] ~~NFSv4 always rewrites ACLs~~ — `--compare` flag skips writes when ACL matches
- [x] ~~DESIGN.md describes earlier Python/pfind architecture, not current Go implementation~~ — rewritten to describe the current Go architecture (fused walk, direct setxattr, kernel + userspace transports, checkpoint/resume, spec validation)
