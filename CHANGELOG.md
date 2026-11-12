# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Issue and pull request numbers (`#50`, `PR #67`) written before the public launch refer to the
> project's earlier private repository. They do not match issues or pull requests here.

## [Unreleased]

### Changed

- `build-spec` checks that `--probe-dir`, and a separate `--verify-write` scratch, exist and are
  directories (not symlinks) before the audit-bypass proof and before either template is read. A
  missing one is refused with `... does not exist` and a hint to create it; build-spec never creates
  it, so a mistyped path cannot put a new directory in live data. Previously a missing probe
  directory failed inside the proof with a bare `no such file or directory`, and a missing
  `--verify-write` scratch failed only after the templates had been read. The GUI's Capture and
  Verify get the same check on their probe folder.
- The userspace transport's server gate no longer prints a per-connection line saying what it
  checked. Accepted or refused, it now says only whether the server is a FlashBlade. Under the
  unsafe server override, the `WARNING:` line carries an opaque `gate code` that support can
  decode, in place of the raw reading, and a malformed gate reply no longer names the attribute
  it was missing.
- The audited-object refusal of a DACL reset no longer says the write "makes FlashArray mark"
  the ACL protected, which read as a claim about the target on FlashBlade too. It names
  FlashArray as the reason and gives both ways out: reset FlashArray objects over SMB, or pass
  `--allow-audited-dacl-reset`.
- The unpreservable-audit refusal (`existing audit ACEs name a principal ...`) lists the
  principals in its own `(who: ...)` and no longer appends the DACL check's text, which said the
  DACL named them.

### Fixed

- On the userspace transport, the transport's own messages (the session slot grant, the
  unsafe-override `WARNING:` lines) go to stderr only. They were also written into `--log` and
  the evidence record, so a clean userspace run's `--log` was not empty and the evidence held
  lines that are not records (#47).

## [0.10.0-rc2] - 2026-11-10

Pre-release, qualified for the same single use as 0.10.0-rc1: a DACL reset on FlashBlade over
NFSv4.1, from Linux, on the kernel and userspace transports. The release notes hold the
acceptance record. 0.10.0-rc1 was tagged and qualified but not published.

### Fixed

- An interrupted run's summary was headed `Complete:` (`Validation complete:` for `--validate`),
  although the run exited 1 and printed `INTERRUPTED:` on stderr. It is now headed
  `Incomplete (interrupted):`, or `Incomplete (stopped making changes after an evidence or log
  write failed):`. Found by release acceptance case L8 on `v0.10.0-rc1`.

## [0.10.0-rc1] - 2026-11-09

First public pre-release. It is qualified for one use: a DACL reset (`acl:` rules, no `--sacl`)
on FlashBlade over NFSv4.1, from Linux, on the kernel and userspace transports. Audit (SACL)
modes, FlashArray, SMB, macOS, Windows capture and the GUI ship in the archives but are not
qualified by this pre-release; see COMPATIBILITY.md. The external-reader trial and the
independent review of the live-read safety work are not done yet, so this is not the self-service
release described in `docs/release-acceptance.md`.

### Added

- `permissionreset` and `build-spec` print a NOTE when the audit-bypass proof passes. It names the
  disposable probe and is printed before the first live ACL read. Before this, a passed proof
  printed nothing, so the run output could not show that the proof ran, or that it ran first
  (#31).

### Changed

- Without `--sacl`, a DACL reset now refuses each object that already carries audit ACEs
  (`ErrAuditedObject`) unless `--allow-audited-dacl-reset` is passed. FlashArray marks the SACL and
  DACL protected (`S:AI` → `S:P`, `D:AI` → `D:P`) on any NFS ACL write, so the audit entries were
  kept but their Windows inheritance was not. A refused object is not written, but on FlashArray
  an object that only inherits still takes its parent's new inheritable ACEs when the parent is
  reset.
- An nfsv4 dry run with `--compare` now prints a NOTE that `--compare` has no effect there: a dry
  run reads no ACL, so objects that already match are counted as applied.
- With `--allow-high-ids`, the FlashBlade high-id WARNING is replaced by a one-line NOTE.

- Renamed the project and its main command from `resetperms` to `permissionreset`. The binary is
  now `permissionreset` (was `resetperms-go`), the command lives in `cmd/permissionreset/`, the
  tuning file is `permissionreset-tuning.yaml`, and environment variables use the `PERMISSIONRESET_`
  prefix. The Go module path is `github.com/PureStorage-OpenConnect/permissionreset`. There is no
  compatibility shim for the old names. Entries below keep the names used at the time.

## [0.9.8] - 2026-10-29

> Release tags drop the `-sacl` suffix from this version on.

### Added
- **Partition manifests for billion-object runs (PS-12, #81).** New `--partitions m.yaml` runs a manifest of disjoint subtrees one at a time, each with its own checkpoint, evidence and error log under the manifest's `state_dir`. An implicit `residual` partition walks the root first and hands off each partition root instead of entering it, so every object belongs to exactly one partition; a root the residual never reaches makes the run incomplete. Overlapping, nested or duplicate partitions, unclean, glob or excluded paths, and (on the kernel transport) symlinked or aliased roots are refused. `--resume` skips completed partitions and resumes the rest from their checkpoints, and is refused if the manifest, mode, tool version, transport or a root's device/inode changed; `--partition NAME` runs only the named ones. Totals are the exact sum of every attempt; an attempt killed before it recorded counts is listed in `uncounted_attempts` and the totals are labelled a lower bound. Measured on 1.1M objects on a lab S200: a single run took 41.7 s and four partitions 41.6 s (median of 3); a SIGKILL mid-partition, `--resume` and `--validate` matched 1,135,010/1,135,010 (`docs/partitions.md`, `benchmarks/partitions-ab-20261029/`). Partitions run serially; concurrency is not supported. Single-target runs and their checkpoints are unchanged.

### Changed
- **Directory listings are read in bounded batches, and checkpoint completion no longer leaks (PS-11, #80).** On the kernel transport each directory is listed 1,024 entries at a time instead of all at once, so one very wide directory no longer dominates memory: walking a single 200,000-file directory peaked at 3.6 MiB of heap instead of 67 MiB, and ran in half the time (no sort). A directory still reaches the apply workers only after its whole listing. Listings are now in filesystem order rather than sorted by name. Fixed in the same audit: a checkpoint completion that arrived before its directory was registered was dropped, so that directory and all its ancestors stayed pending for the rest of the run and were never recorded (a resume redid them, and the root was never written); a resume's skip of a completed subtree did not let its parent complete; and a `--one-filesystem` boundary kept its parent from completing. A listing that fails partway through is now counted as an error rather than silently treated as complete. Bounds and what still grows with depth and subdirectory count: `docs/CHECKPOINT_SCALE.md`.

- **Per-object evidence is sharded, checked, and stops the run when it cannot be written (PS-09, #78).** New `--evidence-dir DIR` writes gzipped record shards (rotated at `--evidence-shard-mb`, default 256) and a `manifest.json` with each shard's SHA-256 and a `complete`/`incomplete` verdict. The JSON summary fills `records` with those shards and adds an `evidence` block. Records pass through a bounded queue, so slow storage slows the run rather than growing memory. Every write, flush, sync and close is checked, `--log` included. On the first failure the run makes no further changes (the walk stops, queued objects are counted as not attempted), lets in-flight changes finish, and exits 1 with the manifest marked incomplete. `--evidence-profile detailed` adds each object's NFSv4 ACL before the write, at the cost of one batched ACL read per object. Measured on 1.1M objects on a lab S200: no elapsed difference outside noise, +4% client CPU for compact and +6% for detailed, 6.6 and 7.7 bytes per object on disk (`docs/evidence.md`, `benchmarks/evidence-ab-20261029/`). Evidence is not a crash-safe journal: it is synced per shard, not per object. `--audit-log PATH` is deprecated: it now writes the evidence directory PATH as one uncompressed shard, refuses an existing file there, and can no longer share a file with `--log`.

### Fixed
- **`generate-tree --transport userspace` resolves the target path on the server and gives its root a safety ACE,** so a test tree generated without a writable kernel mount stays traversable by the running user (#97; the kernel path got the same root ACE in 0.9.7, #96).
- A test that cancels a run mid-way no longer races the evidence writer's buffered flush (#101).

## [0.9.7-sacl] - 2026-10-28

### Changed
- **Set-SaclOnly is strict by default (PS-07, #76).** Any owner, group, DACL (ACE, mask, flags, SID, order, control flags) or `S:P` change across a SACL write is an error and stops the run; writes in flight finish and are checked. FlashBlade's `D:P`-only loss, previously logged and allowed, now needs `-Accept dacl-unprotected` with `-Log`. `-Array FlashBlade` refuses a strict run on a `D:P` root before any write, and `-Summary` writes the policy and counts as JSON. An object whose write trips the stop keeps its new SACL and is counted as `set_then_stopped`, not `set`. Docs now say not to verify DACL flags on FlashBlade with `Get-Acl`, `icacls` or Explorer: they compute `P` and `ID` from the parent rather than reading what the array stores.
- **A DACL reset without `--sacl` now keeps each object's existing auditing, on FlashArray and FlashBlade.** An `acl:` rule with no `sacl:` key used to be refused (`ErrWouldDeleteAudit`) only when the *root* carried audit ACEs, or per object under `--compare`. A subtree with SACLs below a clean root was wiped. Now every object's ACL is read, and the spec DACL is written with that object's audit/alarm entries appended, copied byte for byte. `sacl:` entries still replace them and `sacl: []` still clears them (under `--sacl`). No platform test gates it. An object whose ACL can't be read or parsed is not written, and neither is one whose audit ACEs name nobody or an id ≥ 1e9 (`ErrUnpreservableAudit`). The audit-bypass proof still runs before any live read. `--validate` compares only the DACL for such rules. The run prints `Audit kept: N`, and the JSON summary records `objects.audit_kept`: what was written as NFS shows it, not a read-back and not SMB inheritance state. Cost: one ACL read per object (batched on userspace), and these directories no longer take the fused READDIR+SETATTR write. `ErrWouldDeleteAudit` and `apply.CheckNoAuditACEs` are removed (PS-04, #73).

- **Resume loads the checkpoint in batches (PS-10, #79).** A resume reads 4,096 records at a time instead of one per directory, and sorts with a typed comparison: 1M records load in 0.27 s instead of 1.01 s, 10M in 3.1 s instead of 10.7 s, with the same memory. The checkpoint format is unchanged (`docs/CHECKPOINT_SCALE.md`).

### Fixed
- **The preflight now proves audit-bypass privilege on a disposable probe before reading the live root's ACL.** `CheckKeepDACLTarget` and `CheckNoAuditACEs` both used to read root's live ACL directly, ahead of anything that proved this identity could do so safely; an unprivileged read has been observed on at least one array to empty inherited auditing, which made the very check meant to protect the root's SACL a way to destroy it. `apply.ProveAuditBypass` now runs first, entirely against a disposable probe target, and `runPreflight` fails closed (never reading root) if that proof fails, before either live-root check runs (PS-02, #71).
- **The userspace (NFSv4.1) preflight probe no longer falls back to a live object.** `ProbeTarget` used to return the real target directory, or the export root when that path did not resolve, and `ProbePreflight` wrote and restored a real ACL there -- a restore that cannot reconstruct SMB inheritance metadata an NFS write loses. The userspace transport now creates a disposable probe directory (`Mkdir`/`Remove`, a collision-safe name under the target or export root) exactly as the kernel transport already does with a temp file, and fails before any live-object ACL mutation if disposable probing is unsupported or denied -- it never substitutes a real, existing object (PS-01, #70). A failed cleanup (probe object not removed) is now folded into the preflight's returned error instead of being discarded silently.
- **`--compare`/`--validate` no longer report a false mismatch on `GROUP@` because FlashArray clears the ACE4_IDENTIFIER_GROUP flag when it stores that one well-known who (#87, PS-18).** RFC 7530 §6.2.1.5 defines `GROUP@` as the owning group by definition, so the flag carries no information there; `ACEsEqualIdent`/`ACLEqualIdent` (and therefore `ACLEqual`, which calls `ACLEqualIdent` with a nil resolver) now ignore the `g` flag only when both sides' who is `GROUP@`. A named user or group principal still mismatches on a `g`-flag difference, and this also removes a false `--verify-write` failure on FA for a captured spec that used `GROUP@`. The already-merged 65534-nobody-readback warning (#59) and named-identity comparison (#61) covered the rest of the local 2026-10-17 FA parity plan's items 1–2; this closes the one gap that remained.
- **build-spec's ACL identity summary counts distinct principals, DACL and SACL apart.** It used to count ACEs across both exemplars, audit ACEs included. On FlashBlade, a capture of 3 users and 1 group, with one `EVERYONE@` audit ACE per object, read as 5 numeric users, 2 numeric groups and 2 specials, with none of the specials in a DACL. The summary now prints a DACL line and a SACL line of distinct principals, then each principal with the ACLs it appears in. Alarm ACEs are not counted, since the spec drops them. Numeric ids are labelled as the server returned them, not "unresolved": FlashBlade returns mapped accounts as numbers over NFS. The desktop app's cards follow, with the principal list under them. The spec YAML is unchanged.
- The desktop app's browser mock no longer throws on every render once exports are listed: the frontend stored `Exports()`'s `{exports, supported}` as is but read `list`. The real app never listed exports, because the call ran only before any session existed.

### Added
- **The JSON run summary (schema 2) says what a run proved, and refuses to overstate it.** `--json-summary` gains `run_id`, `accounting` (included, excluded, attempted, succeeded, failed, unverified, `enumeration_complete`), `verification` and `records`. `verification` lists every dimension -- `write_accepted`, `nfs_spec_match`, `smb_descriptor_fidelity`, `sacl_retention`, `effective_access`, `audit_event_delivery` -- with a state (`matched`, `mismatched`, `unreadable`, `not_checked`, `sampled`, `incomplete`), coverage counts, and fixed `proves`/`does_not_prove` text, and derives one verdict. Only `--validate` selects a required check, so a repair run is `not_requested` however clean its writes; an unreadable, incomplete, sampled or unrun required check is `unverified`, never `verified`. `--validate` now counts unreadable objects apart from mismatches. The writer refuses an inconsistent summary, and `summary.Decode` migrates a v1 file conservatively (at best `unverified`). Every v1 field is unchanged. A validate run now keeps only the ten mismatches it prints, not every one (PS-05, #74).
- **The build-spec desktop app covers SACL capture and `--sacl-plan`.** An "Also write the DACL" switch is `--with-dacl`, and it reaches capture and verify-by-replay through `internal/session`. When the exemplars carry audit (U) ACEs, the inspector says whether the spec keeps each object's DACL (`sacl:` only) or replaces it too, and counts the audit ACEs. "SACL plan from spec…" opens a resetperms spec and shows, copies or saves the same JSON as `build-spec --sacl-plan`, naming any `acl:`/`dacl:` rule Set-SaclOnly would refuse. It needs no session. The footer's CLI line follows both. The capture NOTE no longer says the desktop app lacks `--with-dacl`.

## [0.9.6-sacl] - 2026-10-21

### Added
- **`build-spec --sacl-plan SPEC.yaml` prints a spec's SACL plan as JSON** for `tools/set-saclonly/Set-SaclOnly.ps1`, which writes SACLs over SMB. The spec is loaded with full validation. The JSON (`schema: 1`) lists each rule's label, match, `sacl_set`/`keep_dacl`/`has_acl`/`has_dacl`, and its `sacl:` lines translated to Windows audit ACEs (header flags remapped, mask unchanged, SID and SDDL for `EVERYONE@`/`OWNER@`/`GROUP@`), plus the exclude list split into base-name and path patterns as resetperms splits them on Linux. It reads only the spec and refuses any other flag or argument.
- **`tools/set-saclonly/Set-SaclOnly.ps1`, the SMB-side SACL pass, with Pester tests.** It writes only the SACL over SMB, so DACLs written over SMB keep their inheritance and SIDs, which an NFS write-back loses (RISKS.md #11). It moves out of `benchmarks/` and gains two things. *Backup semantics:* every read, write and directory listing goes through a handle opened with backup intent and SeBackupPrivilege, so a directory whose DACL denies Administrators is no longer skipped. *`-Spec`/`-Plan`:* it writes the `sacl:` rules of a resetperms spec and selects each object's rule and excludes as `internal/spec` does, reading the spec through `build-spec --sacl-plan`. A spec with any `acl:`/`dacl:` rule is refused. *Root preflight:* the root is read, set and read back before anything else, so an identity without the array's audit bypass stops there with nothing written. *SACL flags kept:* each object's own `S:P`/`S:AI` is written back, so only the audit ACEs change. A `dacl-unprotected:` summary count covers FlashBlade clearing `D:P` on NFS-reset trees (logged, never restored). Verified live on FA and FB with owner/group/DACL unchanged on every object, and ~11,000 objects/s from one 12-vCPU client.
- **The preflight warns when the array reads a spec principal back as nobody (65534).** FlashArray accepts a `name@domain` with no RFC 2307 uidNumber/gidNumber. It stores the SID, so SMB shows the right account, but over NFS the principal reads back as `65534`: `--compare` rewrites every such object on each run, and an NFS read-and-write-back stores nobody (#50, `benchmarks/dacl-reset-fidelity-20261020/RESULTS-fa.md`). The preflight now writes each distinct spec principal to its probe, reads the ACL back, restores it, and prints a WARNING naming the principals that came back as nobody. The run continues, since the reset itself is correct. `--validate` and dry runs skip the check.

### Fixed
- **`--validate` and `--compare` recognize a principal the array returns by name when the spec gives its numeric id, on clients where sssd uses fully qualified names.** On such a client NSS answers `sacl-map2@example.net` for uid 1000003 and does not resolve the bare `sacl-map2`, so the identity check appended the domain a second time (`sacl-map2@example.net@example.net`) and looked up the bare name. FlashBlade returns numeric spec ids as `name@domain`, so `--validate` reported every correct object as a mismatch and exited 1, and `--compare` rewrote every object on each run; FlashArray did the same for `name@domain` specs. Validate mismatch reports now also name the ACE that really differs, not one that is only the other form of the same identity. Found in the release-candidate regression on FB 4.8.0 and FA lab array A (v0.9.5-sacl is affected).

### Changed
- **Docs no longer say an NFS write-back reorders or merges SMB-written ACEs.** That came from `Get-Acl`, which re-sorts a canonical DACL by SID and merges ACEs for the same SID. A raw `GetFileSecurityW` read of every object in the FlashArray and FlashBlade test trees shows each array keeps the order and every ACE that was written. What does change is real: inherited flags are cleared and the DACL is marked `D:P`. FlashBlade also does not mark SACLs protected by default; `S:PAI` appeared only on trees set up with `Set-Acl` (`benchmarks/dacl-reset-fidelity-20261020/raw-recheck-{fa,fb}-20261021.md` on `test/sacl-unmapped-sid`). The 0.9.4-sacl `--accept-dacl-flattening` entry below is corrected to match.
- `--sacl` help text, the customer README and troubleshooting no longer call SACL mode FlashArray-only: `--sacl` with `acl:` + `sacl:` rules is verified from SMB on Purity//FB 4.8.0 (#50 cell 2). The customer README and troubleshooting now cover the 65534 WARNING and FlashBlade's preflight refusal of a principal with no RFC 2307 id.

## [0.9.5-sacl] - 2026-10-20

### Fixed
- **An apply whose spec names an id ≥ 1,000,000,000 is refused unless `--allow-high-ids` is passed.** A plain `acl:` reset on FlashBlade stored uid 2000000003 and gid 1880600173 as nonexistent `1000000000 + RID` SIDs on all 10 objects, and v0.9.4-sacl only warned and exited 0 (#50, `benchmarks/dacl-reset-fidelity-20261020/RESULTS-fb.md`). The check covers `acl:` and `sacl:` entries, numeric ids and named principals NSS resolves to one, and runs before anything is touched (`ErrHighIDPrincipal`). Dry runs and `--validate` still only warn. Pass `--allow-high-ids` for FlashArray, which is not affected, or for ids that are FlashBlade's own `1000000000 + RID` form of a domain SID (RISKS.md #12).

### Changed
- Docs and the `sacl:` refusal message no longer call audit ACEs FlashArray-only or say a run without `--sacl` is unchecked (README, spec guide .md/.html, limitations, known-limitations). Spotted by the second Windows session.

## [0.9.4-sacl] - 2026-10-20

> **Data-integrity fixes for FlashBlade.** A plain DACL reset deleted SMB-set SACLs on FlashBlade, and an NFS ACL write-back rewrites ids ≥ 1e9 to wrong SIDs (#51, #52). Upgrade.

### Fixed
- **A DACL reset without `--sacl` no longer deletes audit ACEs silently.** FlashBlade multiprotocol file systems return the SACL in `system.nfs4_acl`, as FlashArray does, so an `acl:` write deleted it (10/10 objects on Purity//FB 4.8.0, run reported success). Without `--sacl`, an `acl:` spec is now refused (`ErrWouldDeleteAudit`) when the target root carries audit ACEs, and under `--compare` any object carrying them is refused (#51, RISKS.md #10).
- **A DACL-keeping (`sacl:`-only) write refuses principals with ids ≥ 1,000,000,000.** FlashBlade decodes such ids as `1000000000 + RID` on write, so a real uidNumber that high, or `BUILTIN\Administrators`, came back as a different, unresolvable SID (`ErrSyntheticRangePrincipal`). Named principals are resolved through NSS and checked the same way (#52, RISKS.md #12).

### Changed
- An `acl:` spec that names a numeric principal ≥ 1e9 prints a WARNING at start.
- Docs no longer say FlashBlade has no audit ACEs.

## [0.9.3-sacl] - 2026-10-20

This section also covers the v0.9.2-sacl changes, which had no section of their own.

> **Data-integrity fix.** v0.9.1-sacl and v0.9.2-sacl can silently change Windows DACLs on SMB-written FlashArray data with a `sacl:`-only spec (#48, #49). Upgrade.

### Changed
- **An `--sacl` apply with a `sacl:`-only rule needs `--accept-dacl-flattening`.** FlashArray's NFS view carries no inherited marker, so writing a DACL back stores every inherited ACE as explicit and marks the DACL `D:P`. Effective access is kept, Windows inheritance is not. Without the flag the run is refused before anything is touched. Dry runs and `--validate` are unaffected (RISKS.md #11).
- **SACL mode is opt-in with `--sacl`; `--no-sacl` is removed.** v0.9.1-sacl refused every NFSv4 spec with `acl:` and no `sacl:` key, FlashBlade included, unless `--no-sacl` was passed. Now `acl:` specs run without a flag again, a spec that names `sacl:` (`sacl: []` included) is refused without `--sacl`, and under `--sacl` an `acl:` rule with no `sacl:` key is refused, because on FlashArray that write deletes the object's audit ACEs. Passing `--no-sacl` is now a flag error.
- **The audit-bypass preflight covers `sacl: []`.** A spec whose only `sacl:` keys are empty still reads every object, so apply, `--compare` and `--validate` now prove the bypass for it too, with a placeholder audit ACE on the probe.
- **`build-spec --verify-write` checks audit ACEs per exemplar.** A server that keeps the directory probe's audit ACEs but drops the file probe's now fails verification instead of producing `sacl: []` for files.
- **Release archives include `build-spec`**, and the SBOM covers it. build-spec also prints a NOTE for each `sacl: []` rule it writes.

### Fixed
- **A `sacl:`-only rule no longer silently rewrites DACLs that name unmapped principals.** On FlashArray, every SID with no RFC 2307 id reads over NFS as `65534`. Writing that back, which the DACL-keeping apply did, replaced each such SID with the array's local nobody account, while the NFS view and `--compare` showed no change. Such objects are now refused with `ErrUnmappedPrincipal` and left untouched, and a root or preflight probe that shows one refuses the whole run before anything is written (RISKS.md #11).
- **`build-spec --verify-write` names the audit bypass when it is missing.** A probe write carrying the captured audit (`U`) ACEs that is refused (EACCES/EPERM/NFS4ERR_ACCESS) now says the running identity lacks the array's audit bypass and how to get it, instead of calling the ACL unreproducible by an NFSv4.1 repair.
- **A dry run no longer reads objects under a DACL-keeping (`sacl:`-only) rule.** A dry run, the default without `--apply`, has no audit-bypass preflight, and before Purity//FA 6.12.1 an ACL read without the bypass empties inheriting SACLs. Each such object is now reported as WOULD without being read, and a NOTE says so; use `--validate` to check them.
- `build-spec` puts audit (`U`) ACEs in `sacl:`. By default an exemplar with audit ACEs gives DACL-keeping `sacl:`-only rules (`sacl: []` for an exemplar with none); `--with-dacl` adds `acl:`. Without audit ACEs the output is unchanged. Alarm (`L`) ACEs are dropped with a NOTE. `--verify-write` replays the full ACL and refuses if the server drops the `U` entries. In v0.9.1-sacl the `U` entries landed in `acl:`, which the spec loader rejects.

### Added
- SACL documentation: spec guide section (rule kinds, `S`/`F`, `--sacl`, audit bypass, preflight, limits), FlashArray SACL runbook, `examples/nfsv4_sacl_keep_dacl.yaml`.

## [0.9.1-sacl] - 2026-10-15

Pre-release: shipped without SACL docs, and its `build-spec` fails on a FlashArray exemplar with audit ACEs.

### Added
- FlashArray audit ACEs (PR #42): a `sacl:` spec key for `U` ACEs with the `S`/`F` flags; `U`/`L` are refused in `acl:`.
  - DACL-keeping rules (`sacl:` with no `acl:`): read each object's ACL, keep its `A`/`D` entries byte for byte, replace only the audit entries. Reruns write nothing under `--compare`; `--validate` checks only the SACL.
  - Privilege preflight: refuses to start unless the identity has the array's audit bypass and the array retains the audit ACEs.
  - SACL guard: an `acl:` rule with no `sacl:` key is refused unless `--no-sacl` is passed (replaced by `--sacl` in the next release).
  - `GetACL` sizes and retries once on `ERANGE`.
  - Lab: 1,135,009 objects on Purity//FA 6.12.1 at ~20,500 objects/s (kernel, 64 workers), 0 DACLs changed.
- READDIR+SETATTR fold: append SETATTR to first READDIR page COMPOUND, saving one round-trip per directory (PR #20)
  - 8.3% faster on S500 Purity 4.8.0 (200K vs 185K ops/sec), 5.1% on 4.8.4
  - `ReadDirSetACL` added to `transport.Transport` interface; kernel transport falls back to ReadDir + SetACL
  - Fold activates when: NFSv4, not dry-run, not `--compare`, not `--set-owner`
- Userspace transport for `generate-tree` (PR #23)
  - `planSeedEntries()` generates seed structure in memory — no writable mount needed
  - `--manifest` flag for local manifest output (NFS4.1 client has no OP_WRITE)
  - Path-translation fix: uses `/proc/mounts` resolution instead of naive `TrimPrefix`
- Purity//FB 4.8.4 validation (PR #22): six-phase validation on S500 — protocol probes, functional correctness, kernel+userspace perf, tuning re-sweep, generate-tree regression. No regressions found.
- Tuning re-sweep on 4.8.4: winner shifted to c64/w4096/batch10 (183K ops/sec) from c16/w1024/batch10 (211K ops/sec on 4.8.0, different spec)
- `colossal` scale for generate-tree: 500K copies, 2K seed files, max depth 18

### Fixed
- Staticcheck SA4010: dead outlier collection in userspace generate-tree path

## [0.9.0] - 2026-08-28

### Added
- Userspace NFSv4.1 transport (`--transport=userspace`) with connection pooling, fast encode/decode, and server gate (PR #7)
  - 177K ops/sec at c8 on S500R1 — 1.50× over kernel transport
  - Fast XDR encoder/decoder: 30× faster READDIR decode, 19× less allocation
  - FlashBlade identity gate; FlashArray refused by `eir_server_impl_id`
  - Connection pool with N independent clients (workaround for one-session-per-client-ID limitation)
- Tuning sweeper (`sweep` binary, PR #12): coordinate ascent over 5 transport knobs, probe-first tree sizing, JSONL trial recording
- P1 operability (PR #13): `--json-summary`, enriched run summary, operator plan summary, support bundle, exclude patterns
- Fused pre-pass walk (PR #3): barrier-free parallel top-down directory fix, single-pass convergence
- `internal/run` package (PR #10): shared repair invocation for resetperms and sweep trials
- 4× GETATTR COMPOUND batching for `--validate` under userspace (133–140K checks/sec, up from 98K)
- PGO profile (`cmd/resetperms/default.pgo`) blended from userspace+kernel S500R1 benchmarks
- CI pipeline: gofmt, go vet, staticcheck, govulncheck, test with race detector, 60% coverage floor, CLI smoke tests, arm64 cross-compile
- Phase 2 test expansion: CLI orchestration, walk edge cases, pfind, ACL golden data, ownership ordering, example spec loading, checkpoint corner cases
- Phase 1 exit criteria tests: round-trip apply+validate, exhaustive enumeration count, fault injection
- `COMPATIBILITY.md` with client-a/S500R1 and client-b/S200 tested configurations
- `INSTALL.md` with install, upgrade, downgrade, and checkpoint compatibility instructions
- `CONTRIBUTING.md` with build, test, PR, and PGO update instructions
- `docs/rfc8881-one-session-violation.md`: filing-ready write-up for RFC 8881 §2.10.5 violation
- `docs/spec-guide.md`: spec file guide for Windows-ACL-background operators
- NFSv4-to-SMB rendering verification checklist (internal)
- `docs/CHECKPOINT_SCALE.md`: checkpoint size projections at 100M, 1B, and beyond
- `docs/NAMESPACE_SEMANTICS.md`: exclude, nested mount, rename, and deletion semantics
- `RFC-Deviations.md`: 10 measured protocol deviations across FlashBlade and FlashArray
- `THIRD-PARTY-NOTICES` covering gopkg.in/yaml.v3, golang.org/x/sys, vendored goxdr runtime
- `LICENSE` (Apache-2.0), `SECURITY.md`, release workflow (`.github/workflows/release.yml`)

### Changed
- `--validate` under `--transport=userspace` now batches 4 GETATTR per COMPOUND
- Go test tree generator improved: context-aware cancellation, manifest integrity on partial runs (Issue #15)
- SMB backend rescoped out of scope by design — NFSv4 ACLs authoritative for SMB clients
- DESIGN.md rewritten for Go architecture (fused walk, dual transports, direct setxattr)
- README.md and RISKS.md reconciled with implementation

### Fixed
- Issue #15: `FanOutAndStampContext` and `StampACLsContext` now return `ctx.Err()` after cancellation instead of writing a manifest claiming partial tree is complete
- Issue #16: descriptor exhaustion silently truncating kernel walk (pre-existing, documented)
- `TestConcurrentCallsShareOneWrite` race: forced gather instead of scheduling-dependent assertion
- Pre-pass OOM at 1024 workers from dirent retention (PR #18, 7.2 GB peak eliminated)

## [0.1.0] - 2026-08-27

### Added
- NFSv4 ACL repair via direct `setxattr` with RFC 7530 binary encoding (105K+ ops/sec on FlashBlade S500)
- Userspace NFSv4.1 transport with connection pooling (152K ops/sec, 1.29x kernel transport)
- Parallel walk with fused pre-pass for mode-000 directory recovery
- YAML spec engine with first-match rules, strict validation, and replace semantics
- Directory-level checkpoint/resume for multi-day runs (SIGKILL-safe, zero overhead on first run)
- `--validate` mode for read-only permission checking (98K checks/sec)
- `--compare` mode to skip already-correct objects
- Tuning sweeper (`sweep` binary) for automated transport-tunable measurement
- Go test tree generator (`generate-tree` binary) with 15 ACL scenarios
- CI pipeline: gofmt, go vet, staticcheck, govulncheck, test with race detector, coverage floor, CLI smoke tests, arm64 cross-compile
- Structured JSON summary output (`--json-summary`)
- Support bundle collection (`--support-bundle`)
- Exclude patterns (spec `exclude:` and `--exclude` flag)
- Operator plan summary before apply
- Graceful signal handling with drain and second-signal escalation

### Security
- Non-destructive preflight probe with deferred cleanup
- Traverse-lockout prevention (`CheckTraversePreserved`)
- Symlink detection and skip at enumeration (trusted-tree operating model)
- Dangerous target rejection (`/`, symlink roots)
- `--one-filesystem` traversal boundary
- Strict spec validation at load time (unknown keys, bad modes, malformed ACEs)
- `--apply` flag required; dry-run is the default
- Descriptor exhaustion detection with explicit `ulimit -n` guidance
