# Decision: FlashArray moves to an SMB-native tool

| | |
|---|---|
| Date | 2026-11-07 (section 8 question 1 partly answered the same day) |
| Status | **Accepted:** FlashArray work leaves the NFSv4 tool. **Proposed:** tool name, layout, version tags, CI (sections 4–7), pending maintainer confirmation. |
| Scope | Where FlashArray DACL and SACL work lives, what it is built on, and how it shares this repository with the NFSv4 tool. Not a design for the new tool. |

## 1. Context

The goal is the same on both platforms: reset or repair DACLs, add audit ACEs (SACLs) without
disturbing the DACLs, and do it deterministically across trees of tens of millions of objects.
permissionreset reaches that goal over NFSv4 on FlashBlade. On FlashArray, a year of work over
NFSv4 has produced a growing list of guards rather than a clean path:

- **The NFSv4 view is a translation of an NTFS-aligned model.** FlashArray's file system stores
  SIDs, inherited flags and SACLs natively. Its NFSv4 view has no inherited marker, so a DACL written
  back over NFS stores every inherited ACE as explicit and marks the DACL protected (`D:P`), and a
  SID with no RFC 2307 id comes back as the array's local nobody account (RISKS.md #11).
- **Any NFS ACL write on an audited object marks the SACL and DACL protected** (`S:AI` → `S:P`,
  `D:AI` → `D:P`), even when the bytes are identical (`ErrAuditedObject`, `--allow-audited-dacl-reset`).
- **This behavior is in line with the protocol definitions, not a defect.** The NFSv4 ACL model
  (RFC 7530, RFC 8881) and the SMB security descriptor model (MS-DTYP) define different flags and
  attributes. FlashArray applies each protocol's definition strictly. Inheritance on FlashArray is
  dynamic, but its NFSv4 view never carries `ACE4_INHERITED_ACE` (RISKS.md #11). So an ACL written
  over NFS cannot mark any ACE as inherited, and FlashArray stores what was written: explicit
  ACEs, marked protected. No client-side change can make the NFSv4 view carry Windows inheritance.

The reason for NFSv4 was parallelism: `nconnect`, a userspace transport with a hundred or more
workers, and FlashBlade spreading metadata work across its blades. FlashArray cannot use that
parallelism. One controller does the metadata writes, and it is the limit:

- Kernel transport, one FlashArray: 18,000–20,500 objects/s with 64 workers. More workers or
  `nconnect` did not help (README, `benchmarks/`).
- Userspace transport, one FlashArray: 64 workers was the best of 32/64/128/256 (COMPATIBILITY.md).

So on FlashArray, NFSv4 adds no throughput and loses fidelity. An SMB client talks the array's native
model: SIDs without id mapping, inherited flags as stored, SACLs through `SeSecurityPrivilege`, and
no protected-flag side effect from the transport. The expected bottleneck is the same controller, so
a Windows/SMB client does not need to match the NFSv4 tool's client-side parallelism to match its
FlashArray throughput. That expectation is unmeasured (section 8).

`tools/set-saclonly` already shows the approach works for SACLs: a C# engine (`SaclOnly.cs`) with a
parallel walk, backup-intent handle I/O and permissionreset's rule selection, driven by `build-spec`
so it never parses YAML.

## 2. Decision

1. **New FlashArray work goes to an SMB-native Windows tool**, for DACLs and SACLs. Nothing new is
   added to the NFSv4 tool for FlashArray.
2. **The NFSv4 tool keeps its current FlashArray behavior and guards.** The qualified scope in
   COMPATIBILITY.md stays as recorded, and the refusals (unmapped principals, flattening, audited
   objects) stay. Operator docs will point FlashArray users to the new tool once it exists. Whether
   to later refuse FlashArray outright, as the userspace transport refuses it without its flag, is a
   separate decision, taken once the new tool has a qualified release.
3. **FlashBlade stays on the NFSv4 tool.** FlashBlade evaluates NFSv4-written ACLs for SMB clients,
   and it has no SMB multichannel, so an SMB repair path there could not perform
   (field-preview/known-limitations.md).
4. **The new tool lives in this repository** (section 5). The two tools share the spec format,
   rule semantics, evidence format, test vectors and qualification process. Most of the knowledge is
   there, not in the code.
5. **Set-SaclOnly stays the supported SMB SACL path until the new tool covers it.** After that it is
   retired, not maintained as a second Windows tool.
6. **The Go `protocol: smb` backend (`smbcacls`, one process per object) is not this direction.** It
   stays rejected at spec load (docs/transports.md) and can be removed in a later cleanup.

## 3. Alternatives considered

| Alternative | Why not |
|---|---|
| Keep fixing FlashArray over NFSv4 | The losses come from the protocol mapping, which follows the protocol definitions. Each fix becomes another guard, and the throughput reason does not apply. |
| A separate repository for the FlashArray tool | Splits the spec semantics, test vectors, benchmarks and qualification history that the two tools must agree on. The code shares little in any case, since one is Go and one is .NET. |
| SMB from Linux (`smbcacls`, or a Go SMB client) | The existing backend runs one process per object. A native SMB client in Go would have to rebuild security-descriptor, privilege and backup-intent handling that Windows already provides and Set-SaclOnly already uses. |
| PowerShell (`Get-Acl`/`Set-Acl`) as the engine | Too slow at this scale, and `Get-Acl` re-sorts and merges ACEs, so it cannot verify ACE order, count or flags (README, "SMB-written data"). PowerShell stays a thin front end at most. |

## 4. Naming (proposed)

The repository and product stay **permissionreset**. The existing binary keeps the name
`permissionreset`, and the new tool is **`permissionreset-smb`**. Docs open with a platform-to-tool
table, so readers who start from the hardware land on the right tool.

The names follow the protocol, not the hardware, because the protocol is the real split.
FlashBlade SMB-written data is already a Set-SaclOnly use case (RISKS.md #11, #12). And if
FlashArray's NFSv4 view ever carried inheritance, the NFSv4 tool would be valid there again.
Hardware names (`-fa`/`-fb`) would be wrong in both cases. Renaming the existing tool would also
churn the published repository, its tags, its release archives and operators' scripts.

| Option | Assessment |
|---|---|
| `permissionreset` + `permissionreset-smb` | **Proposed.** No rename, and the names match the real boundary. |
| `permissionreset-nfs` + `permissionreset-smb` | Symmetric. Costs a rename of a published tool. |
| `permissionreset-fb` + `permissionreset-fa` | Names the hardware rather than the boundary, and costs the same rename. |

## 5. Repository layout (proposed)

The Go module stays at the root, because moving it under a subdirectory would rewrite every import
path. The new tool gets one top-level directory:

```
cmd/, internal/          NFSv4 tool, build-spec, generate-tree, sweep (unchanged)
smb/                     permissionreset-smb: .NET solution, tests, README
tools/set-saclonly/      unchanged until permissionreset-smb covers SACL-only, then removed
docs/                    shared: spec-guide.md, evidence.md, this record
benchmarks/              shared: entries name tool, transport and platform
```

The shared contract is behavioral, not code:

- **One spec loader.** `build-spec` already validates a spec and emits a plan that Set-SaclOnly
  consumes (`--sacl-plan`). permissionreset-smb takes the same route, with the plan extended to
  `acl:` rules, so YAML parsing, validation and rule selection have one implementation and
  `docs/spec-guide.md` stays the single reference. Glob and selection vectors
  (`tools/set-saclonly/testdata/`) move to a shared location, and both tools test against them.
- **One evidence format.** permissionreset-smb writes `docs/evidence.md` records, so a FlashArray run
  and a FlashBlade run can be audited with the same tools. Where an SMB-side field needs to exist
  (raw descriptor, control flags), it is added to the format rather than forked.
- **One qualification process.** `docs/release-acceptance.md` and MAINTAINERS.md section 4 apply to
  both tools. COMPATIBILITY.md gets rows per tool.

## 6. Versions and releases (proposed)

The tools release on different schedules, so the versions are independent. `permissionreset` keeps
plain `vX.Y.Z` tags. `permissionreset-smb` uses `smb-vX.Y.Z`, starting at `smb-v0.1.0`. The current
release workflow triggers on `v*`, which `smb-v*` does not match, so the new tool gets its own
release workflow and archive. The existing archives keep shipping Set-SaclOnly until it is retired.

## 7. CI (proposed)

Per MAINTAINERS.md section 5, public CI uses GitHub-hosted runners. A hosted Windows job builds
`smb/`, runs its unit tests, and also runs the Set-SaclOnly Pester suite under Windows PowerShell 5.1
and PowerShell 7. That suite is not run in CI today. Self-hosted runners, including internal Windows
runners, never run code from this repository's pull requests. Hardware qualification stays a
maintainer-run exercise against a pinned revision or artifact, as it is for the NFSv4 tool.

## 8. Open questions (resolve before design)

1. **Can the tool rely on dynamic inheritance?** If FlashArray resolves inheritance on the array, a
   reset may need writes only where explicit ACEs or protection must change, not on every object.
   Standard Windows APIs (`SetNamedSecurityInfo`, `icacls`) propagate inheritance from the client
   and walk the tree. The test is a raw `NtSetSecurityObject` on a root, then a raw-descriptor read
   (`GetFileSecurityW`) of the unchanged children over SMB. If dynamic inheritance holds, the tool's
   write count, and its design, change.

   **Partly answered (2026-11-07, one lab FlashArray, Purity//FA 6.10.7, a 10-object tree):**
   - A single DACL write over SMB to one directory (one `SetFileSecurityW` call, under 10 ms)
     changed the inherited ACEs of every unprotected descendant, with no write to them. The change
     was visible immediately and did not change afterwards. A protected subtree did not change. The
     NFSv4 view agreed.
   - The array stores exactly the DACL written to an object. A directory written with no ACEs and no
     protection stayed empty; the array did not add its parent's inheritable ACEs. That directory's
     unwritten children then re-derived from it and lost their inherited ACEs.
   - Over SMB the array enforces traverse checks under a deny-all directory, and honors backup
     intent (`FILE_FLAG_BACKUP_SEMANTICS` with `SeBackupPrivilege`).

   So inherited-only objects need no write, and an object that should inherit must be written with
   its parent's inheritable ACEs in inherited form. Still open: whether inherited-form ACEs written
   by a client stay dynamic on later ancestor changes or are a frozen copy, and how a root write
   behaves on a large tree (call time, synchronous or not, array load).
2. **Where is the SMB ceiling?** A parallel read-compare-write loop over SMB, on the same tree as the
   NFSv4 measurements, from one Windows host. The expectation that the array limits first must be
   measured, not assumed.
3. **Does an SMB DACL write on an audited object leave `S:AI` and `D:AI` alone?** It is expected to,
   since the write uses the native model, but this must be qualified.
4. **Identity and privileges:** the audit bypass, `SeBackupPrivilege`, `SeSecurityPrivilege`, and how
   a spec's principals resolve to SIDs on the Windows host compared with the NFSv4 tool's ids.
5. **Verification:** raw descriptors only (`GetFileSecurityW`). The claims in MAINTAINERS.md
   section 4 stay distinct: structural ACL agreement, SMB descriptor and inheritance fidelity,
   effective access, stored audit rules and delivered audit events.

## 9. Consequences

- Two toolchains (Go and .NET) and a Windows host requirement for FlashArray users.
- `build-spec` becomes the spec front end for both tools, so changes to its plan output need tests
  on both sides.
- README, COMPATIBILITY.md, docs/field-preview and docs/transports.md gain a platform-to-tool split
  when permissionreset-smb has a first release. Until then they keep describing current behavior.
