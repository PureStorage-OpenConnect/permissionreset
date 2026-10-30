# PS-07 (#76) live checks: results, 2026-10-26

Set-SaclOnly at `feat/ps-07-sacl-retention` `84f2fb2`, against FlashArray and FlashBlade. All three
PR #94 live criteria pass. A separate finding: on FlashBlade, `Get-Acl`, `icacls` and Explorer do
not show the `D:P` loss, so they cannot be used to verify it (see "Reading the DACL").

## Lab

`testdrive-fa-fb-bleeding-edge` (DemoForge profile `config/labs/testdrive-fa-fb-bleeding-edge.psd1`),
an ephemeral TestDrive sandbox. `fa-file-multiprotocol` and `fb-file-multiprotocol` enabled by
DemoForge first.

| | Detail |
|---|---|
| Windows client | `INTRODC01` (Windows Server 2025, the lab DC), elevated pwsh 7.6, as `TESTDRIVE\Administrator` |
| NFS client | `linux1` 192.0.2.2, Rocky 9.5, NFSv4.1 `sec=sys`, nfs4-acl-tools |
| FA | FA1 `flasharray1` 192.0.2.10, Purity//FA 6.12.2. Server `files`, VIF 192.0.2.13, share `\\files.example.local\multiproto` (Z:) |
| FB | FB1 `flashblade1` 203.0.113.20, Purity//FB 4.8.6, S200. FS `multiprotocol`, ACL style `shared`, Safeguard ACLs on (the PR #67 requirement), VIP `fb1data1` 203.0.113.31, share `\\fb1data1.example.local\multiprotocol` (Y:), NFS `/mnt/multiprotocol` on linux1 |
| Scratch | `ps07` directory on each share; FB snapshot `multiprotocol.ps07-before` taken first |

### Privilege setup

`TESTDRIVE\Administrator` starts in each array's local `Administrators` group (DemoForge
`ExternalMembers`). That does not carry the audit privilege: both arrays refused the SACL open
(FA: Access denied; FB: "A required privilege is not held by the client"), and Set-SaclOnly stopped
in its preflight with the `SeSecurityPrivilege` guidance. The identity was added as an external
member to `Audit Operators` and `Backup Operators` on each array's local directory service (FB1
`fb1-ds` via `pureds local group add --external`; FA1 `files-ds` via REST
`/directory-services/local/groups/members`, `resource_type=local/externals`).

The grant only took effect on a new SMB session. Remapping the drive reused the old one; it took
`Remove-SmbMapping -Force` on both drives until `Get-SmbConnection` was empty, then mapping again.

## Results

| Check | Result |
|---|---|
| FA strict passes | **PASS.** 23 objects set, 0 errors, no stop, preflight "root set and read back". Rerun: 23 skipped. The tool's own read-back saw no owner/group/DACL/`S:P` change on any object. |
| FB preflight refuses a strict `-Array FlashBlade` run on a `D:P` root | **PASS.** `STOPPED: preflight: strict policy on FlashBlade with a protected root DACL (D:P) ... No object was written.` Summary `stopped` set, all counts 0. |
| FB strict on an NFS-reset tree stops at the first object | **PASS.** Array unnamed. Stopped on the root, `dacl-unprotected`: `D:P(...)` became `D:(...)` with identical ACEs, and the SACL was set. One object changed; nothing else was written. |
| FB `-Accept dacl-unprotected -Log` lists every object | **PASS.** 24 seen, 23 set, 1 skipped (the root, set by the previous run), `dacl_unprotected_accepted: 23`, 23 log rows, 0 errors. |

FB tree: 24 objects (3 dirs, 21 files), created on linux1 and reset over NFS with `nfs4_setfacl -s`
using `examples/nfsv4_basic.yaml`'s ACEs. That is the same `system.nfs4_acl` write `permissionreset`
makes; `permissionreset` itself was not used (no Go on either host). SMB then showed `D:P` on every object.

Evidence in this directory: `fa-*.txt|json`, `fb-preflight.*`, `fb-strict.*`, `fb-accept.*`
(`fb-accept.csv` is the `-Log`), `sdprobe.ps1` and `sdprobe-output.txt`.

## Reading the DACL on FlashBlade

After the `-Accept` run, `Get-Acl` still showed `D:P` on 22 of 24 objects, and the tool said 23 had
lost it. `sdprobe.ps1` read the same objects six ways at the same moment:

| Reader | FB `a\b\f1.txt` | FB `a\b` |
|---|---|---|
| `GetKernelObjectSecurity`, with or without `ACCESS_SYSTEM_SECURITY` / SACL in the query | `D:`, control `0x8014` | `D:`, no `ID` |
| `GetFileSecurityW` | `D:`, `0x8014` | `D:`, no `ID` |
| `GetNamedSecurityInfoW` | **`D:P`, `0x9014`** | **every ACE `ID`** |
| `Get-Acl` | `D:P`, ACEs reordered | every ACE `ID` |

Every read that returns what the array sent agrees with the tool: FB stores the DACL unprotected.
`GetNamedSecurityInfoW`, which `Get-Acl`, `icacls` and Explorer go through, computes the flags from
the parent. An object whose ACEs cannot come from its parent is reported `P`, and one whose ACEs
match the parent's inheritable ACEs is reported as inherited. The root, whose parent is the share,
is reported as stored. FA stores `P` itself (`0x9004`), so every reader agrees there.

So on FB, Explorer and `icacls` keep showing "inheritance disabled" on objects FB has unprotected.
Whether a later inheritance propagation from a parent then rewrites those objects was not tested.
To check DACL fidelity from SMB, read the descriptor directly (`GetFileSecurityW` or a handle read,
as Set-SaclOnly does), not through `Get-Acl`. This extends the "check from SMB, not NFS" rule in
`benchmarks/sacl-unmapped-sid-20261020/`.

## Teardown

- Scratch `ps07` directories removed from both shares. The FB one had to go from linux1 as root:
  its NFS-written DACLs give no SMB delete right.
- FB1: both grants removed (`pureds local group remove --external`); `Administrators` membership
  left as DemoForge set it.
- **FA1: both grants still in place.** `TESTDRIVE\Administrator` is in `Audit Operators` and
  `Backup Operators` on `files-ds`. `DELETE /directory-services/local/groups/members` answered
  "Local group does not exist" with `member_names`, `member_sids`, and with the directory service
  by name or by id; `member_types=local/externals` is rejected as invalid. Remove it with the FA
  CLI (`pureds local group remove`-equivalent) or let the sandbox expire.
- FB snapshot `multiprotocol.ps07-before` left in place.

## example.net repeat: FB c09-33, 2026-10-26

The FB checks again, on `lab-s200`, an S200 that now reports **Purity//FB 4.8.7** (it
was 4.8.0 for #50–#52, upgraded since). This time the tree was reset with real `permissionreset`.

| | Detail |
|---|---|
| Windows client | `jdoe-win01`, elevated, as `fsa\jdoe`; Set-SaclOnly at `cb8ae8c` |
| NFS client | `client-c`, `/mnt/sacl-fb` (NFSv4.1, `198.51.100.54:/sacl-fb`) |
| FB | FS `sacl-fb`, ACL style `shared`, Safeguard ACLs on; share `\\lab-s200\sacl-fb` |
| Scratch | `ps07/` with `f1`…`f20` (21 objects, created as root); snapshot `sacl-fb.ps07-before` taken first |
| Reset | `permissionreset` `v0.9.6-sacl-32-gcb8ae8c`, `--spec examples/nfsv4_basic.yaml --apply`: 21 enumerated, 21 applied, 0 errors |

`fsa\jdoe` needed no group grants: backup privilege was already on, and both the read and the
write of the SACL succeeded first time. Why it differs from the sandbox's `Audit Operators`/`Backup
Operators` requirement was not looked into.

| Check | Result |
|---|---|
| Dry run | 21 objects, would set 21, 0 errors. |
| FB preflight refuses a strict `-Array FlashBlade` run on a `D:P` root | **PASS.** `STOPPED: preflight: strict policy on FlashBlade with a protected root DACL (D:P)`, nothing written, all counts 0. |
| FB strict on an NFS-reset tree stops at the first object | **PASS.** Array unnamed. Stopped on the root, `dacl-unprotected`: `D:P(...)` became `D:(...)` with identical ACEs, and the SACL was set. `seen 1, set 0, errors 1`, `not_started 0`. |
| FB `-Accept dacl-unprotected -Log` lists every object | **PASS.** 21 seen, 20 set, 1 skipped (the root, set by the previous run), `dacl_unprotected_accepted: 20`, 20 log rows, 0 errors. |

- `not_started` is 0 in the strict run on both labs, where the runbook expected more than 0: the root
  is the pilot and stops the run in the preflight, before any child is listed. The runbook is
  corrected.
- `set 0` for the strict run is the undercount the high-effort review of PR #94 found: the root's
  SACL was written but counted only as an error. From `bdb6cf5` it is counted as `set_then_stopped`.

Teardown: `ps07` removed as root over NFS from linux01. The snapshot `sacl-fb.ps07-before` and
the linux01 mount are left in place.

Evidence (kept in the private lab repository): console output and `-Summary` JSON for each run; `fb-accept.csv` is the `-Log`.
Pester on win01 at `ae2a5eb`: 62 passed, 1 skipped.
