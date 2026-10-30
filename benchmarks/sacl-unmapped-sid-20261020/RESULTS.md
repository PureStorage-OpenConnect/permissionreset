# Unmapped-SID SACL test — results (2026-10-20)

**Array:** lab array A, Purity//FA 6.10.6, `sacl-test:data`
**Tree:** `unmapped-sid-test2`, 10 objects written over SMB
**Tool:** `permissionreset` v0.9.1-sacl-17-g3d3e847, `--sacl`, DACL-keeping spec (one `EVERYONE@` audit ACE)
**Test principals:** `sacl-nomap1` (…-2776) and `sacl-nomap-grp` (…-2777), with no uidNumber/gidNumber. `juser` (…-2699, uid 1445) and `jdoe` (…-2685, uid 1402) are mapped controls.

## Verdict

**FAIL. All 10 objects lost DACL fidelity.** The tool wrote back exactly the bytes it read: `nfs4acl.SplitACL`/`JoinACL`, plus the Phase A write-back with nothing changed. FlashArray accepted every write and returned no errors. The NFS view before and after is identical, and a second run reports 0 changes. The damage shows only from SMB. This is the silent outcome (3).

A FlashArray ACL write over NFS does not preserve an SMB-written DACL. That rules out adding SACLs over NFS on this data, and not only for unmapped users. See finding 3.

## What FlashArray did

1. **Unmapped SIDs collapse to one identity.** On read, every SID without RFC2307 attributes renders as uid `65534`: `sacl-nomap1`, `sacl-nomap-grp`, and also `FSA\Domain Users` (…-513). On write, `65534` becomes `S-1-5-21-2040779448-1261922717-1128908984-501`. That SID is not in the example.net domain. It is probably the array's local guest/nobody account, and it does not resolve on Windows.
2. **Other identities are rewritten too.** `BUILTIN\Administrators` (S-1-5-32-544) reads as uid `0` and writes back as `…-1128908984-500`, the array's local administrator. The group/user distinction is lost: unmapped groups come back without the `g` flag.
3. **The DACL structure changes, mapped principals included.**
   - **Inherited flag dropped on every ACE.** NFS has no way to show it, and FlashArray doesn't emit `INHERITED_ACE`. Every inherited entry becomes explicit, including `juser`'s and `jdoe`'s.
   - **Entries merged or dropped.** Once several SIDs share `65534`, FlashArray keeps one entry per identity. For example, `control-mapped.txt` had user `rx` and group `M`, and now has a single `…-501` `M`.
   - **Entries reordered.** On `\`, `Domain Users` was moved, and the order of the remaining ACEs changed.
4. **The SACL was added on every object** (`sacl-present=True`), so the audit part worked.

## Sample (`writeback-probe.txt`)

| before (SMB) | after (SMB) |
|---|---|
| Deny `sacl-nomap-grp` 0x110000 | Deny `…-501` 0x110000 |
| Allow `sacl-nomap1` 0x1301bf | Allow `…-501` 0x1301bf |
| Allow `juser` rx (inherited) | Allow `…-501` rx |
| Allow `sacl-nomap1` rx (inherited) | Allow `jdoe` FA |
| Allow `sacl-nomap-grp` M (inherited) | Allow `juser` rx |
| Allow `jdoe` FA (inherited) | |

The group deny and the user allow now name the same unresolvable SID. The deny against everyone in the group has become a deny against FlashArray's local nobody account.

## Implications for the 78M-file customer

- RFC2307 attributes in AD would fix finding 1 for the users and groups that have them. Every SID without them still collapses, and that includes built-ins such as `Domain Users` and `BUILTIN\Administrators`.
- RFC2307 does not fix finding 3. With fully mapped principals, inherited flags are still lost and ACEs can still be reordered. That needs its own test: rerun with only mapped principals.
- **Recommended path: apply the SACL from the SMB side.** A Windows write of only the SACL (`SetSecurityInfo` / `Set-Acl` with `SACL_SECURITY_INFORMATION` only) never touches the DACL and involves no SID↔uid translation.
- RISK for `permissionreset --sacl` on FlashArray: on SMB-born data it reports success while damaging the DACL. Before it ships to this customer, it needs a refusal or at least a loud warning when it reads `65534`. It may also need a Windows-side verification step.

## Reproduce

```
Windows:  .\01-setup.ps1 -TestDir <name>
Linux:    sudo ./02-nfs.sh /mnt/sacl-data/<name>
Windows:  .\03-verify.ps1 -TestDir <name>
```

Raw outputs from the Linux side are in `out/`, which is not committed.

---

# Mapped-only control (`mapped-sid-test2`, 2026-10-20)

Same array, tool, and spec. Every SID in every descriptor (owner, group, each ACE) has an RFC 2307 id:
`sacl-map1` uid 2000000003, `sacl-map-grp` gid 1880600173 (the group owner of every object), `juser` 1445, `jdoe` 1402.
`01-setup-mapped.ps1` sets the test dir's whole SDDL, so no share-level entries leak in.

Over NFS every principal rendered as its real id, and groups carried `g`. No `65534` appeared, and the guard did not fire.
The run applied 10 objects with 0 errors, and the second run reported all 10 converged.

## Verdict: identities survive, inheritance does not

| | result |
|---|---|
| Owner and group SIDs | same on all 10 objects |
| ACE SIDs | same on all 10 objects; no SID changed or was lost |
| Objects with only explicit ACEs (`\`, `protected.txt`) | **PASS**: identical DACL, SACL added |
| Objects with inherited ACEs (8) | **FAIL**: the inherited flag is cleared on every inherited ACE |
| Explicit and inherited allow ACEs for the same SID (3 objects) | **merged** into one explicit ACE |

The merges seen:
- `control-mapped.txt`: juser explicit M + juser inherited RX → one explicit juser M
- `explicit-allow.txt`: sacl-map1 explicit F + inherited RX → one explicit F
- `writeback-probe.txt`: sacl-map1 explicit M + inherited RX → one explicit M

Each merged mask already included the other, so effective access is unchanged on all 10 objects in this test.
Deny-first order was kept.

## Why

FA's NFS rendering never exposes an inherited marker. `ACE4_INHERITED_ACE` (0x80) is absent from the raw flags of
every inherited entry (`out-mapped/0-baseline.hex`: flags are only 0x0, 0x3 fd, and 0x40 g). An NFS write therefore carries no inheritance
information, and FA stores every ACE as explicit, folding duplicates by SID. permissionreset cannot tell an inherited ACE
from an explicit one over NFS, so this cannot be detected or avoided per object from the client.

## What it means for a migrated tree

Almost every object in a migrated tree carries inherited ACEs, so after an NFS SACL pass:
- each object keeps today's effective access, but as a flat explicit DACL;
- a later change to a parent folder's permissions in Windows no longer propagates to cleaned-up children the way
  it did. Access removed at the parent stays on the children as explicit entries;
- "Inherited from" in Windows Explorer and `icacls` shows nothing, and DACL-compare tooling flags every object.

That fails the customer requirement that DACLs stay identical, even with full RFC 2307 coverage. **Adding SACLs from SMB,
writing only the SACL, remains the recommended path for SMB-written data.** FlashBlade is still untested.

---

# SMB-side SACL pass (`Set-SaclOnly.ps1`)

This is the recommended path for SMB-written data. It writes only the SACL, with
`SetFileSecurityW(SACL_SECURITY_INFORMATION)`, so the owner, group and DACL are never part of the write and
no SID-to-uid translation happens. It checks owner, group and DACL before and after each object and stops on
any change.

Test (Windows, elevated, as a domain admin):

```powershell
# mapped and unmapped trees, fresh
.\01-setup-mapped.ps1 -TestDir smbsacl-mapped1   -Out before-smbsacl-mapped.json
.\01-setup.ps1        -TestDir smbsacl-unmapped1 -Out before-smbsacl-unmapped.json

$s = '\\198.51.100.242\sacl-data'
.\Set-SaclOnly.ps1 -Path "$s\smbsacl-mapped1"                                 # dry run: "Would set: 10"
.\Set-SaclOnly.ps1 -Path "$s\smbsacl-mapped1"   -Apply -Log smbsacl-mapped.csv
.\Set-SaclOnly.ps1 -Path "$s\smbsacl-unmapped1" -Apply -Log smbsacl-unmapped.csv
.\Set-SaclOnly.ps1 -Path "$s\smbsacl-mapped1"   -Apply                        # rerun: "Skipped: 10"

.\03-verify.ps1 -TestDir smbsacl-mapped1   -Before before-smbsacl-mapped.json     # want: all PASS
.\03-verify.ps1 -TestDir smbsacl-unmapped1 -Before before-smbsacl-unmapped.json   # want: all PASS

# a file created afterwards inherits the audit ACE
'x' | Set-Content "$s\smbsacl-mapped1\sub\new.txt"
(Get-Acl "$s\smbsacl-mapped1\sub\new.txt" -Audit).Sddl                          # want: S:AI(AU;IDSAFA;FA;;;WD)
```

## Result (2026-10-20): PASS

| | mapped tree (`smbsacl-mapped1`) | unmapped tree (`smbsacl-unmapped1`) |
|---|---|---|
| Dry run | Would set: 10, nothing written | n/a |
| Apply | Set: 10, Errors: 0 | Set: 10, Errors: 0 |
| Rerun | Skipped: 10 (already correct) | n/a |
| `03-verify.ps1` | **10/10 PASS**: owner, group and DACL identical, inherited flags included; SACL present | **10/10 PASS**, including unmapped SIDs, `Domain Users`, and `BUILTIN\Administrators` |

- Per-object owner/group/DACL check: never tripped.
- A file created afterwards in `sub\` inherited the audit ACE: `S:AI(AU;IDSAFA;FA;;;WD)`.
- NFS view (`nfs4_getfacl`, root): dirs `U:fdSF:EVERYONE@:rwaDdxtTnNcCoy`, files `U:SF:EVERYONE@:rwadxtTnNcCoy`. That is the same
  layout the NFS spec writes.

**Writing only the SACL over SMB meets the customer requirement on FA 6.10.6 whether or not principals have RFC 2307
ids.** Throughput was not measured: 10 objects is too few, and the script runs on a single thread.

## Throughput

`Set-SaclOnly.ps1` now runs a parallel C# walker (`-Threads`), and `Time-SaclOnly.ps1` sweeps thread counts
on `smbperf\t40k` (45,409 objects) and `smbperf\t200k` (227,009). See WINDOWS.md. Results: _pending_.
