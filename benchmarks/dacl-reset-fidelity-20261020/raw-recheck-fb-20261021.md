# FB raw recheck of the Get-Acl claims (2026-10-21)

FB half of the HANDOFF "At risk" recheck. win01-a has the FA half. Read-only over SMB from win-client
against `\\lab-s200\sacl-fb` (FB 4.8.0). Every object in every tree on the share was read:
170 objects plus the share root, raw (`Get-RawSddl -Audit`, GetFileSecurityW) and `(Get-Acl -Audit).Sddl`.
No array writes. Data: `raw-recheck-fb-20261021.json`. Each object has both SDDLs, the raw DACL and SACL
control, and how Get-Acl differs from raw.

## Why Get-Acl is wrong when it is wrong

.NET's `CommonAcl` reorders and merges a DACL only when it is **already canonical** (denies before allows,
explicit before inherited). Within that order it sorts the ACEs and merges ACEs for the same SID. A
non-canonical DACL passes through unchanged (see d). Every FB object read here is canonical in raw
(0/170 non-canonical), but its ACEs are not sorted by SID. So Get-Acl reorders or merges them, and any claim
about order or merging that was read through Get-Acl is wrong exactly in that case.

## Verdicts

| | Claim | Verdict |
|---|---|---|
| a | FB #52: "ACEs are sorted canonically" after the NFS write-back | **GET-ACL ARTIFACT** |
| b | FB: "every DACL becomes protected (`D:P`)" | **CONFIRMED** |
| c | "FB marks every SACL protected by default" (and `Set-SaclOnly.ps1:167`) | **REFUTED** |
| d | `generate_tree_windows.py`'s non-canonical order lands on disk | **CONFIRMED client side**; not read on the array |

**a. GET-ACL ARTIFACT.** FB keeps the order it was given. The SMB-only twin trees give a raw "before" that
never went through NFS: `fb-smbsacl-unmapped1` for `fb-unmapped1`, and `fb-smbsacl-mapped1` for `fb-mapped2`.
After dropping `ID` and applying the #52 SID rewrite (`S-1-22-2-10001` and `BA` become `<dom>-10001` and
`<dom>-544`), the raw DACL is the same ACE sequence as the twin on **20/20** objects. Get-Acl re-sorted 6
objects in `fb-unmapped1` and merged same-SID ACEs on 10 of the 30 #52 objects (5→4, 6→5, 8→7 ACEs). This
also refutes **"ACEs for the same SID are merged"** on FB (`sacl-unmapped-sid-20261020/WINDOWS.md:137`, and the
`fb-mapped2` table in that dir's `RESULTS.md`, which says "the merge is in FB's SMB rendering"). In raw,
13/30 #52 objects keep both ACEs, for example `control-mapped.txt`: `(A;;0x1301bf;;;juser)(A;;0x1200a9;;;juser)`.
The other #50 trees agree. Raw and Get-Acl ACE order differ on all 80 objects of the eight `D:P` `fb-reset-*`
trees, and in each case only the order differs.

**b. CONFIRMED.** Raw `D:P` (no `AR`/`AI`) on **30/30** objects in `fb-unmapped1`, `fb-mapped1` and
`fb-mapped2`. The earlier "27/27" counted three fewer; all 30 have `D:P`, `writeback-probe.txt` included.
Get-Acl agrees on these. Raw `D:P` is also on 80/80 objects of `fb-reset-c2`, `-c6`, `-hi94`, `-m91`, `-m94`,
`-n91`, `-n94` and `-nhi94`. The SMB-only twins read `D:ARAI` with `ID` ACEs, and `D:PARAI` only on `\` and
`protected.txt`, so the `P` comes from the NFS write. Not part of this claim: `fb-reset-c4`, `-c5` and `-u94`
read `D:ARAI`/`D:PARAI` (not `D:P`). On `fb-sacl51`, 8 objects read raw `D:` after the SMB SACL write that
cleared `P` (as `RESULTS.md` records), and Get-Acl still shows `D:P` on those 8.

**c. REFUTED.** Raw `S:P` appears on **1/170** objects: `fb-sacl51\control-mapped.txt`, which was deliberately
written as `S:P(...)`. Every other SACL and the share root read `S:` with no control flags. Get-Acl agrees with
raw on SACL control for all 170, so it does not add `P`. In the Get-Acl-era before snapshots, `S:PAI` appears
only in trees set up by `01-setup-mapped.ps1`, which uses `Set-Acl` (`before-fbm1`, `-fbm2` and
`-fb-smbsacl-mapped1`). The trees set up with icacls (`before-fbu1`, `-fb-smbsacl-unmapped1` and `-fbs51`)
read `S:`. `fb-smbsacl-mapped1` never had an NFS write, but its `S:PAI` is now `S:` in raw. The SMB write by
`Set-SaclOnly` (`S:AI(...)`) replaced it, so an SMB write clears `P` too.
- `Set-SaclOnly.ps1:167`: the part "stores S:AI(...) as S:(...)" holds (raw `S:` on every object it wrote).
  The part "marks SACLs protected by default" is wrong.
- `RESULTS.md:401`, "`S:PAI` → `S:`: FB marks every SACL protected by default, and the NFS write clears it":
  the first half is wrong. The `PAI` came from the `Set-Acl` setup. The second half is consistent with the
  data, but it is not specific to NFS. The pre-NFS state cannot be read raw now, because those snapshots are
  Get-Acl.

**d. CONFIRMED client side; array not read.** `\\fb-lab-01` is in a separate lab domain and does not resolve or
answer on 445 from win-client (example.net), so no generated tree could be read. Instead, the generator's
`APPLY_PS` path (`New-Object FileSecurity`/`DirectorySecurity`, `SetSecurityDescriptorSddlForm`, `Set-Acl`) was
run on local NTFS with the `noncanonical_order` shape: allow, deny, allow, allow, protected, plus a second
allow for one SID. Raw read back is the exact input order: the deny stays second and the duplicate SID is not
merged. Get-Acl shows the same, because the ACL is non-canonical. On files .NET drops `OICI`, which is expected.
So Set-Acl sends the non-canonical order. Whether the array stores it is unverified. FB kept the raw order it
was given in (a), but none of those inputs was non-canonical. Closing this needs a raw read of a
`noncanonical_order` dir from a host in that domain.

## Follow-ups (not done here)

- `RawSd.ps1`'s header says Get-Acl "re-sorts the DACL into canonical order". More exactly, it sorts and merges
  a DACL that is already canonical, and leaves a non-canonical one alone.
- Fix `WINDOWS.md:137`, the `fb-mapped2` merge row and `S:PAI` row in `RESULTS.md`, and `Set-SaclOnly.ps1:167`.
