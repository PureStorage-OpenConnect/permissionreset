# Raw recheck of the FA Get-Acl claims (2026-10-21, win01-a)

Read-only. Every object in eight trees on lab array A `\\198.51.100.242\sacl-data` was read twice:
raw (`RawSd.ps1` `Get-RawSddl -Audit`) and `Get-Acl -Audit`. Per-object SDDL from both readers is in
`raw-recheck-fa-20261021.json`. Trees: `unmapped-sid-test`, `unmapped-sid-test2`, `mapped-sid-test1`,
`mapped-sid-test2`, `smbsacl-mapped1`, `smbsacl-mapped3`, `smbsacl-unmapped1`, `smbsacl-unmapped3` (81 objects).

Raw and Get-Acl agree on 64 of the 81 objects. They disagree on 17: all 10 in `unmapped-sid-test2`, 3 in
`mapped-sid-test2`, and 2 each in `unmapped-sid-test`, `smbsacl-unmapped1` and `smbsacl-unmapped3`. Each
disagreement is one of two things that Get-Acl does: it re-sorts the DACL, and it merges ACEs that share a SID and
flags into one ACE with the masks ORed. Owner, group, the control flags and the SACL agree on every object.

## Verdicts

| claim (where) | verdict | evidence |
| --- | --- | --- |
| FA "entries reordered" after an NFS write; "on `\`, Domain Users was moved" (`sacl-unmapped-sid-20261020/RESULTS.md` finding 3; RISKS #11) | **Get-Acl artifact** | Raw `unmapped-sid-test2\` keeps the setup order (compare raw `smbsacl-unmapped1\`, which is SMB-only); Domain Users became `…-501` in place. Raw `mapped-sid-test2` matches the NFS `1-after-apply.txt` order ACE for ACE (e.g. `control-mapped.txt`: 1445 M, 1402 F, 1445 RX, 1880600173 M, 2000000003 RX). |
| FA "deny-first order was kept" (`RESULTS.md` mapped-only control) | **Confirmed**, but trivially | Raw deny is at index 0 on `explicit-deny.txt` and `writeback-probe.txt`, the same place as in the NFS view. FA keeps every ACE where it was written, deny or not. |
| FA "explicit and inherited allows for the same SID merged into one explicit ACE" (`RESULTS.md` mapped-only control; README, CHANGELOG, runbook, customer README) | **Get-Acl artifact** | Raw `mapped-sid-test2\control-mapped.txt` has 5 ACEs, including juser `0x1301bf` and juser `0x1200a9` as two separate entries; Get-Acl shows 4. Inherited flags are still lost (the `ID` bits are gone in the raw read too), so that finding stands. |
| FA "entries merged or dropped once several SIDs share 65534" (`RESULTS.md` finding 3) | **Get-Acl artifact** | Raw `unmapped-sid-test2\control-mapped.txt` has 5 ACEs: juser M, juser RX, `…-501` RX, `…-501` M, jdoe F. Get-Acl shows 3. No entry is dropped; they now all name `…-501`, which is still the access loss the RISKS #11 guard prevents. |
| FA `S:P` on a SACL written over NFS | **Confirmed** | Raw reads `S:P` on every object of `unmapped-sid-test2` and `mapped-sid-test2`. SACLs written over SMB by Set-SaclOnly read `S:AI` raw, as written. |

## Docs to correct

Remove "ACEs merged per SID" and "entries reordered" from the FA descriptions (README, CHANGELOG, the
runbook, the customer README, RISKS #11, `sacl-unmapped-sid-20261020/RESULTS.md`). What remains true on FA
after an NFS ACL write is that inherited flags are cleared and the DACL is marked `D:P`, and that an
unmapped principal turns into `…-501` (nobody).
