# #50, FlashBlade half: plain `acl:` reset seen from SMB (2026-10-20)

Lab FB `lab-s200` (Purity//FB 4.8.0), `\\lab-s200\sacl-fb` /
`198.51.100.54:/sacl-fb`. Cell 1: `PRINCIPALS=mapped` (numeric ids), no `--sacl`, kernel
transport. Cell 3 (named principals) is in its own section below. linux01 ran the NFS side (`02-reset.sh`, `1f16611`); win-client built the trees and ran
`03-verify-reset.ps1` (`out/<cell>/verify-win.txt`).

| tree | principals | binary | NFS exit | SMB result |
|---|---|---|---|---|
| `fb-reset-m91` | sacl-map2 / sacl-map2-grp (uid 1000003, gid 9224117) | v0.9.1-sacl (`--no-sacl`) | 0 | PASS 10/10: every ACE exact, in spec order |
| `fb-reset-m94` | same | v0.9.4-sacl | 0 | PASS 10/10: every ACE exact, in spec order; identical to m91 |
| `fb-reset-hi94` | sacl-map1 / sacl-map-grp (uid 2000000003, gid 1880600173) | v0.9.4-sacl | 0 (WARNING) | **SIDs replaced** with nonexistent ones |
| `fb-reset-u94` | sacl-nomap1 / sacl-nomap-grp (no uid/gid), named | v0.9.4-sacl | 1 (preflight EINVAL) | nothing written; 0 of 10 descriptors changed |

## Findings

1. **v0.9.1-sacl is not destructive on FB for mapped ids below 1e9.** On m91 and m94, every spec ACE
   came back over SMB with the right SID, type, mask and inherit flags (`fd`, `fdi` → `OICIIO`,
   `fdn` → `OICINP`). Owner and group were unchanged on all 10 objects, and there was no SACL. The two
   trees are byte-identical in SDDL, so v0.9.1-sacl and v0.9.4-sacl write the same DACL.
2. **FB keeps the spec's ACE order. (Corrected 2026-10-20; this finding first said FB sorts them.)**
   The first verify read through `Get-Acl`, which parses the descriptor into a .NET
   `CommonSecurityDescriptor` that re-sorts the DACL, and reported `reordered` on 10/10 objects
   (`EVERYONE@` from last to second). A raw read with `GetFileSecurityW` returns the DACL in exactly the
   spec's order, with `EVERYONE@` last, and the verifier then passes 10/10 on m91 and m94
   (`out/<cell>/verify-win-raw.txt`). m91 and m94 are still identical in raw SDDL on 10/10. Get-Acl
   re-sorts the untouched u94 objects too, so the sort was never FB's. Every reset DACL is `D:P` with
   no `ID` ACEs, and that holds in the raw read: the protected flag is set on all 30 objects the reset
   wrote. `raw-vs-getacl-20261020.json` has both reads of every object. Do not cite the
   DACL-keeping test (#52) as evidence that FB sorts until it is rechecked raw: it read through Get-Acl
   too.
3. **Ids at or above 1e9 are corrupted by a plain reset too (stop and escalate).** On hi94, uid
   2000000003 came back as `S-1-5-21-<FB domain>-1000000003` and gid 1880600173 as `…-880600173`.
   Neither SID exists, so sacl-map1 and sacl-map-grp lost every grant and the deny on all 10 objects
   (30 missing, 30 extra). v0.9.4-sacl printed the #52 WARNING and exited 0. That warning is the only
   guard on this path: #52's refusal covers DACL-keeping rules, not `acl:` rules naming such ids.
4. **Unmapped named principals are refused by FB.** The u94 spec names `sacl-nomap1@example.net` and
   `sacl-nomap-grp@example.net`, which have no RFC 2307 ids. The preflight probe got EINVAL and the run
   exited 1 before any object was touched. The SMB view matches the before snapshot on all 10 objects
   (the verifier FAILs against the spec only because nothing was written).

## Cell 2: mapped ids with `--sacl` (2026-10-21)

`PRINCIPALS=mapped SACL=1` on `fb-reset-c2`: sacl-map2 / sacl-map2-grp (uid 1000003, gid 9224117), with
a `sacl:` block on every rule. This was the first `--sacl` run on FB.

- **Tree and raw snapshot:** win01-a (`ed9d643`).
- **NFS side:** linux01 as root over NFS, v0.9.5-sacl (`f8a6afc`).
- **SMB verify:** win01-a, raw read with `-ExpectSacl` (`out/fb-reset-c2-mapped-sacl1/verify-win-raw.txt`).

8. **`--sacl` works on FB, and the DACL is the same as in cell 1.** The preflight passed, so FB gives root
   over NFS the audit bypass. The run applied 10 objects with 0 errors and exit 0, and printed only the
   audit-policy NOTE. SMB shows the spec DACL exactly on 10/10: SID, mask, flags, order, owner and group.
   The SACL is present on all 10, as `S:(AU;OICISAFA;0x1f0137;;;WD)` on directories and
   `S:(AU;SAFA;0x1f0137;;;WD)` on files.
9. **FB stores the SACL with no control flags.** A raw read finds no `S:P` and no `S:AI` on any of the 10.
   The DACL is `D:P` on all 10 with no `ID` ACEs, as in the other cells. The SACL matches what
   `Set-SaclOnly.ps1` saw on FB (`S:(AU;…)`, not `S:AI(AU;…)`). An inheriting change made later from
   Windows can therefore reach the SACL: it is not protected.
10. `--compare` re-applied all 10 objects, although the second reset changed no bytes. This is the known FB
    name round-trip.

## Cell 3: named principals (2026-10-21)

`PRINCIPALS=named`, no `--sacl`, kernel transport. Each spec names its mapped user and group as
`name@example.net`; juser and jdoe stay numeric. The trees and raw before snapshots came from win01-a
(`d0053d7`, `65ac571`). linux01 ran the NFS side (`24dcc8b`), and win01-a ran `03-verify-reset.ps1`
with a raw read (`out/<cell>/verify-win-raw.txt`).

| tree | principals in spec | binary | NFS exit | SMB result (raw) |
|---|---|---|---|---|
| `fb-reset-n91` | `sacl-map2@` / `sacl-map2-grp@` (uid 1000003, gid 9224117) | v0.9.1-sacl (`--no-sacl`) | 0 | PASS 10/10 |
| `fb-reset-n94` | same | v0.9.4-sacl | 0 | PASS 10/10 |
| `fb-reset-nhi94` | `sacl-map1@` / `sacl-map-grp@` (uid 2000000003, gid 1880600173) | v0.9.4-sacl | 0, **no WARNING** | **FAIL 10/10: SIDs replaced** (30 missing, 30 extra) |

5. **FB resolves `name@domain` to the same SIDs as the numeric ids.** On n91 and n94, `sacl-map2@example.net`
   came back as `…-2503` (EXAMPLE\sacl-map2) and `sacl-map2-grp@example.net` as `…-2502`, the SIDs cell 1 got from
   uid 1000003 and gid 9224117. Every ACE matches the spec in SID, mask, flags and order, owner and group
   are unchanged, and there is no SACL. v0.9.1-sacl and v0.9.4-sacl again write the same DACL.
6. **A name does not avoid the ≥1e9 decode.** On nhi94, FB resolved `sacl-map1@example.net` to uid 2000000003
   and `sacl-map-grp@example.net` to gid 1880600173, then rendered them over SMB as the nonexistent
   `…-1000000003` and `…-880600173`. That is the same corruption as hi94, on the same 30 ACEs. The NFS view
   still shows both principals by name (`1-after-reset.txt`), so an NFS-side check cannot see the damage.
   v0.9.4-sacl exited 0 **with no WARNING**: its ≥1e9 check looked only at numeric who strings. v0.9.5-sacl
   refuses this case (linux01, 2026-10-21); that refusal was not run here.
7. **`--compare` re-applied all 10 objects on every cell**, though the second reset changed no bytes. This
   is the known FB non-convergence, and it shows up with named principals too.

## Cells 4–6: unmapped tree (2026-10-21)

Trees built by `01-setup.ps1` (sacl-nomap1 `…-2776` / sacl-nomap-grp `…-2777`, no uid or gid), raw before
snapshots (`0edb8e4`). NFS side by linux01 with v0.9.5-sacl (`5ec9eb7`).

| tree | principals in spec | SACL | NFS exit | SMB result (raw) |
| --- | --- | --- | --- | --- |
| `fb-reset-c4` | `sacl-nomap1@` / `sacl-nomap-grp@` | 0 | 1 (preflight EINVAL) | 10/10 descriptors unchanged |
| `fb-reset-c5` | same | 1 | 1 (preflight EINVAL) | 10/10 descriptors unchanged |
| `fb-reset-c6` | sacl-map2 / sacl-map2-grp (uid 1000003, gid 9224117) | 0 | 0 | PASS 10/10 |

10. **FB refuses unmapped principals before writing, with or without `--sacl`.** c4 and c5 repeat u94: the
    preflight probe gets EINVAL and the run exits 1. A raw SMB read matches the before snapshot on all 20
    objects, SACL included. The FA collapse to `65534` cannot happen on FB.
11. **The unmapped owner survives a reset on FB.** On c6, `owner-unmapped.txt` keeps owner `…-2776`
    (EXAMPLE\sacl-nomap1) and group `S-1-22-2-10001`. NFS shows that owner as uid 1000002776 (1e9 + RID). The
    reset writes only the DACL, so FB's ≥1e9 decode never touches the owner. Every ACE matches the spec. The
    DACL is `D:P` with no `ID` ACEs, and there is no SACL.

## Open

- Whether to turn the ≥1e9 WARNING into a refusal for `acl:` rules on FB (the kernel transport cannot
  tell FB from FA). Robert's call. (v0.9.5-sacl refuses ≥1e9 ids, including names that resolve to one,
  per cell 3.)
- `--compare` does not converge on FB: it rewrites every object because FB returns numeric ids as
  `name@example.net` (linux01, `02-reset.sh` output). This is a performance bug, not a data bug.

`03-verify-reset.ps1` now reads raw through `../sacl-unmapped-sid-20261020/RawSd.ps1`, as do the setup,
`03-verify.ps1` and `51-sacl-check.ps1` snapshots. Snapshots record `Reader = 'raw'`, and the verifiers
that diff against one refuse a Get-Acl-era `before*.json`. `03-verify-reset.ps1` uses its `-Before` only
for owner and group, which Get-Acl does not change, so the existing snapshots still work there.

`03-verify-reset.ps1` fix: `$before = @{}` overwrote the `-Before` parameter (PowerShell variable names
are case-insensitive), so any run with `-Before` failed. It is renamed to `$beforeSddl`.
