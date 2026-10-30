# #50, FlashArray half: plain `acl:` reset seen from SMB (2026-10-21)

FA lab array A (Purity//FA 6.10.6), `\\198.51.100.242\sacl-data` / `/mnt/sacl-data` (root,
`vers=4.1,nconnect=8`), kernel transport. All six README cells ran.

- **Trees and raw before snapshots:** win01-a (`1d08736`).
- **NFS side:** linux01 with v0.9.5-sacl (`0fe2113`, the release tarball) (`87e7309`).
- **SMB verify:** win01-a ran `03-verify-reset.ps1` with a raw read (`out/<cell>/verify-win-raw.txt`).

The mapped principals are sacl-map2 / sacl-map2-grp (uid 1000003, gid 9224117), not the README's
sacl-map1. v0.9.5 refuses ids ≥ 1e9, and sacl-map2 makes the cells comparable with `RESULTS-fb.md`.
The unmapped principals are sacl-nomap1 / sacl-nomap-grp, which have no uidNumber or gidNumber.

| cell | tree | principals in spec | `--sacl` | NFS view after reset | `--compare` rerun | SMB result (raw) |
|---|---|---|---|---|---|---|
| c1 | mapped | numeric ids | no | ids | 0 applied | PASS 10/10 |
| c2 | mapped | numeric ids | yes | ids, `U:` ACEs | 0 applied | PASS 10/10, SACL present |
| c3 | mapped | `name@example.net` | no | — | 10 re-applied | PASS 10/10 |
| c4 | unmapped | `sacl-nomap*@example.net` | no | **`65534`** for all 3 nomap ACEs | 10 re-applied | PASS 10/10 |
| c5 | unmapped | `sacl-nomap*@example.net` | yes | **`65534`**, `U:` ACEs | 10 re-applied | PASS 10/10, SACL present |
| c6 | unmapped | numeric ids | no | ids | 0 applied | PASS 10/10 |

Every cell exited 0 with 0 errors. In every cell, the second reset changed no bytes.

## Findings

1. **A plain reset with ids below 1e9 writes exactly the spec DACL on FA (c1).** Every ACE matches the
   spec in SID, type, mask, inherit flags and order. Owner and group are unchanged, and there is no SACL.
   This is the same result as FB cell 1 (m91/m94).
2. **`--sacl` adds the SACL and leaves the DACL as in c1 (c2).** The SMB view shows the spec DACL plus the
   audit ACEs. The NFS view shows `U:fdSF:EVERYONE@` on the 2 directories and `U:SF:EVERYONE@` on the 8
   files.
3. **FA resolves `name@domain` to the same SIDs as the numeric ids (c3).** `sacl-map2@example.net` comes back
   as `…-2503` and `sacl-map2-grp@example.net` as `…-2502`. That matches FB cell 3. `--compare` does not
   converge with names, on FA as on FB.
4. **FA accepts principals that have no uid, keeps their SIDs, and shows them as `65534` over NFS
   (c4, c5).** FB refused the same spec with EINVAL at preflight. FA accepted it, and SMB shows the right
   accounts: EXAMPLE\sacl-nomap1 (`…-2776`) and EXAMPLE\sacl-nomap-grp (`…-2777`), with no `…-501` or
   unresolved SIDs. Over NFS, all three ACEs that name them, user and group alike, read back as `65534`.
   So the data is right, but **the NFS view loses the identity**:
   - Any tool that reads these ACLs over NFS and writes them back would write `65534` and collapse both
     principals into nobody. A DACL-keeping `sacl:` pass is one such tool. The RISKS #11
     `ErrUnmappedPrincipal` guard exists to refuse exactly that.
   - A verifier that works only from NFS cannot tell this tree from a broken one.
   - v0.9.5 let the reset through. The only signal was `02-reset.sh`'s own 65534 check; permissionreset printed
     no refusal. `--compare` re-applies all 10 objects, because the NFS view never matches the spec.
5. **An unmapped owner survives a reset (c6).** `owner-unmapped.txt` keeps owner `…-2776` (sacl-nomap1) and
   group Domain Users, as in the before snapshot. The DACL is replaced with the spec's, and it is `D:P`.
6. **Every reset DACL is `D:P` with no `ID` ACEs, read raw.** Explorer will show no "Inherited from" on
   any object. This is expected for an explicit stamp, and the same as FB.

## Ids at or above 1e9 (2026-10-21)

Two more trees with sacl-map1 / sacl-map-grp (uid 2000000003, gid 1880600173), the principals that FB
corrupts (`RESULTS-fb.md` hi94/nhi94).

- **Trees and raw snapshots:** win01-a (`a079520`).
- **NFS side:** linux01 with v0.9.5-sacl, `--allow-high-ids` passed through `EXTRA_FLAGS` (`f3d9916`).

| tree | principals in spec | NFS exit | `--compare` rerun | SMB result (raw) |
|---|---|---|---|---|
| `fa-reset-hi` | numeric ids | 0, ≥1e9 WARNING | 0 applied | PASS 10/10 |
| `fa-reset-nhi` | `sacl-map1@` / `sacl-map-grp@` | 0, ≥1e9 WARNING | 10 re-applied | PASS 10/10 |

7. **FA has no ≥1e9 problem.** SMB shows EXAMPLE\sacl-map1 (`…-2779`) and EXAMPLE\sacl-map-grp (`…-2778`) on every
   ACE, whether the spec names them by id or by name. There is no 65534. The decode to `1000000000 + RID` is
   FB-only, so `--allow-high-ids` is safe on a FlashArray target, as its help text says.

## FA against FB

| | FA (lab array A) | FB (s200, 4.8.0) |
|---|---|---|
| numeric ids < 1e9 | exact | exact |
| `name@domain` < 1e9 | exact, same SIDs | exact, same SIDs |
| ids ≥ 1e9, numeric or named | exact (`--allow-high-ids`) | SIDs replaced with nonexistent ones |
| principal with no uid | accepted; SID kept; NFS shows `65534` | refused at preflight (EINVAL) |
| ACE order | spec order | spec order |
| `--compare` | converges with ids, not with names or unmapped | does not converge (FB returns names) |

## Open

- A plain `acl:` reset whose principals read back as `65534` should **warn**, not refuse; this is
  expected FA behaviour (Robert, 2026-10-21). win01-a is implementing it on `feat/warn-unmapped-reset`.
