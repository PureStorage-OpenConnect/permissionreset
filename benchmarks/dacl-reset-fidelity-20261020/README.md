# DACL-reset fidelity on FlashArray: run sheet (2026-10-20)

This is the follow-up to `../sacl-unmapped-sid-20261020/`. That test covered a **DACL-keeping** `--sacl`
pass, which reads each object's DACL and writes it back. This one covers a **regular reset**: `acl:` rules
replace the DACL.

The question: when permissionreset writes a spec DACL over NFS, does SMB show exactly that DACL? The test runs
with mapped and unmapped principals, and with and without `--sacl`.

The oracle is the rendered spec, not `before.json`. A reset replaces the DACL, so "same as before" fails
by design. `before.json` is used only to check that the owner and group are unchanged, because setxattr
does not set the owner.

## Files

| file | where | what |
|---|---|---|
| `spec.tmpl.yaml` | — | Spec template. It covers a deny ACE, user and group allows, `fd`, `fdi` (inherit-only), `fdn` (no-propagate) and `EVERYONE@`. `OWNER@`/`GROUP@` are not covered: the trees' owner is also named explicitly, so the two ACEs would be indistinguishable. |
| `02-reset.sh` | Linux, root | Renders the spec for one cell, runs the reset twice (the second with `--compare`), and dumps the NFS view to `out/<cell>/`. |
| `03-verify-reset.ps1` | Windows | Builds the expected DACL from the rendered spec and resolves each principal through AD. It then compares that DACL with what SMB shows and classifies each difference. |
| `../sacl-unmapped-sid-20261020/01-setup-mapped.ps1` | Windows | Builds the mapped tree. Every SID in it has an RFC 2307 id. |
| `../sacl-unmapped-sid-20261020/01-setup.ps1` | Windows | Builds the unmapped tree (`sacl-nomap1` and `sacl-nomap-grp`, with no uid or gid). |

## Axes

- **Principals in the spec** (`PRINCIPALS=`):
  - `mapped`: numeric RFC 2307 ids. FlashArray maps uid/gid to SID.
  - `named`: the same mapped principals, written as `name@example.net`.
  - `unmapped`: `sacl-nomap1@example.net` and `sacl-nomap-grp@example.net`. These have no uidNumber or gidNumber, so this is the cell where uid mapping does not hit.
- **SACL** (`SACL=`):
  - `0`: plain reset with no `--sacl`. This is the main case.
  - `1`: `--sacl`, with a `sacl:` block on every rule.
- **Tree**: built by `01-setup-mapped.ps1` or `01-setup.ps1`. Only the owner and group of the existing tree survive a reset. The unmapped tree tests whether an unmapped owner survives.

**Transport:** kernel only. Userspace refuses FlashArray (`ErrFlashArrayNotSupported`). On kernel, the
`system.nfs4_acl` xattr carries the who strings verbatim, so the client's idmapd is not involved. FlashArray
resolves each name or id itself.

## Before the first cell

```bash
make build    # permissionreset must be v0.9.2-sacl-19-g7d17d01 or later; 02-reset.sh uses $REPO/permissionreset
```

Run the Linux side on a client that mounts the FA data VIF. The scripts default to
`/mnt/sacl-data` from `\\198.51.100.242\sacl-data`. client-a mounts only the FB.
Run as root, because the `--sacl` cells need the audit bypass, as in the earlier test.

For each cell, use a fresh `-TestDir` and its own `before.json`.

## Cells, in priority order

If cell 1 does not render correctly on SMB, the other cells do not matter. Stop there and report.

| # | tree | PRINCIPALS | SACL | answers |
|---|---|---|---|---|
| 1 | mapped | mapped | 0 | Does a plain reset with mapped ids produce the exact DACL on SMB? |
| 2 | mapped | mapped | 1 | Is the DACL identical to cell 1, with a SACL added? |
| 3 | mapped | named | 0 | Does FlashArray resolve `name@domain` to the same SIDs as the numeric ids? |
| 4 | unmapped | unmapped | 0 | What happens to principals without a uid (nobody/65534 collapse, `…-501`)? |
| 5 | unmapped | unmapped | 1 | Same as cell 4, with `--sacl`. |
| 6 | unmapped | mapped | 0 | Does the unmapped owner of `owner-unmapped.txt` survive a reset? |

Cell 1:

```powershell
# Windows
cd ..\sacl-unmapped-sid-20261020
.\01-setup-mapped.ps1 -TestDir reset-c1 -Out ..\dacl-reset-fidelity-20261020\before-c1.json
```
```bash
# Linux
sudo PRINCIPALS=mapped SACL=0 ./02-reset.sh /mnt/sacl-data/reset-c1
```
```powershell
# Windows: copy out/reset-c1-mapped-sacl0/spec.yaml over first
.\03-verify-reset.ps1 -TestDir reset-c1 -Spec .\out\reset-c1-mapped-sacl0\spec.yaml -Before .\before-c1.json
```

The other cells follow the same pattern:

- Cells 2 and 5: add `SACL=1` on Linux and `-ExpectSacl` on Windows.
- Cells 4–6: use `01-setup.ps1` (which prompts for the `sacl-nomap1` password).

For a domain other than example.net, pass these env vars to `02-reset.sh`:

- `MAP_UID`, `MAP_GID`, `CTL_UID`, `ME_UID`: the ids that `01-setup-mapped.ps1` prints.
- `NFS_DOMAIN`.

Also pass `-Domain` and `-UpnSuffix` to the setup scripts.

## Reading the result

- **`02-reset.sh`** prints three checks:
  - whether FlashArray rendered `65534`/nobody back;
  - whether the second reset changed any bytes. A change means FlashArray did not store what was sent;
  - the exit codes. A refused name shows up as a nonzero exit.
- **`03-verify-reset.ps1`** prints PASS or FAIL per object and a tally:
  - `missing ACE`, `extra ACE` (FlashArray-synthesized entries show up here);
  - `mask changed`, `flags changed`, `reordered`;
  - `INHERITED_ACE set`, `RID 500/501 or unresolved SID`;
  - `owner changed` / `group changed`, `SACL state wrong`;
  - whether `OWNER@` came back as the object SID or as CREATOR OWNER.
- **No inherited flag:** permissionreset stamps every object explicitly, so no ACE should carry
  `INHERITED_ACE`, and Explorer will not show "Inherited from". Record that as a finding. Whether it
  breaks the customer's requirement is a call for RESULTS, not a script FAIL.

Record findings in a new `RESULTS.md` here. Leave the committed DACL-keeping `RESULTS.md` in the sibling directory as it is.

`03-verify-reset.ps1` has not been run yet. This host has no `pwsh`. If it fails to parse, the error will
point at the line.
