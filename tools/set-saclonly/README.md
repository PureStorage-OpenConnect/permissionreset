# Set-SaclOnly

Writes audit ACEs (the SACL) on every object in a tree **over SMB**, and nothing else: owner, group and
DACL are never part of the write. Use it for data written over SMB, where an NFS ACL write-back flattens
inheritance on FlashArray and FlashBlade, and also loses or corrupts SIDs (RISKS.md #11, #12). Run it
after any NFS DACL repair: an `acl:` run without `--sacl` deletes SACLs.

| File | What it is |
|---|---|
| `Set-SaclOnly.ps1` | The script: parameters, progress and the summary. |
| `SaclOnly.cs` | The engine, compiled by `Add-Type`: the parallel walk, handle I/O, Go-compatible globs, and rule and exclude matching. |
| `SaclPlan.ps1` | Turns a `build-spec --sacl-plan` JSON into rules and SACLs, and resolves principals to SIDs. |
| `Set-SaclOnly.Tests.ps1` | Pester tests (source repo only, not in the release package). |
| `testdata/` | Source repo only. `glob-vectors.json` (Go's `path.Match` answers, from `genvectors.go`) and `plan-golden.json` (a copy of `cmd/build_spec/testdata/saclplan.golden.json`). |

## Requirements

- Windows PowerShell 5.1 or PowerShell 7, in an elevated shell.
- SeSecurityPrivilege, and SeBackupPrivilege unless you pass `-NoBackup`. Local Administrators hold both.
- On FlashArray, the identity also needs the array's audit bypass to keep SACLs. Domain Admins membership
  alone is not enough.
- For `-Spec`, a `build-spec` with `--sacl-plan`. The script uses `-BuildSpec` if given, then
  `build-spec.exe` beside the script, then PATH. Without one, make the plan on another host and pass `-Plan`.

## Usage

```powershell
# One SACL for the whole tree: Everyone, all access, success and failure.
.\Set-SaclOnly.ps1 -Path \\array\share\dept                                   # dry run
.\Set-SaclOnly.ps1 -Path \\array\share\dept -Apply -Threads 128 -Log sacl.csv

# The sacl: rules of a permissionreset spec, selected per object as permissionreset selects them.
.\Set-SaclOnly.ps1 -Path \\array\share\dept -Spec audit.yaml -Apply -Log sacl.csv
build-spec --sacl-plan audit.yaml > audit-plan.json                          # on a host with build-spec
.\Set-SaclOnly.ps1 -Path \\array\share\dept -Plan audit-plan.json -Apply
```

`Get-Help .\Set-SaclOnly.ps1 -Full` has every parameter.

## Behaviour

- **Backup semantics.** Every object and every directory listing is opened through a handle with backup
  intent. With SeBackupPrivilege enabled, a directory whose DACL denies Administrators is still read,
  listed and given its SACL. The SACL write needs only ACCESS_SYSTEM_SECURITY (SeSecurityPrivilege), so
  SeRestorePrivilege is never used, and is turned off at start: enabled, it would grant a backup-intent
  open READ_CONTROL. `-NoBackup` turns SeBackupPrivilege off, because a child process inherits its
  parent's enabled privileges. Over SMB the array decides what backup intent grants. FlashArray and
  FlashBlade both honor it: in a lab test, a directory and a file whose DACLs grant only another user were
  listed, read and set with it, and refused under `-NoBackup`.
- **Spec selection matches permissionreset.** Rules are tried in order. A rule matches when its type
  (`file`, `directory` or empty) fits and its pattern matches the base name. The first match wins, else
  the default applies. An exclude without `/` matches the base name at any depth. An exclude with `/` is
  anchored at the root. An excluded directory is pruned whole, and the root is never excluded. Patterns
  use Go's glob syntax and are case-sensitive, as on NFS. build-spec validates and splits them, so the
  script never parses YAML.
- **What a spec may contain.** Every rule must be `sacl:`-only. A rule with `acl:` or `dacl:` refuses the
  whole spec before anything is touched, since that spec is for permissionreset. A rule with no `sacl:` key
  leaves the objects it selects untouched. On FlashArray, "untouched" isn't "not audited": an object with
  no explicit audit ACE shows its parent's inheritable ones (`ID`), so an excluded or left object under a
  directory whose SACL is inheritable is audited anyway. FlashBlade doesn't do this. `sacl: []` writes an empty SACL. Owner and group are never
  applied. Principals: `EVERYONE@`, `OWNER@` and `GROUP@` map to `WD`, `CO` and `CG`. A name is looked
  up on this host (`name@domain` or `DOMAIN\name`). A numeric id is refused, because an SMB ACE needs a SID.
- **Root preflight.** Before any other object is opened, the root is read and, with `-Apply`, given its
  SACL and read back, even under `-NoReadback`. A refused read or write, or a SACL the array doesn't keep,
  stops the run with `preflight:` and the missing privilege (on FlashArray, the audit bypass), with no
  other object touched. A root that already has its SACL isn't rewritten, so a rerun proves only the read.
  A root whose rule has no `sacl:` key isn't probed. The `Preflight:` line says which case applied.
- **SACL control flags are kept.** Each write copies the object's own `S:P` (protected) and `S:AI`
  (auto-inherited) flags, so only the audit ACEs change, whatever the plan's SDDL says. An object
  whose `S:P` changed stops the run (`sacl-protection-changed`, below). FlashBlade stores an `S:AI`
  write as `S:`, and that isn't checked, since it changes nothing that's audited.
- **Policy: strict by default.** Owner, group, the DACL (every ACE's type, flags, mask and SID, their
  order, and the DACL's control flags) and the SACL's `S:P` are read before and after every write. Any
  change is an error named in `-Log` (`owner-changed`, `group-changed`, `dacl-changed`,
  `dacl-unprotected`, `sacl-protection-changed`), and the run stops: no further write is started, and
  writes already in flight finish and are checked (`Not started:` counts objects read after the stop).
  Detection is after the write, so the object that tripped it keeps the change; nothing here undoes it.
  It keeps its new SACL too, and is counted under `Set, then stopped:` (`set_then_stopped` in
  `-Summary`) and in `Errors`, not under `Set`.
  An object that already has the wanted SACL is skipped, so a rerun resumes.
- **Accepting FlashBlade's `D:P` loss.** On FlashBlade, a tree that was reset over NFS (`permissionreset` with
  `acl:`) loses the DACL's protected flag (`D:P`) on every object whose SACL this script writes over SMB.
  The ACEs, their order and their flags stay the same, so access is unchanged, but the next time an
  admin propagates permissions from a parent, the parent's inheritable ACEs reach those objects. A
  strict run stops at the first one. `-Accept dacl-unprotected` lets exactly that change through, and
  only with `-Log`: each occurrence is counted (`dacl-unprotected:`) and listed. No other change can be
  accepted. The script never writes the DACL, so it doesn't put `D:P` back. Don't confirm the loss
  with `Get-Acl`, `icacls` or Explorer: on FlashBlade they compute `P` from the parent and keep
  showing inheritance disabled on objects the array stores unprotected. The script's own read-back
  (`GetFileSecurityW`) and `-Log` are the record.
- **`-Array`.** `FlashBlade` refuses a strict run whose root DACL is `D:P` before anything is written,
  since that write is known to clear it. `FlashArray` and `Unknown` (the default) run, and `Unknown`
  says in the `Preflight:` line that the D:P behavior is unchecked, so the first object the array
  changes is the pilot that stops the run.
- **`-Summary`** writes a JSON file (`set-saclonly-summary/1`) with the policy, the accepted changes,
  `-Array`, the preflight result, why the run stopped, and every count.
- **Reparse points** are opened as themselves and never followed.

## Tests

```powershell
Invoke-Pester tools/set-saclonly        # Pester 5 or later
$env:SACLONLY_BUILD_SPEC = 'C:\path\build-spec.exe'   # optional: also run the -Spec end-to-end test
```

The unit tests need nothing special. The tree tests write SACLs on local NTFS under the Pester test drive,
and need an elevated shell holding SeSecurity, SeBackup and SeRestore. Without elevation they are skipped.
They run the script in child processes, cover a directory owned by and open only to SYSTEM, and nothing
touches an array.

To regenerate the glob vectors after a Go upgrade:

```bash
go run tools/set-saclonly/testdata/genvectors.go > tools/set-saclonly/testdata/glob-vectors.json
```
