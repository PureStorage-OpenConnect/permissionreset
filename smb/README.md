# permissionreset-smb

The SMB-native permission repair tool for FlashArray, and for SMB-written data elsewhere. It talks the
array's own model over SMB: SIDs without id mapping, inherited flags as stored, and SACLs through
`SeSecurityPrivilege`. Why it exists, and what is still open before it can write anything, is in
[the decision record](../docs/decision-flasharray-smb-20261107.md).

**Status: released as `smb-v0.1.0`** (tag on `959c505`). It reads and decodes descriptors,
validates plans, checks a tree against a plan (`check`, phase 1 of
[the write-path design](DESIGN-write-path.md)) and resets DACLs (`apply`, phase 2) on FlashArray
over SMB. `smb-v0.1.0` was qualified on FlashArray with a run at `2e0ad61`, then targeted
reruns at `959c505` and on the released exe itself (SHA-256
`211732052b2214846b20a0c8e43c48b91a28f9f3e30b2201700d32995320a139`). The later reruns were
targeted because the change after `2e0ad61` only alters how the plan file is read, before any tree
access. Earlier records: `apply` at `e834ac8`
([record](../benchmarks/qual-smb-apply-e834ac8-20261119/RESULTS.md)), `inspect` and `check`
read-only at `700630b` ([results](../benchmarks/qual-smb-check-700630b-20261116/RESULTS.md)).
Each release is qualified on its own assets. SACL writes (phase 3) are built but not qualified on hardware;
a change to the write path needs its own hardware run before the next `smb-v*` tag.

| Platform | Tool |
|---|---|
| FlashBlade, NFS-written data | `permissionreset` (repository root) |
| FlashArray, any data | `permissionreset-smb` (this directory) |
| SMB-written data, SACL only | `tools/set-saclonly/` (`permissionreset-smb`'s SACL writes are built but unqualified) |

## Commands

```powershell
permissionreset-smb inspect \\array\share\dept \\array\share\dept\a.txt    # raw descriptors, JSON lines
permissionreset-smb inspect --no-sacl \\array\share\dept                  # without SeSecurityPrivilege
permissionreset-smb plan audit-plan.json                                  # validate and summarize a plan
permissionreset-smb check plan.json \\array\share\dept                   # dry run: what a reset would write
permissionreset-smb check --validate plan.json \\array\share\dept        # exit 1 unless every object is right
permissionreset-smb apply --evidence-dir ev plan.json \\array\share\dept  # write what differs, read every write back
permissionreset-smb version
```

`inspect` prints, per path, the owner and group SIDs, the stored control word and its flags
(`DaclAutoInherited`, `DaclProtected`, ...), every DACL and SACL ACE with its flags (`ID` marks an
inherited ACE), and the raw descriptor in base64 so two reads can be compared byte for byte. Nothing
is normalized. It opens each object with backup intent and does not follow reparse points. It needs
an elevated shell with `SeBackupPrivilege`, and `SeSecurityPrivilege` unless `--no-sacl`. On
FlashArray the identity also needs the array's audit bypass, as for Set-SaclOnly.

A path that cannot be read still gets a line, with `error` naming the step and the system's reason
(`"open: Access is denied."`) and `win32_error` its code; it has no `descriptor` and no `sacl_read`.
`inspect` exits 0 when every path was read, 1 when any path failed or a privilege is missing (then
it reads nothing and says which privilege on stderr), and 2 on a usage error.

`plan` reads the JSON that `build-spec --smb-plan` (schema 2, or schema 3 when any rule sets
`sacl:`; both carry the DACL and the SACL shape) or `--sacl-plan` (schema 1) writes. The spec has
one parser, in Go; this tool never reads YAML. A plan with another schema version, another
protocol, an unknown field or an unknown match type is refused rather than guessed at, as is a
schema 2 plan with a `sacl` rule (rebuild it as schema 3) and any schema 3 plan whose audit ACEs
are malformed (no `SA`/`FA`, a creator SID, or a missing or contradictory `sacl` list).

`check` takes a schema 2 plan (a DACL-only `build-spec --smb-plan SPEC.yaml`) and walks the tree
top-down with backup intent, never following a reparse point. For each object it works out the
stored form the reset wants (`inherits`, `explicit_plus_inherits` or `protected`; design section
2.1), reads the
DACL, owner and group, and prints one JSON line: `ok`, `write` (the object needs its own write),
`follows` (it differs only because an ancestor will be written, after which the array re-derives
it), `keep` (its rule has no `acl:`), `excluded`, `reparse` or `error`. A summary goes to stderr.
It reads no SACL — except with a schema 3 plan (any rule sets `sacl:`), where the compare read
covers the SACL and the record carries the two part verdicts (`dacl_outcome`, `sacl_outcome`).
Then `check` enables `SeSecurityPrivilege` and proves the audit bypass on a disposable probe
(under `--probe-dir`, else ROOT) before any tree SACL is read; without a writable probe location
it exits 1, and `--accept-unproven-read` skips the proof with a NOTE. The probe's events go to
`--evidence-dir` as a preflight shard (`preflight-shard-000001.log`, bound in `apply`'s manifest; it opens with step 1's `PROBE-CREATE` lines for the probe directory, subdirectory and file), else to NOTE lines and a `{"probe": ...}` JSON line on stdout. Every principal the plan names, `sacl:` entries included, is resolved once to a
SID on this host first, the resolved principal-SID table is printed, and the check is refused if
one doesn't resolve. `--workers N` (default 16) sets the parallelism. Exit 0
when every object was checked (with `--validate`: and every one is `ok`), 1 otherwise, 2 on a
usage error.

`apply` takes the same schema 2 plan and walks the same way, but writes. Each object whose DACL
differs from its desired form gets one `SetKernelObjectSecurity` with only the parts that differ
(`DACL_SECURITY_INFORMATION` plus `PROTECTED_`/`UNPROTECTED_DACL_SECURITY_INFORMATION`; owner or
group when the rule names them), and is read back. A directory is finished before its children are
read, so objects that only inherit are found right once their parent is, and are not written. Before
anything in the tree is written it runs a **preflight**: a disposable probe directory (under ROOT, or
under `--probe-dir DIR`, which must exist) with one subdirectory and one file gets the root's DACL and
an audit ACE; it must read back exactly, keep the audit ACE (SeSecurityPrivilege and, on FlashArray,
the audit bypass) and pass down exactly what the tool computes. The probe is removed; a refused
preflight writes nothing in the tree. During the walk two guards stop the run, with no override:

- **G1**: an object whose stored DACL has the dynamic shape (unprotected, right explicit part, the
  rest inherited) but whose inherited part is not what its parent passes down. Either the inheritance
  function disagrees with the array, or the object holds a frozen copy; writing it would freeze it.
- **G2**: a write whose read-back differs: the DACL or its protection, owner or group, the SACL, or
  either auto-inherited bit, or a read-back that fails.

After a stop no new write or directory starts; the run reports `stopped` and not-processed counts
and exits 1. With a schema 3 plan (any rule sets `sacl:`), `apply` writes SACLs too: the preflight
then proves the audit bypass, the root's desired audit ACEs on the probe's children and the
recorded `S:AI` rule before any tree SACL is read; the probe's events are the
`preflight-shard-000001.log` in the evidence directory. A two-part object (DACL and SACL both
differ) gets one write per part, in `--write-order` order: `sacl-first` (default) or `dacl-first`,
which prints a NOTE once — new access can go unaudited if a SACL write fails after its DACL
write — and is recorded in the manifest. `--root-sacl-protected` (on `check` too) forces the
root's SACL **Protected**, independently of `--root-protected`.
`--root-protected` (on `check` too) makes the root **Protected**, for a root whose inherited ACEs may
be a frozen copy. `--checkpoint FILE` records complete directories (a directory and all its files
right on every part the plan names) in a v2 checkpoint; on a plan with a `sacl:` rule it also
records each directory's compare-time SACL before any write in that directory. `--resume` skips the
files of complete directories on the next run, schema 3 plans included, and uses the recorded
compare-time SACLs to tell a frozen copy from before the first run (a `Write`) from a child that
should have followed that run's parent write (G1-SACL). It refuses a checkpoint whose plan, root,
`--root-protected`, `--root-sacl-protected`, resolved principal table or `S:AI` rule differ, and it
never resumes a v1 checkpoint from an earlier build: remove it and rerun without `--resume`. Resume
assumes the tree did not change between the runs; run `check --validate` afterwards as the
independent proof (`DESIGN-sacl-write.md` 7.1). `--evidence-dir DIR` (new or empty) writes `shard-000001.log` (one line per object: `OK: set
dacl PATH (form)` with the raw descriptor `before=` and `after=` in base64, `SAME:`, `SKIP:`,
`EXCLUDE:`, `ERR:`) and `manifest.json` (complete or incomplete and why, the shard's SHA-256, the
principal table, privileges, preflight result and counts). `apply` needs SeBackupPrivilege and
SeSecurityPrivilege; SeRestorePrivilege is enabled only when the plan names an owner or group and is
turned off otherwise. Under Windows rules a DACL write then needs `WRITE_DAC` from the object's
DACL or ownership; FlashArray did not require it in qualification. Exit 0
when the preflight passed and every object is right, 1 otherwise, 2 on a usage error.

## Build and test

Needs a .NET 8 SDK. `smb/global.json` pins the release SDK exactly, with `rollForward` off, and
dotnet reads it only when run from `smb/` or below. Run from the repository root, as shown, these
commands use the machine's newest SDK, which is fine for development.

The release exe is reproducible. `pwsh smb/release/pack.ps1`, run from a clean checkout of a
commit, gives an exe with the same SHA-256 as the release workflow's build of that commit, and it
prints that hash. Pass the same `-Version` the tag carries. To get there, the script installs the
pinned SDK into a private directory under the temp directory (with Microsoft's `dotnet-install`
script, downloaded on first use and reused afterwards). It then builds with that copy alone, so
the compiler runs on the SDK's own runtime rather than a newer 8.0 patch installed on the machine,
and it refuses to build if it sees any other 8.0 runtime. The zip also matches when it is packed
under the same PowerShell and .NET major version as the runner, since its compressed bytes come
from that runtime.

```bash
dotnet test smb/PermissionResetSmb.sln
dotnet build smb/PermissionResetSmb.sln -c Release
```

`PermissionReset.Smb.Core` (plan loading, rule selection, descriptor decoding) has no Win32 calls,
so it builds and tests on any OS. The Win32 reads live in `PermissionReset.Smb` and run only on
Windows. Rule selection and glob matching are tested against the same Go-generated vectors as
Set-SaclOnly (`tools/set-saclonly/testdata/glob-vectors.json`) and against build-spec's golden plan
(`cmd/build_spec/testdata/saclplan.golden.json`).

## Versions

Independent of `permissionreset`: tags are `smb-vX.Y.Z`, starting at `smb-v0.1.0` (decision record,
section 6). The first release is `smb-v0.1.0`.

Pushing an `smb-vX.Y.Z` tag runs `.github/workflows/release-smb.yml` on a hosted Windows runner: it
builds and tests the solution, then `smb/release/pack.ps1` publishes a self-contained single-file
`permissionreset-smb.exe` (no .NET runtime needed on the server), zips it with this README and the
LICENSE as `permissionreset-smb_vX.Y.Z_windows_amd64.zip`, smoke-checks the extracted archive and
writes `SHA256SUMS`. Both go to a **draft** release that does not become the repository's latest;
qualification runs on those exact assets before a maintainer publishes it. The tag's X.Y.Z must
equal `<Version>` in `Directory.Build.props`, so bump that file first. CI runs the same pack script
on every pull request, without publishing.
