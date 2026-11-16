# permissionreset-smb

The SMB-native permission repair tool for FlashArray, and for SMB-written data elsewhere. It talks the
array's own model over SMB: SIDs without id mapping, inherited flags as stored, and SACLs through
`SeSecurityPrivilege`. Why it exists, and what is still open before it can write anything, is in
[the decision record](../docs/decision-flasharray-smb-20261107.md).

**Status: pre-release. It writes nothing.** It reads and decodes descriptors, validates plans,
and checks a tree against a plan (`check`, phase 1 of [the write-path design](DESIGN-write-path.md)).
The write itself (phase 2) is not built. Nothing here is qualified beyond `inspect`'s reads.

| Platform | Tool |
|---|---|
| FlashBlade, NFS-written data | `permissionreset` (repository root) |
| FlashArray, any data | `permissionreset-smb` (this directory) |
| SMB-written data, SACL only | `tools/set-saclonly/` until `permissionreset-smb` covers it |

## Commands

```powershell
permissionreset-smb inspect \\array\share\dept \\array\share\dept\a.txt    # raw descriptors, JSON lines
permissionreset-smb inspect --no-sacl \\array\share\dept                  # without SeSecurityPrivilege
permissionreset-smb plan audit-plan.json                                  # validate and summarize a plan
permissionreset-smb check plan.json \\array\share\dept                   # dry run: what a reset would write
permissionreset-smb check --validate plan.json \\array\share\dept        # exit 1 unless every object is right
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

`plan` reads the JSON that `build-spec --smb-plan` (schema 2, DACL and SACL) or `--sacl-plan`
(schema 1) writes. The spec has one parser, in Go; this tool never reads YAML. A plan with another schema version, another protocol, an unknown field or an
unknown match type is refused rather than guessed at.

`check` takes a schema 2 plan (`build-spec --smb-plan SPEC.yaml`) and walks the tree top-down
with backup intent, never following a reparse point. For each object it works out the stored form
the reset wants (`inherits`, `explicit_plus_inherits` or `protected`; design section 2.1), reads the
DACL, owner and group, and prints one JSON line: `ok`, `write` (the object needs its own write),
`follows` (it differs only because an ancestor will be written, after which the array re-derives
it), `keep` (its rule has no `acl:`), `excluded`, `reparse` or `error`. A summary goes to stderr.
It reads no SACL. Every principal the plan names is resolved to a SID on this host first, and the
check is refused if one doesn't resolve. `--workers N` (default 16) sets the parallelism. Exit 0
when every object was checked (with `--validate`: and every one is `ok`), 1 otherwise, 2 on a
usage error.

## Build and test

Needs the .NET 8 SDK (`global.json`).

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
section 6). No release exists yet.
