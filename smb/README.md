# permissionreset-smb

The SMB-native permission repair tool for FlashArray, and for SMB-written data elsewhere. It talks the
array's own model over SMB: SIDs without id mapping, inherited flags as stored, and SACLs through
`SeSecurityPrivilege`. Why it exists, and what is still open before it can write anything, is in
[the decision record](../docs/decision-flasharray-smb-20261107.md).

**Status: pre-release scaffold. It writes nothing.** Today it reads and decodes descriptors and
validates plans; the repair itself waits on the open questions in section 8 of the decision record.

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
permissionreset-smb version
```

`inspect` prints, per path, the owner and group SIDs, the stored control word and its flags
(`DaclAutoInherited`, `DaclProtected`, ...), every DACL and SACL ACE with its flags (`ID` marks an
inherited ACE), and the raw descriptor in base64 so two reads can be compared byte for byte. Nothing
is normalized. It opens each object with backup intent and does not follow reparse points. It needs
an elevated shell with `SeBackupPrivilege`, and `SeSecurityPrivilege` unless `--no-sacl`. On
FlashArray the identity also needs the array's audit bypass, as for Set-SaclOnly.

`plan` reads the JSON that `build-spec --sacl-plan` writes. The spec has one parser, in Go; this tool
never reads YAML. A plan with another schema version, another protocol, an unknown field or an
unknown match type is refused rather than guessed at.

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
