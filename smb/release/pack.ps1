# Builds the permissionreset-smb release archive for Windows and checks it the way an operator
# receives it: extracted into a fresh directory away from the checkout, then run.
#
#   pwsh smb/release/pack.ps1 [-Version X.Y.Z[-suffix]] [-OutDir dist-smb]
#
# Version defaults to <Version> in smb/Directory.Build.props. A given version must carry the same
# X.Y.Z as that file, so a tag cannot ship a binary that reports a different version than the
# source it was built from. The release workflow passes the tag's version; CI passes nothing.
#
# Writes OutDir/permissionreset-smb_vVERSION_windows_amd64.zip and OutDir/SHA256SUMS (sha256sum
# format, so `sha256sum -c SHA256SUMS` works on Linux too). Throws on any failure.
[CmdletBinding()]
param(
    [string]$Version,
    [string]$OutDir = 'dist-smb'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (git rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0) { throw 'pack: not inside a git checkout' }

[xml]$props = Get-Content (Join-Path $root 'smb/Directory.Build.props')
$propsVersion = "$($props.Project.PropertyGroup.Version)".Trim()
if (-not $Version) { $Version = $propsVersion }
if ($Version -notmatch '^(\d+\.\d+\.\d+)(-[0-9A-Za-z.-]+)?$') {
    throw "pack: version '$Version' is not X.Y.Z or X.Y.Z-suffix"
}
$core = $Matches[1]
if ($core -ne $propsVersion) {
    throw "pack: version $Version does not match smb/Directory.Build.props ($propsVersion); bump the file first"
}

$name = "permissionreset-smb_v${Version}_windows_amd64"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = (Resolve-Path $OutDir).Path
$stage = Join-Path $out $name
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }

# Self-contained single file: the target server needs no .NET runtime installed. The PDB is
# embedded so a crash still reports file and line.
dotnet publish (Join-Path $root 'smb/src/PermissionReset.Smb/PermissionReset.Smb.csproj') `
    -c Release -r win-x64 --self-contained true --nologo `
    -p:PublishSingleFile=true -p:DebugType=embedded -p:Version=$Version `
    -o $stage
if ($LASTEXITCODE -ne 0) { throw "pack: dotnet publish exited $LASTEXITCODE" }

$extra = Get-ChildItem $stage | Where-Object { $_.Name -ne 'permissionreset-smb.exe' }
if ($extra) { throw "pack: publish left more than the exe: $($extra.Name -join ', ')" }
Copy-Item (Join-Path $root 'smb/README.md') $stage
Copy-Item (Join-Path $root 'LICENSE') $stage

$zip = Join-Path $out "$name.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $stage -DestinationPath $zip
Remove-Item -Recurse -Force $stage

# Smoke-check the archive, not the staging directory.
$check = Join-Path ([IO.Path]::GetTempPath()) "smb-smoke-$([guid]::NewGuid().ToString('N'))"
try {
    Expand-Archive -Path $zip -DestinationPath $check
    $top = @(Get-ChildItem $check)
    if ($top.Count -ne 1 -or $top[0].Name -ne $name) { throw "pack: $name.zip does not unpack into one directory named $name" }
    foreach ($f in 'permissionreset-smb.exe', 'README.md', 'LICENSE') {
        if (-not (Test-Path (Join-Path $top[0].FullName $f))) { throw "pack: $name.zip is missing $f" }
    }
    $exe = Join-Path $top[0].FullName 'permissionreset-smb.exe'
    $v = (& $exe version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "pack: version exited $LASTEXITCODE" }
    if ($v -ne "permissionreset-smb $core") { throw "pack: version printed '$v', want 'permissionreset-smb $core'" }
    foreach ($p in 'saclplan.golden.json', 'smbplan.golden.json') {
        & $exe plan (Join-Path $root "cmd/build_spec/testdata/$p") | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "pack: plan $p exited $LASTEXITCODE" }
    }
}
finally {
    Remove-Item -Recurse -Force $check -ErrorAction SilentlyContinue
}

$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $out 'SHA256SUMS'), "$hash  $name.zip`n")
Write-Host "packed $name.zip ($Version)"
Get-Content (Join-Path $out 'SHA256SUMS')
