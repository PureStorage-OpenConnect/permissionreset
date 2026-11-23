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
#
# The exe is reproducible: the same commit, packed with the same -Version and the SDK pinned in
# smb/global.json, gives the same bytes on a maintainer's machine as on the release runner. The
# release qualified on hardware must be that exe (docs/release-acceptance.md).
# ContinuousIntegrationBuild maps source paths in the embedded PDB to /_/, so the checkout's
# location does not leak into the exe. SourceLink is off because it embeds the clone's origin
# URL, which differs between a fork, an SSH clone and the runner's checkout.
# dotnet finds global.json by searching up from the working directory, so publish runs from smb/;
# from the repository root it would take whatever SDK the machine has newest. The version check
# turns a missing pinned SDK into a clear error rather than a different exe.
$sdkWant = "$((Get-Content -Raw (Join-Path $root 'smb/global.json') | ConvertFrom-Json).sdk.version)"
Push-Location (Join-Path $root 'smb')
try {
    $sdkHave = "$(dotnet --version)".Trim()
    if ($LASTEXITCODE -ne 0 -or $sdkHave -ne $sdkWant) {
        throw "pack: needs .NET SDK $sdkWant (smb/global.json), found '$sdkHave'"
    }
    dotnet publish 'src/PermissionReset.Smb/PermissionReset.Smb.csproj' `
        -c Release -r win-x64 --self-contained true --nologo `
        -p:PublishSingleFile=true -p:DebugType=embedded -p:Version=$Version `
        -p:ContinuousIntegrationBuild=true -p:EnableSourceLink=false `
        -o $stage
    if ($LASTEXITCODE -ne 0) { throw "pack: dotnet publish exited $LASTEXITCODE" }
}
finally { Pop-Location }

$extra = Get-ChildItem $stage | Where-Object { $_.Name -ne 'permissionreset-smb.exe' }
if ($extra) { throw "pack: publish left more than the exe: $($extra.Name -join ', ')" }
Copy-Item (Join-Path $root 'smb/README.md') $stage
Copy-Item (Join-Path $root 'LICENSE') $stage

$exeHash = (Get-FileHash -Algorithm SHA256 (Join-Path $stage 'permissionreset-smb.exe')).Hash.ToLowerInvariant()

# Zip by hand rather than with Compress-Archive, which stamps each entry with the file's write
# time and whose entry names differ between Windows PowerShell and PowerShell 7. Entries go in a
# fixed order, with forward slashes, stamped with the commit's time (UTC). The deflate bytes still
# come from the zlib in the .NET runtime that runs this script, so the zip matches only when
# packed under the same PowerShell/.NET major version; the exe hash above is the comparison that
# holds everywhere.
$commitTime = [DateTimeOffset]::FromUnixTimeSeconds([long]((git -C $root log -1 --format=%ct).Trim()))
if ($LASTEXITCODE -ne 0) { throw 'pack: cannot read the commit time' }
$zip = Join-Path $out "$name.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Add-Type -AssemblyName System.IO.Compression
$fs = [IO.File]::Open($zip, [IO.FileMode]::CreateNew)
try {
    $archive = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in 'LICENSE', 'README.md', 'permissionreset-smb.exe') {
            $entry = $archive.CreateEntry("$name/$f", [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $commitTime
            $dst = $entry.Open()
            try {
                $src = [IO.File]::OpenRead((Join-Path $stage $f))
                try { $src.CopyTo($dst) } finally { $src.Dispose() }
            }
            finally { $dst.Dispose() }
        }
    }
    finally { $archive.Dispose() }
}
finally { $fs.Dispose() }
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
Write-Host "$exeHash  $name/permissionreset-smb.exe"
