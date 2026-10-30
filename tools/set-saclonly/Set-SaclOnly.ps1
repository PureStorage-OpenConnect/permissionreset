<#
.SYNOPSIS
Add audit ACEs (a SACL) to every object in a tree over SMB, without touching any DACL.

.DESCRIPTION
This is the SMB-side counterpart of `permissionreset --sacl` with a sacl:-only spec, for data written over SMB.
Writing the ACL back over NFS flattens inheritance on FlashArray and FlashBlade, loses SIDs with no RFC 2307
id on FlashArray, and corrupts ids >= 1e9 on FlashBlade (RISKS.md #11). An SMB SACL-only write keeps the DACL.

Each object is opened once, and its SACL is written through that handle with
SetKernelObjectSecurity(SACL_SECURITY_INFORMATION) and nothing else:
  - The owner, group and DACL are not part of the write, so no SID-to-uid translation happens.
  - The object's own SACL control flags, protected (S:P) and auto-inherited (S:AI), are written back
    unchanged, so only the audit ACEs change. The read-back fails an object whose S:P changed.
  - No propagation walk is started. SetNamedSecurityInfo would start one on every directory.

Every open asks for backup intent and, unless -NoBackup, SeBackupPrivilege is enabled, so a directory
whose DACL denies Administrators is still read, listed and given its SACL. Directories are listed through
the same kind of handle. SeSecurityPrivilege grants ACCESS_SYSTEM_SECURITY, which is all the SACL write
needs; SeRestorePrivilege is not used, because nothing but the SACL is ever written.

What is written:
  - Without -Spec/-Plan: one SACL for the whole tree from -Rights/-Trustee/-Flags. Directories get an
    inheritable audit ACE (OICI), so new files and folders inherit it; every existing object also gets
    its own explicit ACE.
  - With -Spec (a permissionreset YAML spec) or -Plan (its `build-spec --sacl-plan` JSON): each object gets
    the sacl: of the rule permissionreset selects for it: rules in order, first match on type and base-name
    glob, else default. Excludes prune the same paths permissionreset prunes. Every rule must be sacl:-only
    (no acl:/dacl:). A rule with no sacl: key leaves the objects it selects untouched. Globs are Go's,
    so they are case-sensitive, as on NFS.

Root preflight: before any other object is opened, the root is read and, with -Apply, given its SACL
and read back. If the read or the write is refused, or the array does not keep the SACL, the run
stops there: the identity lacks the privilege on the array (on FlashArray, the audit bypass), and every
other object would fail the same way. A root that already has its SACL is not rewritten, so a rerun
proves only the read; a root whose rule has no sacl: key is not probed.

Policy: every object is checked. Owner, group, DACL (every ACE, its mask, flags, SID and order, and the
DACL's control flags) and the SACL's protected flag are read before and after the write. The default is
strict: any change stops the run, counts as an error, and no further write is started. Writes already
in flight finish and are checked; the first change itself has already happened and is not undone.
FlashBlade marks every ACL written over NFS protected (D:P), then clears that flag on an SMB SACL write.
That D:P-only change is the one a run may accept, and only with -Accept dacl-unprotected and -Log:
each occurrence is counted and listed, and the run goes on. Access is unchanged, but the next time an
admin propagates permissions from the parent, the parent's inheritable ACEs reach that object. With
-Array FlashBlade, a strict run whose root DACL is protected is refused before anything is written.
An object that already has exactly the wanted SACL is skipped, so a rerun resumes. Without -Apply
nothing is written, which is a dry run.

Parallelism: -Threads workers share one queue of directories. A worker takes a directory, handles
the directory object and every file in it, and queues its subdirectories. The walk and the writes
run in C# (SaclOnly.cs). PowerShell only reports progress.

Needs an elevated shell holding SeSecurityPrivilege (Manage auditing and security log) and, unless
-NoBackup, SeBackupPrivilege (Back up files and directories); local Administrators hold both. Over SMB
the array decides what backup intent grants. On FlashArray the identity also needs the array's audit
bypass to keep SACLs; Domain Admins membership alone is not enough.

.PARAMETER Path       Root of the tree, e.g. \\array\share\dir. The root itself is included and never excluded.
.PARAMETER Rights     SDDL access rights to audit. Default FA (all). 'SDWDWO' = delete, change perms, take ownership.
.PARAMETER Trustee    SDDL SID or alias to audit. Default WD (Everyone).
.PARAMETER Flags      SDDL audit flags: SA (success), FA (failure), or SAFA. Default SAFA.
.PARAMETER Remove     Write an empty SACL instead (undo, or reset for timing). Still never touches the DACL.
.PARAMETER Spec       A permissionreset nfsv4 spec (YAML). Read through `build-spec --sacl-plan`.
.PARAMETER Plan       A saved `build-spec --sacl-plan` JSON, for a host without build-spec.
.PARAMETER BuildSpec  The build-spec binary. Default: build-spec.exe beside this script, then PATH.
.PARAMETER Threads    Parallel workers. Default 16. Measure with Time-SaclOnly.ps1 before a large run.
.PARAMETER Apply      Write. Without it, report what would change.
.PARAMETER NoBackup   Turn SeBackupPrivilege off (it may arrive enabled from the parent process). Objects
                      whose DACL denies this identity then fail.
.PARAMETER NoReadback Do not check that the array kept the SACL. The post-write read returns owner,
                      group, DACL and SACL together, so the check costs nothing. Kept so older command
                      lines still run. The root preflight reads back regardless.
.PARAMETER Log        CSV path: one line per object that would be set, changed (the change's name, e.g.
                      dacl-unprotected), was excluded, was skipped as reparse, or failed.
.PARAMETER Accept     Changes to accept instead of stopping. Only dacl-unprotected (the DACL lost only D:P)
                      can be accepted, and -Apply then needs -Log. Without it the policy is strict.
.PARAMETER Array      FlashArray, FlashBlade or Unknown (default). FlashBlade with a protected root DACL
                      refuses a strict run up front; Unknown says the D:P behavior has not been checked.
.PARAMETER Summary    JSON path: the policy, the array, the preflight result and every count.
.PARAMETER TreeApi    Baseline: do what the Explorer GUI does instead of the parallel walk, with one
                      TreeSetNamedSecurityInfo(TREE_SEC_INFO_RESET) call. Children end up with an
                      inherited audit ACE rather than an explicit one. There is no per-object check,
                      no dry run (needs -Apply) and no -Spec. Use it for timing only.

.EXAMPLE
.\Set-SaclOnly.ps1 -Path \\array\share\dept                         # dry run
.\Set-SaclOnly.ps1 -Path \\array\share\dept -Apply -Threads 32 -Log sacl.csv
.\Set-SaclOnly.ps1 -Path \\array\share\dept -Spec audit.yaml -Apply -Log sacl.csv
#>
[CmdletBinding(DefaultParameterSetName = 'Simple')]
param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(ParameterSetName = 'Simple')] [string]$Rights = 'FA',
    [Parameter(ParameterSetName = 'Simple')] [string]$Trustee = 'WD',
    [Parameter(ParameterSetName = 'Simple')] [ValidateSet('SA', 'FA', 'SAFA')] [string]$Flags = 'SAFA',
    [Parameter(ParameterSetName = 'Simple')] [switch]$Remove,
    [Parameter(ParameterSetName = 'Simple')] [switch]$TreeApi,
    [Parameter(ParameterSetName = 'Spec', Mandatory)] [string]$Spec,
    [Parameter(ParameterSetName = 'Plan', Mandatory)] [string]$Plan,
    [Parameter(ParameterSetName = 'Spec')] [string]$BuildSpec,
    [ValidateRange(1, 512)] [int]$Threads = 16,
    [switch]$Apply,
    [switch]$NoBackup,
    [switch]$NoReadback,
    [string]$Log,
    [ValidateSet('dacl-unprotected')] [string[]]$Accept = @(),
    [ValidateSet('FlashArray', 'FlashBlade', 'Unknown')] [string]$Array = 'Unknown',
    [string]$Summary
)
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'SaclPlan.ps1')
Import-SaclOnlyEngine

[SaclOnly]::EnablePrivilege('SeSecurityPrivilege')
# Never needed, and if it arrives enabled from the parent process a backup-intent open gets
# READ_CONTROL through it (generic write includes it), so -NoBackup would not leave the DACL in charge.
[SaclOnly]::DisablePrivilege('SeRestorePrivilege')
if ($NoBackup) { [SaclOnly]::DisablePrivilege('SeBackupPrivilege') } else { [SaclOnly]::EnablePrivilege('SeBackupPrivilege') }
$isDir = try { [SaclOnly]::IsDirectory($Path) } catch {
    throw "STOPPED: preflight: $($_.Exception.InnerException.Message)`n  The root cannot be opened, so nothing was touched."
}
if (-not $isDir) { throw "$Path is not a directory" }

if ($PSCmdlet.ParameterSetName -eq 'Simple') {
    $set = New-SimpleSaclPlan -Rights $Rights -Trustee $Trustee -Flags $Flags -Remove:$Remove
} else {
    $set = ConvertFrom-SaclPlan (Read-SaclPlan -Spec $Spec -Plan $Plan -BuildSpec $BuildSpec)
}
$logPath = if ($Log) { $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Log) } else { $null }   # relative or absolute

$mode = if ($Apply) { 'APPLY' } else { 'DRY RUN (pass -Apply to write)' }
"Mode:    $mode$(if ($Remove) { ', REMOVE (empty SACL)' })"
"Backup:  $(if ($NoBackup) { 'off (-NoBackup): the DACL decides what can be read and listed' } else { 'on (SeBackupPrivilege, backup-intent opens)' })"
if ($PSCmdlet.ParameterSetName -eq 'Simple') {
    "Dirs:    $($set.Actions[0].DirSddl)"
    "Files:   $($set.Actions[0].FileSddl)"
} else {
    "Spec:    $(if ($Spec) { $Spec } else { "$Plan (plan)" })"
    foreach ($a in $set.Actions) {
        "  {0,-9} {1}" -f $a.Label, $(if ($a.Leave) { 'no sacl: key, left untouched' } else { $a.DirSddl })
    }
    foreach ($n in $set.Notes) { "  NOTE: $n" }
}
"Threads: $Threads$(if ($NoReadback) { ', no SACL read-back' })"
$policy = [SaclOnly]::Policy([string[]]$Accept)
"Policy:  $policy$(if ($Accept) { ' (counted, each listed in -Log)' } else { ' (any owner/group/DACL/S:P change stops the run)' })"
"Array:   $Array"
''
if ($Apply -and $Accept -and -not $Log) { throw '-Accept needs -Log, so every accepted change is listed' }

if ($TreeApi) {
    if (-not $Apply) { throw '-TreeApi writes in one call; pass -Apply' }
    "Mode:    TREE API baseline (Explorer 'replace all child object auditing entries')"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    [SaclOnly]::TreeSetSacl($Path, $set.Actions[0].DirSddl)
    $sw.Stop()
    $count = 0
    try { $count = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue).Count + 1 } catch {}
    'Objects:   {0:N0}' -f $count
    'Set:       not checked (the tree API reports no per-object result)'
    'Errors:    not checked'
    'Elapsed:   {0:N1}s ({1:N0} objects/s)' -f $sw.Elapsed.TotalSeconds, ($count / [Math]::Max($sw.Elapsed.TotalSeconds, 0.001))
    return
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
[SaclOnly]::Start($Path, $set.Rules, $set.Actions, [bool]$Apply, -not $NoReadback, $Threads, $logPath, [string[]]$Accept, $Array)
if ([SaclOnly]::Current.Preflight) { "Preflight: $([SaclOnly]::Current.Preflight)"; '' }
try {
    while (-not [SaclOnly]::Wait(2000)) {
        $r = [SaclOnly]::Current
        $rate = $r.Seen / [Math]::Max($sw.Elapsed.TotalSeconds, 0.001)
        Write-Progress -Activity 'Set-SaclOnly' -Status ('{0:N0} objects  {1:N0}/s  set {2:N0}  skipped {3:N0}  errors {4:N0}' -f $r.Seen, $rate, $r.Applied, $r.Skipped, $r.Errors)
    }
} finally {
    if (-not [SaclOnly]::Wait(0)) { [SaclOnly]::Cancel(); [void][SaclOnly]::Wait(30000) }   # Ctrl+C
    Write-Progress -Activity 'Set-SaclOnly' -Completed
    $r = [SaclOnly]::Current
    $secs = $sw.Elapsed.TotalSeconds
    'Objects:   {0:N0}' -f $r.Seen
    if ($Apply) { 'Set:       {0:N0}' -f $r.Applied } else { 'Would set: {0:N0}' -f $r.Would }
    if ($r.SetStopped) { 'Set, then stopped: {0:N0} (SACL written, but the write changed what the policy refuses; counted in Errors)' -f $r.SetStopped }
    'Skipped:   {0:N0} (already correct)' -f $r.Skipped
    if ($PSCmdlet.ParameterSetName -ne 'Simple') {
        'Left:      {0:N0} (rule has no sacl: key)' -f $r.Left
        'Excluded:  {0:N0} (not descended)' -f $r.Excluded
    }
    'Reparse:   {0:N0} (not followed)' -f $r.Reparse
    if ($Apply -and $Accept) { 'dacl-unprotected: {0:N0} (accepted: DACL lost only D:P; ACEs unchanged; listed in -Log)' -f $r.Unprotected }
    if ($r.NotStarted) { 'Not started: {0:N0} (read after the run stopped; not written)' -f $r.NotStarted }
    'Errors:    {0:N0}' -f $r.Errors
    'Elapsed:   {0:N1}s ({1:N0} objects/s)' -f $secs, ($r.Seen / [Math]::Max($secs, 0.001))
    if ($Summary) {
        [ordered]@{
            schema = 'set-saclonly-summary/1'; path = $Path; apply = [bool]$Apply; policy = $policy
            accept = @($Accept); array = $Array; preflight = $r.Preflight; stopped = $r.Stopped
            counts = [ordered]@{
                seen = $r.Seen; set = $r.Applied; would_set = $r.Would; skipped = $r.Skipped; left = $r.Left
                excluded = $r.Excluded; reparse = $r.Reparse; dacl_unprotected_accepted = $r.Unprotected
                not_started = $r.NotStarted; set_then_stopped = $r.SetStopped; errors = $r.Errors
            }
            log = $logPath
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Summary) -Encoding UTF8
    }
}
if ($r.Stopped) { throw "STOPPED: $($r.Stopped)" }
if ($r.Errors) { exit 1 }
