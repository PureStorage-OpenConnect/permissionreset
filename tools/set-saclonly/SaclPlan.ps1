# Functions Set-SaclOnly.ps1 uses to turn a permissionreset spec into SaclRules and SaclActions.
# Dot-sourced by Set-SaclOnly.ps1 and by the Pester tests. SaclOnly.cs must already be loaded.
#
# The spec is never parsed here. `build-spec --sacl-plan <spec.yaml>` loads it with permissionreset' spec loader
# (the same validation permissionreset runs) and prints a JSON plan: the rules in order, the excludes
# already split into base-name and relative-path globs, and each sacl: ACE translated to Windows
# ACE flags and mask. This file only checks the plan, resolves principals to SIDs and builds SDDL.

function Import-SaclOnlyEngine {
    if (-not ('SaclOnly' -as [type])) {
        Add-Type -Language CSharp -TypeDefinition (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'SaclOnly.cs') -Raw)
    }
}

# Find-BuildSpec returns the build-spec binary: -BuildSpec when given, else build-spec.exe beside
# this script, else build-spec on PATH.
function Find-BuildSpec([string]$BuildSpec) {
    if ($BuildSpec) {
        if (-not (Test-Path -LiteralPath $BuildSpec -PathType Leaf)) { throw "build-spec not found at $BuildSpec" }
        return (Resolve-Path -LiteralPath $BuildSpec).Path
    }
    foreach ($name in 'build-spec.exe', 'build-spec') {
        $beside = Join-Path $PSScriptRoot $name
        if (Test-Path -LiteralPath $beside -PathType Leaf) { return $beside }
    }
    $cmd = Get-Command build-spec -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    throw 'build-spec not found: pass -BuildSpec, put build-spec.exe beside Set-SaclOnly.ps1, or put it on PATH'
}

# Read-SaclPlan returns the parsed plan, from a spec (through build-spec) or a saved plan file.
function Read-SaclPlan {
    param([string]$Spec, [string]$Plan, [string]$BuildSpec)
    if ($Spec) {
        $exe = Find-BuildSpec $BuildSpec
        $out = & $exe --sacl-plan $Spec 2>&1
        $code = $LASTEXITCODE
        $stdout = @($out | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
        $stderr = @($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
        if ($code -ne 0) { throw "build-spec --sacl-plan $Spec failed (exit $code): $stderr" }
        $json = $stdout
    } else {
        $json = Get-Content -LiteralPath $Plan -Raw
    }
    $p = $json | ConvertFrom-Json
    if ($p.schema -ne 1) { throw "unsupported sacl plan schema '$($p.schema)' (this script reads schema 1)" }
    if ($p.protocol -ne 'nfsv4') { throw "spec protocol is '$($p.protocol)'; only an nfsv4 spec carries sacl: rules" }
    return $p
}

# The SDDL ACE-flag string for Windows ACE header flags.
function ConvertTo-SddlAceFlags([int]$Flags) {
    $known = @(@(0x01, 'OI'), @(0x02, 'CI'), @(0x04, 'NP'), @(0x08, 'IO'), @(0x10, 'ID'), @(0x40, 'SA'), @(0x80, 'FA'))
    $s = ''
    $rest = $Flags
    foreach ($k in $known) {
        if ($Flags -band $k[0]) { $s += $k[1]; $rest = $rest -band (-bnot $k[0]) }
    }
    if ($rest) { throw ('ACE flags 0x{0:x} carry bits with no SDDL name (0x{1:x})' -f $Flags, $rest) }
    return $s
}

# Resolve-SaclPrincipal returns the SID string for one plan ACE. A well-known principal comes with
# its SID from build-spec. A name (name@domain or DOMAIN\name) is looked up here. A numeric id has
# no SID over SMB and is refused.
function Resolve-SaclPrincipal($Ace, [hashtable]$Cache) {
    if ($Ace.sid) { return $Ace.sid }
    $who = [string]$Ace.principal
    if ($Cache.ContainsKey($who)) { return $Cache[$who] }
    if ($who -match '^\d+$') {
        throw "sacl: principal '$who' is a numeric id. Over SMB an audit ACE needs a SID: name the account (name@domain) in the spec"
    }
    try {
        $sid = ([System.Security.Principal.NTAccount]$who).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "sacl: principal '$who' does not resolve to a SID on this host: $($_.Exception.InnerException.Message)"
    }
    $Cache[$who] = $sid
    return $sid
}

# ConvertTo-SaclSddl builds the SACL ("S:AI" plus one AU ACE per line) for one plan rule.
function ConvertTo-SaclSddl($Rule, [hashtable]$Cache) {
    $aces = foreach ($a in @($Rule.sacl)) {
        if ($null -eq $a) { continue }
        if ($a.windows_type -ne 2) { throw "$($Rule.label): ACE '$($a.line)' is not an audit ACE (type $($a.windows_type))" }
        $sid = Resolve-SaclPrincipal $a $Cache
        '(AU;{0};0x{1:x};;;{2})' -f (ConvertTo-SddlAceFlags $a.windows_flags), [int64]$a.windows_mask, $sid
    }
    return 'S:AI' + (@($aces) -join '')
}

# ConvertFrom-SaclPlan checks a plan and returns @{ Rules; Actions; Notes }.
# Set-SaclOnly writes only SACLs, so every rule that would write a DACL (acl: or dacl:) is refused:
# that spec is for permissionreset. A rule with no sacl: key leaves the objects it selects alone, the
# same as permissionreset leaves their audit ACEs: its owner/group (permissionreset --set-owner) is not applied.
function ConvertFrom-SaclPlan($Plan) {
    $rules = New-Object SaclRules
    $actions = New-Object System.Collections.Generic.List[SaclAction]
    $cache = @{}
    $refused = @()
    $notes = @()
    $all = @(@($Plan.rules) | Where-Object { $null -ne $_ }) + @($Plan.default)
    foreach ($r in $all) {
        if ($r.has_acl -or $r.has_dacl) { $refused += $r.label; continue }
    }
    if ($refused) {
        throw ("{0} write a DACL (acl:/dacl:). Set-SaclOnly writes only SACLs: use permissionreset for that spec, or make every rule sacl:-only." -f ($refused -join ', '))
    }
    foreach ($r in @($Plan.rules) | Where-Object { $null -ne $_ }) {
        $type = switch ($r.match.type) {
            ''          { [SaclRules]::AnyType }
            'file'      { [SaclRules]::FileType }
            'directory' { [SaclRules]::DirType }
            default     { throw "$($r.label): unknown match type '$($r.match.type)'" }
        }
        $rules.AddRule($type, [string]$r.match.pattern)
    }
    foreach ($g in @($Plan.exclude.base)) { if ($g) { $rules.AddExcludeBase($g) } }
    foreach ($g in @($Plan.exclude.path)) { if ($g) { $rules.AddExcludePath($g) } }

    foreach ($r in $all) {
        $a = New-Object SaclAction
        $a.Label = $r.label
        if (-not $r.sacl_set) {
            $a.Leave = $true
            if ($r.owner -or $r.group) { $notes += "$($r.label): owner/group are not applied (Set-SaclOnly writes only the SACL)" }
        } else {
            $sddl = ConvertTo-SaclSddl $r $cache
            $a.DirSddl = $sddl
            $a.FileSddl = $sddl
            if ($r.owner -or $r.group) { $notes += "$($r.label): owner/group are not applied (Set-SaclOnly writes only the SACL)" }
        }
        [SaclOnly]::Prepare($a)
        $actions.Add($a)
    }
    foreach ($k in $cache.Keys) { $notes += "principal $k -> $($cache[$k])" }
    return @{ Rules = $rules; Actions = $actions.ToArray(); Notes = $notes }
}

# New-SimpleSaclPlan is the plan for -Rights/-Trustee/-Flags: no rules, one default action with an
# inheritable ACE on directories and a plain one on files. -Remove writes an empty SACL.
function New-SimpleSaclPlan([string]$Rights, [string]$Trustee, [string]$Flags, [switch]$Remove) {
    $a = New-Object SaclAction
    $a.Label = 'default'
    if ($Remove) {
        $a.DirSddl = 'S:AI'; $a.FileSddl = 'S:AI'
    } else {
        $a.DirSddl  = "S:AI(AU;OICI$Flags;$Rights;;;$Trustee)"
        $a.FileSddl = "S:AI(AU;$Flags;$Rights;;;$Trustee)"
    }
    [SaclOnly]::Prepare($a)
    return @{ Rules = (New-Object SaclRules); Actions = @($a); Notes = @() }
}
