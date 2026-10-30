# Pester 5+ tests for Set-SaclOnly.ps1.
#
#   Invoke-Pester tools/set-saclonly            # from the repo root, Windows PowerShell 5.1 or 7
#
# Offline: nothing here touches an array. The unit tests need nothing special. The tree tests
# write SACLs on local NTFS under $TestDrive and need an elevated shell holding SeSecurityPrivilege,
# SeBackupPrivilege and SeRestorePrivilege (local Administrators); without them they are skipped.
# Each script run goes in a child process: a privilege the test process enabled for its fixtures
# would otherwise still be enabled for -NoBackup.

BeforeDiscovery {
    $script:Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

BeforeAll {
    $here = $PSScriptRoot
    . (Join-Path $here 'SaclPlan.ps1')
    Import-SaclOnlyEngine
    $script:Golden = Get-Content -LiteralPath (Join-Path $here 'testdata/plan-golden.json') -Raw

    # Ace returns a regex for one ACE as .NET renders it back (masks become aliases such as SD).
    function Ace([string]$Sddl) { [regex]::Escape(([SaclOnly]::Normalize("S:$Sddl")).Substring(2)) }
    function Sacl([string]$Sddl) { [SaclOnly]::Normalize($Sddl) }

    # A plan built from the golden one, with only sacl:-only rules left and every principal one
    # this host can resolve.
    function New-TestPlan {
        $p = $script:Golden | ConvertFrom-Json
        $p.rules = @($p.rules[0], $p.rules[1])
        $p.rules[0].sacl[0].principal = 'BUILTIN\Users'
        return $p
    }
}

Describe 'GoGlob' {
    It 'matches every Go path.Match vector' {
        $vectors = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'testdata/glob-vectors.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $vectors.Count | Should -BeGreaterThan 1000
        $wrong = @(foreach ($v in $vectors) {
            if ([GoGlob]::Match($v.pattern, $v.name) -ne $v.match) { "'$($v.pattern)' vs '$($v.name)': Go says $($v.match)" }
        })
        $wrong | Should -BeNullOrEmpty
    }
    It 'is case-sensitive, as on NFS' {
        [GoGlob]::Match('*.tmp', 'A.TMP') | Should -BeFalse
    }
}

Describe 'SaclRules.MatchRule (internal/spec MatchRule)' {
    BeforeAll {
        # TestEffectivePerms: directory; file *.sh; file.
        $r = New-Object SaclRules
        $r.AddRule([SaclRules]::DirType, '')
        $r.AddRule([SaclRules]::FileType, '*.sh')
        $r.AddRule([SaclRules]::FileType, '')
    }
    It 'selects <want> for <name> (dir=<dir>)' -ForEach @(
        @{ name = 'src';        dir = $true;  want = 0 }
        @{ name = 'run.sh';     dir = $false; want = 1 }
        @{ name = 'readme.txt'; dir = $false; want = 2 }
        @{ name = 'run.sh';     dir = $true;  want = 0 }
    ) {
        $r.MatchRule($name, $dir) | Should -Be $want
    }
    It 'falls back to the default when no rule matches' {
        $d = New-Object SaclRules
        $d.AddRule([SaclRules]::FileType, '*.sh')
        $d.MatchRule('a.txt', $false) | Should -Be ([SaclRules]::Default)
        $d.MatchRule('a.sh', $true) | Should -Be ([SaclRules]::Default)
    }
    It 'takes the first match' {
        $d = New-Object SaclRules
        $d.AddRule([SaclRules]::FileType, '*.sh')
        $d.AddRule([SaclRules]::FileType, '')
        $d.MatchRule('deploy.sh', $false) | Should -Be 0
    }
    It 'matches the base name only, and an empty type matches both' {
        $d = New-Object SaclRules
        $d.AddRule([SaclRules]::AnyType, 'audit*')
        $d.MatchRule('audit-2026', $true) | Should -Be 0
        $d.MatchRule('audit.log', $false) | Should -Be 0
        $d.MatchRule('x', $false) | Should -Be ([SaclRules]::Default)
    }
}

Describe 'SaclRules.IsExcluded (internal/spec Excluder.Match)' {
    BeforeAll {
        $e = New-Object SaclRules
        $e.AddExcludeBase('.snapshot'); $e.AddExcludeBase('*.tmp'); $e.AddExcludePath('logs/*.gz')
    }
    It 'excludes <rel>' -ForEach @(
        @{ rel = '.snapshot' }, @{ rel = 'a/b/.snapshot' }, @{ rel = 'a/x.tmp' }, @{ rel = 'logs/old.gz' }
    ) { $e.IsExcluded($rel) | Should -BeTrue }
    It 'keeps <rel>' -ForEach @(
        @{ rel = 'a' }, @{ rel = 'snapshot' }, @{ rel = 'a/x.tmpx' },
        @{ rel = 'a/logs/old.gz' },   # a slash pattern is anchored at the root
        @{ rel = 'logs/a/old.gz' }    # and its wildcards do not cross '/'
    ) { $e.IsExcluded($rel) | Should -BeFalse }
    It 'never excludes the root' {
        $r = New-Object SaclRules
        $r.AddExcludeBase('*')
        $r.IsExcluded('') | Should -BeFalse
        $r.IsExcluded('case42') | Should -BeTrue
    }
}

Describe 'ConvertTo-SddlAceFlags' {
    It 'renders <flags> as <want>' -ForEach @(
        @{ flags = 195; want = 'OICISAFA' }, @{ flags = 75; want = 'OICIIOSA' }, @{ flags = 80; want = 'IDSA' },
        @{ flags = 0x84; want = 'NPFA' }, @{ flags = 0x40; want = 'SA' }
    ) { ConvertTo-SddlAceFlags $flags | Should -BeExactly $want }
    It 'refuses a bit with no SDDL name' {
        { ConvertTo-SddlAceFlags 0x60 } | Should -Throw '*no SDDL name*'
    }
}

Describe 'ConvertFrom-SaclPlan' {
    It 'refuses the golden plan, naming every rule that writes a DACL' {
        { ConvertFrom-SaclPlan ($script:Golden | ConvertFrom-Json) } | Should -Throw 'rule`[2`], rule`[3`] write a DACL*'
    }
    It 'builds one action per rule plus the default, in order' {
        $set = ConvertFrom-SaclPlan (New-TestPlan)
        $set.Rules.Count | Should -Be 2
        @($set.Actions).Count | Should -Be 3
        $set.Actions[0].Label | Should -Be 'rule[0]'
        $set.Actions[0].DirSddl | Should -BeExactly (Sacl 'S:AI(AU;OICIIOSA;0x10046;;;BU)(AU;FA;0x10000;;;CG)')
        $set.Actions[1].DirSddl | Should -BeExactly (Sacl 'S:AI')     # sacl: [] writes an empty SACL
        $set.Actions[2].Label | Should -Be 'default'
        $set.Actions[2].FileSddl | Should -BeExactly (Sacl 'S:AI(AU;OICISAFA;0x1f01e7;;;WD)')
    }
    It 'carries the excludes build-spec split' {
        $set = ConvertFrom-SaclPlan (New-TestPlan)
        $set.Rules.IsExcluded('a/.snapshot') | Should -BeTrue
        $set.Rules.IsExcluded('logs/x.gz') | Should -BeTrue      # from ./logs/*.gz
        $set.Rules.IsExcluded('x/logs/x.gz') | Should -BeFalse
    }
    It 'leaves objects alone under a rule with no sacl: key' {
        $p = New-TestPlan
        $p.rules[1].sacl_set = $false; $p.rules[1].keep_dacl = $false; $p.rules[1].owner = 'root'
        $set = ConvertFrom-SaclPlan $p
        $set.Actions[1].Leave | Should -BeTrue
        $set.Notes | Should -Contain 'rule[1]: owner/group are not applied (Set-SaclOnly writes only the SACL)'
    }
    It 'refuses a numeric principal' {
        $p = New-TestPlan
        $p.rules[0].sacl[0].principal = '1000003'
        { ConvertFrom-SaclPlan $p } | Should -Throw '*numeric id*'
    }
    It 'refuses a principal that does not resolve' {
        $p = New-TestPlan
        $p.rules[0].sacl[0].principal = 'no-such-account-7f3a@invalid.example'
        { ConvertFrom-SaclPlan $p } | Should -Throw '*does not resolve*'
    }
    It 'refuses a dacl: rule' {
        $p = New-TestPlan
        $p.default.has_dacl = $true
        { ConvertFrom-SaclPlan $p } | Should -Throw 'default write a DACL*'
    }
}

Describe 'SaclOnly.Diff (what a SACL write changed besides the audit ACEs)' {
    BeforeAll { $base = 'O:BAG:SYD:P(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:(AU;SA;FA;;;WD)' }
    It 'reports <want> for <name>' -ForEach @(
        @{ name = 'nothing but the audit ACEs'; after = 'O:BAG:SYD:P(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:(AU;FA;FA;;;WD)'; want = '' }
        @{ name = 'D:P only';            after = 'O:BAG:SYD:(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:(AU;SA;FA;;;WD)'; want = 'dacl-unprotected' }
        @{ name = 'D:P gained';          after = 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:(AU;SA;FA;;;WD)'; want = 'dacl-changed' }
        @{ name = 'an ACE mask';         after = 'O:BAG:SYD:P(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1301bf;;;BU)S:(AU;SA;FA;;;WD)'; want = 'dacl-changed' }
        @{ name = 'ACE order';           after = 'O:BAG:SYD:P(D;;WD;;;BU)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)S:(AU;SA;FA;;;WD)'; want = 'dacl-changed' }
        @{ name = 'ACE flags';           after = 'O:BAG:SYD:P(A;OICIID;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:(AU;SA;FA;;;WD)'; want = 'dacl-changed' }
        @{ name = 'a SID';               after = 'O:BAG:SYD:P(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BG)S:(AU;SA;FA;;;WD)'; want = 'dacl-changed' }
        @{ name = 'D:P lost and an ACE'; after = 'O:BAG:SYD:(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)S:(AU;SA;FA;;;WD)'; want = 'dacl-changed' }
        @{ name = 'the owner';           after = 'O:SYG:SYD:P(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:(AU;SA;FA;;;WD)'; want = 'owner-changed' }
        @{ name = 'the group';           after = 'O:BAG:BAD:P(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:(AU;SA;FA;;;WD)'; want = 'group-changed' }
        @{ name = 'S:P gained';          after = 'O:BAG:SYD:P(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:P(AU;SA;FA;;;WD)'; want = 'sacl-protection-changed' }
        @{ name = 'S:AI only';           after = 'O:BAG:SYD:P(A;OICI;FA;;;BA)(D;;WD;;;BU)(A;;0x1200a9;;;BU)S:AI(AU;SA;FA;;;WD)'; want = '' }
    ) {
        [SaclOnly]::Diff($base, $after) | Should -BeExactly $want
    }
}

Describe 'Policy' {
    It 'is strict by default: nothing but no change passes' {
        [SaclOnly]::Policy(@()) | Should -Be 'strict'
        [SaclOnly]::Accepts(@(), '') | Should -BeTrue
        [SaclOnly]::Accepts(@(), 'dacl-unprotected') | Should -BeFalse
    }
    It 'accepts only what was named, and never anything but dacl-unprotected' {
        [SaclOnly]::Accepts(@('dacl-unprotected'), 'dacl-unprotected') | Should -BeTrue
        foreach ($c in 'dacl-changed', 'owner-changed', 'group-changed', 'sacl-protection-changed') {
            [SaclOnly]::Accepts(@('dacl-unprotected', $c), $c) | Should -BeFalse -Because $c
        }
    }
    It 'refuses a strict FlashBlade run on a protected root before any write' {
        $p = New-Object System.Security.AccessControl.RawSecurityDescriptor 'O:BAG:SYD:P(A;;FA;;;BA)'
        $u = New-Object System.Security.AccessControl.RawSecurityDescriptor 'O:BAG:SYD:(A;;FA;;;BA)'
        [SaclOnly]::KnownIncompatible('FlashBlade', @(), $p) | Should -Match 'FlashBlade clears D:P'
        [SaclOnly]::KnownIncompatible('FlashBlade', @(), $u) | Should -BeNullOrEmpty
        [SaclOnly]::KnownIncompatible('FlashBlade', @('dacl-unprotected'), $p) | Should -BeNullOrEmpty
        [SaclOnly]::KnownIncompatible('Unknown', @(), $p) | Should -BeNullOrEmpty
        [SaclOnly]::KnownIncompatible('FlashArray', @(), $p) | Should -BeNullOrEmpty
    }
}

Describe 'Read-SaclPlan' {
    It 'refuses an unknown schema' {
        $f = Join-Path $TestDrive 'p.json'
        ($script:Golden -replace '"schema": 1', '"schema": 2') | Set-Content -LiteralPath $f
        { Read-SaclPlan -Plan $f } | Should -Throw '*schema*'
    }
    It 'reports a build-spec failure with its stderr' {
        $fake = Join-Path $TestDrive 'fake-build-spec.cmd'
        Set-Content -LiteralPath $fake "@echo spec x: bad 1>&2`r`n@exit /b 2"
        { Read-SaclPlan -Spec 'x.yaml' -BuildSpec $fake } | Should -Throw '*exit 2*bad*'
    }
}

Describe 'Set-SaclOnly on a local NTFS tree' -Skip:(-not $script:Elevated) {
    BeforeAll {
        Add-Type -TypeDefinition @'
using System; using System.ComponentModel; using System.Runtime.InteropServices; using System.Security.AccessControl;
public static class TestSd {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetKernelObjectSecurity(IntPtr h, uint info, byte[] sd);
    // Owner, group and DACL through a backup-intent handle: with SeRestorePrivilege, on any object.
    public static void Set(string path, string sddl) {
        IntPtr h = CreateFileW(path, 0x000C0000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "open " + path);
        try {
            var sd = new RawSecurityDescriptor(sddl); var b = new byte[sd.BinaryLength]; sd.GetBinaryForm(b, 0);
            uint info = 7 | (((sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0) ? 0x80000000u : 0x20000000u);
            if (!SetKernelObjectSecurity(h, info, b)) throw new Win32Exception(Marshal.GetLastWin32Error(), "set " + path);
        } finally { CloseHandle(h); }
    }
    // The SACL alone, protected or not as the SDDL says (S:P...).
    public static void SetSacl(string path, string sddl) {
        IntPtr h = CreateFileW(path, 0x01000000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "open " + path);
        try {
            var sd = new RawSecurityDescriptor(sddl); var b = new byte[sd.BinaryLength]; sd.GetBinaryForm(b, 0);
            uint info = 8 | (((sd.ControlFlags & ControlFlags.SystemAclProtected) != 0) ? 0x40000000u : 0x10000000u);
            if (!SetKernelObjectSecurity(h, info, b)) throw new Win32Exception(Marshal.GetLastWin32Error(), "set " + path);
        } finally { CloseHandle(h); }
    }
    // The DACL alone, protected or not as the SDDL says (D:P...); owner and group are left as they are.
    public static void SetDacl(string path, string sddl) {
        IntPtr h = CreateFileW(path, 0x00040000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "open " + path);
        try {
            var sd = new RawSecurityDescriptor(sddl); var b = new byte[sd.BinaryLength]; sd.GetBinaryForm(b, 0);
            uint info = 4 | (((sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0) ? 0x80000000u : 0x20000000u);
            if (!SetKernelObjectSecurity(h, info, b)) throw new Win32Exception(Marshal.GetLastWin32Error(), "set " + path);
        } finally { CloseHandle(h); }
    }
    // A hook for after each SACL write: replaces the DACL with one that adds an Everyone read ACE,
    // which strict refuses, on every object but root, so the root preflight passes and the walk trips.
    public static Action<string> AddEveryoneReadBelow(string root) {
        string r = root.TrimEnd('\\');
        return p => {
            if (p.TrimEnd('\\').EndsWith(r, StringComparison.OrdinalIgnoreCase)) return;
            SetDacl(p, "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;;FR;;;WD)");
        };
    }
}
'@
        foreach ($p in 'SeSecurityPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege') { [SaclOnly]::EnablePrivilege($p) }
        $script:Script = Join-Path $PSScriptRoot 'Set-SaclOnly.ps1'
        $script:Shell = (Get-Process -Id $PID).Path

        # Runs the script in a fresh process (fresh token), returns @{ Out; Code }.
        function Invoke-SaclOnly([string[]]$Arguments) {
            $out = & $script:Shell -NoProfile -ExecutionPolicy Bypass -File $script:Script @Arguments 2>&1
            return @{ Out = ($out | Out-String); Code = $LASTEXITCODE }
        }
        function Get-Count([string]$Out, [string]$Name) {
            if ($Out -match "(?m)^${Name}:\s+([\d,]+)") { return [int]($Matches[1] -replace ',', '') }
            throw "no '$Name' line in:`n$Out"
        }
        # Every object's owner/group/DACL, keyed by path, for the before/after check.
        function Get-Dacls([string]$Root) {
            $m = @{}
            foreach ($p in @($Root) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force | ForEach-Object FullName)) {
                $m[$p] = [SaclOnly]::GetOGD($p)
            }
            return $m
        }
    }

    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N').Substring(0, 8))
        foreach ($d in 'a', 'a\deep', 'audit-1', 'logs', '.snapshot') { New-Item -ItemType Directory -Path (Join-Path $root $d) -Force | Out-Null }
        foreach ($f in 'top.txt', 'a\x.tmp', 'a\deep\y.txt', 'audit-1\z.txt', 'logs\old.gz', '.snapshot\s.txt') {
            Set-Content -LiteralPath (Join-Path $root $f) -Value $f
        }
        $objects = 12   # root + 5 dirs + 6 files
    }

    It 'dry run writes nothing; apply sets every SACL and keeps every DACL; a rerun skips all' {
        $before = Get-Dacls $root
        $r = Invoke-SaclOnly @('-Path', $root)
        $r.Code | Should -Be 0
        Get-Count $r.Out 'Would set' | Should -Be $objects
        [SaclOnly]::GetSacl($root) | Should -Not -Match 'AU;'

        $r.Out | Should -Match 'Preflight: root read \(dry run'

        $r = Invoke-SaclOnly @('-Path', $root, '-Apply', '-Threads', '4')
        $r.Code | Should -Be 0
        $r.Out | Should -Match 'Preflight: root set and read back'
        Get-Count $r.Out 'Objects' | Should -Be $objects    # the root is counted once, by the preflight
        Get-Count $r.Out 'Set' | Should -Be $objects
        Get-Count $r.Out 'Errors' | Should -Be 0
        [SaclOnly]::GetSacl($root) | Should -Match '\(AU;OICISAFA;FA;;;WD\)'
        [SaclOnly]::GetSacl((Join-Path $root 'top.txt')) | Should -Match '\(AU;SAFA;FA;;;WD\)'
        $after = Get-Dacls $root
        foreach ($k in $before.Keys) { $after[$k] | Should -BeExactly $before[$k] -Because $k }

        $r = Invoke-SaclOnly @('-Path', $root, '-Apply')
        $r.Out | Should -Match 'Preflight: root read; it already has its SACL'
        Get-Count $r.Out 'Skipped' | Should -Be $objects
        Get-Count $r.Out 'Set' | Should -Be 0
    }

    # A root this identity cannot read stands in for an array that refuses the SACL: the preflight
    # must stop the run before any child, all of them open to Administrators, is touched.
    It 'stops at the root preflight when the root cannot be read, touching nothing else' {
        # Administrators may open and stat the root (read attributes, synchronize), but not read its security.
        [TestSd]::Set($root, 'O:SYG:SYD:P(A;;FA;;;SY)(A;;0x100080;;;BA)')
        try {
            $r = Invoke-SaclOnly @('-Path', $root, '-Apply', '-NoBackup')
            $r.Code | Should -Not -Be 0
            $r.Out | Should -Match 'STOPPED: preflight: '
            ($r.Out -replace '[\s|]+', ' ') | Should -Match 'audit bypass'
            Get-Count $r.Out 'Objects' | Should -Be 1
            [SaclOnly]::GetSacl((Join-Path $root 'top.txt')) | Should -Not -Match 'AU;'
            [SaclOnly]::GetSacl((Join-Path $root 'a\deep\y.txt')) | Should -Not -Match 'AU;'
        } finally {
            [TestSd]::Set($root, 'O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)')
        }
    }

    It 'keeps each SACL''s protected flag, changing only the audit ACEs' {
        $prot = Join-Path $root 'a'; $protFile = Join-Path $root 'top.txt'
        [TestSd]::SetSacl($prot, 'S:P(AU;SA;FA;;;BU)')
        [TestSd]::SetSacl($protFile, 'S:P')
        [SaclOnly]::GetSacl($prot) | Should -Match '^S:P'     # the fixture really is protected

        $r = Invoke-SaclOnly @('-Path', $root, '-Apply')
        $r.Code | Should -Be 0 -Because $r.Out
        Get-Count $r.Out 'Set' | Should -Be $objects
        [SaclOnly]::GetSacl($prot) | Should -Match ('^S:P(AI)?' + [regex]::Escape('(AU;OICISAFA;FA;;;WD)') + '$')
        [SaclOnly]::GetSacl($protFile) | Should -Match ('^S:P(AI)?' + [regex]::Escape('(AU;SAFA;FA;;;WD)') + '$')
        [SaclOnly]::GetSacl((Join-Path $root 'a\deep')) | Should -Not -Match '^S:P'

        $r = Invoke-SaclOnly @('-Path', $root, '-Apply', '-Remove')
        [SaclOnly]::GetSacl($prot) | Should -Match '^S:P(AI)?(NO_ACCESS_CONTROL)?$'   # NTFS may hand an empty SACL back as NULL
    }

    It 'reports the policy, and -Accept needs -Log' {
        $r = Invoke-SaclOnly @('-Path', $root)
        $r.Out | Should -Match 'Policy:  strict'
        $r.Out | Should -Match 'array not named'
        $r = Invoke-SaclOnly @('-Path', $root, '-Apply', '-Accept', 'dacl-unprotected')
        $r.Code | Should -Not -Be 0
        $r.Out | Should -Match '-Accept needs -Log'
        [SaclOnly]::GetSacl($root) | Should -Not -Match 'AU;'
    }

    It 'refuses a strict -Array FlashBlade run on a protected root, writing nothing' {
        [TestSd]::Set($root, 'O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)')
        $r = Invoke-SaclOnly @('-Path', $root, '-Apply', '-Array', 'FlashBlade', '-Summary', (Join-Path $TestDrive 's.json'))
        $r.Code | Should -Not -Be 0
        $r.Out | Should -Match 'STOPPED: preflight: strict policy on FlashBlade'
        [SaclOnly]::GetSacl($root) | Should -Not -Match 'AU;'
        $s = Get-Content (Join-Path $TestDrive 's.json') -Raw | ConvertFrom-Json
        $s.policy | Should -Be 'strict'
        $s.counts.set | Should -Be 0
    }

    # Cancel stops new writes; a write already started finishes its check. Either way, every SACL
    # that changed was counted as set, and no DACL moved.
    It 'counts every write when cancelled mid-run' {
        foreach ($i in 1..300) { Set-Content -LiteralPath (Join-Path $root "a\f$i.txt") 'x' }
        $before = Get-Dacls $root
        $set = New-SimpleSaclPlan -Rights 'FA' -Trustee 'WD' -Flags 'SAFA'
        [SaclOnly]::Start($root, $set.Rules, $set.Actions, $true, $true, 8, $null, @(), 'Unknown')
        [SaclOnly]::Cancel()
        [SaclOnly]::Wait(30000) | Should -BeTrue
        $r = [SaclOnly]::Current
        $changed = @($before.Keys | Where-Object { [SaclOnly]::GetSacl($_) -match 'AU;' }).Count
        $r.Applied | Should -Be $changed
        $r.Errors | Should -Be 0
        $after = Get-Dacls $root
        foreach ($k in $before.Keys) { $after[$k] | Should -BeExactly $before[$k] -Because $k }
    }

    # A strict stop leaves the SACL it tripped on written. That object, and any write in flight
    # that trips too, counts as set-then-stopped and as an error, never as set, so set plus
    # set-then-stopped is every SACL that changed.
    It 'counts a write that stops a strict run as set, then stopped' {
        foreach ($i in 1..50) { Set-Content -LiteralPath (Join-Path $root "a\f$i.txt") 'x' }
        $before = Get-Dacls $root
        $set = New-SimpleSaclPlan -Rights 'FA' -Trustee 'WD' -Flags 'SAFA'
        [SaclOnly]::AfterSetForTest = [TestSd]::AddEveryoneReadBelow($root)
        try {
            [SaclOnly]::Start($root, $set.Rules, $set.Actions, $true, $true, 8, $null, @(), 'Unknown')
            [SaclOnly]::Wait(30000) | Should -BeTrue
        } finally { [SaclOnly]::AfterSetForTest = $null }
        $r = [SaclOnly]::Current
        $r.Stopped | Should -Match '^dacl-changed on '
        $changed = @($before.Keys | Where-Object { [SaclOnly]::GetSacl($_) -match 'AU;' }).Count
        $r.Preflight | Should -Match '^root set and read back'
        $r.Applied | Should -BeGreaterOrEqual 1                  # the root
        $r.SetStopped | Should -BeGreaterThan 0
        $r.Errors | Should -Be $r.SetStopped
        ($r.Applied + $r.SetStopped) | Should -Be $changed
        $changed | Should -BeLessThan $before.Count
    }

    It '-Remove empties every SACL' {
        Invoke-SaclOnly @('-Path', $root, '-Apply') | Out-Null
        $r = Invoke-SaclOnly @('-Path', $root, '-Apply', '-Remove')
        Get-Count $r.Out 'Set' | Should -Be $objects
        [SaclOnly]::GetSacl($root) | Should -Not -Match 'AU;'
    }

    Context 'a directory that denies Administrators' {
        BeforeEach {
            $locked = Join-Path $root 'locked'
            New-Item -ItemType Directory -Path "$locked\inner" -Force | Out-Null
            Set-Content -LiteralPath "$locked\secret.txt" 'x'
            Set-Content -LiteralPath "$locked\inner\deeper.txt" 'y'
            $lockedObjects = @("$locked\inner\deeper.txt", "$locked\inner", "$locked\secret.txt", $locked)
            foreach ($p in $lockedObjects) { [TestSd]::Set($p, 'O:SYG:SYD:P(A;OICI;FA;;;SY)') }
        }
        AfterEach {
            foreach ($p in $lockedObjects[3..0]) { [TestSd]::Set($p, 'O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)') }
        }

        It 'is read, listed and set with backup semantics' {
            $r = Invoke-SaclOnly @('-Path', $root, '-Apply', '-Log', (Join-Path $TestDrive 'b.csv'))
            $r.Code | Should -Be 0
            Get-Count $r.Out 'Set' | Should -Be ($objects + 4)
            Get-Count $r.Out 'Errors' | Should -Be 0
            [SaclOnly]::GetSacl("$locked\inner\deeper.txt") | Should -Match '\(AU;SAFA;FA;;;WD\)'
            [SaclOnly]::GetOGD("$locked\secret.txt") | Should -BeExactly 'O:SYG:SYD:P(A;OICI;FA;;;SY)'
        }
        It 'fails under -NoBackup, so the test really denies access' {
            $r = Invoke-SaclOnly @('-Path', $root, '-Apply', '-NoBackup', '-Log', (Join-Path $TestDrive 'nb.csv'))
            $r.Code | Should -Be 1
            Get-Count $r.Out 'Errors' | Should -BeGreaterThan 0
            [SaclOnly]::GetSacl("$locked\secret.txt") | Should -Not -Match 'AU;'
        }
    }

    It '-Plan follows rules and excludes the way internal/spec does' {
        $p = New-TestPlan
        $plan = Join-Path $TestDrive 'plan.json'
        $p | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $plan
        $log = Join-Path $TestDrive 'plan.csv'
        $r = Invoke-SaclOnly @('-Path', $root, '-Plan', $plan, '-Apply', '-Log', $log)
        $r.Code | Should -Be 0
        Get-Count $r.Out 'Excluded' | Should -Be 2            # .snapshot (pruned whole) and logs/old.gz
        # 9 objects are in scope (12 minus .snapshot, its pruned s.txt, and logs\old.gz). a\x.tmp
        # selects sacl: [] and already has an empty SACL, so it is skipped.
        Get-Count $r.Out 'Set' | Should -Be 8
        Get-Count $r.Out 'Skipped' | Should -Be 1

        # rule[0]: directory audit*
        [SaclOnly]::GetSacl((Join-Path $root 'audit-1')) | Should -Match ('^S:(AI)?' + (Ace '(AU;OICIIOSA;0x10046;;;BU)') + (Ace '(AU;FA;0x10000;;;CG)') + '$')
        # rule[1]: file *.tmp, sacl: [] -> empty
        [SaclOnly]::GetSacl((Join-Path $root 'a\x.tmp')) | Should -Not -Match 'AU;'
        # default, file and directory alike
        [SaclOnly]::GetSacl((Join-Path $root 'audit-1\z.txt')) | Should -Match (Ace '(AU;OICISAFA;0x1f01e7;;;WD)')
        [SaclOnly]::GetSacl((Join-Path $root 'a\deep')) | Should -Match (Ace '(AU;OICISAFA;0x1f01e7;;;WD)')
        # excluded
        [SaclOnly]::GetSacl((Join-Path $root '.snapshot\s.txt')) | Should -Not -Match 'AU;'
        [SaclOnly]::GetSacl((Join-Path $root 'logs\old.gz')) | Should -Not -Match 'AU;'
        (Import-Csv $log | Where-Object action -eq 'excluded').Count | Should -Be 2
    }

    # Needs a build-spec with --sacl-plan: set SACLONLY_BUILD_SPEC, or put build-spec.exe beside the script.
    It '-Spec reads a YAML spec through build-spec' -Skip:(-not ($env:SACLONLY_BUILD_SPEC -or (Test-Path (Join-Path $PSScriptRoot 'build-spec.exe')))) {
        $yaml = Join-Path $TestDrive 'audit.yaml'
        Set-Content -LiteralPath $yaml @'
protocol: nfsv4
exclude:
  - "*.tmp"
rules:
  - match:
      type: directory
      pattern: "audit*"
    sacl:
      - "U:fdS:EVERYONE@:wadD"
default:
  sacl:
    - "U:F:EVERYONE@:rwadDxtTcCoy"
'@
        $args = @('-Path', $root, '-Spec', $yaml, '-Apply')
        if ($env:SACLONLY_BUILD_SPEC) { $args += @('-BuildSpec', $env:SACLONLY_BUILD_SPEC) }
        $r = Invoke-SaclOnly $args
        $r.Code | Should -Be 0 -Because $r.Out
        Get-Count $r.Out 'Excluded' | Should -Be 1
        [SaclOnly]::GetSacl((Join-Path $root 'audit-1')) | Should -Match (Ace '(AU;OICISA;0x10046;;;WD)')
        [SaclOnly]::GetSacl((Join-Path $root 'top.txt')) | Should -Match (Ace '(AU;FA;0x1f01e7;;;WD)')
        [SaclOnly]::GetSacl((Join-Path $root 'a\x.tmp')) | Should -Not -Match 'AU;'
    }

    It '-Plan refuses a spec that writes DACLs, before touching anything' {
        $plan = Join-Path $TestDrive 'golden.json'
        Set-Content -LiteralPath $plan $script:Golden
        $r = Invoke-SaclOnly @('-Path', $root, '-Plan', $plan, '-Apply')
        $r.Code | Should -Not -Be 0
        $r.Out | Should -Match 'write a DACL'
        [SaclOnly]::GetSacl($root) | Should -Not -Match 'AU;'
    }

    It 'skips a junction without following it' {
        $target = Join-Path $TestDrive 'elsewhere'
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $target 'out.txt') 'o'
        New-Item -ItemType Junction -Path (Join-Path $root 'j') -Target $target | Out-Null
        $r = Invoke-SaclOnly @('-Path', $root, '-Apply')
        Get-Count $r.Out 'Reparse' | Should -Be 1
        [SaclOnly]::GetSacl((Join-Path $target 'out.txt')) | Should -Not -Match 'AU;'
    }
}
