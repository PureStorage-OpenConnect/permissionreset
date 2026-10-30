#!/usr/bin/env python3
"""
Generate a Windows test file tree with EXPLICIT, NAMED-PRINCIPAL ACLs.

Purpose
-------
Test fodder for recursive permission repair on FlashBlade.  The point of this
generator is what it deliberately does *not* do: it does not build ACLs out of
well-known SIDs (Everyone, BUILTIN\\Users, CREATOR OWNER, Authenticated Users).

Those principals are exactly the ones FlashBlade's NFS/SMB translation layer can
collapse into the NFSv4 special principals OWNER@ / GROUP@ / EVERYONE@, which
in turn collapse into POSIX mode bits.  A repair tool tested only against them
can pass while being completely unable to carry a real identity through
ID-mapping.  So every ACL this tool writes contains named domain principals
resolved to real SIDs, and most scenarios are constructed so that the resulting
DACL is provably *not* representable as a 3-class POSIX mode.

ACLs are applied as full SDDL security descriptors (owner + group + DACL) via
Set-Acl, not icacls, because SDDL gives exact control over ACE order,
inherit-only flags, no-propagate flags, and granular access masks that icacls
cannot express.

Every applied descriptor is recorded to an ACL manifest (JSON) so a post-repair
validator can diff intent against reality.

Usage
-----
    # dry run: resolve principals, print the scenarios, touch nothing
    python generate_tree_windows.py \\\\flashblade\\share\\testdata ^
        --principals examples\\principals_example.json --dry-run

    # build + stamp
    python generate_tree_windows.py Z:\\testdata ^
        --principals examples\\principals_example.json --scale small

    # re-stamp ACLs on a tree that already exists
    python generate_tree_windows.py Z:\\testdata ^
        --principals examples\\principals_example.json --acls-only

Gotchas learned the hard way
----------------------------
* A safety ACE for Domain Admins is NOT a safety net.  UAC hands a
  non-elevated process a filtered token in which Domain Admins and
  BUILTIN\\Administrators are present but marked deny-only, so the ACE grants
  the running process nothing and a protected DACL locks you out of the tree
  you just created.  The safety ACE is therefore always anchored to the
  running account's own SID.
* Set-Acl preserves non-canonical ACE order (allow before deny), which is what
  makes the noncanonical_order scenario meaningful.  It does reorder among
  same-type ACEs.
* Setting owner/group needs WRITE_OWNER or SeRestorePrivilege.  Where it is
  refused the applier retries with the DACL alone and records owner_set=false
  in the manifest rather than failing the path.

No dependencies beyond the Python 3 standard library.  Windows only.
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Tree shape
# ---------------------------------------------------------------------------

SCALES = {
    # copies = how many times to replicate the seed tree
    "small":  {"copies": 10,  "seed_files": 50,  "max_depth": 6},
    "medium": {"copies": 50,  "seed_files": 100, "max_depth": 10},
    "large":  {"copies": 200, "seed_files": 200, "max_depth": 14},
}

EXTENSIONS = [".txt", ".sh", ".dat", ".conf", ".log", ".csv", ".json", ".xml", ".py", ".md"]
DEPT_NAMES = ["engineering", "finance", "marketing", "ops", "legal", "hr", "data", "infra"]
PROJECT_NAMES = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
SUBDIR_NAMES = ["src", "docs", "config", "logs", "tmp", "archive", "reports", "scripts",
                "input", "output", "staging", "backup", "shared", "private", "templates"]

# ---------------------------------------------------------------------------
# SDDL building blocks
# ---------------------------------------------------------------------------

# Access masks, as hex.  Named for what they mean on a file/dir.
FULL        = 0x1F01FF   # Full control
MODIFY      = 0x1301BF   # Modify
READ_EXEC   = 0x1200A9   # Read & execute
READ        = 0x120089   # Read
WRITE       = 0x100116   # Write
# Granular masks with no POSIX equivalent whatsoever:
APPEND_ONLY = 0x120004   # SYNCHRONIZE | READ_CONTROL | FILE_APPEND_DATA
LIST_ONLY   = 0x120001   # SYNCHRONIZE | READ_CONTROL | FILE_LIST_DIRECTORY
TAKE_OWNER  = 0x1200A9 | 0x80000   # Read&Execute + WRITE_OWNER
CHANGE_PERM = 0x1200A9 | 0x40000   # Read&Execute + WRITE_DAC
DELETE_CHILD = 0x120040  # SYNCHRONIZE | READ_CONTROL | FILE_DELETE_CHILD

# Well-known SIDs, tracked so we can count/limit their use rather than
# accidentally leaning on them.
WELL_KNOWN_SIDS = {
    "S-1-1-0":      "Everyone",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-11":     "NT AUTHORITY\\Authenticated Users",
    "S-1-3-0":      "CREATOR OWNER",
    "S-1-3-1":      "CREATOR GROUP",
    "S-1-5-18":     "NT AUTHORITY\\SYSTEM",
    "S-1-5-7":      "Anonymous Logon",
}


def ace(atype, flags, mask, sid):
    """Build one SDDL ACE string.

    atype: 'A' (allow) or 'D' (deny)
    flags: inheritance flag string, e.g. 'OICI', 'OICIIO', 'CINP', or ''
    mask:  integer access mask
    sid:   SID string
    """
    return "({};{};0x{:X};;;{})".format(atype, flags, mask, sid)


def sddl(owner_sid, group_sid, aces, protected=False):
    """Assemble a full SDDL security descriptor string.

    protected=True emits 'P', which blocks inheritance from the parent --
    the SMB equivalent of a subtree that has been severed from its template.
    """
    flags = "P" if protected else ""
    # 'AI' marks the DACL as auto-inherit-capable; without it Windows will not
    # propagate our OI/CI ACEs to objects created later.
    return "O:{}G:{}D:{}AI{}".format(owner_sid, group_sid, flags, "".join(aces))


def sids_in(aces):
    """Extract the SID from each ACE string."""
    out = []
    for a in aces:
        out.append(a.strip("()").split(";")[5])
    return out


# ---------------------------------------------------------------------------
# Scenario library
# ---------------------------------------------------------------------------
#
# Each scenario returns (aces, owner_role, group_role, protected).  Roles are
# looked up in the roster and resolved to SIDs by the caller.
#
# The `posix_representable` field is the whole point: False means the DACL
# cannot be expressed as owner/group/other mode bits, so any repair tool that
# round-trips through POSIX will visibly lose information.

def _scenarios():
    return [
        {
            "name": "named_dept_full",
            "desc": "Three distinct named principals, no well-known SIDs at all",
            "posix_representable": False,
            "why": "Two named groups with different masks plus a named owner is "
                   "four identity classes; POSIX has three and one is 'other'.",
            "owner": "owner_primary",
            "group": "group_primary",
            "protected": False,
            "aces": lambda R: [
                ace("A", "OICI", FULL,      R["owner_primary"]),
                ace("A", "OICI", MODIFY,    R["group_primary"]),
                ace("A", "OICI", READ_EXEC, R["group_readonly"]),
            ],
        },
        {
            "name": "deny_named_user",
            "desc": "Explicit DENY for one named user inside an allowed group",
            "posix_representable": False,
            "why": "POSIX cannot deny a single user who is a member of an "
                   "allowed group. Canonical order: deny ACE first.",
            "owner": "owner_secondary",
            "group": "group_secondary",
            "protected": False,
            "aces": lambda R: [
                ace("D", "OICI", MODIFY,    R["user_denied"]),
                ace("A", "OICI", FULL,      R["owner_secondary"]),
                ace("A", "OICI", MODIFY,    R["group_secondary"]),
                ace("A", "OICI", READ_EXEC, R["user_collaborator"]),
            ],
        },
        {
            "name": "noncanonical_order",
            "desc": "Allow ACE placed before a deny ACE (non-canonical DACL)",
            "posix_representable": False,
            "why": "Exercises whether the repair tool normalizes ACE order. "
                   "Windows evaluates in stored order, so this DACL actually "
                   "grants where the deny was meant to bite.",
            "owner": "owner_tertiary",
            "group": "group_secondary",
            "protected": True,
            "aces": lambda R: [
                ace("A", "OICI", MODIFY,    R["user_collaborator"]),
                ace("D", "OICI", FULL,      R["user_denied"]),
                ace("A", "OICI", FULL,      R["owner_tertiary"]),
                ace("A", "OICI", READ_EXEC, R["group_readonly"]),
            ],
        },
        {
            "name": "inherit_only_template",
            "desc": "Inherit-only ACEs: no effect on the dir, stamped on children",
            "posix_representable": False,
            "why": "IO flag has no POSIX analogue. The directory's own effective "
                   "ACL differs from what its children receive.",
            "owner": "owner_primary",
            "group": "group_array",
            "protected": False,
            "aces": lambda R: [
                ace("A", "",       FULL,      R["owner_primary"]),
                ace("A", "OICIIO", MODIFY,    R["group_array"]),
                ace("A", "OICIIO", READ_EXEC, R["user_auditor"]),
            ],
        },
        {
            "name": "no_propagate_one_level",
            "desc": "CI+NP ACE: applies to immediate children only",
            "posix_representable": False,
            "why": "NO_PROPAGATE_INHERIT means depth-1 children get the ACE and "
                   "grandchildren do not. Nothing in POSIX or plain NFSv4 mode "
                   "bits expresses a depth-limited grant.",
            "owner": "owner_secondary",
            "group": "group_primary",
            "protected": False,
            "aces": lambda R: [
                ace("A", "OICI",   FULL,      R["owner_secondary"]),
                ace("A", "CINP",   MODIFY,    R["group_secondary"]),
                ace("A", "OICI",   READ_EXEC, R["group_primary"]),
            ],
        },
        {
            "name": "append_only_service",
            "desc": "Service account with append-data but not write-data",
            "posix_representable": False,
            "why": "FILE_APPEND_DATA without FILE_WRITE_DATA is a log-drop "
                   "pattern. POSIX 'w' grants both.",
            "owner": "owner_tertiary",
            "group": "group_primary",
            "protected": False,
            "aces": lambda R: [
                ace("A", "OICI", FULL,        R["owner_tertiary"]),
                ace("A", "OICI", APPEND_ONLY, R["service_account"]),
                ace("A", "OICI", READ,        R["group_readonly"]),
                ace("A", "OICI", MODIFY,      R["group_primary"]),
            ],
        },
        {
            "name": "delegated_admin_rights",
            "desc": "Split WRITE_DAC / WRITE_OWNER across two named principals",
            "posix_representable": False,
            "why": "Permission-to-change-permissions and take-ownership are "
                   "separate bits in NTFS/NFSv4 (C and o). POSIX ties both to "
                   "being the owner.",
            "owner": "owner_primary",
            "group": "group_array",
            "protected": False,
            "aces": lambda R: [
                ace("A", "OICI", FULL,        R["owner_primary"]),
                ace("A", "OICI", CHANGE_PERM, R["user_collaborator"]),
                ace("A", "OICI", TAKE_OWNER,  R["group_array"]),
                ace("A", "OICI", READ_EXEC,   R["group_readonly"]),
            ],
        },
        {
            "name": "owner_holds_no_ace",
            "desc": "Owner has no ACE; access comes only from a named group",
            "posix_representable": False,
            "why": "Catches tools that assume OWNER@ always maps to an existing "
                   "owner ACE, or that synthesize one during repair.",
            "owner": "owner_secondary",
            "group": "group_primary",
            "protected": True,
            "aces": lambda R: [
                ace("A", "OICI", MODIFY,    R["group_primary"]),
                ace("A", "OICI", READ_EXEC, R["group_secondary"]),
            ],
        },
        {
            "name": "protected_severed_subtree",
            "desc": "Inheritance blocked (P), named principals only",
            "posix_representable": False,
            "why": "The classic broken subtree: someone hit 'disable "
                   "inheritance' and the tree diverged from its template.",
            "owner": "owner_tertiary",
            "group": "group_secondary",
            "protected": True,
            "aces": lambda R: [
                ace("A", "OICI", FULL,      R["owner_tertiary"]),
                ace("A", "OICI", READ,      R["user_auditor"]),
                ace("A", "OICI", LIST_ONLY, R["group_readonly"]),
            ],
        },
        {
            "name": "six_way_split",
            "desc": "Six distinct named principals, six distinct masks",
            "posix_representable": False,
            "why": "Maximum identity pressure. Anything that reduces to three "
                   "classes loses at least three principals here.",
            "owner": "owner_primary",
            "group": "group_primary",
            "protected": True,
            "aces": lambda R: [
                ace("A", "OICI", FULL,         R["owner_primary"]),
                ace("A", "OICI", MODIFY,       R["owner_secondary"]),
                ace("A", "OICI", READ_EXEC,    R["user_collaborator"]),
                ace("A", "OICI", READ,         R["user_auditor"]),
                ace("A", "OICI", DELETE_CHILD, R["group_secondary"]),
                ace("A", "OICI", APPEND_ONLY,  R["service_account"]),
            ],
        },
        {
            "name": "mixed_named_and_wellknown",
            "desc": "Named principals alongside Everyone (control case)",
            "posix_representable": False,
            "why": "Deliberately includes S-1-1-0 so we can confirm the tool "
                   "keeps the named ACEs instead of over-collapsing the whole "
                   "DACL to the EVERYONE@ it recognizes.",
            "owner": "owner_primary",
            "group": "group_primary",
            "protected": False,
            "allow_wellknown": True,
            "aces": lambda R: [
                ace("A", "OICI", FULL,      R["owner_primary"]),
                ace("A", "OICI", MODIFY,    R["group_primary"]),
                ace("A", "OICI", READ_EXEC, "S-1-1-0"),
            ],
        },
    ]


# File-level scenarios: no inheritance flags, applied to individual files to
# create explicit-ACE outliers inside otherwise-uniform subtrees.
def _file_scenarios():
    return [
        {
            "name": "file_denied_user",
            "desc": "Single file denying one named user",
            "posix_representable": False,
            "why": "Per-user deny on one file inside an inherited subtree.",
            "owner": "owner_primary",
            "group": "group_primary",
            "protected": True,
            "aces": lambda R: [
                ace("D", "", FULL,   R["user_denied"]),
                ace("A", "", FULL,   R["owner_primary"]),
                ace("A", "", MODIFY, R["group_primary"]),
            ],
        },
        {
            "name": "file_append_only",
            "desc": "Append-only file for the service account",
            "posix_representable": False,
            "why": "Log file the service can extend but not rewrite.",
            "owner": "owner_tertiary",
            "group": "group_primary",
            "protected": True,
            "aces": lambda R: [
                ace("A", "", FULL,        R["owner_tertiary"]),
                ace("A", "", APPEND_ONLY, R["service_account"]),
                ace("A", "", READ,        R["group_readonly"]),
            ],
        },
        {
            "name": "file_orphan_owner",
            "desc": "File owned by a user with no ACE, readable by auditor only",
            "posix_representable": False,
            "why": "Owner cannot read their own file -- legal in NTFS/NFSv4, "
                   "impossible to express in mode bits.",
            "owner": "owner_secondary",
            "group": "group_secondary",
            "protected": True,
            "aces": lambda R: [
                ace("A", "", READ, R["user_auditor"]),
            ],
        },
        {
            "name": "file_four_principal",
            "desc": "Four named principals on one file",
            "posix_representable": False,
            "why": "Four identity classes on a leaf object.",
            "owner": "owner_primary",
            "group": "group_array",
            "protected": True,
            "aces": lambda R: [
                ace("A", "", FULL,      R["owner_primary"]),
                ace("A", "", MODIFY,    R["group_array"]),
                ace("A", "", READ_EXEC, R["user_collaborator"]),
                ace("A", "", READ,      R["user_auditor"]),
            ],
        },
    ]


# ---------------------------------------------------------------------------
# Principal resolution
# ---------------------------------------------------------------------------

RESOLVE_PS = r"""
param([string]$InFile,[string]$OutFile)
$names = Get-Content -Raw -LiteralPath $InFile | ConvertFrom-Json
$out = @{}
foreach ($n in $names) {
    try {
        $acct = New-Object System.Security.Principal.NTAccount($n)
        $sid  = $acct.Translate([System.Security.Principal.SecurityIdentifier])
        $out[$n] = $sid.Value
    } catch {
        $out[$n] = $null
    }
}
$out | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $OutFile -Encoding utf8
"""


def run_powershell(script_body, args, timeout=300):
    """Write a PowerShell script to a temp file and run it."""
    fd, path = tempfile.mkstemp(suffix=".ps1")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script_body)
        cmd = ["powershell.exe", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-File", path] + args
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def resolve_principals(roster, workdir):
    """Resolve every roster account name to a SID. Fails hard on any miss."""
    roles = roster["roles"]
    names = sorted(set(roles.values()))

    in_file = os.path.join(workdir, "names.json")
    out_file = os.path.join(workdir, "sids.json")
    with open(in_file, "w", encoding="utf-8") as f:
        json.dump(names, f)

    result = run_powershell(RESOLVE_PS, [in_file, out_file])
    if not os.path.exists(out_file):
        print("ERROR: SID resolution failed to produce output.", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    with open(out_file, encoding="utf-8-sig") as f:
        name_to_sid = json.load(f)

    unresolved = [n for n in names if not name_to_sid.get(n)]
    if unresolved:
        print("ERROR: these principals do not resolve to a SID on this host:",
              file=sys.stderr)
        for n in unresolved:
            print("  {}".format(n), file=sys.stderr)
        print("\nFix the roster or check domain connectivity. Refusing to fall "
              "back to well-known SIDs -- that would defeat the purpose of this "
              "generator.", file=sys.stderr)
        sys.exit(1)

    role_to_sid = {role: name_to_sid[acct] for role, acct in roles.items()}

    # Guard: a named principal that happens to BE a well-known SID is not a
    # named principal for our purposes.
    for role, sid in role_to_sid.items():
        if sid in WELL_KNOWN_SIDS:
            print("ERROR: role '{}' -> {} resolves to well-known SID {} ({}). "
                  "Pick a real domain account.".format(
                      role, roles[role], sid, WELL_KNOWN_SIDS[sid]), file=sys.stderr)
            sys.exit(1)

    return role_to_sid, name_to_sid


def current_user_sid():
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
        capture_output=True, text=True)
    return r.stdout.strip()


def sid_is_effective(sid):
    """Is this SID actually usable for access by the running process?

    Group membership in AD is not the same as group membership in the current
    token.  UAC hands non-elevated processes a filtered token in which
    Domain Admins and BUILTIN\\Administrators are present but marked DENY-only,
    so an ACE granting them provides no access at all.  IsInRole respects the
    filtered token, which is exactly the question we need answered.
    """
    cmd = ("$p = New-Object System.Security.Principal.WindowsPrincipal("
           "[System.Security.Principal.WindowsIdentity]::GetCurrent()); "
           "$p.IsInRole([System.Security.Principal.SecurityIdentifier]'{}')".format(sid))
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                        "-Command", cmd], capture_output=True, text=True)
    return r.stdout.strip().lower() == "true"


# ---------------------------------------------------------------------------
# Tree construction (unchanged shape from the original generator)
# ---------------------------------------------------------------------------

def build_seed(seed_root, n_files, max_depth):
    print("Building seed tree: {} files, max depth {}".format(n_files, max_depth))
    os.makedirs(seed_root, exist_ok=True)
    count = 0

    current = seed_root
    chain_depth = min(max_depth, 12)
    for i in range(chain_depth):
        current = os.path.join(current, "deep_{:02d}".format(i))
        os.makedirs(current, exist_ok=True)
        ext = random.choice(EXTENSIONS)
        fpath = os.path.join(current, "nested_{:02d}{}".format(i, ext))
        with open(fpath, "w") as f:
            f.write("deep file level {}\n".format(i))
        count += 1

    wide = os.path.join(seed_root, "bulk_data")
    os.makedirs(wide, exist_ok=True)
    wide_count = min(n_files // 4, 500)
    for i in range(wide_count):
        ext = random.choice(EXTENSIONS)
        fpath = os.path.join(wide, "file_{:04d}{}".format(i, ext))
        with open(fpath, "w") as f:
            f.write("bulk file {}\n".format(i))
        count += 1

    remaining = n_files - count
    _build_branch(seed_root, "mixed", min(max_depth - 2, 6), remaining, [0])

    total = sum(len(files) for _, _, files in os.walk(seed_root))
    print("  Seed: {} files created".format(total))
    return total


def _build_branch(base, name, depth, budget, counter):
    if depth <= 0 or counter[0] >= budget:
        return
    path = os.path.join(base, name)
    os.makedirs(path, exist_ok=True)

    remaining = budget - counter[0]
    if remaining < 2:
        return
    n_files = random.randint(2, min(15, remaining))
    for i in range(n_files):
        if counter[0] >= budget:
            return
        ext = random.choice(EXTENSIONS)
        fpath = os.path.join(path, "f_{:02d}{}".format(i, ext))
        with open(fpath, "w") as f:
            f.write("file {} in {}\n".format(i, name))
        counter[0] += 1

    n_sub = random.randint(1, min(4, depth))
    for i in range(n_sub):
        if counter[0] >= budget:
            return
        subname = random.choice(SUBDIR_NAMES) + "_{}".format(i)
        _build_branch(path, subname, depth - 1, budget, counter)


def fan_out(seed_root, target_root, n_copies):
    print("Fanning out {} copies of seed tree".format(n_copies))
    os.makedirs(target_root, exist_ok=True)

    depts = random.sample(DEPT_NAMES, min(len(DEPT_NAMES), max(2, n_copies // 10)))
    copy_idx = 0

    for dept in depts:
        dept_path = os.path.join(target_root, dept)
        os.makedirs(dept_path, exist_ok=True)

        projs_per_dept = max(1, n_copies // len(depts))
        for p in range(projs_per_dept):
            if copy_idx >= n_copies:
                break
            proj = "{}_{:02d}".format(random.choice(PROJECT_NAMES), p)
            dest = os.path.join(dept_path, proj)
            shutil.copytree(seed_root, dest)
            copy_idx += 1
            if copy_idx % 10 == 0:
                print("  {}/{} copies done".format(copy_idx, n_copies), end="\r")

        if copy_idx >= n_copies:
            break

    print("\n  {} copies created".format(copy_idx))
    return copy_idx


# ---------------------------------------------------------------------------
# ACL planning
# ---------------------------------------------------------------------------

def plan_acls(target_root, role_sids, safety_sids, files_per_subtree):
    """Walk the tree and decide which security descriptor each path gets.

    Returns a list of job dicts, ordered parent-before-child so that a
    protected DACL on a parent never blocks us from reaching its children.
    """
    dir_scenarios = _scenarios()
    file_scenarios = _file_scenarios()
    jobs = []

    # Project directories -- the second level under the root -- each get a
    # scenario, and it propagates down their subtree by inheritance.  We stamp
    # the subtree root explicitly and let OI/CI carry it to new children;
    # existing children were created before the stamp, so we stamp the
    # directories explicitly too.
    subtree_roots = []
    for dept in sorted(os.listdir(target_root)):
        dept_path = os.path.join(target_root, dept)
        if not os.path.isdir(dept_path):
            continue
        for proj in sorted(os.listdir(dept_path)):
            proj_path = os.path.join(dept_path, proj)
            if os.path.isdir(proj_path):
                subtree_roots.append(proj_path)

    if not subtree_roots:
        print("  WARNING: no project subtrees found under {}".format(target_root),
              file=sys.stderr)

    for idx, root in enumerate(subtree_roots):
        # Round-robin so every scenario is exercised regardless of tree size.
        scenario = dir_scenarios[idx % len(dir_scenarios)]
        jobs.extend(_jobs_for_subtree(root, scenario, role_sids, safety_sids))

        # Sprinkle explicit-ACE file outliers inside this subtree.
        candidates = []
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                candidates.append(os.path.join(dirpath, fn))
        if candidates:
            n = min(len(candidates), files_per_subtree)
            for j, fpath in enumerate(random.sample(candidates, n)):
                fscen = file_scenarios[j % len(file_scenarios)]
                jobs.append(_job(fpath, False, fscen, role_sids, safety_sids))

    # Parent before child.  Path depth is the ordering key; the file outliers
    # sort naturally after the directories that contain them.
    jobs.sort(key=lambda j: (j["path"].count(os.sep), j["path"]))
    return jobs


def _jobs_for_subtree(root, scenario, role_sids, safety_sids):
    """One job for the subtree root plus one for every directory beneath it."""
    out = [_job(root, True, scenario, role_sids, safety_sids)]
    for dirpath, dirnames, _ in os.walk(root):
        for d in dirnames:
            out.append(_job(os.path.join(dirpath, d), True, scenario,
                            role_sids, safety_sids))
    return out


def _job(path, is_dir, scenario, role_sids, safety_sids):
    aces = list(scenario["aces"](role_sids))

    # Safety ACEs: without a guaranteed path back in, a protected DACL that
    # excludes the running account makes the subtree unreadable to the
    # generator itself and to the validator afterward.  These are inherited
    # full-control grants, appended last so they never perturb the deny/allow
    # ordering the scenario is testing.
    for s in safety_sids:
        flags = "OICI" if is_dir else ""
        aces.append(ace("A", flags, FULL, s))

    owner_sid = role_sids[scenario["owner"]]
    group_sid = role_sids[scenario["group"]]
    descriptor = sddl(owner_sid, group_sid, aces, scenario.get("protected", False))

    used = sids_in(aces)
    named = [s for s in used if s not in WELL_KNOWN_SIDS and s not in safety_sids]
    wellknown = [WELL_KNOWN_SIDS[s] for s in used if s in WELL_KNOWN_SIDS]

    return {
        "path": path,
        "isDir": is_dir,
        "sddl": descriptor,
        "scenario": scenario["name"],
        "desc": scenario["desc"],
        "posix_representable": scenario["posix_representable"],
        "why": scenario["why"],
        "owner": owner_sid,
        "group": group_sid,
        "named_sids": named,
        "wellknown_sids": wellknown,
        "aces": aces,
    }


# ---------------------------------------------------------------------------
# ACL application
# ---------------------------------------------------------------------------

APPLY_PS = r"""
param([string]$JobFile,[string]$ResultFile)
$ErrorActionPreference = 'Stop'
# PS 5.1's ConvertFrom-Json emits a JSON array as ONE pipeline item, so a
# bare @() wrap yields a single-element array containing the array. Normalize.
$parsed = Get-Content -Raw -LiteralPath $JobFile | ConvertFrom-Json
if ($parsed -is [System.Array]) { $jobs = $parsed } else { $jobs = @($parsed) }
$total = $jobs.Count
$results = New-Object System.Collections.ArrayList
$i = 0
foreach ($j in $jobs) {
    $i++
    if ($i % 200 -eq 0) { Write-Host "  applied $i/$total" }
    $rec = [ordered]@{ path = $j.path; ok = $true; ownerSet = $true; error = $null }
    try {
        if ($j.isDir) { $sd = New-Object System.Security.AccessControl.DirectorySecurity }
        else          { $sd = New-Object System.Security.AccessControl.FileSecurity }
        $sd.SetSecurityDescriptorSddlForm($j.sddl)
        Set-Acl -LiteralPath $j.path -AclObject $sd
    } catch {
        # Owner/group assignment needs WRITE_OWNER or SeRestorePrivilege.
        # Retry with the DACL alone so the ACE content still lands, and record
        # that ownership did not take.
        $rec.ownerSet = $false
        try {
            $daclOnly = $j.sddl -replace '^O:[^G]+G:\S*?(?=D:)', ''
            if ($j.isDir) { $sd2 = New-Object System.Security.AccessControl.DirectorySecurity }
            else          { $sd2 = New-Object System.Security.AccessControl.FileSecurity }
            $sd2.SetSecurityDescriptorSddlForm($daclOnly)
            Set-Acl -LiteralPath $j.path -AclObject $sd2
        } catch {
            $rec.ok = $false
            $rec.error = $_.Exception.Message
        }
    }
    [void]$results.Add([pscustomobject]$rec)
}
ConvertTo-Json -InputObject @($results) -Depth 4 | Set-Content -LiteralPath $ResultFile -Encoding utf8
Write-Host "  applied $i/$total"
"""


def apply_acls(jobs, workdir):
    """Hand the whole job list to one PowerShell process."""
    job_file = os.path.join(workdir, "acl_jobs.json")
    result_file = os.path.join(workdir, "acl_results.json")

    slim = [{"path": j["path"], "isDir": j["isDir"], "sddl": j["sddl"]} for j in jobs]
    with open(job_file, "w", encoding="utf-8") as f:
        json.dump(slim, f)

    print("Applying {} security descriptors via Set-Acl".format(len(slim)))
    result = run_powershell(APPLY_PS, [job_file, result_file],
                            timeout=max(600, len(slim) * 2))
    if result.stdout:
        print(result.stdout.rstrip())
    if result.returncode != 0 and not os.path.exists(result_file):
        print("ERROR: ACL application failed.", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    with open(result_file, encoding="utf-8-sig") as f:
        results = json.load(f)
    if isinstance(results, dict):   # single-element JSON is not an array
        results = [results]
    return {r["path"]: r for r in results}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def write_manifest(path, target_root, roster, role_sids, jobs, results):
    entries = []
    for j in jobs:
        r = results.get(j["path"], {}) if results else {}
        entries.append({
            "path": j["path"],
            "type": "directory" if j["isDir"] else "file",
            "scenario": j["scenario"],
            "description": j["desc"],
            "posix_representable": j["posix_representable"],
            "rationale": j["why"],
            "sddl": j["sddl"],
            "owner_sid": j["owner"],
            "group_sid": j["group"],
            "named_principal_sids": j["named_sids"],
            "wellknown_principal_sids": j["wellknown_sids"],
            "aces": j["aces"],
            "applied": r.get("ok"),
            "owner_set": r.get("ownerSet"),
            "error": r.get("error"),
        })

    manifest = {
        "generated_target": target_root,
        "domain": roster.get("domain"),
        "roles": roster["roles"],
        "role_sids": role_sids,
        "entry_count": len(entries),
        "entries": entries,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def summarize(jobs, results):
    by_scenario = {}
    for j in jobs:
        s = by_scenario.setdefault(j["scenario"], {"count": 0, "ok": 0, "owner": 0})
        s["count"] += 1
        r = results.get(j["path"], {}) if results else {}
        if r.get("ok"):
            s["ok"] += 1
        if r.get("ownerSet"):
            s["owner"] += 1

    print("\nScenario coverage:")
    print("  {:<28} {:>7} {:>8} {:>10}".format("scenario", "paths", "applied", "owner set"))
    for name in sorted(by_scenario):
        s = by_scenario[name]
        print("  {:<28} {:>7} {:>8} {:>10}".format(name, s["count"], s["ok"], s["owner"]))

    named_free = [j for j in jobs if not j["named_sids"]]
    if named_free:
        print("\n  WARNING: {} descriptors contain no named principal".format(len(named_free)))
    else:
        print("\n  All {} descriptors carry at least one named domain SID.".format(len(jobs)))

    non_posix = sum(1 for j in jobs if not j["posix_representable"])
    print("  {}/{} descriptors are not expressible as POSIX mode bits.".format(
        non_posix, len(jobs)))

    failures = [p for p, r in (results or {}).items() if not r.get("ok")]
    if failures:
        print("\n  {} paths failed to apply. First few:".format(len(failures)))
        for p in failures[:5]:
            print("    {}: {}".format(p, results[p].get("error")))


def print_plan(jobs):
    seen = {}
    for j in jobs:
        seen.setdefault(j["scenario"], j)
    print("\nScenarios that would be applied:\n")
    for name in sorted(seen):
        j = seen[name]
        print("  {}".format(name))
        print("    {}".format(j["desc"]))
        print("    POSIX-representable: {}".format(j["posix_representable"]))
        print("    why: {}".format(j["why"]))
        print("    example path: {}".format(j["path"]))
        print("    SDDL: {}".format(j["sddl"]))
        print("")


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a Windows test tree with explicit named-principal ACLs")
    parser.add_argument("root",
                        help="Target path, e.g. \\\\server\\share\\testdata or Z:\\testdata")
    parser.add_argument("--principals", required=True,
                        help="JSON roster mapping roles to real account names")
    parser.add_argument("--scale", choices=SCALES.keys(), default="small",
                        help="Tree size: small (~500 files), medium (~5k), large (~40k)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--acls-only", action="store_true",
                        help="Skip tree creation; stamp ACLs on an existing tree")
    parser.add_argument("--no-acls", action="store_true",
                        help="Build the tree but do not touch ACLs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Resolve principals and print the plan; change nothing")
    parser.add_argument("--files-per-subtree", type=int, default=4,
                        help="Explicit-ACE file outliers per project subtree")
    parser.add_argument("--control-principal",
                        help="Extra account to grant a full-control safety ACE, "
                             "in addition to the running account (which is "
                             "always granted one). Default: the roster's "
                             "'control' role, if present.")
    parser.add_argument("--no-safety-ace", action="store_true",
                        help="Omit the safety ACEs entirely. Protected DACLs "
                             "will then lock you out of the tree you just "
                             "created, and only an elevated session can "
                             "recover it.")
    parser.add_argument("--manifest", default=None,
                        help="Where to write the ACL manifest "
                             "(default: <root>\\acl_manifest.json)")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("ERROR: this generator requires Windows (Set-Acl, SID resolution).",
              file=sys.stderr)
        sys.exit(1)

    with open(args.principals, encoding="utf-8") as f:
        roster = json.load(f)
    if "roles" not in roster:
        print("ERROR: roster has no 'roles' map.", file=sys.stderr)
        sys.exit(1)

    random.seed(args.seed)
    scale = SCALES[args.scale]
    workdir = tempfile.mkdtemp(prefix="acltree_")

    try:
        print("Resolving principals against the domain")
        role_sids, name_to_sid = resolve_principals(roster, workdir)
        for role in sorted(role_sids):
            print("  {:<18} {:<32} {}".format(
                role, roster["roles"][role], role_sids[role]))

        # The account being denied must not be the account running the
        # generator, or we lock ourselves out mid-run.
        me = current_user_sid()
        denied_sid = role_sids.get("user_denied")
        if me and denied_sid == me:
            print("\nERROR: role 'user_denied' is the account running this script. "
                  "Pick a different user.", file=sys.stderr)
            sys.exit(1)

        safety_sids = []
        if not args.no_safety_ace:
            # Always anchor on the running account's own SID.  A group ACE is
            # not a safety net: UAC's filtered token marks Domain Admins and
            # BUILTIN\Administrators deny-only in a non-elevated process, so
            # granting them full control grants this process nothing.
            if not me:
                print("ERROR: could not determine the current user's SID.",
                      file=sys.stderr)
                sys.exit(1)
            safety_sids.append(me)

            extra = args.control_principal or (
                roster["roles"].get("control") if "control" in role_sids else None)
            if extra:
                if args.control_principal:
                    extra_in = os.path.join(workdir, "ctl_in.json")
                    extra_out = os.path.join(workdir, "ctl_out.json")
                    with open(extra_in, "w", encoding="utf-8") as f:
                        json.dump([extra], f)
                    run_powershell(RESOLVE_PS, [extra_in, extra_out])
                    with open(extra_out, encoding="utf-8-sig") as f:
                        extra_sid = json.load(f).get(extra)
                    if not extra_sid:
                        print("ERROR: control principal {} does not resolve.".format(
                            extra), file=sys.stderr)
                        sys.exit(1)
                else:
                    extra_sid = role_sids["control"]

                if extra_sid != me:
                    if sid_is_effective(extra_sid):
                        safety_sids.append(extra_sid)
                    else:
                        print("\nNOTE: control principal {} ({}) is not effective "
                              "in this process's token -- most likely UAC filtering "
                              "of an admin group. Adding it anyway for the benefit "
                              "of elevated callers, but your access comes from your "
                              "own SID.".format(extra, extra_sid))
                        safety_sids.append(extra_sid)

            print("\nSafety ACEs: full control for {}".format(", ".join(safety_sids)))

        t0 = time.time()
        t1 = t2 = t0

        if not args.acls_only:
            if os.path.exists(args.root) and os.listdir(args.root):
                print("ERROR: {} exists and is not empty. Use --acls-only to "
                      "re-stamp it.".format(args.root), file=sys.stderr)
                sys.exit(1)
            if args.dry_run:
                print("\n[dry-run] would build a '{}' tree at {}".format(
                    args.scale, args.root))
                print("[dry-run] cannot plan ACLs without a tree on disk; "
                      "run --acls-only --dry-run against an existing tree to "
                      "see the descriptors.")
                return
            seed_dir = os.path.join(args.root, ".seed")
            seed_count = build_seed(seed_dir, scale["seed_files"], scale["max_depth"])
            t1 = time.time()
            copies = fan_out(seed_dir, args.root, scale["copies"])
            shutil.rmtree(seed_dir, ignore_errors=True)
            t2 = time.time()
            print("  ~{:,} files across {} subtrees".format(seed_count * copies, copies))
        else:
            if not os.path.isdir(args.root):
                print("ERROR: {} does not exist.".format(args.root), file=sys.stderr)
                sys.exit(1)

        if args.no_acls:
            print("Skipping ACL stamping (--no-acls)")
            return

        print("\nPlanning ACLs")
        jobs = plan_acls(args.root, role_sids, safety_sids, args.files_per_subtree)
        print("  {} paths planned across {} scenarios".format(
            len(jobs), len({j["scenario"] for j in jobs})))

        if args.dry_run:
            print_plan(jobs)
            print("[dry-run] nothing was applied.")
            return

        t3 = time.time()
        results = apply_acls(jobs, workdir)
        t4 = time.time()

        manifest_path = args.manifest or os.path.join(args.root, "acl_manifest.json")
        write_manifest(manifest_path, args.root, roster, role_sids, jobs, results)
        summarize(jobs, results)

        print("\nManifest: {}".format(manifest_path))
        print("Timing:")
        if not args.acls_only:
            print("  seed build:  {:.1f}s".format(t1 - t0))
            print("  fan-out:     {:.1f}s".format(t2 - t1))
        print("  ACL stamp:   {:.1f}s ({:.0f} paths/s)".format(
            t4 - t3, len(jobs) / max(t4 - t3, 0.001)))

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
