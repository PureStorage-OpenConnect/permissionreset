# Windows-side runbook: SMB SACL pass (`Set-SaclOnly.ps1`)

Everything here runs on the lab Windows host that can reach lab array A over SMB. No NFS is needed.

## Setup

1. `git clone` this repo (or `git pull`) and check out `feat/sacl-unmapped-guard` (PR #47). Then:
   `cd benchmarks\sacl-unmapped-sid-20261020`
2. Open an **elevated** PowerShell as a domain admin. The script enables SeSecurityPrivilege
   ("Manage auditing and security log") and fails at once without it.
3. **Windows PowerShell 5.1** (`powershell.exe`) on .NET Framework 4.6.2+ (Server 2016 or later); long `\\?\UNC\` paths need 4.6.2. PowerShell 7 is untested: its C# compile references a different set of assemblies.
4. Unsigned scripts: prefix each command with `powershell -ExecutionPolicy Bypass -File`, or run
   `Set-ExecutionPolicy -Scope Process Bypass` once in the shell.
5. **After a `git pull` that changes `Set-SaclOnly.ps1`, open a new shell.** The C# part is compiled
   once per session, and a stale copy stays loaded.

## 1. Correctness (already passed on 2026-10-20; rerun after any script change)

```powershell
$s = '\\198.51.100.242\sacl-data'
.\01-setup-mapped.ps1 -TestDir smbsacl-mapped2   -Out before-m2.json
.\01-setup.ps1        -TestDir smbsacl-unmapped2 -Out before-u2.json
.\Set-SaclOnly.ps1 -Path "$s\smbsacl-mapped2"   -Apply -Threads 8
.\Set-SaclOnly.ps1 -Path "$s\smbsacl-unmapped2" -Apply -Threads 8
.\03-verify.ps1 -TestDir smbsacl-mapped2   -Before before-m2.json    # want: all PASS
.\03-verify.ps1 -TestDir smbsacl-unmapped2 -Before before-u2.json    # want: all PASS
```

## 2. Timing

Two trees are already on the share. They were created over NFS, plain files under 4 levels of directories:

| Tree | Objects | Dirs |
|---|---|---|
| `\\198.51.100.242\sacl-data\smbperf\t40k` | 45,409 | 5,409 |
| `\\198.51.100.242\sacl-data\smbperf\t200k` | 227,009 | 27,009 |

```powershell
$p = '\\198.51.100.242\sacl-data\smbperf'

# Thread sweep on the small tree. With 1 thread, expect several minutes.
.\Time-SaclOnly.ps1 -Path "$p\t40k"

# The same sweep without the post-write SACL read-back (one round trip less per object)
.\Time-SaclOnly.ps1 -Path "$p\t40k" -ThreadList 16,32,64,128 -NoReadback

# Confirm the best thread count holds on the bigger tree (put the winner from above in place of 64)
.\Time-SaclOnly.ps1 -Path "$p\t200k" -ThreadList 64
```

Each row prints `PerSec` and `Hours78M` (the projected time for 78M objects at that rate) and is saved
to a `time-sacl-*.csv` beside the scripts. While a run is going, also note the client's CPU in Task
Manager and its network throughput. That shows whether the client or the array is the limit.

**Send back:** the CSVs, the Windows host name, its core count and NIC speed, and the round-trip
time to the array (`Test-Connection 198.51.100.242 -Count 5`).

## How the parallelism works

- `-Threads N` workers share one queue of directories. A worker takes a directory, does that
  directory object and every file in it, and pushes its subdirectories back onto the queue. Wide,
  deep, and lopsided trees all keep every worker busy, with no up-front split.
- The walk, the SMB calls, the counters and the CSV log are all in C#. PowerShell only shows
  progress every 2 s, so it is not the bottleneck.
- The rate is limited by round trips: about 4 per object with read-back, 3 without, each a
  `GetFileSecurity`/`SetFileSecurity` over SMB. With latency L, one thread gets at most about
  1/(4L) objects/s. Threads hide that latency until the array's SMB metadata rate, or the
  client's CPU, becomes the limit. The sweep finds that point.
- **More than one Windows host:** to go past one client, give each host a disjoint set of
  top-level folders, one `-Path` per folder. The skip-if-already-correct check makes a rerun
  over everything safe, so overlap costs time, never correctness.
- A stopped or interrupted run resumes by rerunning the same command. Finished objects are
  skipped, at about 1 round trip each.

## Cleanup (when done)

```powershell
Remove-Item -Recurse -Force '\\198.51.100.242\sacl-data\smbperf'
```
The `*-sid-test*` and `smbsacl-*` folders from the correctness runs can go the same way.
