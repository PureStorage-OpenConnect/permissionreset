# FlashArray SACL Runbook

How to add file-access auditing (audit ACEs, the SACL) to a FlashArray tree with permissionreset while
keeping every object's existing DACL. Spec syntax and the full list of limits are in
[spec-guide.md](../spec-guide.md#audit-aces-sacl-on-flasharray). This runbook covers the run.

## Prerequisites

- [ ] Linux client with a **kernel** NFSv4.1 mount of the FlashArray export (`vers=4.1`). The
      SACL runs on record used the kernel transport; userspace on FlashArray is implemented but has no hardware run.
- [ ] An identity with the array's **audit bypass**: root over AUTH_SYS with root squash off on
      the export, or an AD identity the array grants the bypass. Domain Admins membership is not
      enough.
- [ ] `permissionreset` v0.9.4-sacl or later (`permissionreset -version`). Earlier versions have no guard against the DACL damage on SMB-written data and ids >= 1e9 (#48, #49, #52), and v0.9.3-sacl and earlier delete SACLs on a plain DACL reset (#51). v0.9.1-sacl used `--no-sacl`,
      which is gone.
- [ ] A DACL-keeping spec: `sacl:` rules with no `acl:`. Start from
      `examples/nfsv4_sacl_keep_dacl.yaml`, or capture one with `build-spec` as an identity with
      the bypass.
- [ ] An **audit policy** on the managed directory with a log target. Without one the SACL is
      stored but nothing is logged, and permissionreset cannot check this over NFS.
- [ ] A FlashArray snapshot of the file system, taken and verified restorable. permissionreset has no
      rollback.
- [ ] **Know where the data came from.** If it was written over SMB, an NFS SACL pass does not keep
      DACLs identical. A SID with no RFC 2307 id (users, groups, `Domain Users`, `BUILTIN\*`) would
      become the array's nobody account, so permissionreset refuses those objects. Every inherited ACE
      comes back as an explicit one and the DACL is marked protected (`D:P`): effective access is
      kept, inheritance is not. Applies need `--accept-dacl-flattening`. To keep SMB DACLs exactly as they are, add
      the SACL from the SMB side instead (RISKS.md #11).
- [ ] A quiet window. A DACL change someone makes between permissionreset' read and its write of the
      same object is lost (milliseconds per object).

## 1. Snapshot

Take a snapshot of the managed directory or file system on the FlashArray before any write. The
only undo for a wrong spec is restoring it.

## 2. Preflight and plan

Every command needs `--sacl`. Without it a spec with `sacl:` is refused.

```bash
# Plan only (dry run): shows dacl=keep, sacl=N entries per rule. No preflight, and objects
# under a sacl:-only rule are not read (a read without the bypass emptied inheriting SACLs on
# 6.10.6, 3/3 on 2026-10-15; the "fixed in 6.12.1" boundary is not confirmed -- see limit 5 and
# benchmarks/sacl-item7-20261016/RESULTS.md), so each is listed as WOULD whether or not it
# already matches.
sudo permissionreset --sacl --spec sacl.yaml /mnt/fa/target

# Preflight without writing to the tree: --validate runs the audit-bypass probe first
sudo permissionreset --sacl --spec sacl.yaml --validate /mnt/fa/target/canary
```

The probe writes a temporary file with a DACL and an audit ACE and reads it back. If it fails, the
run stops before the walk. See [troubleshooting.md](troubleshooting.md#sacl-runs).

Every SACL run prints the audit-policy NOTE. It is a reminder, not an error.

## 3. Canary

```bash
sudo permissionreset --sacl --accept-dacl-flattening --spec sacl.yaml --apply /mnt/fa/target/canary
sudo permissionreset --sacl --spec sacl.yaml --validate /mnt/fa/target/canary
```

- `Errors` should be 0. An object with no allow/deny entries is failed on purpose and not
  written: a SACL-only ACL would take away all access.
- `--validate` checks only the SACL: the object's audit ACEs must equal the spec's, at the end of
  the ACL. It does not compare the DACL.
- To confirm DACLs were kept, compare a few objects' `nfs4_getfacl` output (as root) from before
  and after. The `A`/`D` lines should be identical. Use the raw `nfs4_getfacl`/`GetFileSecurityW`
  output for ACE order, count, inheritance flags and `D:P`, not `Get-Acl`, which re-sorts the DACL
  by SID, merges same-SID ACEs and can report a protected flag the object does not have (`PR #57`). On FlashBlade, `Get-Acl`, `icacls` and Explorer
  compute `P` and `ID` from the parent rather than reading what the array stores
  (`benchmarks/sacl-ps07-20261026/RESULTS.md`).
- **Canary procedure — three distinct results, verify each separately:**
  1. **Stored SACL** (confirmed by this runbook): `--validate` after the apply shows the audit ACEs
     present and matching the spec, at the end of the ACL.
  2. **Audit policy attached and enabled**: confirm out of band (array config, not over NFS —
     permissionreset cannot check this). `permissionreset` only prints a reminder NOTE; it does not verify
     the policy exists.
  3. **Delivered event**: make one allowed access (e.g. a read by a principal with an `A` ACE) and
     one denied access (e.g. a read attempt by a principal with no matching `A`/`D` entry) on the
     canary as an ordinary user, with the expected actor (the test principal's resolved
     SID/uid), action (open/read) and event type (success/failure) recorded before the test, then
     confirm both appear in the array's audit log with those fields. **If the array has no audit
     policy and log target configured, or the log target cannot be read, report event delivery as
     unverified — do not infer it from the stored SACL alone.** A stored SACL with no attached
     policy logs nothing (see step 2); evidence of (1) is not evidence of (3).

## 4. Full run

```bash
sudo permissionreset --sacl --accept-dacl-flattening --spec sacl.yaml --apply --log errors.log /mnt/fa/target
```

Lab rate: 1,135,009 objects in 55 s (~20,500 objects/s) on Purity//FA 6.12.1, kernel transport,
64 workers, 0 DACLs changed. At that rate 78M objects take about an hour on one array (an
extrapolation; nothing larger was measured).

A rerun with `--compare` writes nothing if the tree has not changed.

## 5. Rerun on a schedule until the 6.12.1 fix boundary is confirmed

On 6.10.6, files and folders created after the run inherit the SACL from their parent, and one ACL
read over NFSv4.1 by a user without the bypass emptied that inherited SACL — reproduced 3/3 on
lab array A on 2026-10-15. SMB reads do not do this. **Do not treat "6.12.1 fixed it" as confirmed**: the
same 6.10.6 repro failed to reproduce the next day, most likely (not proven) because of an
unplanned controller role swap between sessions rather than a firmware difference, and lab array B's
6.12.1 non-reproduction was never checked against its own controller state either
(`benchmarks/sacl-item7-20261016/RESULTS.md`).

Until a controller-controlled retest confirms the version boundary, rerun the same command on a
schedule (for example nightly) with `--compare` on every array, regardless of firmware version, so
only objects whose SACL is wrong are written:

```bash
sudo permissionreset --sacl --accept-dacl-flattening --spec sacl.yaml --apply --compare --log errors.log /mnt/fa/target
```

## Things this does not cover

- **Changing the audit rule later.** Every object holds its own copy of the SACL, so editing a
  parent's SACL does not reach stamped children. Change the spec and rerun.
- **Replaced files.** A file copied and renamed over the original, or re-created, carries only the
  parent's inherited SACL. On 6.10.6/6.11.x that is exposed as in step 5.
- **Plain DACL specs on FlashArray.** An `acl:` spec run without `--sacl` keeps each object's
  existing audit ACEs as the NFS view shows them (PS-04), and refuses an object whose audit ACEs it
  cannot keep exactly. With `--sacl`, an `acl:` rule needs a `sacl:` key. Versions before v0.9.4-sacl
  deleted audit ACEs on a plain DACL reset (#51): once the array carries audit ACEs, tell the
  customer's other operators to use a current version for any DACL repair.
