# Live ACL read contract

This page states when `permissionreset` and `build-spec` read the ACL of an existing object, and
what each one must prove first. It is the Phase 0 behavior table of the release candidate.

## The rule

On an NFSv4 export, no tool reads the ACL of an existing object before it proves the audit bypass.
An unprivileged read has been observed on at least one array to empty inherited auditing (PS-02).

The proof (`internal/auditproof`) runs on a disposable probe, never on a live object:

1. Create the probe.
2. Write an ACL with an audit (`U`) entry to the probe.
3. Read the probe back. The audit entry must still be there.
4. Remove the probe.

A failure at any step stops the run before the first live read. The errors are
`ErrAuditPrivilege` (the write was refused) and `ErrAuditNotRetained` (the entry was dropped).
A POSIX spec has no audit entries and no probe.

A passed proof prints one line on stderr, before the first live read (#31):

```
NOTE: audit-bypass proof passed: the array kept an audit ACE written to disposable probe file <probe>, and the probe was removed
```

`<probe>` is the probe's path, and `file` becomes `directory` on the userspace transport, whose
probe is a directory. `permissionreset` and the `build-spec` CLI print it. The GUI does not show it
yet. A run that prints no such line made no proof: it read no live ACL (a POSIX spec, a dry run),
or it ran with `--accept-unproven-read`, which prints its own NOTE.

`--validate` and capture write only this 1 probe. An `--apply` run then writes more disposable
probes in the target for the preflight, which writes the spec's DACL. The run removes all of them.

## Repair runs (`permissionreset`)

| Spec / invocation | What happens |
|---|---|
| `acl:` without `sacl:`, without `--sacl` | Proves the bypass. Then replaces the DACL of each object with no audit entries; an object with audit entries is refused unless `--allow-audited-dacl-reset`, which keeps them (PS-04). |
| `acl:` without `sacl:`, with `--sacl` | Refused: the write would delete the object's audit entries. |
| `acl:` plus `sacl:`, with `--sacl` | Replaces both components. The full preflight runs first. |
| `sacl:` without `acl:`, with `--sacl` | Proves the bypass. Keeps each object's DACL, subject to the identity guards. Replaces the SACL. `--apply` needs `--accept-dacl-flattening`. |
| Any `sacl:` key without `--sacl` | Refused. |
| `sacl: []` | Removes the auditing. |
| `--compare` or `--resume` (forces `--compare`) | Proves the bypass before the first compare read, for every NFSv4 spec. |
| `--dry-run` | Reads no live ACL and writes nothing. With `--compare`, it does not report converged objects, because that needs a read. The summary line `Applied: N` counts objects that a real run would write. |
| `--validate`, spec with a `sacl:` key | Runs the full preflight, which writes a disposable probe. Then reads and compares. |
| `--validate`, any other NFSv4 spec | Proves the bypass on a disposable probe. Then reads and compares. |
| `--validate`, POSIX spec | Reads mode and owner only. No probe. |

`--validate` compares the stored permission components with the spec. It does not prove effective
access or policy intent. It writes only the disposable probe.

Partitioned runs (`--partitions`) and `sweep` trials go through the same `internal/run` path, so the
same rows apply. `sweep` never sets `--sacl`, `--compare` or `--validate`.

## Template capture (`build-spec`, GUI)

Capture reads 2 templates: 1 directory and 1 file. All 3 entry points use
`speccapture.CaptureWithOptions`: the `build-spec` CLI, GUI Capture and GUI Verify.

| Invocation | What happens |
|---|---|
| `--probe-dir DIR` | Proves the bypass under `DIR`, then reads the templates. |
| `--verify-write DIR` | `DIR` is also the default probe folder. |
| GUI Verify | Uses its scratch folder as the probe folder. |
| `--accept-unproven-read` (GUI: "Read without proof") | Reads with no proof. The output carries a NOTE that says so. |
| None of the above | Refused with `ErrUnprovenRead`. Nothing is read. |

The probe folder must be on the same mount as the templates (kernel transport) or inside the
export (userspace transport). It must already exist and be a directory, not a symlink: capture
refuses a missing one (`ErrDirMissing`) or a non-directory (`ErrNotDir`) before the probe, and
never creates it. A `--verify-write` folder separate from the probe folder is checked the same way,
also before the templates are read. Capture never writes the templates. The probe and `--verify-write`
are its only writes to the array.

What capture emits:

| Templates | Output |
|---|---|
| No audit entries | A DACL spec (`acl:` only). |
| Audit entries, default options | `sacl:`-only rules. The template DACL is not copied. |
| Audit entries, `--with-dacl` | Both components. Applying it replaces the destination auditing too. |

## What this contract does not claim

- Preserved NFS ACE bytes do not prove identical raw SMB descriptors, inheritance state,
  owner/group or effective access. Check DACL fidelity from SMB.
- The proof shows that this client, with this identity, keeps audit entries on this export. It does
  not prove the array's audit policy.
- A passing proof does not show that the identity is privileged. On an array that does not gate
  audit writes by privilege, any identity that can create the probe passes. Observed on one lab
  FlashBlade over `sec=sys`: a domain user with no admin groups passed the proof on both
  transports, and the array kept the probe's audit entry. This is one observation, not a product
  claim about FlashBlade.
- `ErrAuditPrivilege` has been tested on hardware: FlashArray Purity//FA 6.10.x and 6.12.x, kernel
  transport, as a domain user without the audit bypass. `--apply`, `--validate` and a `--sacl`
  DACL-keeping `--apply` each stopped when the probe's audit write was refused. No live ACL was
  read or written, and the target's inherited and explicit auditing was unchanged.
  `ErrAuditNotRetained` has not been tested on hardware.
  It needs a test identity that has no audit bypass.
