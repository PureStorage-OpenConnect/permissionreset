# Troubleshooting

Decision tree for common failures. Check the exit code and error category first, then follow the branch.

## Exit code 0, everything looks normal

This is the expected case. Verify with `--validate` to confirm.

If `--validate` reports mismatches after a successful apply, the spec's principal format does not match what the server stores. See identity-checklist.md section 3.

## Exit code 1

### Fix errors (identity mapping)

```
Errors: 42 (fix 42, walk 0, apply 0)
```

The pre-pass tried to fix a directory and failed. Almost always an identity-mapping problem.

**Check:**
1. `nfs4_getfacl /mnt/fb/target/` — can the client read ACLs at all?
2. Do the principals in the spec match what `nfs4_getfacl` returns?
3. Is idmapd running? `systemctl status nfs-idmapd`
4. Does the idmapd domain match the spec's principal domain?

### Walk errors (enumeration incomplete)

```
Errors: 10 (fix 0, walk 10, apply 0)
WARNING: walk reported 10 errors — some objects may not have been enumerated
```

Objects were missed during enumeration.

**Check:**
1. `ulimit -n` — must be at least `workers + 10`. At `ulimit -n 16`, a 71K tree drops to 3.5K enumerated.
2. NFS mount health: `mount | grep <export>`, `ls /mnt/fb/target/`
3. Network errors: `dmesg | grep nfs`

### Apply errors

```
Errors: 5 (fix 0, walk 0, apply 5)
```

Individual objects failed to have their permissions set.

**Check:**
1. Ownership errors if `--set-owner` is on: requires root or CAP_CHOWN
2. EACCES: check export policy (`no_root_squash` for root operations)
3. ESTALE: file was deleted or renamed during the run

### Readdir errors (descriptor exhaustion)

```
Errors: 1480 (fix 0, walk 0, apply 0, readdir 1480)
WARNING: descriptor exhaustion — raise ulimit -n
```

The process ran out of file descriptors.

**Fix:** `ulimit -n 4096` (or higher) before running permissionreset. The tool needs `--workers` descriptors plus a small reserve (~10).

## EINVAL on every object

The preflight probe should catch this before the run starts. If it reaches the bulk run:

- The principal in the spec is not resolvable by this client
- On FlashBlade, a `name@domain` principal with no RFC 2307 uidNumber/gidNumber is refused this
  way (`preflight probe failed: setxattr …: invalid argument`). Nothing is written. Give the account
  an id in AD, or name a principal that has one.
- See identity-checklist.md for diagnosis

## `WARNING: the array reads these spec principals back as nobody (65534)`

FlashArray accepted a `name@domain` that has no RFC 2307 uidNumber/gidNumber. It keeps the SID, so
SMB shows the right account and the reset is correct. The run continues. Over NFS, though, the
principal reads as `65534`: `--compare` rewrites those objects on every run, and a later
DACL-keeping `sacl:` run refuses them (RISKS.md #11). To clear the warning, give the listed accounts
ids in AD.

## SACL runs

### `set sacl: (audit ACEs)` ... `Pass --sacl to turn it on`

The spec has `sacl:` (even `sacl: []`) and `--sacl` was not passed. Add `--sacl` if this is a
audit run (FlashArray, or FlashBlade, which also stores audit ACEs on multiprotocol file systems).

### `object has audit (SACL) ACEs, and this acl: rule has no sacl: key`

A DACL reset without `--sacl` found audit ACEs on the target root, or on an object under `--compare`.
Writing the DACL would delete them, on FlashArray and FlashBlade alike. Pass `--sacl` and give each
`acl:` rule a `sacl:` key: the audit ACEs to keep, or `sacl: []` to remove them on purpose.

### `DACL names a principal whose id is at or above 1000000000`

A `sacl:`-only (DACL-keeping) run found a principal with an id of 1000000000 or more. FlashBlade
reads such ids as `1000000000 + RID` on write and would store a different SID (RISKS.md #12). Move
the RFC 2307 ids below 1000000000, or add the SACL over SMB.

### `the spec names principals with ids at or above 1000000000`

The spec names a principal whose id is 1000000000 or more, as a number or as a name that resolves to
one. On FlashBlade a plain reset stored every such ACE as a different, nonexistent SID (RISKS.md
#12, #50), so an apply is refused before anything is written. For a FlashBlade target, move the RFC
2307 ids below 1000000000. Pass `--allow-high-ids` only if the target is a FlashArray, or if each
listed id is FlashBlade's own `1000000000 + RID` form of a SID in the array's domain.

### `set acl: with no sacl: key`

Under `--sacl`, a rule sets `acl:` but has no `sacl:` key. On FlashArray and FlashBlade that write deletes the
object's audit ACEs. Either add the audit ACEs you want to that rule, add `sacl: []` if an empty
audit list is intended, or drop `acl:` to make it DACL-keeping.

### `preflight: audit (SACL) ACE write was refused`

The running identity lacks the array's audit bypass. Run as root over AUTH_SYS with root squash
off on the export (a root NFSv4.1 mount), or as an AD identity the array grants the bypass. Domain
Admins membership is not enough. Check the export policy before anything else.

### `preflight: audit (SACL) ACEs were accepted but the array did not retain them`

The array accepted the write but the read-back has no audit ACEs. Check that the mount is the
FlashArray export you meant to target: an export that does not keep audit ACEs cannot be audited
with permissionreset.

### `object has no ALLOW/DENY entries to keep`

A DACL-keeping rule found an object whose ACL has no allow or deny entries. It is not written,
because a SACL-only ACL would take away all access. Fix that object's DACL by hand, then rerun.

### SACL applied but nothing is logged

The managed directory needs an audit policy with a log target on the array. permissionreset cannot see
that over NFS. Some accesses are also logged once per change, not once per access, and a denied
lookup is never logged.

## Slow throughput

Expected baselines (FlashBlade S500R1, 12-CPU client):

| Transport | Expected |
|---|---|
| Kernel (nconnect=16) | ~118K ops/sec |
| Userspace (c4+) | ~152K ops/sec |

If significantly below:

1. **Check nconnect:** `mount | grep nconnect`. Without nconnect, kernel throughput drops to ~30K.
2. **Check worker count:** default is 128 (kernel) or 1024 (userspace on FlashBlade). Too few workers underfeeds the pipeline.
3. **`--compare` on first run:** adds ~20% overhead reading each object's current ACL. Normal on subsequent runs where most objects are skipped.
4. **Client CPU saturation:** `top` during the run. If CPU is >90%, reduce `--workers` or use the userspace transport.
5. **Run the tuning sweeper:** `sweep` measures optimal settings for your specific client/array pair.

## Checkpoint mismatch on resume

```
ERROR: checkpoint hash mismatch
```

The checkpoint was created with a different spec, target, tool version, or exclude patterns.

**Fix:** delete the checkpoint file and restart:

```bash
rm run.ckpt
permissionreset -spec spec.yaml -apply -checkpoint run.ckpt /mnt/fb/target
```

Re-enumeration cost is minutes (readdir), not hours (apply). Already-correct objects are fast when `--compare` is on.

## Support bundle

Collect diagnostics before escalating:

```bash
permissionreset -support-bundle bundle.tar.gz \
  -spec spec.yaml \
  -log errors.log \
  -json-summary summary.json \
  -checkpoint run.ckpt
```

The bundle includes version, system info, spec (principals hashed by default), summary, checkpoint header, and error log. It does not include file contents or the checkpoint body.

Pass `--no-redact` only if the escalation engineer needs raw principal names.
