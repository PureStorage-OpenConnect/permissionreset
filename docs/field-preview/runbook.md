# Operator Runbook

Step-by-step procedure for running permissionreset on a FlashBlade filesystem.

## Prerequisites

- [ ] Linux amd64 or arm64 client with NFS mount to the target FlashBlade export
- [ ] `permissionreset` binary installed (see INSTALL.md)
- [ ] YAML spec file written and reviewed for the target tree
- [ ] FlashBlade snapshot taken and verified restorable (see snapshot-runbook.md)
- [ ] Identity mapping verified (see identity-checklist.md)
- [ ] `ulimit -n` is at least `--workers + 10` (default workers is 128, so at least 138)

## 1. Pre-flight checks

Verify the binary version:

```bash
permissionreset -version
```

Review the plan without making changes:

```bash
permissionreset -spec spec.yaml /mnt/fb/target
```

Without `--apply`, the default is dry-run. The output shows:

- Protocol and target path
- Rule coverage: which rules match which types and patterns
- Effective permissions per rule
- Identity summary (principals referenced in the spec)

Confirm the plan matches your intent before proceeding.

## 2. Canary run

Pick a small representative subtree (a single department directory, ~1K-10K objects):

```bash
# Dry-run the canary first
permissionreset -spec spec.yaml /mnt/fb/target/dept_a

# Apply to the canary
permissionreset -spec spec.yaml -apply /mnt/fb/target/dept_a
```

Check the summary:

- `Enumerated` should match the expected object count
- `Errors` should be 0
- `Applied + Skipped` should equal `Enumerated`

Validate the canary independently:

```bash
permissionreset -spec spec.yaml -validate /mnt/fb/target/dept_a
```

Zero mismatches means the stored ACLs match the spec: the tool wrote what the spec says. It does not
show that the spec grants the access you meant. Before the full run, check access as ordinary users,
not as root or an administrator: a user who should have access can read (and write, if intended), a
user who should not is refused, and a new file or directory created in the canary inherits the ACL
you expect. If mismatches appear, review the spec and the identity-checklist before proceeding.

The reset writes each ACL explicitly. Over SMB the DACLs show as protected, with no "Inherited from"
entries (`benchmarks/dacl-reset-fidelity-20261020/`). Plan for that if anyone relies on inheritance
from a parent above the target.

If multiprotocol access is in use, verify from a Windows SMB client that the ACLs render correctly.

## 3. Full run

Run with checkpointing and logging:

```bash
permissionreset -spec spec.yaml \
  -apply \
  -checkpoint run.ckpt \
  -log errors.log \
  -json-summary summary.json \
  /mnt/fb/target
```

Optional flags:

- `-evidence-dir DIR` — per-object evidence: gzipped shards plus `manifest.json` (see `docs/evidence.md` for sizes). Use a new, empty directory per run. If a shard cannot be written (disk full, say), the run stops making changes and exits 1 with the manifest marked `incomplete`; free space and re-run with `-resume`. `-audit-log` still works but is deprecated.
- `-compare` — skip objects already matching the spec (adds ~20% overhead on first run, saves time on re-runs)
- `-workers N` — tune parallelism (default 128 for kernel, 1024 for userspace on FlashBlade)
- `-quiet` — suppress the progress line

Monitor progress via the status line. The rate and ETA are printed every second.

### Interruption and resume

If the run is interrupted (Ctrl-C, SIGTERM, or crash):

```bash
permissionreset -spec spec.yaml \
  -apply \
  -checkpoint run.ckpt \
  -resume \
  -log errors.log \
  -json-summary summary.json \
  /mnt/fb/target
```

Completed directories are skipped during enumeration. Resume cost is proportional to tree depth, not tree size.

### Very large trees: partitions

For a tree too large to restart as one run, split it into disjoint subtrees in a manifest (`examples/partitions/manifest.yaml`, `docs/partitions.md`). The manifest names the root, spec, excludes and a local `state_dir`, so `-spec`, a target path, `-exclude`, `-checkpoint`, `-evidence-dir`, `-audit-log`, `-log` and `-pfind` are refused alongside `-partitions`.

```bash
permissionreset -partitions manifest.yaml                          # dry run: validates the manifest, writes nothing
permissionreset -partitions manifest.yaml -apply -json-summary summary.json
permissionreset -partitions manifest.yaml -apply -resume -json-summary summary.json   # after a failure or interruption
permissionreset -partitions manifest.yaml -validate                # post-run validation, every partition
```

- An implicit `residual` partition runs first and covers everything outside the named partitions. The run is `complete` only when every partition completed and the residual reached every partition root.
- A failed partition does not stop the others. `-resume` skips completed partitions and resumes the rest from their own checkpoints. It is refused if the manifest, mode, tool version, transport or a partition root changed since the run began.
- Without `-resume`, an existing `state_dir` is refused, never overwritten. Use a new `state_dir` for a fresh run.
- `state_dir/report.json` holds per-partition status and totals summed over every attempt. If it lists `uncounted_attempts` (the process was killed), the totals are a lower bound: reconcile with a `-validate` run instead.

## 4. Post-run validation

Run an independent validation pass:

```bash
permissionreset -spec spec.yaml -validate /mnt/fb/target
```

This reads every object's permissions and compares against the spec. It changes no object in the
tree; on an NFSv4 export it first writes and removes one disposable probe to prove the audit bypass
([live-read contract](../live-read-contract.md)). It checks stored ACLs, not effective access.

Expected output: zero mismatches, `Checked` equals the full tree count.

## 5. Reconcile counts

Compare the apply summary with the validation summary:

| Field | Apply run | Validation |
|---|---|---|
| Enumerated / Checked | Must match | Must match apply |
| Applied | Objects changed | N/A |
| Skipped | Already correct | N/A |
| Errors | Must be 0 | Must be 0 |
| Mismatches | N/A | Must be 0 |

If `Enumerated` differs between apply and validate, investigate: a file was created or deleted between runs, or enumeration was truncated.

The JSON summary (`-json-summary`) contains all counts in machine-readable form for automation.

## 6. When to escalate

Escalate to engineering if any of these occur:

- **Exit 0 but counts don't add up** — `Applied + Skipped + Errors != Enumerated`
- **Validation mismatches after a successful apply** — the stored ACL differs from the spec
- **Walk errors with exit 1** — enumeration was incomplete; objects were missed
- **Repeated EINVAL errors** — identity mapping is broken (see identity-checklist.md)
- **OOM or crash** — collect a support bundle first:

```bash
permissionreset -support-bundle bundle.tar.gz \
  -spec spec.yaml \
  -log errors.log \
  -json-summary summary.json \
  -checkpoint run.ckpt
```

Escalation: open an issue at https://github.com/PureStorage-OpenConnect/permissionreset/issues with the command,
`permissionreset -version` output, run summary and error log. Report security issues as described in
[SECURITY.md](../../SECURITY.md), not in a public issue.
