# Getting started: from a template to a repaired tree

This guide takes you from a downloaded release to a repaired and verified tree, using one approved
template directory and file. It assumes no ACL expertise. Each step says what it changes on the
array, and links to the detailed runbook where there is one.

The main route is **Linux, FlashBlade, kernel NFSv4.1 mount, a DACL (access) repair**. Short
branches cover FlashArray, macOS, and templates that carry auditing. Work through the steps in
order; do not skip the snapshot or the canary.

> `permissionreset --apply` replaces the ACL of every object under the target. It has no undo:
> your snapshot is the undo.

## 1. Decide what you are changing

An NFSv4 ACL on FlashBlade and FlashArray has two parts, and SMB clients see the same ACL:

- **The DACL (access):** who can read, write, or change each file and directory. This is what most
  repairs replace. A spec's `acl:` lines are DACL entries.
- **The SACL (auditing):** which accesses the array logs. A spec's `sacl:` lines are audit entries.

A normal repair replaces the DACL and **keeps each object's existing audit entries** as the NFS view
shows them. Auditing is changed only on purpose, with `--sacl` (step 6 explains when).

What a repair does not do: it does not change owner or group (unless you pass `--set-owner`), file
contents, or anything outside the target and its excludes. It never follows symlinks. The array may
recompute an object's mode bits from its new ACL.

## 2. Check that your route is supported

| You have | Use | Notes |
|---|---|---|
| Linux client, FlashBlade | `permissionreset` and `build-spec`, kernel or userspace transport | Main route of this guide |
| Linux client, FlashArray | Kernel transport only (userspace refuses FlashArray) | See [the FlashArray branch](#flasharray) |
| macOS client, FlashBlade | Userspace transport (the only one on macOS) | One hardware run recorded on 0ed7524 (darwin/arm64); name principals in the spec, not numeric ids. See [COMPATIBILITY.md](../../COMPATIBILITY.md) |
| Windows | `build-spec.exe` for capture only | No Windows repair; run the repair from Linux |

[COMPATIBILITY.md](../../COMPATIBILITY.md) says which array and client combinations have hardware
evidence, and for which version. Download the archive for your machine as described in
[INSTALL.md](../../INSTALL.md#install-from-a-release), verify its checksum, and run
`permissionreset -version` and `build-spec -version`.

## 3. Collect prerequisites

Get these before the change window. The storage and directory-service administrators own most of
them.

- [ ] **The export and a mount point.** For the kernel transport, an NFSv4.1 mount:
      `mount -t nfs -o vers=4.1,nconnect=16,noatime,nodiratime 192.0.2.50:/share /mnt/fb`.
      The userspace transport needs only `--server` and `--export`.
- [ ] **The exact target path**, and any subtrees to leave alone (`--exclude`).
- [ ] **An identity with the array's audit bypass.** Before it reads or repairs ACLs, each tool
      proves the identity keeps audit entries (see [the live-read contract](../live-read-contract.md));
      without the bypass it refuses and changes nothing. On FlashArray that is root over AUTH_SYS
      with root squash off on the export, or an AD identity the array grants the bypass.
- [ ] **Working identity mapping.** Every user and group in the spec must resolve the same way on the
      client and the array. Run the [identity checklist](identity-checklist.md) for your transport.
- [ ] **A scratch directory on the same export**, outside the target, for the disposable probe
      (`/mnt/fb/scratch` below).
- [ ] **A quiet window.** Objects created or renamed during the run may be missed; plan for no
      heavy writers.
- [ ] `ulimit -n` of at least 138 (workers + 10).

## 4. Take and verify a snapshot

Take a snapshot of the file system and **verify you can restore it** before changing anything:

- FlashBlade: [snapshot runbook](snapshot-runbook.md).
- FlashArray: the snapshot step in the [SACL runbook](sacl-runbook.md) prerequisites.

Know what a restore costs. Restoring rolls back the whole file system, so every data change made
after the snapshot, by anyone, is lost too, not only the ACL changes. A snapshot does not stop other
users writing in the meantime. When the target is one subtree of a file system that holds other
data, you can instead put back that subtree's ACLs from the file system's `.snapshot` directory
([subtree restore](snapshot-runbook.md#restore-one-subtree-from-the-snapshot-directory)). On such a
file system, check the snapshot directory, not a whole-file-system restore. If neither is
acceptable, agree a plan with the data owner before you start.

## 5. Prepare two approved templates

Make one directory and one regular file whose ACLs are exactly what you want the tree to have. Keep
them **outside the target**. A directory's ACL carries the inheritable entries that new children get,
and a file's ACL does not, so the tool needs one of each.

Have the owner of the data approve them, and check them as the people involved:

- a user who should have access can open (and, if intended, change) the file and list the directory;
- a user who should not is refused;
- a new file created in the directory gets the access you expect.

Do these checks as ordinary users, not as root or an administrator, who can bypass the ACL.

## 6. Capture the spec and read it

```bash
build-spec --output spec.yaml --probe-dir /mnt/fb/scratch \
  /mnt/fb/templates/folder /mnt/fb/templates/file.txt
```

macOS or the userspace transport:

```bash
build-spec --server 192.0.2.50 --export /share \
  --auth-uid 10010 --auth-gid 10000 \
  --output spec.yaml --probe-dir /share/scratch \
  /share/templates/folder /share/templates/file.txt
```

Every flag goes before the two paths. `build-spec` never writes the templates. It writes and removes
one disposable probe under `--probe-dir` first, and refuses to read the templates without it.

Read `spec.yaml` before using it. The [spec guide](../spec-guide.md) explains each part. The things to
check:

- **`acl:` lines** are the DACL that will be written. `OWNER@` and `GROUP@` mean each object's own owner
  and group, so they follow the object; named users and groups (`name@domain` or numeric ids) are the
  same for every object.
- **`sacl:` lines appear only if a template carries auditing.** Then, by default, the spec has
  `sacl:` rules and **no** `acl:`: it would keep each object's DACL and change only its auditing. That
  is not a DACL repair. If you want a DACL repair, capture from templates without audit entries; to
  change auditing as well, read the [SACL runbook](sacl-runbook.md) before using `--with-dacl`,
  which copies the templates' auditing too.
- **The identity report** on stderr lists every principal as the array returned it. A principal
  reported as `nobody`, `65534` or an unexpected number is an identity-mapping problem: fix it
  before going on.

## 7. Preview with a dry run

```bash
permissionreset --spec spec.yaml /mnt/fb/target
```

Without `--apply`, the run lists the tree but reads no ACL and writes nothing. It reports which rule
each object would get and how many objects a real run would write. It does not show that you have permission to
write, that the spec grants the access you meant, or which objects you cannot read; the canary does.

## 8. Apply to a canary

Copy a small, representative part of the tree (1,000 to 10,000 objects, with the usual file types
and some existing exceptions) to a disposable location, or pick a subtree whose owner agrees to be
first. Note its object count, then:

```bash
permissionreset --spec spec.yaml --apply /mnt/fb/canary
```

Check the summary: `Errors` is 0, and `Applied + Skipped` equals `Enumerated` and the count you
noted. The [field runbook](runbook.md#2-canary-run) has the detail.

## 9. Verify the canary

```bash
permissionreset --spec spec.yaml --validate /mnt/fb/canary
```

Zero mismatches means the stored ACLs match the spec. It does **not** mean the access is right.
Repeat the ordinary-user checks from step 5 on the canary: allowed users get in, refused users do not,
and a new file and directory inherit what you expect. If SMB clients use the data, check from a
Windows client too. Objects the repair wrote show a protected DACL with no "Inherited from"
entries, because the repair writes each ACL explicitly. Objects created afterwards are different, and
both of these are expected:

- A new object gets its ACEs by inheritance from its directory, so on SMB they show as inherited.
- A new **file** inherits the directory rule's file-inheritable entries, not the file rule. If those
  entries grant execute, new files get it (for example mode 750) although the file rule does not,
  and a later `--validate` reports those files as mismatches. If that is not what you want, remove
  execute from the file-inheritable entries in the directory template and capture again.

If anything is wrong, stop, fix the templates or the spec, and repeat from step 6.

## 10. Run the full tree

Keep the checkpoint, log and summary **outside the target**:

```bash
permissionreset --spec spec.yaml --apply \
  --checkpoint ~/repair/run.ckpt --log ~/repair/errors.log \
  --json-summary ~/repair/summary.json \
  /mnt/fb/target
```

If the run stops (Ctrl-C, a lost session, a crash), rerun the same command with `--resume`. Then run
`--validate` on the whole target and reconcile the counts as in the
[field runbook](runbook.md#5-reconcile-counts). An exit code of 1, any walk error, or `Checked`
differing from `Enumerated` means part of the tree may not have been reached: treat the run as
incomplete. For very large trees, see [partitions](../partitions.md). Tuning is optional.

## 11. Recover or escalate

- **Wrong result:** restore the snapshot (step 4), with the data-loss cost it carries, or put back
  just the target's ACLs from `.snapshot` ([subtree restore](snapshot-runbook.md#restore-one-subtree-from-the-snapshot-directory)).
- **Errors or refusals:** look the message up in [troubleshooting](troubleshooting.md).
- **Anything unexplained:** collect a support bundle and open an issue, as in
  [the runbook](runbook.md#6-when-to-escalate). Remove principal names and paths you cannot share.
  Report a security problem privately ([SECURITY.md](../../SECURITY.md)).

## FlashArray

- Kernel transport only; the userspace transport refuses FlashArray.
- A plain DACL repair (step 6 without `sacl:` lines) keeps each object's audit entries. An object whose
  audit entries cannot be kept exactly is refused, not written.
- Data written over SMB carries details an NFS write cannot reproduce. Read RISKS.md #11 in
  [RISKS.md](../../RISKS.md) and check results from an SMB client, not only from NFS.
- To change auditing, follow the [SACL runbook](sacl-runbook.md) instead of steps 6 to 10.
