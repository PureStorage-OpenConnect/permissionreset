# Snapshot, Rollback, and Restore

Always create a FlashBlade snapshot before the first apply. permissionreset modifies ACLs in place with no built-in undo — a snapshot is the only rollback path.

## When to snapshot

- Before the first `--apply` on any target
- Before re-running with a different spec
- Before upgrading permissionreset and re-running

## Create a snapshot

Use the FlashBlade GUI or the REST API. With a suffix of `pre-repair`, the snapshot is named
`<filesystem>.pre-repair`.

```bash
# REST API example
curl -X POST "https://<fb>/api/2.x/file-system-snapshots" \
  -H "x-auth-token: $TOKEN" \
  -d '{"source": {"name": "<filesystem>"}, "suffix": "pre-repair"}'
```

## Verify the snapshot is restorable

**Do this before relying on it.** A snapshot that cannot be restored is not a safety net.

On a non-production filesystem or a test export (on a file system that holds other data, check
the [snapshot directory](#restore-one-subtree-from-the-snapshot-directory) instead):

1. List the file system's snapshots and confirm `pre-repair` is there.
2. FlashBlade restores only the latest snapshot, so destroy and eradicate any snapshots newer than
   `pre-repair` first.
3. Restore `pre-repair`.
4. Remount the NFS export on the client.

Verify the restored tree has the expected pre-repair state (e.g., `nfs4_getfacl` on a sample file shows the old ACL).

## Restore after a failed or incorrect repair

```bash
# Unmount first if the mount is stale
sudo umount /mnt/fb/target

# Restore pre-repair (GUI or REST API; destroy newer snapshots first), then remount:
sudo mount /mnt/fb/target
mount | grep <export>
ls /mnt/fb/target/
```

## Restore one subtree from the snapshot directory

Restoring a snapshot rolls back the **whole file system**. Every change made since the snapshot,
by anyone, anywhere in it, is lost. When the target is one subtree of a file system that holds
other data, put back only that subtree from the file system's snapshot directory instead.

Every snapshot of the file system can be read from the `.snapshot` directory at its root. It is
read-only, and holds the tree as it was when the snapshot was taken, ACLs included. It may not
appear in `ls -a`; address it by name:

```bash
ls /mnt/fb/.snapshot/                  # one directory per snapshot; find the pre-repair one
SNAP=/mnt/fb/.snapshot/<snapshot directory>
nfs4_getfacl "$SNAP/projects/target"   # the ACL from before the repair
```

`/mnt/fb` here is a mount of the file system's root. `projects/target` is the repaired subtree,
relative to that root.

### Check before you rely on it

On a file system that holds other data, don't test a whole-file-system restore. Before the repair,
check that `$SNAP` exists and that `nfs4_getfacl` on a few objects under it shows their current
ACLs. That shows the subtree can be put back.

### Put back only the ACLs

A permission repair changes ACLs and nothing else, so putting back the ACLs undoes it. File
contents and objects created since the snapshot are kept. Run this as the identity that ran the
repair, with the audit bypass, on a kernel mount with `nfs4-acl-tools` installed:

```bash
LIVE=/mnt/fb
SUB=projects/target
ACL=$(mktemp)
cd "$SNAP" && find "$SUB" ! -type l -print0 |
while IFS= read -r -d '' p; do
  if [ -e "$LIVE/$p" ] && [ ! -L "$LIVE/$p" ]; then
    nfs4_getfacl "$p" | grep -v '^#' > "$ACL" &&
      nfs4_setfacl -S "$ACL" "$LIVE/$p" || echo "FAILED: $p" >&2
  else
    echo "SKIPPED (deleted, or now a symlink): $p" >&2
  fi
done
rm -f "$ACL"
```

- Objects deleted since the snapshot are skipped. Objects created since keep their current ACL.
  Symlinks are skipped, as the repair skips them.
- Names go through idmapd in both directions, so the identity-mapping checks from the
  [identity checklist](identity-checklist.md) apply here as well. A principal shown as `nobody` or
  a bare number on the read side will be written back that way.
- An identity without the audit bypass doesn't see audit entries, so it would write the ACLs back
  without them. Use the same identity as the repair.
- This runs two commands per object. It suits a canary or a subtree, not millions of objects.

### Or copy the subtree back

If the contents must be rolled back too, or the subtree is disposable (a trial fixture, say), copy
it back from `$SNAP`. This loses every change made in the subtree since the snapshot. Copy tools
don't all carry the NFSv4 ACL, so compare `nfs4_getfacl` on a sample of copied objects with the
`.snapshot` copy. If they differ, run the ACL loop above on the copied tree.

### Verify

Compare `nfs4_getfacl` on a sample of objects with their `.snapshot` copies, and repeat the
ordinary-user access checks from before the repair. `permissionreset --validate` checks the tree
against the spec, so after a restore it reports mismatches. That is expected.

## Retention

Keep the pre-repair snapshot until:

- The data owner has reviewed and accepted the repaired permissions
- An independent `--validate` pass shows zero mismatches
- Any multiprotocol verification (SMB client check) is complete

Only then destroy the snapshot, and eradicate it if you need the space back immediately.

## Snapshot storage impact

FlashBlade snapshots are copy-on-write. Storage cost is proportional to the data that changes after the snapshot, not the total filesystem size. For a permission-only repair (no file content changes), the overhead is metadata only — negligible even at millions of objects.
