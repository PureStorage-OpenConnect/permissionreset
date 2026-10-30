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

On a non-production filesystem or a test export:

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

## Retention

Keep the pre-repair snapshot until:

- The data owner has reviewed and accepted the repaired permissions
- An independent `--validate` pass shows zero mismatches
- Any multiprotocol verification (SMB client check) is complete

Only then destroy the snapshot, and eradicate it if you need the space back immediately.

## Snapshot storage impact

FlashBlade snapshots are copy-on-write. Storage cost is proportional to the data that changes after the snapshot, not the total filesystem size. For a permission-only repair (no file content changes), the overhead is metadata only — negligible even at millions of objects.
