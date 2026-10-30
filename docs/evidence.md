# Run evidence (`--evidence-dir`)

`--evidence-dir DIR` records what a run did to each object, and closes with a
manifest that says whether that record is complete. It replaces `--audit-log`,
which still works but is deprecated (see the end of this page).

```bash
permissionreset --spec permspec.yaml --apply --log errors.log \
  --evidence-dir /data/evidence/run-20261029 --json-summary run.json /mnt/fb/data
```

Give every run its own new or empty directory. A directory that already holds
files is refused, so two runs never share a manifest.

## What is in the directory

| File | Contents |
|---|---|
| `shard-000001.log.gz`, `shard-000002.log.gz`, … | Records, one line each, in the order the run produced them. A new shard starts after `--evidence-shard-mb` MiB of records (default 256). Gzipped unless `--evidence-gzip=false`, in which case the suffix is `.log`. |
| `manifest.json` | The verdict: `status` (`complete` or `incomplete`) and the reasons, record counts, and every shard's name, SHA-256, size and record count. |

The JSON summary (`--json-summary`) carries the same verdict in `evidence` and
lists the shards in `records`, with the same digests. Its `run_id` matches the
manifest's.

### Records

The record lines are the per-object lines permissionreset has always written:
`OK:`, `WOULD:`, `FALLBACK:`, `SKIP:`, `EXCLUDE:` and `ERR:`. Errors also go to
`--log` when it is set; the evidence holds both kinds in one stream.

Two profiles, set with `--evidence-profile`:

- **`compact`** (default): the outcome and the path, e.g.
  `OK: setxattr nfs4_acl /mnt/fb/data/a/b.txt`. A posix apply line already names the
  old mode (`(was 0600)`).
- **`detailed`**: on nfsv4, adds the object's ACL before the write, after a tab:
  `…/b.txt<TAB>before=A::OWNER@:rwatTnNcCoy,A:g:GROUP@:…`. Getting it costs one ACL
  read per object, batched with the reads the run already makes. Objects the run did
  not read say `before=unread`. Directories written through the fused READDIR+SETATTR
  path have no before-state, because nothing reads them first. On posix and smb,
  `detailed` records the same as `compact`.

## Size

Measured on a lab FlashBlade with 1.1M objects whose paths are about 100 characters
long (`benchmarks/evidence-ab-20261029/`):

| Profile | Before gzip | On disk (gzip) | 100M objects on disk | 1B objects on disk |
|---|---|---|---|---|
| compact | 128 bytes/object | 6.6 bytes/object | ~0.7 GB | ~7 GB |
| detailed (6-ACE ACLs) | 247 bytes/object | 7.7 bytes/object | ~0.8 GB | ~8 GB |
| `--log` only | 0 on a clean run | — | bounded by failures | bounded by failures |

Bytes per object scale with path length, and for `detailed` with ACL length. A dry
run's `WOULD:` lines are longer: 182 bytes per object on the same tree. Without gzip,
plan on the "before gzip" column: about 13 GB per 100M objects for `compact`.

## Cost

On the same 1.1M-object tree, a kernel-transport `--apply` took 40.7 s with no
evidence, 40.8 s with `compact` and 41.0 s with `detailed`. That's within run-to-run
noise. Client CPU rose 4% and 6%, and peak RSS rose about 10 MiB. The `detailed` read
was measured only with a warm client cache; its cold-cache cost is not yet measured.

Memory is bounded by the queue (65,536 records), a 1 MiB write buffer and the gzip
state, whatever the tree size. When storage is slower than the run, the queue fills
and the workers wait: the run slows down rather than growing. The manifest's
`queue_stalls` and `queue_stall_seconds` say how often and for how long that happened.

## When evidence cannot be written

Every write, flush, sync and close is checked. On the first failure (disk full, an
I/O error, a failed close), and also on a failed `--log` write:

1. the run makes no further changes. The walk stops, and objects already queued are
   counted as not attempted;
2. changes already in flight finish;
3. the run exits 1 with `ERROR: … making no further changes`;
4. the manifest is still written if it can be, with `status: incomplete` and the error.

A shard whose write failed is left out of the manifest's list, and its records count
as dropped. `records_submitted = records_written + records_dropped` always holds.
`records_in_flight` counts the dropped records that never reached a shard: each is a
change the run made with no record kept. It is at most the queue size plus two per
worker. In the JSON summary, `evidence.not_attempted` counts the objects the run
reached but left alone, and `accounting.enumeration_complete` is false.

To finish such a run, free space and re-run it with `--checkpoint` and `--resume`
and a new evidence directory. The first run's evidence stays valid for what it lists.

An interrupted run (Ctrl-C) writes an `incomplete` manifest with the reason
`run interrupted`. A run refused before it walked anything writes one with
`run ended before it finished`. Apply errors do not make evidence incomplete: they
are in it.

## What evidence does not promise

Evidence is a record of the run, not a crash-safe journal or a way to undo it.

- **The crash-loss window.** Records sit in the queue (up to 65,536) and a 1 MiB
  buffer before they reach the file, and a shard is fsynced only when it rotates or
  the run ends. A crash, kill -9 or power loss can therefore lose the records of the
  last changes made, and every record in the shard still being written may be
  unsynced. Nothing is fsynced per object, by design: that would cost a disk sync per
  ACL write.
- **No manifest means the run did not finish.** The manifest is written last. A
  directory without one came from a run that crashed or was killed, and its last shard
  may be truncated. Treat it as partial.
- **No rollback.** Even `detailed` records only what the NFS view showed before the
  write, not SMB inheritance state. It is not a restore source. Take a snapshot first.
  Durable recovery evidence is tracked separately (PS-17).

## `--audit-log` (deprecated)

`--audit-log PATH` still works and prints a deprecation warning. PATH is now the
evidence directory, written the old way: one uncompressed shard,
`PATH/shard-000001.log`, never rotated, plus `PATH/manifest.json`. A script that read
the old file needs only to read that shard instead. An existing *file* at PATH is
refused rather than replaced. `--log` and `--audit-log` can no longer name the same
file: errors are already in the evidence.
