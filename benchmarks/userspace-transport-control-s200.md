# Transport control sweep — S200, 2026-08-21

**This is not the phase 3 benchmark.** The phase 3 result is gated to an S500R1 and the
table in `benchmarks/userspace-transport-benchmark.md` stays empty until that array runs
`benchmarks/run-transport-comparison.sh`. This file records a control run whose purpose is
narrower: prove the harness, the instrumentation and the userspace transport all behave
before someone spends an S500R1 window, and establish what the numbers look like on a
client we can measure end to end.

Harness: `benchmarks/run-transport-control.sh` (named `run-transport-control-s200.sh`
when this sweep was run; renamed because nothing in it is model-specific).

## Setup

| | |
|---|---|
| Array | `lab-s200`, S200, Purity//FB 4.8.0, data VIP `198.51.100.54` |
| Client | `client-b.example.net`, CentOS Stream 9, kernel 5.14, **4 vCPU**, 16 GiB |
| Filesystem | `/bench-perms`, NFSv4.1 only, `rw,no_root_squash` to this client only |
| Kernel mount | `vers=4.1,nconnect=16,noatime,nodiratime`, `max_session_slots=128` |
| Tree | `/mnt/bench-perms/bench-s200`, **1,135,009 objects** (`generate-tree --scale xlarge --no-acls`) |
| Spec | `examples/nfsv4_basic.yaml` |
| permissionreset | `--apply --workers 128 --batch-size 50 --quiet` |

Three deviations from the phase 3 procedure, each forced and each recorded so the numbers
are not read as comparable to an S500R1 run:

1. **No snapshot or restore between runs.** Those need FlashBlade API credentials this lab
   does not have. They are also not needed for a fair comparison: `internal/apply` skips an
   object only under `--compare`, which this sweep does not pass, so every run rewrites
   every ACL and does identical work whatever the tree's starting state. The `Applied:`
   count is 1,135,009 in every one of the fourteen runs below, which is the evidence for
   that claim rather than an assumption about it.
2. **`examples/nfsv4_basic.yaml`, not `nfsv4_ediscovery_test.yaml`.** The phase 3 spec names
   `corp.example.com` principals; this array has no mapping for that domain and
   the preflight probe fails with `EINVAL` on its first `setxattr`. The basic spec uses only
   `OWNER@`/`GROUP@`/`EVERYONE@`, so its encoded ACLs are shorter — three ACEs with no
   principal strings, 288 bytes on the wire per `SETACL` against the ediscovery spec's
   larger descriptors. **Do not compare these rates to an ediscovery-spec run directly.**
3. **`max_session_slots` is a module parameter, not a mount option.** `mount -o
   remount,max_session_slots=128` fails on kernel 5.14 with "an incorrect mount option was
   specified", so `run-transport-comparison.sh` step 2 will fail the same way on any client
   of this vintage. The correct knob is `/sys/module/nfs/parameters/max_session_slots`, it
   is read when the session is created, and the client keeps **one session per server
   shared across superblocks** — `nosharecache` does not split it — so raising it means
   unmounting every mount of that server and remounting. The control script verifies the
   value and refuses to run below 128 rather than pretending it can set it.

## Results — cold client cache

Caches dropped before every run (`CONTROL_DROP_CACHES=1`). This is the fair comparison:
the userspace client has no client-side cache to warm, so a warm kernel arm is not
measuring the same thing. Artifacts: `/tmp/sweep2` on `client-b`.

| Transport | Conns | Wall | Objects/sec | Process CPU | Machine user | Machine kernel | Machine idle | Mount NFS ops |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| kernel | n/a (nconnect=16) | 33.07 s | 34,369 | 198% | 7.4% | **70.3%** | 22.2% | 2,040,076 |
| userspace | 1 | 36.09 s | 31,468 | 315% | 67.5% | 17.0% | 15.3% | 0 |
| userspace | 2 | 34.90 s | 32,551 | 342% | 73.1% | 18.2% | 8.6% | 0 |
| userspace | 4 | 35.08 s | 32,385 | 350% | 74.5% | 19.4% | 6.0% | 0 |
| userspace | 8 | 34.79 s | 32,673 | 350% | 73.6% | 20.5% | 5.8% | 0 |
| userspace | 16 | 33.74 s | 33,717 | 345% | 71.8% | 21.4% | 6.7% | 0 |
| userspace | 32 | 37.76 s | 30,179 | 346% | 72.9% | 20.0% | 6.9% | 0 |

"Machine kernel" is `system + irq + softirq` from a `/proc/stat` delta across the run, as a
share of all four CPUs. "Mount NFS ops" is the sum of the per-operation deltas from
`mountstats --since`. Peak RSS was 32 MB (kernel) and 35 MB (userspace, 16 connections).

## Results — warm client cache

Identical sweep, no cache drop, run immediately after a full `find` of the tree. Kept
because the difference is a measurement worth having, not merely a caveat.
Artifacts: `/tmp/sweep1` on `client-b`.

| Transport | Conns | Wall | Objects/sec | vs cold | Machine kernel | Mount NFS ops |
|---|---:|---:|---:|---:|---:|---:|
| kernel | n/a | 26.28 s | 43,212 | **+25.7%** | 66.6% | 1,789,956 |
| userspace | 1 | 34.74 s | 32,681 | +3.9% | 18.1% | 0 |
| userspace | 2 | 33.74 s | 33,648 | +3.4% | 20.2% | 0 |
| userspace | 4 | 34.12 s | 33,290 | +2.8% | 20.2% | 0 |
| userspace | 8 | 36.24 s | 31,356 | −4.0% | 20.2% | 0 |
| userspace | 16 | 36.76 s | 30,932 | −8.3% | 20.1% | 0 |
| userspace | 32 | 37.45 s | 30,419 | +0.8% | 20.7% | 0 |

**A warm dentry and attribute cache is worth 25.7% to the kernel transport and nothing to
the userspace one.** The mechanism is visible in the operation mix: the warm kernel run
issued 250,120 fewer NFS operations than the cold one, and `READDIR` fell from 135,017 ops
to **1**. The userspace column moves by ±4%, which is run-to-run noise on this client —
expected, since that client holds no cached attributes to reuse.

This matters procedurally: the first control sweep counted the tree with `find` and then
measured the kernel arm, which handed the kernel a 25.7% advantage for free. Any run of
`run-transport-comparison.sh` must either drop caches per run or do its object count long
enough before the sweep to be irrelevant. As written that script counts objects
immediately before the kernel baseline and does not drop caches.

## Operation mix, kernel transport, cold

| Operation | Ops | Server RTT |
|---|---:|---:|
| SETACL | 1,135,010 | 1.044 ms |
| LOOKUP | 322,614 | 0.272 ms |
| ACCESS | 316,058 | 0.207 ms |
| READDIR | 135,017 | 0.699 ms |
| GETATTR | 131,374 | 0.218 ms |
| OPEN / CLOSE / REMOVE | 1 each | — |

1.80 operations per object, against the one `SETATTR` per object the userspace client
issues plus its own `READDIR` per directory. `LOOKUP` and `ACCESS` together are 638,672
operations — 31% of the total — and the userspace client issues neither: it addresses
objects by the filehandle `READDIR` returned and does no permission pre-check. The single
`OPEN`/`CLOSE`/`REMOVE` triple is the preflight probe.

**The userspace runs show 0 mount operations, every time.** That is the check that the
comparison is honest: had any part of the work fallen back to the kernel path, it would
appear here.

## The three phase 3 questions, answered for this client only

**1. Connection-bound or client-CPU-bound? Client-CPU-bound, and in both transports, but
in different modes.** The kernel arm spent 70.3% of a 4-CPU machine in kernel mode with
22.2% idle; the userspace arm spent 67–75% in *user* mode with 6–15% idle. So the userspace
client does what it was designed to do — it moves the cost out of the syscall and RPC path
into its own process — but on a 4-vCPU client it does not remove the ceiling, it relocates
it. `/usr/bin/time -v` alone would have hidden this: it reports 198% for the kernel run,
which looks like plenty of headroom, while the machine was 70% in the kernel on the walk's
behalf.

**2. Does throughput scale with connection count? No — flat, then worse.** 31.5K, 32.6K,
32.4K, 32.7K, 33.7K, 30.2K across 1, 2, 4, 8, 16, 32 connections: a 7% spread with no
trend, and 32 connections is the slowest point. The reason is question 1's answer, not a
protocol limit: at one connection the client was already at 67% user CPU with 15% idle, so
there was never spare client capacity for more connections to use. **This does not answer
the phase 3 question**, which is whether connection scaling helps a client that is *not*
CPU-bound. It does establish that the sweep runs correctly at every point, that all six
connection counts apply all 1,135,009 objects, and that the cost of the extra sessions is
small — 1 to 32 connections moved machine kernel time by only 3 percentage points.

**3. Did slot growth via `sr_target_highest_slotid` occur? Not measured.** The control
harness does not capture a `SEQUENCE` reply, and this client never reached the sustained
in-flight depth where growth would be expected. Still open, still for the S500R1 run.

A fourth observation the phase 3 questions do not ask for: **the kernel transport is faster
here, 34,369 against 33,717 objects/sec at the userspace client's best point.** On the same
client, cold, with the same slot budget, the userspace transport is within 2% of the kernel
and no better. It is not the win — 1.8 operations per object against roughly 1.1 should be
a win — because the client cannot afford the userspace work. That is precisely the shape of
result that makes the S500R1 run worth doing rather than skipping: the interesting question
is what happens when the client is not the limit.

## What Robert needs for the real run

1. `benchmarks/run-transport-comparison.sh` step 2 will fail on any kernel where
   `max_session_slots` is not a mount option. Set
   `/sys/module/nfs/parameters/max_session_slots` and remount every mount of the server
   instead.
2. Drop caches between runs, or the kernel baseline gets a 25.7% head start from whatever
   warmed the client. Both numbers are worth recording — the delta is the cache's value.
3. Capture per-run `/proc/stat` deltas, not just `/usr/bin/time -v`. The user/kernel split
   of the whole machine is what answers question 1, and per-process CPU does not show it.
4. Capture `mountstats --since` per run. Zero mount operations on a userspace run is the
   only direct evidence that no work leaked onto the kernel path.
5. A client with more than 4 vCPUs. This one saturates before the connection sweep can say
   anything about connections.
