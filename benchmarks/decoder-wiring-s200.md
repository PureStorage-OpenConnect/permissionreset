# Hand-written decoder, measured end to end on the S200

Date: 2026-08-21. Supersedes the rate figures in commit `18b13f2`'s message, which
did not reproduce; see **The correction** below.

| | |
|---|---|
| Array | `lab-s200`, S200, Purity//FB 4.8.0, data VIP `198.51.100.54` |
| Client | `client-b.example.net`, CentOS Stream 9, kernel 5.14, **4 vCPU**, 16 GiB |
| Tree | `/bench-perms/bench-s200`, **1,135,009 objects**, every run reported `Applied: 1135009  Errors: 0` |
| Spec | `examples/nfsv4_basic.yaml` (not the ediscovery spec — its principals do not resolve in this lab) |
| Parameters | `--transport=userspace --apply --workers 128 --batch-size 50`, client caches dropped before every run |

## The three-way A/B

Three binaries, built from three commits, run interleaved in the same session so
array state and load are shared rather than compared across hours. Two passes,
16 connections, objects/sec overall:

| Binary | Pass 1 | Pass 2 |
|---|---:|---:|
| `408a83b` — generated decoder only | 27,958 | 32,865 |
| `875fe78` — decoder written, READDIR wired | 31,343 | 31,503 |
| `18b13f2` — GETATTR and SETATTR wired too | 54,635 | 55,305 |

Connection sweep on `18b13f2`, cold cache: **44,827** at 1 connection, **52,983**
at 4, **54,585** at 16.

The kernel arm was re-run the same day rather than compared against the earlier
control, so both transports are measured against the same array state:
**33,558** and **33,273** objects/sec, which agrees with the control's 34,369.
Userspace is therefore **1.64x the kernel transport** on this client and this
tree -- the first measurement in this project where it wins.

## The correction

Commit `18b13f2`'s message claims +29% at 16 connections for wiring READDIR
through the hand-written decoder, from a run that measured 43,612. **That figure
does not reproduce.** Re-measured today, the READDIR-only commit is
indistinguishable from the commit before the decoder existed: 31.3-31.5K against
28.0-32.9K, inside this client's run-to-run spread. Do not carry the 43,612
number forward.

The whole of the improvement comes from wiring GETATTR and SETATTR, and that is
the arithmetically sensible answer rather than a surprising one. A run of this
tree decodes roughly **135,000 READDIR replies and 1,135,009 SETATTR replies** —
one per object. Making the rare reply 30x cheaper to decode moves a rate very
little; making the per-object reply cheaper moves it 1.7x. The isolated decoder
benchmark (2,328,313 -> 76,456 ns/op) measured a READDIR reply because that is
the reply that was captured, and reading it as a whole-run prediction was the
error.

The lesson generalises past this commit: **weight a decode cost by how many
replies of that shape a run actually decodes** before believing a microbenchmark
about it.

## Reproducing

The array is not reachable from a workstation on the corporate network — TCP to
port 2049 resolves into ZScaler's CGNAT range and times out. Build for the client
and run there:

```bash
PATH="/usr/local/go/bin:$PATH" go build -o /tmp/permissionreset ./cmd/permissionreset/
scp /tmp/permissionreset examples/nfsv4_basic.yaml client-b.example.net:/tmp/
ssh client-b.example.net
sync; sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
sudo /tmp/permissionreset --spec /tmp/nfsv4_basic.yaml --transport=userspace --apply \
    --workers 128 --batch-size 50 --server 198.51.100.54:2049 \
    --export /bench-perms --connections 16 /bench-perms/bench-s200
```

`sudo` is required: the export is `no_root_squash` to this client, and as an
unprivileged user the preflight probe fails with `NFS4ERR_PERM` on the export
root before any work starts.

## What this does not answer

This is a 4-vCPU client, which both control sweeps found to be the binding
constraint. It says the decoder change is worth 1.7x here; it does not say what
it is worth on the 12-CPU S500R1 client, where the userspace arm had 38% idle and
something other than client CPU was holding it at ~55K. That run is Robert
Cantu's, and it should be repeated on `18b13f2` or later — the profile it was
diagnosing has changed underneath it.
