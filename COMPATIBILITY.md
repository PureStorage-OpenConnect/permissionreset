# Compatibility Matrix

Configurations on which `permissionreset` has been run on real hardware. Each entry is historical
evidence for the version and configuration it names. It does not qualify a later release by itself:
a release is verified only by checks run against that release's artifacts. Untested configurations
may work but carry no guarantee.

## Support at a glance

| Operation | Array | Client OS | Transport | Evidence |
|---|---|---|---|---|
| DACL reset (`acl:`) | FlashBlade | Linux | kernel, userspace | Lab runs on Purity//FB 4.8.0 and 4.8.4, kernel and userspace, 2026-11-02 to 2026-11-08, each on a recorded candidate build (the audited-object refusal on 4.8.0, both transports). `v0.10.0-rc2` and `v0.10.0-rc3` archives qualified on Purity//FB 4.8.x, kernel and userspace, 2026-11-10; `v0.10.0-rc4` archives on the same, 2026-11-12 ([v0.10.0-rc4 scope](#v0100-rc4-scope)) |
| DACL reset (`acl:`) | FlashArray | Linux | kernel | Historical hardware run, v0.9.5-sacl, Purity//FA 6.10.6, with an SMB raw-descriptor check (`benchmarks/dacl-reset-fidelity-20261020/RESULTS-fa.md`) |
| DACL-keeping SACL (`sacl:` only, `--sacl`) | FlashArray | Linux | kernel | Historical hardware runs, Purity//FA 6.10.6 and 6.12.1 (section below) |
| Any repair | FlashArray | any | userspace | Refused by design |
| DACL reset (`acl:`) | FlashBlade | macOS | userspace | One hardware run on 0ed7524, darwin/arm64, Purity//FB version not recorded (section below) |
| DACL-keeping SACL (`sacl:` only, `--sacl`) | FlashBlade | macOS | userspace | No hardware run recorded; offline tests in CI only |
| Any repair | FlashArray | macOS | userspace | Refused by design (userspace refuses FlashArray) |
| Any repair | either | Windows | — | Does not build |
| Template capture (`build-spec`) | either | Linux, macOS, Windows | kernel (Linux), userspace | Offline tests in CI; capture on hardware recorded in `benchmarks/` only for Linux |

Offline CI tests, compiling for a platform, a historical hardware run and verification of the current
release are different evidence. This table says which one each row has.

## v0.10.0-rc4 scope

`v0.10.0-rc4` is a pre-release. It is qualified for one use: a DACL reset (`acl:` rules, without
`--sacl`) on FlashBlade over NFSv4.1, from Linux, on the kernel and userspace transports. The
linux_amd64 archive attached to its release passed [release acceptance](docs/release-acceptance.md)
for that scope on 2026-11-12: Ubuntu 24.04 (Linux 6.8.x, x86_64) against one FlashBlade on
Purity//FB 4.8.x, as an ordinary directory user over `sec=sys`. On rc4 itself ran L10, the
`build-spec` probe and scratch directory checks, and the userspace gate and `--log` checks.
The rest carries over, because nothing between rc3 and rc4 changes ACL writes, spec handling,
traversal or checkpoints: L2 and L5's unpreservable-audit refusal from `v0.10.0-rc3`, L8 from
`v0.10.0-rc2`, and L1, L5's spec refusal, L7 and L9 from `v0.10.0-rc1`. Its release notes are the
record, with the candidate commit and archive checksums. `v0.10.0-rc2` and `v0.10.0-rc3` were
qualified for the same scope and published; `v0.10.0-rc1` was not published.

Not covered by this pre-release, though it ships in the archives:

- Audit (SACL) modes: `sacl:` rules and `--sacl`.
- FlashArray, and SMB descriptors (acceptance cases L4 and L6).
- The missing-audit-bypass refusal on FlashBlade (L3). The lab FlashBlades keep a non-admin
  identity's audit entries, so the refusal cannot be reached there; it is qualified on FlashArray.
- The userspace transport's unsafe server override, which needs a server other than a FlashBlade.
- linux_arm64, macOS, Windows capture and the GUI.
- The external-reader trial and the independent review of the live-read safety work, which the
  self-service release still needs.

Known limits that apply within the scope:

- An object that carries audit ACEs is refused by a DACL reset unless
  `--allow-audited-dacl-reset` is passed.
- A spec naming an id at or above 1000000000 is refused on an apply: FlashBlade would store it as a
  different SID. `--allow-high-ids` is for FlashArray and must not be used here.
- An interrupted `--validate` prints no `INTERRUPTED:` line on stderr; its summary heading and exit
  code 1 mark it incomplete.
- `build-spec` refuses an existing `--output` file only when it writes the spec, after the
  audit-bypass proof and both template reads. Nothing is overwritten
  ([#51](https://github.com/PureStorage-OpenConnect/permissionreset/issues/51)).

**macOS**: builds, ships, and runs `--transport=userspace`. One hardware run is recorded, on a
FlashBlade (see [macOS hardware run](#macos-hardware-run)). Everything below that mentions idmapd
applies to `--transport=kernel` and therefore to Linux only: the userspace transport sends the
principal string verbatim and the array resolves it.

## Tested Configurations

| Field | client-a | client-b |
|---|---|---|
| **FlashBlade model** | S500R1 | S200 |
| **Purity//FB version** | 4.8.0 | 4.8.0 |
| **Access-control style** | NFSv4 ACL | NFSv4 ACL |
| **Client hostname** | client-a | client-b |
| **Client OS** | Ubuntu 24.04.4 LTS | CentOS Stream 9 |
| **Client kernel** | 6.8.0-138-generic | 5.14.0-737.el9.x86_64 |
| **Client arch** | x86_64 (amd64) | x86_64 (amd64) |
| **Client CPU** | Xeon Gold 6226R, 12 cores | Xeon (Icelake, virtual), 4 vCPU |
| **Client RAM** | 8 GB | 16 GB |
| **NFS version** | 4.1 | 4.1 |
| **Mount options** | `nconnect=16,noatime,nodiratime` | `nconnect=16,noatime,nodiratime` |
| **Security** | `sec=sys` | `sec=sys` |
| **Identity mapping** (kernel transport only) | idmapd, domain `corp.example.com` | idmapd, `Domain` unset — defaults to DNS domain `example.net` |
| **Kerberos** | Yes (user principal in the AD realm) | No (`krb5-workstation` not installed, no keytab) |
| **Go toolchain** | 1.25.0 | 1.26.5 (Red Hat 1.26.5-1.el9) |
| **nfs-utils version** | 2.6.4 | 2.5.4 (`nfs-utils-2.5.4-45.el9`) |
| **Transport tested** | kernel, userspace | kernel, userspace |
| **Peak throughput (kernel)** | 118K ops/sec | 34K ops/sec cold, 43K warm |
| **Peak throughput (userspace)** | 152K ops/sec @ c4+ | 34K ops/sec @ c16 stock; 66K tuned |
| **Tree scale tested** | 1.1M objects | 1.1M objects |

### Notes on the client-b / S200 column

- **VM, not bare metal.** 4 vCPU on OpenShift Virtualization. Both transports are client-CPU-bound
  here, so these throughput figures characterise the VM at least as much as the S200 — see
  `benchmarks/userspace-transport-control-s200.md`, where the kernel arm spends 70.3% of the machine
  in kernel mode.
- **Kernel figures are cache-sensitive.** 34,369 obj/s cold (caches dropped, the fair comparison) and
  43,212 obj/s warm — a 25.7% swing. The userspace transport moves <4% between the two, having no
  client-side cache to warm. Quote the cold number unless you say otherwise.
- **Userspace: two numbers, two meanings.** 33,717 obj/s @ c16 is the control sweep at stock settings
  (workers 128, batch 50), directly comparable to the client-a column. 65,814 paths/s is the
  confirmed median from the tuning sweep at this pair's swept-optimal knobs
  (`connections=32 slots=0 workers=1024 batch-size=10 max-ops-per-compound=16`) —
  `benchmarks/tuning-sweeper-live-s200-20260824.md`.
- **A third mount exists** on this client for assertions only: `/mnt/bench-perms-readback`
  (`vers=4.1,actimeo=0,nosharecache`). It is not the mount under test; the row above describes
  `/mnt/bench-perms`. A `vers=3` mount also exists and is unused by these runs.
- The previous `55K ops/sec (4 vCPU)` entry has been replaced: no S200 measurement in `benchmarks/`
  produces it, and the nearest 55K figures are pre-decoder-wiring S500R1 runs (see `README.md`
  "Earlier same-day runs").

## FlashArray (audit ACEs, `--sacl`)

DACL-keeping SACL specs (`examples/nfsv4_sacl_keep_dacl.yaml`). A plain DACL reset was run separately
on lab array A with v0.9.5-sacl; see `benchmarks/dacl-reset-fidelity-20261020/RESULTS-fa.md`.

| Field | client-c → lab array A | client-c → lab array B |
|---|---|---|
| **Purity//FA version** | 6.10.6 | 6.12.1 |
| **Client OS / kernel** | Ubuntu 24.04.4 LTS, 6.8.0-142-generic | same |
| **Client CPU** | 12 | same |
| **NFS version / security** | 4.1, `sec=sys`, root mount | same |
| **Transport tested** | kernel (userspace refuses FlashArray) | kernel |
| **Tree scale tested** | 6,006 objects | 6,006 and 1,135,009 objects |
| **Throughput** | — (medium tree only) | ~20,500 objects/s, 64 workers |
| **DACLs changed / SACL mismatches** | 0 / 0 | 0 / 0 |
| **Audit records checked** | Yes (audit policy + log target) | No (no audit policy on the array) |

Details: `benchmarks/sacl-fa-20261015/`.

## How to Add an Entry

After a successful run on new hardware, add a column with:

```bash
uname -r                              # kernel
cat /etc/os-release | grep VERSION=   # OS
nproc && free -h | grep Mem           # CPU count, RAM
mount | grep <export>                 # mount options, NFS version
cat /etc/idmapd.conf | grep Domain    # identity domain
go version                            # Go toolchain
nfsstat --version                     # nfs-utils
```

Then run apply + validate on a known tree and record the throughput.

## Known Limitations

- **arm64**: cross-compiles but untested on hardware
- **macOS**: builds and ships; `--transport=userspace` is the only transport and the default there, and `--transport=kernel` is refused by value. `--pfind`/`--no-pfind` are hidden and refused. `sweep` refuses at startup on macOS — every scratch backend it can build reads its trial tree through a mounted path. `generate-tree` is not ported. The offline test suite runs on Linux and macOS in CI; one repair from a Mac has been run on hardware ([macOS hardware run](#macos-hardware-run)).
- **Windows**: only `build-spec` (capture) builds and ships. `permissionreset`, `sweep` and `generate-tree` do not build yet. `internal/walk`, `internal/apply`, `internal/nfs4acl`, `internal/transport` and `internal/treegen` use Linux syscalls with no Windows equivalent, and `internal/platform` has no Windows capability file yet; the port is a follow-up.
- **POSIX-only mode**: tested on local filesystems only, not on NFS mounts
- **SMB backend**: none by design — NFSv4 ACLs are authoritative for SMB clients on FlashBlade; `protocol: smb` rejected at spec load. NFSv4-to-SMB rendering verification pending
- **FlashArray**: userspace transport refuses FlashArray by design; kernel transport tested for DACL-keeping SACL specs only (table above)
- **sec=krb5**: untested (identity mapping behavior may differ)

## macOS hardware run

Candidate `0ed7524`, `make build` for darwin/arm64, userspace transport from a macOS client to a
FlashBlade over NFSv4.1. The Purity//FB version was not recorded. The evidence is held outside this
repository.

- Passed: a DACL reset keeps each object's audit entries byte for byte, inherited ones included
  (PS-04). `--validate`, `--compare` and `--resume` converge with no change to the tree.
  `sacl:` without `--sacl` and `acl:` with `--sacl` refuse with no change. `--dry-run --compare`
  changes nothing.
- Checked by outcome only: the order of the audit-bypass proof, and the absence of ACL reads in a
  dry run.
- Not run: the kernel transport (not on macOS), the no-bypass refusal path (this FlashBlade over
  `sec=sys` keeps a non-admin identity's audit entries), and resume from a partial checkpoint.
- Found: numeric principals in a spec never compare equal on macOS userspace, because the array
  returns names and the client has no id mapper. Name principals in the spec
  ([#30](https://github.com/PureStorage-OpenConnect/permissionreset/issues/30)).
