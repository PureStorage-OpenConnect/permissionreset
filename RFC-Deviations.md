# RFC deviations observed on Everpure arrays

Protocol behaviours found while building `permissionreset`' userspace NFSv4.1 transport that
depart from RFC 8881 (NFSv4.1) or RFC 7530 (NFSv4.0 ACLs), together with what the client
does about each.

Everything here was measured against hardware, not inferred. Arrays and releases:

| Array | Model | Release |
|---|---|---|
| FlashBlade | S200 | Purity//FB 4.8.0 |
| FlashBlade | S500R1 | Purity//FB 4.8.0 |
| FlashArray | //X90R2 | Purity//FA 6.10.6 |

A deviation on one model and release is not a claim about the product line. Where a
behaviour was seen on only one platform, that is stated.

---

## 1. One session per client ID — contradicts a MUST

**Platform:** FlashBlade
**RFC 8881 §2.10.5:** *"Servers MUST support client ID trunking for specific network
addresses if they support session trunking for those same addresses."*

A second `CREATE_SESSION` on a client ID that already has a session is refused with
`NFS4ERR_INVAL`. The array plainly supports session trunking on the same address — the
Linux kernel client mounts it `nconnect=16` daily — so the MUST applies.

Four arms, to exclude the alternatives:

| Arm | Setup | Result |
|---|---|---|
| A | One `EXCHANGE_ID`, two `CREATE_SESSION`s on two connections | second `NFS4ERR_INVAL` |
| B | `EXCHANGE_ID` per connection, same owner and verifier | **same client ID returned**, second `CREATE_SESSION` still `NFS4ERR_INVAL` |
| C | Both `CREATE_SESSION`s down the **same** connection | `NFS4ERR_INVAL` |
| D | 16 connections, each its own client owner and client ID | **16 usable sessions** |

Arm B is the important one: the array hands back the *same* client ID for the same owner
and verifier on a second connection — so it advertises client ID trunking — and then
refuses the session anyway. Arm C removes the connection from the picture. What remains is
a per-client-ID session limit of one.

Two alternative explanations are excluded by measurement rather than argument:

- **`csa_sequence` is not the cause.** Arm B sent 1, arms A and C sent 2; all three were
  refused with `INVAL`, where §18.36.4 specifies `NFS4ERR_SEQ_MISORDERED` for a sequencing
  fault.
- **Client encoding is not the cause.** A packet capture of arm C shows the two
  `CREATE_SESSION4args` on one connection are 144 bytes each and **differ in exactly one
  byte** — `csa_sequence` 1 → 2. The first returns `NFS4_OK`, the second `INVAL`. Nothing
  else on the wire differs.

**Client behaviour:** the connection pool uses N independent clients — one `EXCHANGE_ID`
with its own client owner per connection — which is the only shape the hardware accepts.
The cost is that locking state is not shared across the pool. That costs this client
nothing, because it sends only `SETATTR`, `GETATTR` and `READDIR`, never `OPEN` or `LOCK`,
but it forecloses any future feature needing state shared across connections.

**Reportable.** The symptom for any client attempting client ID trunking is an opaque
`NFS4ERR_INVAL` with no indication that the limit is one session per client ID.

---

## 2. At most one mutating operation per COMPOUND

**Platform:** FlashBlade
**RFC 8881 §15.2:** a COMPOUND carries an arbitrary sequence of operations, bounded only by
the negotiated `ca_maxoperations`.

A COMPOUND containing two `SETATTR`s is refused with `NFS4ERR_INVAL` (22) and **zero
results** — the whole COMPOUND is rejected before any operation executes, so nothing can be
inferred about which operation offended.

Accepted: `PUTFH+GETATTR`; `PUTFH+GETATTR+PUTFH+GETATTR`; `PUTFH+SETACL`;
`PUTFH+SETACL+GETATTR`; `PUTFH+SETACL+PUTFH`; `PUTFH+SETACL+PUTFH+GETATTR`.

Refused, all `NFS4ERR_INVAL` with 0 results: two `PUTFH+SETACL` pairs on the same
filehandle; two on **distinct files**; directory then child; two `SETATTR(mode)` pairs on
distinct files; `SETACL` then `SETATTR(mode)`; three pairs.

So it is the second mutating operation itself — not the operation count (four operations
pass), not the attribute (mode fails exactly as ACL does), not the object (distinct files
fail exactly as one does), and not ordering. Reproduced on both the raw path and the session
path with `SEQUENCE`, which returns zero results identically.

**Known limitation, not planned to be fixed.**

**Client behaviour:** one mutation per COMPOUND on FlashBlade. FlashArray accepts at least
seven, so this is not a protocol-wide constraint — see §6.

---

## 3. GETATTR count capped below `ca_maxoperations`

**Platform:** FlashBlade (confirmed on S200 and S500R1, Purity//FB 4.8.0)
**RFC 8881 §18.36:** `ca_maxoperations` is the negotiated bound on operations per COMPOUND.
The RFC defines no per-operation-class sub-limit beneath it.

`ca_maxoperations` is granted as 16, but a COMPOUND is refused once it carries more than
**four** `GETATTR`s. Measured by sweeping N until refusal:

| Shape | Largest accepted |
|---|---|
| `GETATTR(mode)` on distinct files | 4 |
| `GETATTR(ACL)` on distinct files | 4 |
| `GETATTR` repeated against one `PUTFH` | 4 |
| Mixed `GETATTR(ACL)` + `GETATTR(mode)` | 4 (total across bitmaps) |
| `READDIR` on distinct directories | ≥7 |

Reply size is not the binding factor: `GETATTR(ACL)` returns a far larger reply than
`GETATTR(mode)` and caps at the same 4. Nor is it about the current filehandle — the
single-`PUTFH` arm caps at 4 too. Mixed bitmaps (2×ACL + 2×mode = 4 total) confirm
the cap counts GETATTR operations regardless of requested attributes. `READDIR` is
**not** subject to the cap.

Refusal is `NFS4ERR_RESOURCE` (status 22) with zero results returned — the entire
COMPOUND is rejected, not partially executed.

**Client behaviour:** no more than four `GETATTR`s per COMPOUND on FlashBlade.

---

## 4. Over-limit COMPOUND refused at the RPC layer, not the NFS layer

**Platform:** FlashBlade
**RFC 8881 §18.36 / §2.10.6.4:** exceeding `ca_maxoperations` should yield
`NFS4ERR_TOO_MANY_OPS`.

Exceeding the operation ceiling causes the array to fail RPC argument decoding — the reply
is an RPC-level *"server could not decode procedure arguments"* rather than an NFS status.
The client therefore cannot distinguish "this COMPOUND was too long" from "this client
encoded something malformed", which are very different bugs.

FlashArray answers the same over-length COMPOUND with a clean `NFS4ERR_TOO_MANY_OPS`, which
is what the RFC specifies.

**Client behaviour:** treats an RPC decode failure as a possible shape refusal and falls
back rather than assuming a client encoding bug.

---

## 5. COMPOUND accepted without a leading SEQUENCE

**Platform:** FlashBlade (FlashArray conforms)
**RFC 8881 §2.10.6.2:** in NFSv4.1, every COMPOUND other than a small exempt set
(`EXCHANGE_ID`, `CREATE_SESSION`, `DESTROY_SESSION`, `BIND_CONN_TO_SESSION`) MUST begin
with `SEQUENCE`, and one that does not MUST be rejected with `NFS4ERR_OP_NOT_IN_SESSION`.

FlashBlade accepts and answers session-less COMPOUNDs such as a bare `PUTFH+GETATTR`.
FlashArray refuses every one with `NFS4ERR_OP_NOT_IN_SESSION` (10071), which is correct.

This one is worth stating carefully: **FlashArray is conforming and FlashBlade is not.** The
practical hazard is diagnostic rather than functional — a probe written against FlashBlade's
permissiveness reports a uniform refusal on FlashArray that says nothing about the shape
under test, which is how one round of measurement in this project produced a false negative.

**Client behaviour:** always sends `SEQUENCE`. Diagnostic probes supply it explicitly so
they measure the same thing on both platforms.

---

## 6. Platform capability summary

Same client binary, same code path, measured the same afternoon. Included because several
behaviours above read as protocol constraints until the other platform disproves them.

| Class | FlashBlade | FlashArray |
|---|---|---|
| Mutating operations per COMPOUND | **1** | 7 (operation budget) |
| `GETATTR` on distinct files | **4** | 7 (operation budget) |
| `GETATTR` repeated, one `PUTFH` | **4** | ≥12, no cap found |
| `READDIR` on distinct directories | ≥7 | ≥7 |
| Operation ceiling (`ca_maxoperations`) | 16 | 16 |
| Over-limit refusal | RPC decode failure | `NFS4ERR_TOO_MANY_OPS` |
| Session-less COMPOUND | accepted | `NFS4ERR_OP_NOT_IN_SESSION` |
| `eir_server_impl_id` | empty | product name and version |
| Zeroed `csa_back_chan_attrs` | accepted | `NFS4ERR_TOOSMALL` |

FlashArray shows no operation-class-specific cap at all — every arm stops exactly where
`ca_maxoperations` stops it.

The last two rows are not deviations — both behaviours are permitted — but they are the
two places where a client written against one platform fails against the other, so they
belong in the same table. See "Not deviations" below for what each one costs.

---

## 7. ACL normalisation drops the group flag on `GROUP@`

**Platform:** FlashArray
**RFC 7530 §6.2.1.5:** `GROUP@` identifies the owning group, and an ACE whose `who` names a
group carries `ACE4_IDENTIFIER_GROUP`.

An ACL written with `ACE4_IDENTIFIER_GROUP` set on a `GROUP@` ACE reads back with the flag
cleared. The ACL is otherwise intact. A client comparing stored bytes against intended bytes
therefore never finds a match, and rewrites every object on every run.

**Client behaviour:** `--compare` compares ACLs structurally, not bytewise. Byte comparison
is unsafe against any array that normalises what it stores.

---

## 8. Named principals returned as numeric identifiers

**Platform:** FlashArray
**RFC 8881 §5.9:** ACE `who` values are `name@domain` strings when an identity-mapping
service is configured.

An ACE written as `user@domain` reads back with a numeric UID in the `who` field. The access
control is preserved; the textual identity is not.

For contrast, FlashBlade refuses a named principal it cannot map with `NFS4ERR_BADOWNER`,
which the RFC permits. The deviation is returning a number where a name was stored, not the
refusal.

**Client behaviour:** structural comparison (see §7) treats the numeric and named forms of
the same identity as unequal, so a spec written with named principals will rewrite on every
run against FlashArray. Use numeric identifiers in specs targeting FlashArray, or accept the
rewrite.

---

## 9. Setting an ACL invalidates the current filehandle

**Platform:** FlashArray
**RFC 8881 §16.2.3 / §2.2.1:** an operation's effect on the current filehandle is defined
per operation. `SETATTR` does not change it.

In a COMPOUND of `PUTFH + SETATTR(ACL) + GETATTR`, the trailing `GETATTR` returns
`NFS4ERR_STALE`. Specific to the ACL attribute — setting mode in the same position does not
provoke it — and independent of which attribute the `GETATTR` requests. A fresh `PUTFH`
before the read clears it.

**Client behaviour:** never places an operation after a mutating one on the same filehandle;
each object in a multi-object COMPOUND carries its own `PUTFH`.

---

## 10. Multi-component LOOKUP restricted across a filesystem boundary

**Platform:** FlashBlade
**RFC 8881 §18.25:** `LOOKUP` resolves one component against the current filehandle;
chaining several in one COMPOUND is ordinary usage.

A COMPOUND of `PUTROOTFH, LOOKUP a, LOOKUP b, …, GETFH` fails at the **second** `LOOKUP` —
the first one crossing from the pseudo-filesystem into the export. Chaining *within* a
filesystem is unrestricted; only the crossing is.

**Client behaviour:** resolution starts from `PUTFH(exportRoot)` whenever the export root is
known, which is every call except the initial one that resolves the export itself. That one
walks a component per COMPOUND. The common case remains a single round trip.

---

## Not deviations

Recorded because each was suspected during measurement and cleared, so the next reader does
not re-open them.

- **`rd_maxcount` larger than the reply returned.** A `READDIR` with `rd_maxcount` of 64 KiB,
  128 KiB and 256 KiB returned an identical ~32 KiB reply on the same directory. RFC 8881
  §18.23 makes `rd_maxcount` a maximum, so a smaller reply is conforming. Worth knowing for
  tuning — raising `rd_maxcount` past ~32 KiB achieves nothing on this array — but it is not
  a deviation.
- **`ca_maxresponsesize_cached` traded for slots.** Requesting 8 MiB and requesting 0 both
  granted `ca_maxrequests` 128, `ca_maxresponsesize` 526336 and `ca_maxoperations` 16 —
  identical channel attributes. The array does not trade reply-cache budget for slots.
- **`NFS4ERR_BADOWNER` for an unmappable principal.** Permitted by RFC 8881 §5.9.
- **`eir_server_impl_id` empty on FlashBlade.** RFC 8881 §18.35 makes the field OPTIONAL, so
  supplying nothing conforms. It is recorded because of what it costs, not because it is
  wrong — see below.
- **`NFS4ERR_TOOSMALL` for a zeroed `csa_back_chan_attrs`.** A client that declines callbacks
  has no obvious way to say so in `CREATE_SESSION`, and zeroing the back-channel attributes
  is one reading of it. FlashArray refuses that; FlashBlade accepts it. A zeroed structure is,
  read literally, a set of values that are all too small, so the error is defensible. Offer a
  modest populated back channel — one slot, two operations, a few KiB — and both platforms
  accept it, even though nothing will ever travel on it.

### Identifying the platform: use `eir_server_impl_id` first

Not a deviation, but the practical conclusion the table above forces, recorded here because
it is the part most likely to be got wrong by a later client.

There are two candidate signals for "what am I talking to", and they have opposite coverage:

- **`eir_server_impl_id`** (`EXCHANGE_ID`) is a real product identifier — name, version,
  domain — on FlashArray, and **empty** on FlashBlade (measured on two models and two
  releases; `eir_server_owner` and `eir_server_scope` carry only the data VIP there).
- **A server attribute fingerprint** is stable on FlashBlade across the releases measured,
  but on FlashArray it **changed with the release** (FA File 6.6.10), so one product answers
  two different ways depending on version. Which attribute, and the values it is matched
  against, are in `internal/nfs41/client.go`.

So the order matters, and it is `impl_id` first, the fingerprint second. Identifying a
FlashArray by fingerprint means encoding both of its answers and keeping that list correct
for every future release — a table that silently misidentifies the platform each time the
product changes. `impl_id` names the product directly and is version-proof.

The fingerprint cannot simply be replaced, because it is the *only* signal on FlashBlade.
The correct shape is therefore `impl_id` where the server supplies one and the fingerprint as
the fallback where it does not — not one displacing the other.

**Implemented as a refusal, not yet as support.** The client asks `eir_server_impl_id`
first and refuses a FlashArray outright, before it resolves the export — a distinct refusal
from the fingerprint one, because a FlashArray *is* a Pure array and "requires a FlashBlade"
read against one sends the reader hunting a cabling fault. The fingerprint is consulted
second and only for servers that name themselves nothing, which is the FlashBlade case.
FlashArray runs the kernel transport.

The ordering is what closes the hole. Before it, an FA on a release earlier than 6.6.10
answered the fingerprint exactly as a FlashBlade does, passed the gate, and was then labelled
a FlashBlade — which would have handed it a concurrency default measured on a FlashBlade
against an array that saturates two orders lower.

One residual gap, stated because the check cannot cover it: an array that supplies no
implementation ID is judged on the fingerprint alone, so if any FlashArray release populates
nothing there, it is still indistinguishable from a FlashBlade. The measurements to date show
FlashArray populating the field and FlashBlade leaving it empty, but that is two platforms on
three releases, not a guarantee about every release.

When FlashArray support is wanted, the refusal is the place it attaches: the branch becomes
the supported path, and nothing else about the gate has to move.

---

## Appendix A. Why not libnfs — wire evidence

This evidence was the basis for building the userspace NFSv4.1 transport natively in Go
rather than binding libnfs. Preserved here because it exists nowhere else.

### Wire capture

libnfs 7.0.0 (HEAD `8d4c2f6`) built and pointed at a FlashBlade export with `version=4`.
The COMPOUND it emits, byte-exact off the wire:

```
0x0080:  0000 0000   0000 0001   0000 0023
         minorvers=0  numops=1    argop=35 (OP_SETCLIENTID)
```

FlashBlade answers `NFS4ERR_MINOR_VERS_MISMATCH` (10021). libnfs never gets past its first
COMPOUND, and it does not fall back — it fails with an empty error string, which is a
separate small bug in libnfs.

### libnfs source archaeology

- `grep -rn minorversion lib/` returns nothing. The client never sets the field, so it is
  always 0.
- Every 4.1 session op (`EXCHANGE_ID`, `CREATE_SESSION`, `SEQUENCE`, `DESTROY_SESSION`,
  `BIND_CONN_TO_SESSION`, `RECLAIM_COMPLETE`) exists in the XDR at `nfs4/nfs4.x` and has
  **zero** references in `lib/nfs_v4.c`.
- PR #413 — the one whose title claims NFS 4.1 support — was merged 2022-12-10 and added
  767 lines across 9 files. It added XDR wire definitions for `EXCHANGE_ID` and
  `BIND_CONN_TO_SESSION` lifted from RFC 5661, finished `open_claim4`, and added a poll
  timeout setter. Structs and encoders only. No session state machine, no slot table, no
  minorversion plumbing. The PR body is accurate; the title oversells it.
- There is no ACL write at any version. `nfs4_getacl` exists (`lib/nfs_v4.c:2797`, sync
  wrapper at `lib/libnfs-sync.c:2338`, both exported). There is no `nfs4_setacl`. The only
  `OP_SETATTR` builders in libnfs are truncate, chmod, chown and utimes — nothing sets
  `FATTR4_ACL`.

Binding libnfs would also mean cgo, which costs the `CGO_ENABLED=0` single static binary.
