# Provenance of the vendored XDR bindings

Everything in this directory is either third-party or generated. Nothing here is
hand-written by Everpure, and nothing here should be hand-edited: `make regen-xdr`
reproduces `xdr_generated.go` byte-for-byte from the two `.x` files, and a dirty
working tree after that target means someone edited generated output.

The one file that is *not* reproduced by `regen-xdr` is `types.go`. See below.

---

## RFC verification record

**Verified 2026-08-20 against RFC 5661 (January 2010), retrieved from
`https://www.rfc-editor.org/rfc/rfc5661.txt` (MD5 `3facc4123eba2b4bcb2cc87b44729d6c`).
Compared field by field, in declaration order, including each field's XDR type.**

Upstream's `.x` is RFC 3530 (NFSv4.0) with 4.1 grafted on by a third party and was
unverified when vendored, so this is a real comparison against the RFC text rather
than a plausibility check. The comparison was made against the *generated Go* as well
as the `.x`, because the `.x` being right is not sufficient — goxdr's field ordering
and type mapping are what actually reach the wire.

| Struct | RFC 5661 section | Result |
| --- | --- | --- |
| `EXCHANGE_ID4args` | 18.35.1 | **checked, matches** — 4 fields, in order |
| `EXCHANGE_ID4resok` | 18.35.2 | **checked, matches** — 7 fields, in order |
| `channel_attrs4` | 18.36.1 | **checked, matches** — 7 fields, in order |
| `CREATE_SESSION4args` | 18.36.1 | **checked, matches** — 7 fields, in order |
| `CREATE_SESSION4resok` | 18.36.2 | **checked, matches** — 5 fields, in order |
| `SEQUENCE4args` | 18.46.1 | **checked, matches** — 5 fields, in order |
| `SEQUENCE4resok` | 18.46.2 | **checked, matches** — 6 fields, in order |

**No discrepancy was found. No `.x` file was changed by this verification.**

`EXCHANGE_ID` was the highest-risk pair, because it is absent from upstream entirely
and was transcribed by hand from RFC 5661 18.35 rather than inherited. It was checked
hardest and is correct, including the three supporting structures the RFC defines
outside section 18.35 and the transcription therefore had to pull from elsewhere:

- `client_owner4` (RFC 5661 section 2.4, `{ verifier4 co_verifier; opaque co_ownerid<NFS4_OPAQUE_LIMIT> }`) — matches
- `server_owner4` (RFC 5661 section 2.5, `{ uint64_t so_minor_id; opaque so_major_id<NFS4_OPAQUE_LIMIT> }`) — matches
- `nfs_impl_id4` (RFC 5661 section 3.3.21, `{ utf8str_cis nii_domain; utf8str_cs nii_name; nfstime4 nii_date }`) — matches

The rest of the transcribed 18.35 block was checked with the same method and also
matches: all nine `EXCHGID4_FLAG_*` constants and their values, `state_protect_ops4`,
`ssv_sp_parms4`, `state_protect_how4`, `state_protect4_a`, `ssv_prot_info4`,
`state_protect4_r`, `typedef opaque gsshandle4_t<>`, and `EXCHANGE_ID4res`.

Because a field's type is only correct if its typedef is, the base typedefs these
structs resolve through were checked against the RFC 5661 section 3.2 table and
section 3.1 constants. All match: `bitmap4` = `uint32_t<>`, `count4` = `uint32_t`,
`clientid4` = `uint64_t`, `sequenceid4` = `uint32_t`, `slotid4` = `uint32_t`,
`sessionid4` = `opaque[NFS4_SESSIONID_SIZE]`, `verifier4` = `opaque[NFS4_VERIFIER_SIZE]`,
`sec_oid4` = `opaque<>`, `utf8str_cis` / `utf8str_cs` = `utf8string`,
`nfstime4` = `{ int64_t seconds; uint32_t nseconds }`, `NFS4_OPAQUE_LIMIT` = 1024,
`NFS4_SESSIONID_SIZE` = 16, `NFS4_VERIFIER_SIZE` = 8.

Two further checks were made because a defect there produces the same
looks-like-a-server-bug failure mode as a wrong field, at no extra cost:

- **All 13 `SEQ4_STATUS_*` constants** (RFC 5661 18.46.2) — values match.
- **The entire `nfs_opnum4` enum** (RFC 5661 section 16.2.1, the `COMPOUND`
  arguments, where the enum is declared) was
  diffed against the vendored enum. Every operation number is identical, including
  `OP_EXCHANGE_ID` = 42, `OP_CREATE_SESSION` = 43, `OP_SEQUENCE` = 53, and
  `OP_ILLEGAL` = 10044. The only differences are the two deliberate omissions
  recorded below (`OP_BACKCHANNEL_CTL` = 40 and `OP_BIND_CONN_TO_SESSION` = 41).
  Because every enumerator carries an explicit value, omitting those two shifts
  nothing. `nfs_argop4` and `nfs_resop4` carry the corresponding arms for all three
  session operations, so they are reachable through `COMPOUND`.

### If you are re-verifying

Do not verify from memory, and do not verify the `.x` alone. Fetch RFC 5661, read the
`.x`, and read the generated Go — the third step is the one that catches a generator
mapping problem rather than a transcription problem.

---

## Upstream: the `.x` files and `types.go`

- **Project:** `github.com/Cyberax/go-nfs-client`
- **Commit:** `eeba7350de5b260f1c52f52bdd2ea1cb9932d517` (2021-11-02)
- **License:** Apache-2.0, Copyright 2020 Aleksei Besogonov
- **License text:** `LICENSE-Apache-2.0.txt` in this directory, retaining the
  `Copyright 2020, Aleksei Besogonov` line verbatim
- **NOTICE file:** none exists upstream, so Apache-2.0 section 4(d) imposes nothing
  to propagate

### Three files are taken, not two

1. `nfs4.x` — the NFSv4 XDR description
2. `rpc.x` — the ONC RPC message format (RFC 5531)
3. `types.go` — **hand-written upstream, not generated**

`types.go` is easy to mistake for generated output and is not optional. `nfs4.x` uses
`uint32_t`, `uint64_t`, and `int64_t` without ever declaring them, and they are not
goxdr builtins; upstream supplies them from this file as Go type aliases. Without it
the package does not compile no matter how the `.x` files are processed, and the
failure reads as a generator bug rather than a missing input. It is **not reproduced
by `make regen-xdr`** — regenerating will not bring it back if it is deleted.

Its only modification is the package rename from `internal` to `xdr`, noted in its own
header.

What we deliberately do **not** take is upstream's client. That client is NFSv4.0,
built on `SETCLIENTID`, `OPEN`, and `CLOSE` — precisely the machinery this design
exists to avoid.

### The `.x` copyright position

`nfs4.x` carries only `Copyright (C) The Internet Society (1998-2002)`, the pre-2008
RFC 3530 header, with **no Simplified BSD code-components grant**. That grant arrived
with the 2008 IETF Trust Legal Provisions and appears in RFC 5661. `rpc.x` carries no
copyright line at all.

Practically, these definitions ship in Linux, nfs-ganesha, FreeBSD, and libnfs, so the
exposure is low. The mitigation, applied here, is to take every addition from RFC 5661
— which *does* carry the code-components grant — and annotate provenance per block, so
the two copyright regimes stay visually separable in the file. Do not merge an Everpure
addition into a surrounding upstream block; that destroys the separation.

### Fallback if OSS review objects

The `.x` files are the only load-bearing piece taken from upstream, and they can be
transcribed from RFC 5661 directly, dropping Cyberax and Apache-2.0 entirely. goxdr
still generates from that under its Apache-2.0 option. This is a few days of
transcription, held in reserve rather than done pre-emptively.

---

## Generator: goxdr

- **Project:** `github.com/xdrpp/goxdr`
- **Pin:** **tag `v0.1.3`**, published 2025-05-16, which resolves to upstream commit
  `53faa028671120e96db8e8bd2d95e8ea1d19d085` (`refs/tags/v0.1.3`); module zip hash
  `h1:Tfp/jVQ+P+GcE+yYqXF1UcCck6tB1OVRcoG/DBYw+C4=`
- **License:** dual licensed, **GPLv3-or-later OR Apache-2.0 at the distributor's
  option.** Copyright (C) 2018-19 David Mazieres, all rights reserved.
- **Invocation:** the `regen-xdr` target in the repo `Makefile`
- goxdr never enters `go.mod` and is never a build dependency of the shipped binary.
  Its own `go.mod` requires `golang.org/x/tools v0.31.0`; that is a build-host
  dependency of the generator only and does not reach this repo's module graph.

### Why a tag and not a commit — this is a deliberate deviation

The userspace transport design doc (section 13; kept in the private lab repository) pins commit `cef459259820318541db8e569446afab70e1dc00` (2026-05-07). **That
pin does not work and was abandoned during Task 5a.** An auditor comparing this file
against the design doc will otherwise see a commit pin silently become a tag pin, so
the reasoning is recorded here rather than left to be rediscovered:

- `go run github.com/xdrpp/goxdr/cmd/goxdr@cef4592` fails outright. The published
  module at that commit omits its goyacc-generated parser (`cmd/goxdr/parse.go` and
  `header.go`) and the build dies with `undefined: T_CONST`.
- Building it locally means running goyacc first — a second, unpinned input in the
  generation path, which defeats the entire point of pinning.
- The tagged release `v0.1.3` ships the generated parser and works from a clean
  machine with no extra tooling.

What matters legally is the terms of the version we elected under, and that must be
pinned to be provable. A git tag is mutable in principle, so the underlying commit
hash and the module zip hash are recorded above alongside the tag. Those are
immutable, and the Go module proxy will refuse a changed zip against that hash.

### We elect Apache-2.0. Why the election reaches the shipped binary

goxdr is offered under GPLv3-or-later **or** Apache-2.0, at the distributor's option.
**Everpure elects Apache-2.0.**

This election is load-bearing rather than ceremonial, and the reason is the `-B` flag
on the generate command. `-B` bundles goxdr's own runtime boilerplate — its
`cmd/goxdr/header.go.in`, roughly 780 lines of David Mazieres' source — verbatim into
the generated output. In `xdr_generated.go` it occupies the region between the
`// begin boilerplate` and `// end boilerplate` markers (currently lines 15721-16500).
That code is compiled into `permissionreset`. The generator's license therefore reaches the
**shipped binary**, not merely the build host, and the choice between GPLv3 and
Apache-2.0 is a choice about what license binds our distributed artifact.

A later audit will grep this tree, find "GPL", and reasonably raise an alarm. **This
paragraph is the answer to that alarm.** The alternative to `-B` is `-b`, emitting the
boilerplate into a separate file in the same package — which changes where the code
sits, not whether it ships.

The verbatim attribution and grant from goxdr's `COPYING`, retained here because the
bundled boilerplate carries no notice of its own:

> Copyright (C) 2018-19 David Mazieres.  All rights reserved.
>
> Anyone is premitted to distribute this software under the terms of the GNU General
> Public License (GPL) version 3 or later. [...]
>
> Anyone is also permitted to distributed this software under the terms of the Apache
> License version 2.0 [...]

(Typos are upstream's.) Note that `xdr_generated.go` carries **no** copyright notice
of its own — only the `Code generated by goxdr ...; DO NOT EDIT.` line. This directory carries the Apache 2.0 text as
`LICENSE-Apache-2.0.txt`, and the repository root's `THIRD-PARTY-NOTICES` lists the goxdr runtime
alongside `yaml.v3` and `golang.org/x/sys`, which covers Apache-2.0 section 4 for distribution.

### OSS review status

OSS review of the goxdr Apache-2.0 election is owned by Justin and runs in parallel.
It does **not** gate phases 1-3. A rejection affects only this subdirectory — not
`rpc.go`, `session.go`, `ops.go`, or `client.go` — and the fallback above applies.

---

## Modifications: four, all marked inline

Apache-2.0 section 4(b) requires stating that files were modified. Both `.x` files and
`types.go` carry a `MODIFIED BY EVERPURE` header, and every change below is marked at
its site in the file. Two are additions and two are removals.

### Added

**1. `OP_EXCHANGE_ID` and the whole `EXCHANGE_ID` block — `nfs4.x`**

From **RFC 5661 section 18.35**, which carries the IETF Trust code-components grant
(Simplified BSD). Absent from upstream entirely: upstream's `.x` is RFC 3530 and has
no `EXCHANGE_ID` at all. Marked `EVERPURE ADDITION — RFC 5661 section 18.35`.

`BIND_CONN_TO_SESSION` and `BACKCHANNEL_CTL` were **not** added. This client wants
neither, and an unused operation in the generated surface is an invitation to use it.
Their absence from `nfs_opnum4` is intentional and shifts no other value.

**2. `AUTH_TLS = 7` — `rpc.x`**

From **RFC 9289 section 5.1**, same grant. Upstream's `auth_flavor` enum declares
flavors 0-3 only. Added now, while the file was already being modified and
regenerated, so NFS over TLS (phase 6) needs no second regeneration cycle. Unused
today.

Marked `TLS INJECTION POINT 2 of 2`. The marker string is exactly
`TLS INJECTION POINT` so that `grep -rn "TLS INJECTION POINT" internal/nfs41/` finds
the complete set. Point 1 of 2 is the `Dialer` seam in `rpc.go` and lands with that
file; until then this grep returns only point 2.

### Removed

**3. `RPCSEC_GSS = 6` from `rpc.x`'s `auth_flavor` enum**

`nfs4.x` already declares `const RPCSEC_GSS = 6` for its `secinfo4` union, and both
`.x` files generate into **one** Go package, so keeping both is a genuine
redeclaration rather than a stylistic duplicate. This client only ever sends
`AUTH_SYS`, which makes the enum member the removable half. The value is unchanged and
nothing on the wire moves. Marked `EVERPURE MODIFICATION` at the site.

**4. The entire NFS4 callback section from `nfs4.x`**

`CB_GETATTR`, `CB_RECALL`, `CB_ILLEGAL`, `nfs_cb_opnum4`, `nfs_cb_argop4`,
`nfs_cb_resop4`, and `CB_COMPOUND` — everything from the
`NFS4 Callback Procedure Definitions and Program` comment to the end of the upstream
file. Replaced with an `EVERPURE MODIFICATION` block giving both reasons:

- It is the **back channel this client does not implement.** `CREATE_SESSION` omits
  `CREATE_SESSION4_FLAG_CONN_BACK_CHAN`, there is no callback server, and no
  delegation is ever requested.
- Separately, **it does not compile.** `nfs_cb_argop4` and `nfs_cb_resop4` switch on a
  `uint32_t` discriminant while their case labels are `nfs_cb_opnum4`, so goxdr emits
  assignments across the two types. `-lax-discriminants` does not rescue this one: the
  defect is in an assignment, not merely in a case label.

`callback_sec_parms4` is deliberately **kept**. It looks like back-channel machinery
and is not optional — `CREATE_SESSION4args.csa_sec_parms` references it, and we send
it as an empty array. It is the sole reason `-lax-discriminants` appears on the
generate command at all.

This second reason is also the answer to "why not just do what upstream did":
**upstream's committed `.go` files are not reproducible from upstream's own `.x` with a
current goxdr.** Their `rpc.go` omits the `auth_flavor` constants entirely and their
`nfs4.go` predates this breakage. Do not spend time trying to match their output.

---

## Regenerating

```bash
PATH="/usr/local/go/bin:$PATH" make regen-xdr
```

The target's own comment block explains its three non-obvious flags. Two constraints
worth restating because violating either produces a confusing failure:

- **One invocation over both `.x` files, into one output file.** goxdr's `-B` implies
  `-b`, so two invocations emit the runtime boilerplate twice into a single Go package
  and every runtime symbol is redeclared. Two separate output files were the original
  design and cannot work.
- **The output must be byte-stable.** Running the target must leave the working tree
  clean. That is the proof `xdr_generated.go` was never hand-edited.

Gates that must hold after regenerating:

```bash
PATH="/usr/local/go/bin:$PATH" CGO_ENABLED=0 go build ./internal/nfs41/xdr/ || exit 1
PATH="/usr/local/go/bin:$PATH" go list -deps ./internal/nfs41/xdr/ | grep '\.' | grep -v flashblade-permissionrepair
PATH="/usr/local/go/bin:$PATH" git diff --exit-code go.mod go.sum
```

Expected: builds clean, the dependency listing is **empty**, and `go.mod` / `go.sum`
are untouched. Read the build result first every time — `go list -deps` on a package
that fails to compile prints nothing, so an empty listing from a broken build is a
vacuous pass rather than a real one.

## Amendment: nfsstat4 completed to RFC 5662

The upstream `.x` truncated the `nfsstat4` enum at `NFS4ERR_RECALLCONFLICT = 10061`.
RFC 5662's definition runs to `NFS4ERR_DELEG_REVOKED = 10087`, so 25 enumerators were
missing. They have been added to `nfs4.x` and the bindings regenerated; the change to
`xdr_generated.go` is purely additive (92 insertions, 0 deletions).

**Source.** RFC 5662, `https://www.rfc-editor.org/rfc/rfc5662.txt`, md5
`b161eaa80da19b850804defd300d8d2c`. RFC 5662 rather than RFC 5661 because 5661 names these
statuses in prose but assigns no numbers — the numeric enum lives only in the XDR
description document. That distinction is why the gap survived the Task 5b verification
pass, which checked the session structs and the whole `nfs_opnum4` enum against RFC 5661
but did not check `nfsstat4` for completeness.

`10073` is genuinely absent from RFC 5662. The gap is the RFC's, not a transcription slip.

**Why it mattered.** Two of the 25 are load-bearing. `NFS4ERR_SEQ_MISORDERED` (10063) and
`NFS4ERR_DEADSESSION` (10078) are the two most likely session faults, and the client cannot
classify — therefore cannot recover from — a status it has no name for. Task 7 stopped
rather than substituting RFC literals for the missing aliases, which is what surfaced this.

**Verification of what was already there.** Every `nfsstat4` value the implementation plan
already aliased was cross-checked against RFC 5662 in the same pass and all sixteen match:
`NFS4_OK` 0, `PERM` 1, `NOENT` 2, `ACCESS` 13, `INVAL` 22, `STALE` 70, `BADHANDLE` 10001,
`NOTSUPP` 10004, `TOOSMALL` 10005, `DELAY` 10008, `GRACE` 10013, `RESOURCE` 10018,
`NOT_SAME` 10027, `OP_ILLEGAL` 10044, `BADSESSION` 10052, `BADSLOT` 10053.

## Deliberate omission: `BIND_CONN_TO_SESSION` (op 41)

RFC 5661 operation 41 is absent from this vendored subset — not in `nfs4.x`, not in
`xdr_generated.go`, and not in the `nfs_opnum4` enum. That is deliberate and matches the
design's non-goals: the client does not implement trunking, because it holds one session
per TCP connection with exclusive slot ownership and so has no shared state for
`BIND_CONN_TO_SESSION` to protect.

**The consequence, found by Task 9.** `fakeServer.BindConnToSessionCount()` exists so
Task 14 can assert the count stayed zero — a regression guard against someone adding
trunking without noticing. But with no arm in the generated union, unmarshalling a whole
`Nfs_argop4` array panics on op 41 without revealing *which* op it choked on, so the
counter could not distinguish `BIND_CONN_TO_SESSION` from any other unknown op and the
assertion would have been worthless.

The fake therefore dispatches on the **raw opnum word** rather than unmarshalling
`Nfs_argop4`, and declares `opBindConnToSession = uint32(41)` locally. That literal is a
documented exception to this package's alias-don't-transcribe rule, and it is the only
correct option: there is no generated symbol to alias, and adding one would mean
generating a union arm for an operation the client must never send.

**Do not "fix" this by adding op 41 to `nfs4.x`.** An arm that exists is an arm that can
be sent by accident, and the whole point of the omission is that it cannot be.

## Deliberate non-modification: the decoder's allocation behaviour

The phase 3 benchmark found the userspace transport's cost is dominated by allocation in
this package's *generated* decode path, not by the network. A CPU profile of a 1,135,009
object run (S200, 29.9 s wall, 337% CPU, 101 s of samples) attributes 37.0% cumulative to
`runtime.mallocgc`, 29.8% to `XdrIn.Marshal`, 24.7% to `ParseCompound`, and 22.5% to
`xdrReadN` -> `io.CopyN` -> `io.Copy`, against 10.2% in actual syscalls. Roughly a quarter
more sits in `scanObject`, sweep, and `tryDeferToSpanScan`. On a 12-CPU client the same
workload leaves 38% of the machine idle while running out of CPU, which is the signature
of a GC-bound program rather than an I/O-bound one.

The mechanism is one function, `xdrReadN`:

```go
func xdrReadN(in io.Reader, n uint32) []byte {
	var b bytes.Buffer
	if _, err := io.CopyN(&b, in, int64(n)); err != nil {
```

`xdrGet32` calls it for **every 32-bit field**, so each 4-byte integer costs a fresh
`bytes.Buffer`, an `io.CopyN`/`io.Copy` through `ReadFrom` with its own internal buffer,
and at least one heap allocation. A `READDIR` reply carrying hundreds of `Entry4`s, each
with a four-attribute `Fattr4`, therefore costs thousands of allocations. That the profile
ranks `Entry4.XdrMarshal` at 38% of `Marshal`'s callers is this arithmetic showing up as
time.

**`xdr_generated.go` will not be hand-edited to fix it.** The regeneration contract above
requires that `make regen-xdr` leave the working tree clean, and that byte-stability is
the only evidence anyone has that this 506 KB file was never hand-edited. Trading that for
a local speed-up would be a bad bargain twice over: the edit is silently reverted by the
next regeneration, and the guarantee it breaks covers all 16,000 lines, not just the four
it touched.

Note also that the four modifications recorded above are all edits to the **`.x` inputs**,
which is why they survive regeneration. There is no `.x` construct that changes how goxdr
emits its runtime reader, so this problem cannot be fixed the way those were.

**The supported route is a hand-written decoder outside this package** for the hot reply
types only — `READDIR4res`/`Entry4`/`Fattr4`/`SEQUENCE4res` — reading from the
`bytes.Reader` that `ParseCompound` already has, slicing it rather than copying field by
field. That leaves the vendored surface untouched and byte-stable, keeps the generated
decoder as the reference implementation for everything cold, and is testable against it:
a hand-written decoder can be differentially tested against the generated one over the
golden `testdata/` bytes, which is a stronger check than either has alone.

Two things NOT to do:

- Do not fork goxdr to emit a better reader. The generator is vendored by provenance, not
  by preference, and a forked generator is a permanent maintenance obligation for a
  problem confined to four reply types.
- Do not conclude the answer is fewer RPCs. Phase 4's premise was that batching
  `PUTFH`+`SETATTR` pairs per COMPOUND is the win, and this measurement says the kernel
  transport beats userspace 2.1x while issuing 1.80 NFS operations per object against
  roughly 1.1 — so operation count is demonstrably not the binding constraint. Batching
  would optimise the thing that is not the problem, and would decode *larger* replies with
  the same allocator.
