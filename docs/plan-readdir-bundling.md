# Plan: N-way READDIR bundling

Scoping document. Nothing here is implemented. Written against `nfs41-userspace-transport`
at `9d4333a`, verified by reading the code rather than by trusting the archived
measurements — where the two disagree, this document says so and follows the code.

Status: **complete draft. Feature DECLINED 2026-08-24; the bug fixes it found were taken.**

## Why it was declined

The scoping was sound; the payoff was not. READDIR's share of RPCs is roughly
`1 / (1 + entries per directory)`, so on the workload customers actually have — file shares
full of user and group home directories — it sits near 3%, and bundling 3% of the traffic
seven ways cannot move a run. Two further limits compound it: the bundle width is
*subdirectory fan-out*, not entry count, so a wide-but-shallow tree bundles poorly; and a
directory large enough to need continuations cannot bundle at all, because its cookies are
serial.

Hardware measurement then removed the premise entirely. The S200 sustains at least 141,876
metadata ops/sec while this client runs at ~68,000, so enumeration is not the constraint —
and the same measurements showed the real cost sits in the ACL SETATTR service time on the
array, which no client-side batching touches.

**Stages 1-6 were implemented** — they are bug fixes that stand on their own, and the
GARBAGE_ARGS session-rebuild storm in particular was a live defect that had already
abandoned two hardware runs partway through, with objects already modified. Everything from
stage 7 onward is the feature, and is not built.

Kept rather than deleted because the analysis is the expensive part. Anyone re-proposing
READDIR bundling should start from the three limits above and be ready to say what changed.

---

## 0. What this is and what it is not

The change: let the userspace NFSv4.1 client enumerate up to seven sibling directories in
one COMPOUND, instead of one directory per COMPOUND.

Not in scope, and not fixable: the apply path. FlashBlade accepts at most one mutating
operation per COMPOUND (`RFC-Deviations.md` §2, measured, "known limitation, not planned to
be fixed"), so `SETATTR` is permanently one round trip per object. Nothing in this plan
touches that term.

---

## 1. Facts verified against the code

Each of these was re-derived from the source, not taken from the archived tag.

### 1.1 Width 7 is a protocol ceiling, not a tuning choice

`internal/nfs41/session.go:21` pins `maxSessionOperations = 16`, and `session.do`
(`session.go:922`) refuses locally any COMPOUND with `len(ops)+1 > attrs.MaxOperations`.
FlashBlade grants exactly 16 (`RFC-Deviations.md` §3, §6). A bundle member costs
`PUTFH + READDIR` = 2 operations, and SEQUENCE takes one:

```
width = floor((MaxOperations - 1) / 2) = floor(15/2) = 7
```

Width 8 would be 17 operations and would be rejected by the client before it reached the
wire. So the "seven" in the archived measurements is not an empirical sweet spot — it is
the largest width the negotiated channel permits. **This matters for §5: the client can
compute its own maximum width and never has to discover it by probing.**

### 1.2 The response-size objection does not bind on FlashBlade, and the probe never tested it

`readdirbundle_live_test.go:205-208`:

```go
maxcount := budget / uint32(n)
if maxcount > uint32(64<<10) {
    maxcount = uint32(64 << 10)
}
```

`budget = attrs.MaxResponseSize - readdirCompoundOverhead`. FlashBlade grants
`ca_maxresponsesize = 526336` (`RFC-Deviations.md`, "Not deviations"), and
`readdirCompoundOverhead = 116` (`client.go:34-58`: 28 + 12 + 44 + 8 + 24). So
`budget = 526220`, and:

| width | `budget/width` | after the 64 KiB cap |
|---|---|---|
| 1 | 526220 | 65536 |
| 2 | 263110 | 65536 |
| 4 | 131555 | 65536 |
| 7 | 75174  | 65536 |

**Every arm of the probe ran at `rd_maxcount = 65536`.** The division by width never took
effect, because `budget/7` is still above the 64 KiB cap. The commit message for `a3079b0`
describes the probe as "dividing the `rd_maxcount` budget by width exactly as a real
implementation would have to", and the tag annotation repeats it. That is not what the code
did on this array. The arms were identical in `rd_maxcount` and the measurement is a clean
comparison of bundle width alone.

This is good news rather than bad, and it generalises: a real implementation does **not**
have to divide the budget on FlashBlade, because

```
7 × 65536 + (28 + 12 + 44) + 7×8 + 7×24 = 458752 + 84 + 56 + 168 = 459060 < 526336
```

Seven members at the full production `rd_maxcount` fit inside `ca_maxresponsesize` with
67 KiB to spare. Reinforcing that, `RFC-Deviations.md` records under "Not deviations" that
FlashBlade returns an identical ~32 KiB reply for `rd_maxcount` of 64, 128 and 256 KiB — so
a member will never actually consume more than about half of what it asks for, and a
seven-way reply is bounded near 224 KiB in practice.

Consequence for §5: **width does not need to adapt to directory size on this platform.** The
mechanism that would have forced adaptation is absent.

Caveat, stated because it is the one that would reverse this: `budget/7 > 65536` requires
`ca_maxresponsesize > 458868`. A server granting less would make the division bind. The
implementation must therefore compute the per-member `rd_maxcount` as
`min(64 KiB, budget_for_width_N)` rather than hardcoding 64 KiB, even though on measured
hardware the first term always wins.

### 1.3 The bundling path *can* reach the broken generated decoder today

This is the question the brief asked to be answered clearly. The answer is **yes, and by the
shortest possible route**, so it must be closed before any bundling ships.

`session.decodeSessionReply` (`session.go:892-907`):

```go
if wantFast && fastDecodeEnabled {
    status, results, ok, err := decodeCompoundFast(reply)
    if err == nil && ok {
        return status, decodedReply{fast: results}, nil
    }
    // Fall through on both a decline and an error.
}
status, results, err := ParseCompound(reply)
```

Three live routes from a bundled READDIR reply into `ParseCompound`:

1. **An attribute the fast decoder was not taught.** `decodeFattr4`
   (`fastdecode.go:329-332`) returns false for any bit outside its known-width table.
   Inside a READDIR, that propagates `decodeDirlist` false → the `OP_READDIR` arm returns
   `errShortReply` (`fastdecode.go:259-262`) → `err != nil` → `ParseCompound`.
2. **A truncated or trailing-byte reply.** Same arm, same outcome
   (`fastdecode.go:273-275`).
3. **The kill switch.** `fastDecodeEnabled` (`session.go:841`) is a package variable
   explicitly documented as existing so a test can force the generated path and prove it
   still serves every caller. If bundling ships without a guard, flipping that variable
   turns a debugging aid into a data-corruption-shaped failure.

Route 1 and 2 land on exactly the shape the archived tag records the generated decoder
failing on: a large READDIR result followed by another result, decoded as an opnum from
entry-name bytes. `ParseCompound` then returns "invalid Resop", `session.do` wraps it as an
error, and `classify(status, err)` with `err != nil` returns `dispRebuild`
(`errors.go:64-66`). **The latent decoder bug feeds directly into the session-rebuild storm
that killed the last attempt.** It is not an independent hazard sitting alongside the error
classification problem; it is one of its causes.

Note also that `TestReadDirFollowedByOp`'s third arm (`READDIR then GETATTR`, one READDIR)
shows the trigger is not bundle width. The invariant that must hold is stronger and simpler:

> **The generated decoder must never be handed a COMPOUND in which a READDIR is not the
> last operation.**

Width-1 fallback preserves that invariant exactly, because the width-1 shape is
`SEQUENCE + PUTFH + READDIR` with READDIR last. See §4 for how the fallback is wired so that
this is guaranteed rather than hoped for.

### 1.4 A shape refusal is currently indistinguishable from a dead connection

`RFC-Deviations.md` §4 says an over-limit COMPOUND comes back as an RPC decode failure.
Following that through the code:

- `rpc.go:714-715` turns `xdr.GARBAGE_ARGS` into
  `fmt.Errorf("rpc: xid %d: server could not decode procedure arguments", d.xid)` — a plain
  formatted error with **no sentinel and no wrapped type**. Nothing downstream can test for
  it except by string matching.
- `session.do:949-957` receives it from `s.c.Call`, and because it is not `ErrNotSent`,
  calls `table.release(sl)`.
- `retryCall:1549` calls `classify(status, callErr)`; `errors.go:64-66` returns
  `dispRebuild` for any non-nil error, first, before any status is consulted.
- `rebuildEntry:1586` calls `Session.Rebuild`, which is `DESTROY_SESSION` + `CREATE_SESSION`
  on the same client ID — and `RFC-Deviations.md` §1 is the one-session-per-client-ID limit.

That is the storm, reproduced by reading. And there is a **second feeder** the archived note
does not mention:

`table.release` advances the slot's sequence ID (`session.go:127-138`: `release` keeps
`acquire`'s increment; only `reclaim` undoes it). A GARBAGE_ARGS reply means the server could
not decode the arguments, so it never executed SEQUENCE and never consumed the sequence ID.
Releasing therefore leaves the client's next request on that slot one ahead of the server's
expectation, which earns `NFS4ERR_SEQ_MISORDERED` — and `errors.go:84-85` maps that to
`dispRebuild` too. So a single shape refusal today produces a rebuild *and* poisons a slot
into producing a second rebuild. Two independent paths into the same violated MUST.

Both are fixed in §4.

### 1.5 The fake server models the mutation cap and nothing else in this family

`fakeserver_test.go:1397-1406` scans the argarray before executing and returns
`NFS4ERR_INVAL` with an empty `Resarray` when more than one forward-required operation is
present — a faithful model of §2, including the empty result array.

What it does **not** model:

- the GETATTR cap of four (the archived tag's blocker #2, still true);
- `ca_maxoperations` at all — there is no operation-count check anywhere in `runCompound`;
- `GARBAGE_ARGS` as a *reply*. `handleRecord` (`rpc.go`-side fake, `fakeserver_test.go:568`)
  drops the connection's answer for a call it cannot parse, which the comment there
  describes as "the same thing a real server's GARBAGE_ARGS-then-hangup looks like". It is
  not the same thing: FlashBlade answers with a well-formed RPC reply carrying
  `GARBAGE_ARGS`, and the client's handling of that reply is the entire subject of §4;
- any accounting of `ca_maxresponsesize` across several READDIRs in one COMPOUND
  (`fakeserver_test.go:2358-2368` bounds each READDIR individually).

Multi-READDIR *is* structurally supported: `compoundState` carries a per-COMPOUND current
filehandle, so `PUTFH+READDIR+PUTFH+READDIR` executes correctly today. The fake can serve
the happy path without change. It cannot serve any of the refusal paths without the work in
§7.

### 1.6 COMPOUND stops at the first failing operation, and this tree needs that

RFC 8881 §15.2, honoured by both decoders (`fastdecode.go:202-205` returns early on the first
non-OK status; `fakeserver_test.go:1462-1467` truncates `Resarray` the same way) and by
`session.do:993`, which only requires a full-length result array when the COMPOUND status is
`NFS4_OK`.

This is not an edge case for this tool. `walk.Prepass` (`walk.go:401-418`) deliberately
attempts `ReadDir` *before* fixing a directory, and falls back to fix-then-retry when the
read fails. A permission-repair tool run against a tree that needs repairing will meet
unreadable directories as a matter of course. In a bundle, an `NFS4ERR_ACCES` at member *k*
means members *k+1 … N-1* were never attempted — a bundle can therefore return between one
and *N* useful results, and the design must treat partial completion as ordinary rather than
exceptional. §4 covers it; §9 notes the pathological case where it makes bundling a net loss.

### 1.7 Incidental defect found while reading (not caused by this work)

`walk.go:298-343`: the `Prepass` doc comment block runs to line 334 and is immediately
followed, with no blank line, by the `childDir` comment and `type childDir`. Go therefore
attaches the whole 46-line block — including "Pass `ch == nil` for fix-only behavior" — as
the doc comment for `type childDir`, and `func Prepass` at line 345 has no doc comment at
all. Introduced when `childDir` was inserted in `db86931`. A one-line fix (blank line, or
move the type above the comment); mentioned here so it is not re-found, not because it
blocks anything.

---

## 2. Blast radius

Nothing in this change is exported outside the module. "Public-ish" below means *consumed by
another package in this repo*, which is where a change costs review effort and a compile
break; "internal" means confined to one file.

### 2.1 `internal/transport/transport.go` — public-ish, additive only

| Symbol | Change |
|---|---|
| `Transport` interface | **unchanged** |
| `BundleReadDirer` (new optional interface) | added |
| `Ref`, `Dirent`, `Attr` | unchanged |

The kernel transport (`internal/transport/kernel.go`) is **not modified** and does not
implement the new interface. See §3.

### 2.2 `internal/nfs41/client.go` — public-ish (`*Client` is the `Transport` impl)

| Symbol | Kind | Change |
|---|---|---|
| `Client.ReadDir` | exported method | unchanged signature; body refactored so the single-directory enumeration loop is callable as `readDirOne` |
| `Client.ReadDirBundle` | exported method | **new** — satisfies `transport.BundleReadDirer` |
| `readDirReply.page` | internal | signature changes from `page(parentPath string)` to `pageAt(index int, parentPath string)`; the `len(r.fast) != 3` / `r.fast[2]` hardcoding is what this removes |
| `readDirResult` | internal | same: takes a result index rather than assuming 2 |
| `readDirPage`, `readDirPage.addEntry` | internal | **unchanged** — the per-entry rules, including the `.`/`..` skip, are shared by both widths as they are today by both decoders |
| `decodeFilehandleAttribute` | internal | **unchanged** |
| `readdirCompoundOverhead` | internal const | split into a fixed part and a per-member part; see §2.6 |
| `sessionDoFast` | internal | gains a variant that forbids the generated fallback (§4.2) |
| `maxBundleWidth` | internal field on `Client` | **new**, `atomic.Int32`, monotonically decreasing |

`var _ transport.Transport = (*Client)(nil)` at `client.go:1673` gains a sibling assertion
for the new interface.

### 2.3 `internal/nfs41/session.go` — internal to the package

| Symbol | Change |
|---|---|
| `Session.DoFast` | unchanged |
| `Session.DoFastStrict` (new) | fast decoder only; returns `ErrFastDecodeDeclined` instead of falling back to `ParseCompound` |
| `session.do` | gains one parameter (or a small options struct) carrying "no generated fallback"; the slot handling for `GARBAGE_ARGS` changes from `release` to `reclaim` (§4.1, staged separately) |
| `decodeSessionReply` | gains the same flag |

### 2.4 `internal/nfs41/rpc.go` — internal

Add `ErrGarbageArgs` as a package-level sentinel and wrap it at `rpc.go:714`. One line plus a
`var`. No behaviour change on its own — this is stage 1 and is independently useful, because
today no caller can tell that error apart from a socket failure.

### 2.5 `internal/nfs41/errors.go` — internal

`classify` is **not** changed. The bundle path does not use it (§4.3). Adding a
`dispShapeRefusal` arm would silently change how a *width-1* GARBAGE_ARGS is handled, and a
width-1 GARBAGE_ARGS really is a client encoding bug that should stay loud.

### 2.6 Overhead accounting — internal, easy to get wrong

`readdirCompoundOverhead` (`client.go:58`) is `rpcReplyHeaderSize + compoundReplyHeaderSize +
sequenceReplySize + putfhReplySize + readdirReplyFixedSize`. Two of those terms are
*per-member*, not per-COMPOUND: `putfhReplySize` (8) and `readdirReplyFixedSize` (24). For a
bundle of width *W* the budget is

```
budget(W) = MaxResponseSize - (rpcReplyHeaderSize + compoundReplyHeaderSize + sequenceReplySize)
                            - W × (putfhReplySize + readdirReplyFixedSize)
```

and the per-member `rd_maxcount` is `min(64 KiB, budget(W)/W)`. At `W = 1` this must
reproduce the existing value exactly, or
`TestReadDirLeavesHeadroomForCompoundOverhead` (which the comment at `client.go:54-55`
explicitly warns pins the exact cap) will fail — and it *should* fail if the refactor drifts.

### 2.7 `internal/walk/walk.go` — public-ish (`Prepass` is called from `cmd/permissionreset`)

| Symbol | Change |
|---|---|
| `Prepass` | signature unchanged; the descent loop at `walk.go:479-490` changes shape |
| `PrepassOptions` | one new field, `ReadDirBundle` (see §3), default zero = today's behaviour |
| `PrepassResult` | one new counter pair, `BundledReadDirs` / `SingleReadDirs`, so a run can prove the feature was actually engaged |
| `childDir` | unchanged |
| `sameFilesystem` | unchanged |
| `ParallelWalk`, `Walk`, `Pfind` | unchanged — kernel-only paths |

### 2.8 `cmd/permissionreset/main.go` — user-visible

One flag, `--readdir-bundle N` (0 or 1 = off, default TBD by §9's measurement), plumbed into
`PrepassOptions`. Printed in the run banner next to `Workers:` so a benchmark result can
never be attributed to the wrong configuration.

### 2.9 Files that must NOT change

- `internal/transport/kernel.go` — the whole point of the interface choice in §3.
- `internal/nfs41/xdr/**` — `PROVENANCE.md` requires `make regen-xdr` to leave the tree
  clean, and byte-stability is the only evidence the 506 KB generated file was never
  hand-edited. **The generated decoder's READDIR desync is therefore not fixable in place.**
  This constrains §4: the only available remedy is to stop sending it the shape it cannot
  decode.
- `internal/apply/**` — the mutation cap makes the apply path irreducible.

---

## 3. The transport interface decision

### Options

**(a) Change `Transport.ReadDir` to take a slice of `Ref`.**
Rejected. It forces `internal/transport/kernel.go` to grow a batched implementation that
would be a `for` loop over `os.ReadDir` — a fake batch that pays interface cost for nothing —
and it breaks every existing caller and test of a method that is currently one of the
simplest things in the codebase. It also breaks the doc contract in `transport.go:86-87` for
a transport where the contract is free.

**(b) Add `ReadDirBundle` to `Transport` as a required method.**
Rejected for the same reason in weaker form: the kernel transport would need a stub, and a
stub that loops is indistinguishable at the call site from a real implementation, so
`Prepass` could not tell whether bundling is worth forming a batch for. Worse, it makes the
interface assert a capability that is a property of *one server's* COMPOUND semantics.

**(c) Optional interface, type-asserted at the call site. — RECOMMENDED.**

```go
// BundleReadDirer is implemented by transports that can enumerate several
// directories in one server round trip. It is optional: a transport that does not
// implement it is used one directory at a time, which is what every caller must be
// able to fall back to anyway, because a bundle can refuse.
type BundleReadDirer interface {
    // MaxReadDirBundle returns the largest width this transport will accept
    // right now. It may decrease during a run and must never increase. A return
    // of 1 or less means bundling is off and callers must use ReadDir.
    MaxReadDirBundle() int

    // ReadDirBundle enumerates up to MaxReadDirBundle directories in one round
    // trip, invoking fn once per directory, in the order given.
    //
    // fn is called for every ref the server answered, with err non-nil for one
    // that failed. Refs the server never reached are reported by returning
    // `attempted < len(refs)`; the caller re-issues those, and MUST NOT treat
    // that as an error.
    //
    // entries passed to fn is valid only for the duration of the call and
    // aliases decode-local storage. A callback that retains it must clone.
    ReadDirBundle(refs []Ref, fn func(i int, entries []Dirent, err error)) (attempted int, err error)
}
```

Reasoning, in order of weight:

1. **The kernel transport keeps working with a zero-line diff.** That is a hard requirement
   from the brief and this is the only option that meets it literally.
2. **The optional-ness is honest, not a shortcut.** Bundling is not a property of "a
   filesystem"; it is a property of a server that accepts multi-READDIR COMPOUNDs, and §1.4
   says the client cannot always tell whether it still does. An interface that a transport
   may decline to implement, and that may decline *at runtime* via `MaxReadDirBundle`
   returning 1, models that accurately. A required method cannot express "I could yesterday
   and cannot now".
3. **The callback shape is a memory decision, not a style decision.** See §4.5 and §5. A
   `([][]Dirent, error)` return would hold seven directories' worth of dirents live
   simultaneously in a walk that already has an OOM under investigation. The callback holds
   one at a time and lets the aliasing discipline `fastdecode.go` already relies on extend
   to the batch.
4. **`attempted` is the partial-completion channel.** §1.6 makes short bundles ordinary. An
   API that could only say "error" would force the caller to guess how much of the batch ran,
   and guessing wrong means either lost directories (silent under-walk — the worst failure
   this tool can have) or re-walked ones.

The type assertion lives in exactly one place, `walk.Prepass`, and is captured into
`PrepassOptions` by the caller so the walk package does not import `internal/nfs41`:

```go
// PrepassOptions
// ReadDirBundle, when non-nil, is used to enumerate sibling directories several
// at a time. nil means one at a time, which is the kernel transport and is also
// what the userspace transport does after a shape refusal.
ReadDirBundle transport.BundleReadDirer
```

`cmd/permissionreset/main.go` does the assertion when it builds the options:

```go
if b, ok := tr.(transport.BundleReadDirer); ok && *readdirBundle > 1 {
    popts.ReadDirBundle = b
}
```

### What the recommendation costs

The `Transport` doc comment's "ReadDir must return entries sorted by name" contract has to be
restated for the bundle: `ReadDirBundle` sorts each member's entries before invoking `fn`,
for the same determinism reason. That is a real constraint on the implementation — it means a
member is not delivered until it reaches EOF (see §5's eviction rule), which is a design
consequence worth naming rather than a footnote.

---

## 4. Error classification — the thing that killed the last attempt

The governing constraint, restated from `RFC-Deviations.md` §4: **on FlashBlade a COMPOUND
refused for its shape and a COMPOUND that the client encoded wrongly produce the identical
wire response.** The client cannot tell them apart. Every decision below follows from
accepting that rather than trying to defeat it.

The second governing constraint, from §1: a rebuild is not a cheap remedy on this array.
`RFC-Deviations.md` §1 means the pool cannot reliably re-establish sessions under load, and
the archived tag records what that costs — runs abandoned at 28k–74k of 1.1M objects, with
one arm having already applied a single object, so the failure mode is *partial application*.

### 4.1 Make the ambiguity narrower before relying on it (stage 1)

Two mechanical changes that reduce, but do not eliminate, the ambiguity:

```go
// rpc.go
// ErrGarbageArgs is an RPC-layer refusal of the call's arguments. On FlashBlade
// it is ALSO how an over-length COMPOUND is refused (RFC-Deviations.md section 4),
// so a caller that sends a speculative COMPOUND shape must treat it as a possible
// shape refusal rather than as a client bug. A caller that sends only shapes the
// server has already accepted should treat it as a client bug and say so loudly.
var ErrGarbageArgs = errors.New("rpc: server could not decode procedure arguments")

case xdr.GARBAGE_ARGS:
    return nil, fmt.Errorf("rpc: xid %d: %w", d.xid, ErrGarbageArgs)
```

and, in `session.do`'s `Call` error handling:

```go
if errors.Is(err, ErrNotSent) || errors.Is(err, ErrGarbageArgs) {
    table.reclaim(sl)
} else {
    table.release(sl)
}
```

The second change is the fix for the second storm feeder in §1.4. The argument that it is
correct: the server reports GARBAGE_ARGS from RPC argument decoding, which precedes NFS
operation execution, so SEQUENCE cannot have run and the sequence ID cannot have been
consumed. The argument that it is *safe even if that is wrong*: reclaiming a consumed
sequence ID reissues it; because `sa_cachethis` is always false (`session.go:777-779`) the
server holds no cached reply to compare against, so the reissue is answered normally or with
`NFS4ERR_RETRY_UNCACHED_REP`, which `classify` already maps to `dispRetry` under a bounded
budget. Releasing an *unconsumed* sequence ID, by contrast, yields `SEQ_MISORDERED`, which
maps to `dispRebuild` — a violated MUST. The asymmetry is decisive and the errors are not
comparable in severity.

**This must still be confirmed on hardware, not shipped on the argument alone** — see §7.3.
It is stage 1 precisely so it can be measured on its own, before anything depends on it.

### 4.2 The bundle path never reaches the generated decoder (stage 2)

From §1.3, the invariant is: *the generated decoder must never be handed a COMPOUND in which
a READDIR is not the last operation.* Enforce it structurally.

```go
// ErrFastDecodeDeclined means the hand-written decoder could not decode this
// reply and the caller forbade the generated fallback.
//
// The generated decoder desyncs on a COMPOUND reply carrying a READDIR result
// that is not the last result -- it reads entry-name bytes as an opnum. Measured;
// see the archive/compound-batching-spike tag. It cannot be fixed in place,
// because internal/nfs41/xdr/PROVENANCE.md requires the generated file to stay
// byte-stable under `make regen-xdr`. So the remedy is to never send it that
// shape, and this error is how a caller that CAN send that shape says "decode it
// with the fast decoder or tell me you could not".
var ErrFastDecodeDeclined = errors.New("nfs41: fast decoder declined and the generated fallback is forbidden")
```

`decodeSessionReply(reply, wantFast, allowGenerated bool)`: when `wantFast &&
!allowGenerated` and the fast decoder declines or errors, return `ErrFastDecodeDeclined`
rather than calling `ParseCompound`. Slot handling is unchanged from the existing
parse-failure arm (`session.go:960-965`: `release`, because the record did reach the server
and SEQUENCE may have run).

`ReadDirBundle` calls `DoFastStrict`. Width-1 `ReadDir` continues to call `DoFast` and keeps
its generated fallback, because at width 1 the shape is one the generated decoder handles.

Also guard the kill switch: `ReadDirBundle` must check `fastDecodeEnabled` and report
`MaxReadDirBundle() == 1` when it is false. A test that flips the switch to exercise the
generated path must not thereby route bundles into the decoder that cannot read them.

### 4.3 The bundle path does not use `retryCall`, and cannot rebuild a session (stage 3)

This is the load-bearing decision.

`retryCall` (`client.go:1502-1563`) is all-or-nothing: it returns an error whenever
`status != NFS4_OK`, and it calls `classify`, which routes every transport error to
`dispRebuild`. Both are wrong for a bundle. A bundle with a per-member `NFS4ERR_ACCES` is a
*successful* bundle with a per-member answer, and a bundle refused for its shape must not
touch the session.

`ReadDirBundle` therefore issues its COMPOUND directly (one `DoFastStrict`, no retry loop)
and classifies the outcome itself into exactly four buckets:

| Outcome | Detection | Response |
|---|---|---|
| **Full success** | COMPOUND status `NFS4_OK`, `len(results) == 2W+1` | deliver all *W* members |
| **Short but well-formed** | COMPOUND status ≠ OK, results end at a failing op | deliver members before the failure; report the failing member's status through `fn`; return `attempted = k+1` so the caller re-issues the rest |
| **Shape refusal (suspected)** | `errors.Is(err, ErrGarbageArgs)`, or `ErrFastDecodeDeclined`, or COMPOUND status is `NFS4ERR_REP_TOO_BIG` / `NFS4ERR_TOO_MANY_OPS` with zero or one result | **de-escalate** (§4.4). Return `attempted = 0` and a nil error. The caller re-issues every member through the ordinary `ReadDir`. **No session is rebuilt.** |
| **Genuine transport failure** | any other non-nil error from `Call` | return `attempted = 0` and the error. The caller falls back to per-directory `ReadDir`, whose `retryCall` will classify and, if warranted, rebuild — **once, on one directory, not once per bundle.** |

The fourth row is what keeps session recovery working at all. Rebuild is not removed from the
system; it is moved behind the width-1 path, which only ever sends a shape the array has
accepted for the whole life of this client. A rebuild therefore happens only when the
evidence for "the session is broken" is not contaminated by "the shape might be the problem".

**Mapping a short result array back to members.** With the COMPOUND laid out as
`SEQUENCE, (PUTFH, READDIR) × W`, result index *j ≥ 1* belongs to member `(j-1)/2`, and the
failing operation is the last result. So:

- last result is `OP_PUTFH` with a bad status → member `(j-1)/2` has a stale or bad
  filehandle. Report that status through `fn`; the caller's per-directory retry does the
  `resolvePath` recovery that `ReadDir`'s `recoverStale` closure already implements.
- last result is `OP_READDIR` with a bad status → member `(j-1)/2` got a real NFS answer.
  `NFS4ERR_ACCES` here is the common case and is exactly what `Prepass`'s fix-then-retry
  exists for.
- last result is `OP_SEQUENCE` with a bad status → not a bundle problem at all; this is the
  session layer's business and `session.do` has already reclaimed the slot
  (`session.go:976-991`). Return the error and let the width-1 path classify it.

**`NFS4ERR_TOOSMALL`, `NFS4ERR_NOT_SAME` and `NFS4ERR_REP_TOO_BIG` on a single member** are
delivered to `fn` as that member's error and the member is re-issued through the ordinary
`ReadDir`, which owns the grow/shrink/restart convergence loop (`client.go:726-765`) and the
`growLimit` reasoning that makes the two arms terminate as a pair. **That loop is not
reimplemented in the bundler.** Duplicating it is how the two paths would drift, and its
correctness argument is subtle enough that one copy is the right number.

### 4.4 De-escalation: monotone, sticky, and loud exactly once

```go
// Client
maxBundleWidth atomic.Int32   // starts at min(configured, (MaxOperations-1)/2)
```

`MaxReadDirBundle()` returns `int(c.maxBundleWidth.Load())`.

On a suspected shape refusal:

```
narrow to 1 immediately, permanently for the run, and log once.
```

Not "halve and retry". The reasoning is §1.1: **the client already knows the only width the
protocol permits.** It computed 7 from the negotiated `ca_maxoperations`, and it sized the
reply against the negotiated `ca_maxresponsesize`. If a bundle is refused anyway, the client's
model of the server is wrong in a way it cannot diagnose (§4's governing constraint), and
every intermediate width is equally unjustified. Probing down through 4 and 2 spends a
refused round trip per step per worker on a guess, and — critically — under 1024 workers those
probes are concurrent, so "one refusal per step" is really "up to 1024 refusals per step".
That is the shape of the storm even after the session rebuild is removed from it.

Cost of getting this wrong in the conservative direction: the run completes at today's
performance. Cost of getting it wrong in the aggressive direction: a refused round trip per
bundle for the rest of a 1.1M-object run, roughly doubling the READDIR term. The asymmetry
again decides it.

The single log line must name both possibilities, because the client genuinely does not know
which it is:

```
[readdir] server refused a 7-way READDIR bundle (rpc: server could not decode procedure
arguments). This is either a server that does not accept this COMPOUND shape or a bug in
this client's encoding of it -- FlashBlade reports both identically (RFC-Deviations.md
section 4). Continuing with one directory per COMPOUND for the rest of this run.
```

`PrepassResult.BundledReadDirs` / `SingleReadDirs` (§2.7) make the de-escalation visible in
the run summary, so a benchmark that quietly ran at width 1 cannot be reported as a width-7
result.

### 4.5 What this design deliberately does not do

- It does not add a disposition to `classify`. §2.5.
- It does not retry a refused bundle at the same width. Ever.
- It does not attempt to distinguish "shape refusal" from "client bug" by inspection. It
  cannot, so it narrows and says so.
- It does not let a bundle failure reach `rebuildEntry` on any path.

---

## 5. How `Prepass` groups siblings, and what it costs in memory

### 5.1 The grouping is already there

`walk.go:433-472` builds `childDirs []childDir` for the current directory before descending,
and `walk.go:479-490` iterates it spawning or inlining `process` per child. **The sibling
group is an existing data structure.** Bundling changes the iteration, not the collection:

```
for each chunk of up to W consecutive entries in childDirs:
    if W == 1 or ReadDirBundle == nil:
        today's spawn-or-inline per child
    else:
        one ReadDirBundle call covering the chunk;
        per member, run the rest of today's process() body for that child
```

Grouping is **within one parent only**. No cross-parent batching, no queue, no batching
timer. That choice is not laziness; it is what keeps the concurrency structure intact — see
§5.2 — and it is what makes the memory answer in §5.3 defensible.

The cost is that a directory with fewer than *W* subdirectories forms an under-full bundle.
On the bench tree (mean 5 entries per directory, p50 3, per `a3079b0`) most bundles will be
two or three wide, not seven. **This is the largest unquantified risk in the payoff estimate
and §9 makes it the first thing to measure**: the archived "~28% of all RPCs" assumed
width 7, and a mean fan-out of 5 entries — of which only some are directories — will not
deliver width 7 from single-parent grouping. Cross-parent batching would, at the cost of a
work queue, a batching delay, and the memory profile this design exists to avoid.

### 5.2 What it does to the token/inline-recursion structure

The current structure (`walk.go:380`, `479-490`): a bounded `tokens` channel caps goroutines
at `Workers`; when no token is free the caller recurses **inline** rather than blocking, so a
single goroutine can be many levels deep and work never stalls.

Bundling interacts with this in three ways, two benign and one that needs care:

1. **Benign.** The bundle's *READDIR* happens in the calling goroutine, before any spawn.
   That is a straight substitution for the READDIR each child would have done in its own
   goroutine, so the token pool's meaning is unchanged: a token still bounds one in-flight
   directory *subtree*, not one in-flight RPC.
2. **Benign.** Inline recursion still works. A chunk is read, then its members are spawned or
   inlined exactly as today.
3. **Needs care.** Today the child's READDIR runs *inside* the child's goroutine, so the
   READDIRs of *W* siblings overlap across *W* goroutines. After bundling they are one
   serial RPC in the parent's goroutine. That is the whole point — one round trip instead of
   *W* — but it means **the achieved RPC concurrency drops by up to a factor of W for the
   same `Workers`**. With `--workers 1024` (`main.go:99`, `defaultWorkers`) and 16
   connections × 128 slots = 2048 slots, the client is currently able to keep ~1024 RPCs in
   flight; after bundling the same 1024 workers issue ~1024/W times as many RPCs but each
   covers *W* directories, so *throughput* is flat-to-better while *slot occupancy* falls.
   **The measured 1.80x from the archived `--compare` arm was taken at `Connections: 1` in
   the probe (`readdirbundle_live_test.go:62`), which deliberately pins per-RPC cost and says
   nothing about how this interacts with 1024 workers.** §9 lists re-measuring at production
   concurrency as a gate.

   The mitigation, if measurement shows under-utilisation: raise `Workers` when bundling is
   on. That is a tuning change, not a design change, and it should not be made blind.

### 5.3 Memory: does grouping make the retention problem worse?

Yes, in one term, by a bounded factor, and no in another. Honestly:

**Unchanged.** `childDirs` is built today, in full, before descent
(`walk.go:434`, and the comment at `walk.go:428-432` explaining why). Bundling reads the same
slice in chunks. **Zero additional retained state for the grouping itself.** This is the
single best property of single-parent grouping and the reason not to build a cross-parent
queue: a queue would hold `childDir` records for directories whose parents' frames have
already exited, which is exactly the "workers × depth" retention that `db86931` was written
to remove.

**Worse: concurrent live dirent sets.** Today, `process` holds one directory's `[]Dirent`
(`walk.go:401`) and consumes it before descending. Under bundling, a chunk's members are
decoded in one reply, so up to *W* directories' entries are reachable at once in the calling
goroutine. The multiplier is the walk's structure: `workers × inline-depth × W` instead of
`workers × inline-depth`.

The callback API in §3 is what bounds this. With
`fn func(i int, entries []Dirent, err error)` and the documented "valid only for the duration
of the call" contract, `ReadDirBundle` decodes member *i*, hands it to `fn`, and `fn` runs the
existing per-entry loop (`walk.go:435-472`) to completion — emitting to `ch`, appending to
`childDirs` — before member *i+1* is decoded. **Only one member's `[]Dirent` is live at a
time.** What is held for the whole call is the reply buffer, which the entries alias
(`fastdecode.go:33-36`).

So the honest accounting, per in-flight bundle:

| Term | Today (W=1) | Bundled (W=7) | Notes |
|---|---|---|---|
| `childDir` records | unchanged | unchanged | already fully materialised |
| live `[]Dirent` | 1 directory | 1 directory | *only if the callback API is used* |
| reply buffer | 1 directory's reply | up to 7 directories' replies | allocated per record, sized to the actual reply (`rpc.go:147-151`) — **not** to `rd_maxcount` |

The reply-buffer term is the real cost and it is worth putting numbers on it, because a 7.2 GB
OOM is under investigation. `rpc.go:147-151` allocates the record buffer at the reply's
*actual* size, so on the bench-tree distribution (mean 5 entries, ~100–150 bytes per entry
with a filehandle and four attributes) a single-directory reply is well under 1 KiB and a
seven-way reply is a few KiB. At 1024 workers that is single-digit MB either way — noise
against 7.2 GB.

The ceiling is what deserves the attention: a seven-way bundle may legitimately return up to
7 × ~32 KiB ≈ 224 KiB (`RFC-Deviations.md`, "Not deviations": the array returns ~32 KiB
regardless of `rd_maxcount`), against ~32 KiB today. At 1024 concurrent workers that is a
worst case of ~230 MB of live reply buffers versus ~33 MB. **A 7× increase in a term that is
currently ~33 MB.** That is a real regression in exactly the dimension under investigation,
but it is 200 MB, not gigabytes, and it is bounded — which today's per-directory
accumulation in `ReadDir` (`client.go:782-785`, `out` grows across pages for the whole
directory) is not.

**The rule that keeps it bounded — evict any member that did not reach EOF.** A bundle member
whose reply has `eof == false` is a directory too large to finish in one page. Rather than
carrying its partial accumulation across bundle rounds — which would reintroduce *W*
concurrent unbounded accumulations, the worst possible outcome here — hand that member to the
ordinary single-directory `ReadDir` and drop it from the bundle. Consequences:

- bundling becomes explicitly a *small-directory* optimisation, which is where the payoff
  measured on the bench tree comes from (p50 of 3 entries);
- the bundle path's per-member retention is capped at one page;
- large directories keep exactly today's behaviour, including the `growLimit` convergence;
- and the "must return sorted" contract from §3 is satisfiable, because a member is only
  delivered to `fn` when it is complete.

**Interaction with the OOM investigation.** One second-order effect must be said plainly:
bundling speeds up the *producer* (enumeration) and does nothing for the *consumer* (apply,
irreducible per §0). `entryCh` is a bounded channel of `workers × 100 = 102,400` entries
(`main.go:556`), so it cannot itself grow — the walk blocks on a full channel instead. That
bound is what stops this from being a runaway. But it also means the visible effect of
bundling on a run that is already apply-bound may be nil, and it means any memory measurement
of this change must be taken with the apply path running, not on a `--dry-run` enumeration
sweep, or the reply-buffer term above will be the only thing it sees.

**Recommendation:** do not land this on top of an unresolved OOM. Land §4's stages (which are
net-neutral to net-positive on memory and independently valuable) first, and gate the
bundling stages on the 7.2 GB investigation reaching a diagnosis. If the OOM turns out to be
the reply-buffer or dirent term, this change makes it 7× worse and must be redesigned; if it
is elsewhere, this change adds ~200 MB at the worst case and can proceed.

---

## 6. Adaptive width

**Recommendation: fixed at `min(configured, (MaxOperations-1)/2)` — 7 on measured hardware —
with a monotone one-way de-escalation to 1 on refusal (§4.4). No size-driven adaptation.**

The case for adapting to directory size is that the win is a property of the directory-size
distribution. That is true of the *win*. It is not true of the *constraint*, and adaptation
is only worth its complexity if it relieves a constraint.

1. **The constraint it would relieve does not exist on this platform.** §1.2: seven members
   at the full 64 KiB `rd_maxcount` fit inside `ca_maxresponsesize` with 67 KiB to spare, and
   the array returns ~32 KiB per READDIR regardless of what is asked. There is no
   budget-splitting penalty to adapt away from.
2. **The information needed to adapt is not available in time.** Width must be chosen before
   the first READDIR of a batch, and directory size is only known after it. Any adaptation is
   therefore a prediction from siblings or from a running average — a heuristic with no
   measured payoff, added to a path whose failure mode is a partial-application storm.
3. **Width already adapts for free, downward.** Single-parent grouping (§5.1) means a
   directory with three subdirectories forms a three-wide bundle. Fan-out *is* the adaptation
   signal, it costs nothing, and it is exact rather than predicted.
4. **The EOF-eviction rule (§5.3) is the size adaptation, expressed as a policy rather than a
   width.** A directory too large for one page leaves the bundle after one round trip. That
   is one wasted member slot, not a wrong width for the whole run.
5. **§4's governing constraint punishes cleverness.** Every additional width the client can
   emit is another shape whose refusal it cannot diagnose. Two shapes (W and 1) is the
   smallest set that delivers the win.

What *should* be configurable: `--readdir-bundle N`, so a benchmark can sweep 1/2/4/7 without
a rebuild and so an operator has an off switch. Configuration is not adaptation.

One thing genuinely worth adapting, and deliberately deferred: nothing here changes
`rd_maxcount` from its current 64 KiB. `RFC-Deviations.md` records that raising it past
~32 KiB achieves nothing on this array; *lowering* it to ~32 KiB would shrink the request and
the worst-case reply buffer without losing anything measured. That is a separate, smaller
change with its own measurement, and folding it in here would confound the bundling result.

---

## 7. Test strategy

### 7.1 Testable without hardware — but only after the fake stops flattering us

The archived tag's blocker #2 is the governing lesson: *the fake modelled the mutation cap but
not the GETATTR cap, which is why a broken thing looked graceful in tests.* The generalisation
is that **a fake that models only the limits a feature respects will pass every test the
feature can fail.** So the fake work comes first, and it is not optional.

Fake-server additions required, in `internal/nfs41/fakeserver_test.go`:

| Capability | Why | Where |
|---|---|---|
| `ca_maxoperations` enforcement, refusing over-limit COMPOUNDs **as a well-formed RPC reply carrying `GARBAGE_ARGS`** | §1.5: the fake currently has no operation-count check at all, and drops the reply rather than answering. Without this, §4.3's shape-refusal row is untested. | `runCompound` prologue; and a new arm in the fake's RPC layer that can emit an accepted reply with a non-`SUCCESS` accept status |
| A configurable per-operation-class cap, seeded with the measured GETATTR cap of 4 | Pays off the archived blocker directly and makes the cap a knob rather than a constant, so READDIR's *absence* from the cap is an assertion rather than an omission | alongside `isForwardRequiredOp` |
| `ca_maxresponsesize` accounting across the whole COMPOUND | So a bundle that legitimately overruns produces `NFS4ERR_REP_TOO_BIG` and §4.3's REP_TOO_BIG row is reachable | `runReadDir`, summed in `compoundState` |
| A knob to make an arbitrary member fail with an arbitrary status | The partial-completion path (§1.6) is the most likely place for an off-by-one in member mapping | existing injection machinery |
| A "large directory" fixture whose first page is not EOF | Exercises §5.3's eviction rule | existing tree fixtures |

With those in place, the following are covered on the fake:

- **Member mapping.** A W-wide bundle where member *k* fails at PUTFH, and one where it fails
  at READDIR, for every *k* in 0…W-1. Assert: members < *k* delivered, member *k* reported
  with the right status, `attempted == k+1`, members > *k* not delivered and not lost.
- **Width-1 equivalence.** The same tree walked at width 1 and width 7 must produce
  byte-identical entry streams (after the per-directory sort). This is the single most
  valuable test in the set: it catches a dropped member, a duplicated member, a lost
  continuation, and a mis-sorted page in one assertion.
- **De-escalation.** Fake refuses a 7-wide COMPOUND with GARBAGE_ARGS. Assert: the run
  completes with every directory enumerated, `MaxReadDirBundle()` is 1 afterwards, the log
  line appears **exactly once**, and — the assertion that would have caught the last attempt
  — `Session.Rebuild` was never called and the fake's `sessionCount` never increased.
- **Slot hygiene after a refusal.** Refuse one COMPOUND with GARBAGE_ARGS, then issue a
  normal call on the same slot. Assert no `SEQ_MISORDERED`. This is the fake-side half of
  §4.1; the hardware half is §7.3.
- **Kill-switch interaction.** With `fastDecodeEnabled = false`, assert
  `MaxReadDirBundle() == 1` and that `ParseCompound` is never handed a multi-READDIR reply.
- **EOF eviction.** A large-directory fixture in a bundle: assert it is delivered exactly
  once, complete and sorted, and that its continuations went through the single-directory
  path.
- **Overhead arithmetic.** Property test: for every width 1…7, the computed per-member
  `rd_maxcount` times the width, plus the exact per-COMPOUND and per-member reply overheads,
  is ≤ `MaxResponseSize`; and at width 1 the value equals today's constant exactly
  (guarding `TestReadDirLeavesHeadroomForCompoundOverhead`).
- **Walk-level.** `Prepass` against a fake-backed transport, at widths 1 and 7, with and
  without `--one-filesystem`, asserting identical `PrepassResult` counters and identical
  entry sets.

### 7.2 What the fake fundamentally cannot answer

- **Whether FlashBlade still accepts seven READDIRs in one COMPOUND** on the release under
  test. The fake accepts whatever it is told to accept; §3, §6 of `RFC-Deviations.md` are
  measurements with a date on them.
- **Whether a refusal really arrives as GARBAGE_ARGS** rather than as something else on a
  newer Purity.
- **Whether reclaiming the slot after GARBAGE_ARGS is right** (§4.1). This is a claim about
  server-side sequence-ID state and only the server can settle it.
- **Any timing claim whatsoever.** Including the one this whole plan rests on.

### 7.3 Needs `PERMISSIONRESET_TEST_SERVER`

New live tests, all read-only (READDIR and one deliberately malformed COMPOUND), skipping
without the environment, following the existing pattern in `bounds_live_test.go` and
`readdirbundle_live_test.go`:

1. **`TestGarbageArgsLeavesTheSlotUsable`** — the gate on §4.1. Send a COMPOUND with 17
   operations (over `ca_maxoperations`) on a known slot; assert the reply is
   `ErrGarbageArgs`; then send a normal `PUTFH+GETATTR` on the *same slot* with the sequence
   ID reclaimed, and assert `NFS4_OK` rather than `SEQ_MISORDERED`. Run the mirror arm with
   `release` semantics to confirm it *does* produce `SEQ_MISORDERED` — a test that only
   proves the new behaviour works, without proving the old one was broken, is not evidence.
2. **`TestBundleWidthStillAccepted`** — re-run the width probe from `TestBundleBounds` for
   READDIR only, on the current release, and fail loudly if width 7 is no longer accepted.
   Cheap, and it is the thing that will silently change under a Purity upgrade.
3. **`TestReadDirBundleTiming` (existing, `readdirbundle_live_test.go:50`)** — re-run against
   the *implementation* rather than the probe, at production `Connections` rather than 1
   (§5.2), and on both the bench tree and a tree with large directories, so the
   size-distribution dependence is visible rather than assumed.
4. **`TestReadDirFollowedByOp` (existing, `readdirbundle_live_test.go:358`)** — keep as a
   regression witness for the decoder bug, and extend it with an arm that asserts
   `DoFastStrict` returns `ErrFastDecodeDeclined` rather than desyncing.
5. **End-to-end payoff** — §9's gate measurements. Not a `go test`; a benchmark run.

---

## 8. Staged commit sequence

Each stage builds, passes `go test ./...`, and leaves the tree shippable. Stages 1–3 are
worth landing **even if the measurement in §9 says do not build the feature**, because each
fixes a real defect that exists today.

| # | Commit | Contents | Independently valuable? |
|---|---|---|---|
| 1 | Give an RPC argument refusal a name the client can test for | `ErrGarbageArgs` sentinel in `rpc.go`, wrapped at the `GARBAGE_ARGS` arm; unit test. No behaviour change. | Yes — today no caller can tell a shape refusal from a dead socket |
| 2 | Reclaim the slot when the server never decoded the arguments | The `session.do` `reclaim`/`release` change from §4.1, plus the fake-server GARBAGE_ARGS reply arm and the slot-hygiene test, plus the live test in §7.3.1 | **Yes — this is a live bug.** One over-limit COMPOUND today poisons a slot into a spurious session rebuild |
| 3 | Teach the fake server the limits it was flattering us about | `ca_maxoperations` enforcement as a GARBAGE_ARGS reply; the configurable per-class cap seeded with GETATTR=4; whole-COMPOUND `ca_maxresponsesize` accounting. **Existing tests that pass only because these were missing must be fixed here, not later.** | **Yes — this is the archived blocker #2**, and it retroactively strengthens every existing COMPOUND test |
| 4 | Let the fast decoder decline instead of falling through to a decoder that desyncs | `ErrFastDecodeDeclined`, `decodeSessionReply` flag, `Session.DoFastStrict`. No caller uses it yet. Test: force a decline, assert `ParseCompound` is not reached. | Yes — closes the route in §1.3 before anything can take it |
| 5 | Decode a READDIR result at any position in the reply | `readDirReply.pageAt(index, path)` and `readDirResult(results, index, path)` replacing the `len(...) != 3` / `[2]` hardcoding; `ReadDir` passes 2 and is otherwise untouched. Pure refactor, no new behaviour. | Neutral, but it is the smallest reviewable unit of the mechanical change |
| 6 | Split the READDIR reply-overhead constant into per-COMPOUND and per-member terms | §2.6. `budget(1)` must equal today's value exactly; `TestReadDirLeavesHeadroomForCompoundOverhead` unchanged and still passing is the proof | Neutral |
| 7 | Add the optional batched-enumeration interface | `transport.BundleReadDirer` with its doc comment. No implementations, no callers. Compiles alone. | Neutral; keeps the interface debate in its own review |
| 8 | Enumerate several directories in one COMPOUND | `Client.ReadDirBundle`, `maxBundleWidth`, the four-bucket classification of §4.3, de-escalation of §4.4, EOF eviction of §5.3. Fake-server tests from §7.1 except the walk-level ones. **Feature is unreachable from the CLI at the end of this stage** — nothing calls it | No, but it is inert |
| 9 | Group siblings in the pre-pass when the transport can batch | `PrepassOptions.ReadDirBundle`, the chunked descent loop, `PrepassResult` counters, walk-level equivalence tests | No |
| 10 | Wire `--readdir-bundle` and default it off | Flag, banner line, type assertion in `main.go`. **Default 1.** | No |
| 11 | Turn bundling on by default, or delete stages 7–10 | Gated on §9's measurements. This commit either changes one default and records the numbers in `RFC-Deviations.md`, or reverts the feature and leaves stages 1–6 in place | — |

Stage 11 is deliberately a decision point with a written outcome either way. The archived
spike's lesson is that a parked feature with no recorded verdict gets re-proposed.

---

## 9. What would make this not worth doing

The honest position: **the measured payoff is from a configuration that is not the one being
optimised today, on a different array, and it may not transfer.**

### 9.1 Where the number came from

- The 1.80x (22.9s → 12.7s) in the archived tag is **FlashBlade `--compare` with 4-way GETACL
  bundling** on an **S200**. That configuration does not exist in shipped code: the mutation
  and GETATTR bundling it depended on was parked.
- The "READDIR is 32% of RPCs / 45% of the worker pool / 7-way removes ~28% of all RPCs"
  figures from `a3079b0` are explicitly *conditional on that same 4-way GETACL bundling*.
  The commit says so: READDIR was 32% "rather than the ~11% the plan assumed, **because
  bundling the ACL side by 4x shrank the other term**."
- **Without GETACL bundling, READDIR is back near 11% of RPCs, and a 7-way bundle removes
  roughly 6/7 of 11% ≈ 9% of RPCs — not 28%.** That is the single most important sentence in
  this document. The headline number is not available in the current build, and recovering it
  means also building 4-way GETACL bundling, which is a second feature with its own version
  of every problem in §4.

  The 11% is the *plan's assumption*, not a measurement, so it deserves a check. The
  arithmetic corroborates it: with READDIR at fraction *r* of RPCs and the rest at *1−r*,
  bundling the rest 4-way gives a new READDIR share of `r / (r + (1−r)/4)`. At `r = 0.11`
  that is 33%, against the 32% actually measured. The two figures are mutually consistent,
  which is decent evidence that the unbundled share really is near 11% and that the 32% is an
  artefact of shrinking the denominator rather than a property of the enumeration.
- The current 211K ops/sec sweep is the **apply path on an S500R1**. Per §0 the mutation term
  there is irreducible at one round trip per object. Enumeration is a smaller share of a run
  that is dominated by a term this change cannot touch, and Amdahl applies without mercy.

### 9.2 What must be measured before stage 11

Ordered so the cheapest disqualifier runs first.

1. **Directory fan-out on the target tree, before anything else.** Single-parent grouping
   (§5.1) yields a mean bundle width equal to the mean number of *subdirectories* per
   directory, capped at 7 — not the mean number of *entries*. The bench tree's mean of 5
   entries and p50 of 3 is an entry count; the subdirectory count is smaller. **If the mean
   subdirectory fan-out is below about 3, the achieved width is below 3, the RPC saving is
   below 67% of the READDIR term, and everything downstream is marginal.** This is a
   read-only histogram over an existing tree and can be run today, before a line is written.
2. **READDIR's share of RPCs in the shipped configuration**, on the S500R1, in the apply path,
   at production `--workers`. Measure it; do not carry the 32% forward. If it is ~11%, the
   ceiling on the whole change is ~9% of RPCs.
3. **Wall-clock, not RPC count.** The FlashArray arms in the archived tag are the cautionary
   tale: client CPU halved with **no wall-clock change**, because the array was
   server-bound. If the S500R1 apply path is server-bound, removing client-side round trips
   from the enumeration term will show the same signature — and the same non-result. Report
   client CPU alongside wall clock precisely so this signature is recognisable.
4. **The concurrency interaction of §5.2.** Bundling reduces achieved RPC concurrency by up
   to *W* at fixed `Workers`. Measure at production `Connections` and `Workers`, not at
   `Connections: 1` as the probe did. It is entirely possible that at 1024 workers the client
   is already saturating the array's metadata path and bundling buys nothing but lower CPU.
5. **Memory, with the apply path running** (§5.3). Compare peak RSS at width 1 and width 7
   using the existing `--memprofile` / `--memprofile-interval` instrumentation
   (`main.go:139-140`).

### 9.3 The kill criteria, stated in advance

Do not proceed past stage 10 if **any** of these holds:

- **Mean achieved bundle width < 3** on representative trees. The complexity in §4 is not
  worth a 50% reduction in a 10% term.
- **End-to-end wall clock improves by less than 5%** on the S500R1 apply path at production
  concurrency, even if RPC count falls as predicted. Client CPU reduction alone is not a
  result; the archived FlashArray arms already bought that and it changed nothing.
- **Peak RSS rises materially** while the 7.2 GB OOM is unresolved (§5.3).
- **Width 7 is no longer accepted** by the Purity release under test (§7.3.2). The whole
  design rests on a measurement from 4.8.0.
- **The GARBAGE_ARGS slot behaviour in §4.1 cannot be confirmed on hardware.** Without it,
  every shape refusal still poisons a slot, and §4.4's de-escalation cannot be made safe.

### 9.4 The case for doing stages 1–6 regardless

Even under every kill criterion, stages 1–3 fix a live defect (a spurious session rebuild
after any over-limit COMPOUND), stage 3 pays off the archived blocker that made a broken thing
look graceful, and stage 4 closes a route from a truncated reply into a decoder known to
desync. Those are worth landing on their own merits, and they are the stages that make the
system honest about what it can and cannot tell apart.

### 9.5 The one thing that would clearly make it worth doing

If `--compare` (the GETACL read path) becomes a first-class shipped configuration — a
verification sweep over a large tree — then READDIR's share rises toward the measured 32%,
the 1.80x arm becomes the relevant one, and this change goes from marginal to the largest
remaining lever on that path. **The decision to build READDIR bundling is really a decision
about whether the `--compare` path matters**, and that question should be answered by whoever
owns the roadmap before this is scheduled, not inferred from a benchmark.

---

## 10. Open questions

1. What is the mean subdirectory fan-out on the trees this tool actually runs against?
   §9.2.1 — cheapest disqualifier and answerable today.
2. Does the 7.2 GB OOM on `userspace-memory-optimization` implicate the dirent or reply-buffer
   term? If yes, §5.3's 7× ceiling is disqualifying and the design needs revisiting.
3. Should `rd_maxcount` drop from 64 KiB to ~32 KiB independently (§6)? Separate change,
   separate measurement, would reduce this plan's worst-case memory by half.
4. Is `--compare` a shipped configuration or a diagnostic? §9.5 — this is the question that
   actually decides the feature.
