# internal/nfs41

Userspace NFSv4.1 client implementing `transport.Transport`. Talks RPC/XDR
directly to a FlashBlade data VIP over TCP — no kernel mount, no cgo, no
subprocess.

## Client lifecycle

`New(ctx, Config)` → TCP dial → `ExchangeID` → `NewSession` → server gate
(max-file-size + impl_id check) → resolve export/target → open remaining pool
connections. Each pool entry gets its own EXCHANGE_ID (FlashBlade allows one
session per client ID — measured, not spec-derived; see `trunkprobe_live_test.go`).

`Close()` is once-only: destroys each session best-effort, closes each TCP
connection, returns same error to all concurrent callers.

## Key types

- **`Client`** (`client.go`): pool of `poolEntry`, filehandle cache, retry
  policy, server gate. Implements `transport.Transport`.
- **`poolEntry`**: one `Conn` + `Session` + generation counter. `lifecycle`
  RWMutex serializes rebuild against operations. Operations on different entries
  are fully independent.
- **`Session`** (`session.go`): one NFSv4.1 session — session ID, slot table,
  channel attributes. `Do()` and `DoFast()` acquire a slot, prepend SEQUENCE,
  send COMPOUND, validate reply, release slot.
- **`slotTable`** (`session.go`): exclusive-ownership slots with condition-wait
  via channel close. `acquire()` increments seqID; `release()` marks available;
  `reclaim()` rolls back seqID on cancelled calls.
- **`Conn`** (`rpc.go`): one TCP connection with record-mark framing, xid
  tracking, concurrent Call(). Reader goroutine dispatches replies by xid.
- **`RetryPolicy`** / **`disposition`** (`errors.go`): three buckets — retry
  (transient), rebuild (session state), fail (real answer). Every operation is
  idempotent, so retry is always safe.

## COMPOUND building

`ops.go` has helper constructors: `OpPutFH`, `OpGetAttr`, `OpSetAttr`,
`OpSetACL`, `OpReadDir`, `OpSequence`, `OpLookup`, `OpGetFH`, `OpPutRootFH`.

`BuildCompound(tag, ops)` tries `fastencode.go` first, falls back to generated
XDR. `ParseCompound(b)` is generated-only (cold path).

Attribute bitmap: `attributeBitmap(bits)` packs RFC 7530 bitmap words.
`EncodeAttrList` / `DecodeAttrList` handle the ordered-concatenation wire format
with no per-attribute delimiters.

## Fast encode/decode

**Why:** generated XDR decoder allocates per 32-bit field via `xdrReadN` →
`bytes.Buffer`. Profile showed 37% in malloc, 22% in xdrReadN. Binary was GC-bound,
not IO-bound.

**`fastdecode.go`**: hand-written cursor-based decoder. Returns `[]fastResult`
aliasing the reply buffer (zero-copy). Handles SEQUENCE, PUTFH, GETATTR,
SETATTR, READDIR. Declines unknown ops → generated fallback. 30x faster on
READDIR, 19x less allocation.

**`fastencode.go`**: hand-written encoder. Handles PUTFH, PUTROOTFH, LOOKUP,
GETFH, GETATTR, SETATTR, READDIR, SEQUENCE. Declines unknown → generated
fallback. Differential test proves byte-identical output.

Kill switches: `fastDecodeEnabled`, `fastEncodeEnabled` (vars, not consts, so
tests can force the generated path).

## Dual decode path

`Session.DoFast()` returns `(fast []fastResult, gen []xdr.Nfs_resop4)` — exactly
one is non-nil. Callers must handle both. `readDirReply` wraps this; `page()`
hides which decoder ran.

`callRefFast` is the per-object call path (SetACL, GetACL, Chmod, Stat). It
uses `DoFast` and handles both result shapes.

`sessionDo` uses `Do` (generated only) — used by `resolveComponents` and
`GetACLBatch`.

## Retry and recovery (`retryCall`)

Generic over result type (Go 1.21 type parameter). Three recovery paths:

1. **Stale filehandle** (`NFS4ERR_STALE`, `NFS4ERR_BADHANDLE`): caller-supplied
   `recoverStale` re-resolves the path via LOOKUP. Result cached in `fhCache`.
2. **Session fault** (`BADSESSION`, `DEADSESSION`, `BADSLOT`,
   `SEQ_MISORDERED`): `rebuildEntry` — Rebuild session on same connection; if
   connection dead or clientid stale, replace entire entry.
3. **Transient** (`DELAY`, `GRACE`, `RESOURCE`, `RETRY_UNCACHED_REP`):
   exponential backoff, retry same call.

Generation check prevents two failed callers from rebuilding the same entry
twice. Budget caps total attempts.

## ProbeTarget (disposable probes, PS-01/#70)

`ProbeTarget` used to return the real target directory (falling back to the export root when the
path did not resolve) because this client implements no OPEN. It now uses the `Mkdir`/`Remove` it
already has to create a disposable probe directory under the resolved target (or export root) with
a collision-safe name (`probeName`, `crypto/rand`-backed, `.permissionreset-probe-<hex>`), and removes it
via the returned cleanup. Any create failure other than a name collision (`IsExist`) fails the probe
closed with an actionable error — it never substitutes a live, existing object; a restored NFS ACL
cannot reconstruct SMB inheritance metadata lost in translation. The collision-retry/fail-closed
policy itself (`probeTargetWith`) takes injectable `resolveDir`/`mkdir`/`remove`/`newName` funcs so
it is unit-tested (`probetarget_test.go`) without a live or fake RPC server.

## GetACLBatch and the 4×GETATTR cap

`maxGetAttrsPerCompound = 4` — FlashBlade hard limit, confirmed on S200 and
S500R1. `GetACLBatch(refs)` resolves all filehandles, then chunks into groups of
4, building `N×(PUTFH+GETATTR(ACL))` COMPOUNDs. Uses `sessionDo` (generated
path, not fast), `retryCallOn` for session recovery but no per-file stale-FH
recovery (batch fails as a unit).

## ReadDir

Cookie-chased enumeration with three inline recoveries: `NFS4ERR_TOOSMALL`
(double rd_maxcount), `NFS4ERR_REP_TOO_BIG` (halve rd_maxcount),
`NFS4ERR_NOT_SAME` (restart from cookie 0). `growLimit` tracks the anti-cycle
bound between TOOSMALL and REP_TOO_BIG. Results sorted by name.

READDIR requests `fattr4Type`, `fattr4Mode`, `fattr4Filehandle`, `fattr4FSID`
per entry — filehandle removes LOOKUP from steady state.

## Filehandle cache

`fhCache` is NOT a whole-tree index. Steady state holds export root + target
root only. Stale-FH recovery adds entries; capped at 4096, dropped wholesale on
overflow (roots preserved). Callers pass `Ref.FH` from READDIR — no cache
needed per object.

## Path resolution

`resolvePath` chains from export root FH via PUTFH+LOOKUP+GETFH. Falls back to
per-component resolution from PUTROOTFH when export root is unknown (init only).
FlashBlade refuses cross-filesystem LOOKUP in one COMPOUND — this is measured
behavior, not spec.

## Server gate

Two checks at construction: `isFlashArrayIdentity` (refuses FA by impl_id name)
then `pureMaxFileSizes` table (FATTR4_MAXFILESIZE gate). `AllowNonPureServer`
overrides both. Platform recorded as `PlatformFlashBlade` or `PlatformFlashArray`.

## Test patterns

**Offline tests** (run in CI, no network):
- `fakeserver_test.go`: in-process NFSv4.1 server. Implements EXCHANGE_ID,
  CREATE_SESSION, SEQUENCE, READDIR, SETATTR, PUTFH, LOOKUP, GETATTR, GETFH.
  Injects faults (DELAY, BADSESSION, TCP reset, TOOSMALL, stale FH).
- `client_test.go` (37 tests): retry, recovery, ReadDir edge cases, Chmod, pool.
- `fastencode_test.go`, `fastdecode_test.go`: differential tests against
  generated encoder/decoder. Byte-identical required.
- `errors_test.go`: disposition classification table.
- `ops_test.go`: EncodeAttrList/DecodeAttrList round-trip.

**Live tests** (`*_live_test.go`, gated by env vars):
- `PERMISSIONRESET_TEST_SERVER`, `PERMISSIONRESET_TEST_EXPORT`, `PERMISSIONRESET_TRAVERSE_DIR`
- Protocol probes: COMPOUND shape limits, slot grants, trunk refusal, max file
  size, GETATTR cap, READDIR bundling, CREATE w/ ACL, cached-size.
- Results recorded in `RFC-Deviations.md` and `COMPATIBILITY.md`.

## Gotchas and invariants

- Every operation is idempotent (SETATTR, GETATTR, READDIR). No OPEN, LOCK, or
  delegations. SEQUENCE.cachethis = false always.
- Reply buffer aliasing: fast-path results alias the connection read buffer.
  Clone before retaining. `ReadDir` clones via `cloneRef`; `getAttributes`
  copies values out of the map.
- One session per client ID on FlashBlade. Pool entries are independent clients,
  not sessions on a shared registration.
- `"." / ".."` entries from READDIR are skipped before cookie bookkeeping —
  os.ReadDir never returns them, so kernel path is structurally immune.
- `fhCache` must not be seeded by READDIR (was the cause of O(tree) memory).
