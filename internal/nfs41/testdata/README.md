# Golden NFSv4.1 wire bytes

Captured traffic between a Linux NFSv4.1 client and a **10-blade FlashBlade S500R1** at
`192.0.2.50`, taken on `notcorp` by Robert Cantu. These are the bytes a real server
actually accepted, which is the entire point: a round-trip test against our own encoder
passes happily when the encoder and the decoder are wrong in the same direction, and the
positional `fattr4` unpack in `ops.go` invites exactly that failure.

## Files

| File | Bytes | What it is |
| --- | --- | --- |
| `nfs41-golden.pcap` | 29432 | The raw capture, 186 packets. The source of truth; keep it. |
| `v41probe-s500.log` | — | `v41probe.py` session negotiation output, human-readable. |
| `exchange_id_call.bin` | 128 | One `EXCHANGE_ID` COMPOUND call, from the `v41probe.py` run. |
| `exchange_id_reply.bin` | 112 | The matching reply. |
| `setattr_acl_call.bin` | 232 | `SEQUENCE` + `PUTFH` + `SETATTR` writing an NFSv4 ACL. |

Each `.bin` is **one complete RPC record including its 4-byte record marker**, exactly as
it appeared on the wire — not a TCP segment, and not a payload with the framing stripped.
That distinction is load-bearing; see "Framing" below.

## Which tests consume these

- `TestSetACLCompoundMatchesCapturedBytes` extracts the `SETATTR` operation from
  `setattr_acl_call.bin` and compares it byte-for-byte against `OpSetACL`'s output.
- `TestParseCompoundOnCapturedExchangeIDReply` strips the RPC reply header from
  `exchange_id_reply.bin` and parses the COMPOUND result.

Both skip if the files are absent. **Never fabricate these bytes to make the tests run** —
a golden test built from our own encoder's output is worse than no test, because it reports
confidence it has not earned.

## What the capture settled

**The `attrlist4` single-wrap, confirmed.** The captured `SETATTR` op decodes as:

```
00000022                             op 34 = OP_SETATTR
00000000 00000000 00000000 00000000  stateid4: 16 zero bytes, the anonymous stateid
00000001                             attrmask: one word
00001000                             bit 12 = FATTR4_ACL
0000001c                             attrlist4 opaque length = 28   <- ONE length
00000001                             fattr4_acl ACE count = 1       <- a COUNT, not a length
00000000                             acetype4  = ACE4_ACCESS_ALLOWED
00000000                             aceflag4  = 0
0016019f                             acemask4
00000006                             who length = 6
4f574e455240 0000                    "OWNER@" + 2 bytes of padding
```

Earlier revisions of the plan instructed wrapping each attribute value in its own XDR
opaque. That would have produced a second length word here and a COMPOUND every unit test
in the package accepts and a real FlashBlade rejects with `NFS4ERR_BADXDR`. The capture is
what turns that from a reasoned argument into a settled one.

The anonymous stateid is confirmed too: 16 zero bytes, accepted by the server for a
`SETATTR` of `FATTR4_ACL`. That is what lets this client skip `OPEN` entirely.

**`eir_server_impl_id` is not populated.** `v41probe-s500.log` shows `server_owner` and
`server_scope` are both the literal string `192.0.2.50` — the IP address — and there is no
impl id at all. So **no product identification is available from `EXCHANGE_ID`**, which is
why the server gate in `client.go` uses a `FATTR4_MAXFILESIZE` heuristic instead. That is a
measured fact now, not an assumption. A client must treat a missing impl id as normal.

**Granted channel attributes**, for the `CREATE_SESSION` clamp:

| Attribute | Value |
| --- | --- |
| `ca_maxrequestsize` | 526336 |
| `ca_maxresponsesize` | 526336 |
| `ca_maxresponsesize_cached` | 1104 |
| `ca_maxoperations` | 16 |
| `ca_maxrequests` | 128 |

All well inside `rpc.go`'s 8 MiB `maxRecordSize`. 16 ops per COMPOUND minus one for
`SEQUENCE` leaves 15 usable, i.e. 7 `PUTFH`+`SETATTR` pairs per round trip.

## Framing

The capture is unusually clean and the extraction depends on it: every one of the 32
directional TCP streams reassembled with **no gaps, no retransmits, and zero trailing
bytes**, and every RPC record was a single final fragment. Nothing needed reassembly across
fragments.

Do not assume that of the next capture. `tshark -e tcp.payload` emits a TCP *segment*, and
servers routinely coalesce two RPC records into one segment or split one across two. Both
`compoundPayload` and `stripRPCReplyHeader` require exactly one record, and
`ParseCompound` rejects trailing bytes. `compoundPayload` reports a framing mismatch
explicitly rather than falling through to a confusing "COMPOUND minor version is
`<garbage>`" — but the fix for that error is to re-extract one record per file, not to
relax the check.

## Regenerating the .bin files

`extract_golden.py` reads the pcap and writes the three `.bin` files. It has no
dependencies beyond the standard library — this host had neither `tshark` nor `scapy`, and
hand-rolling the parse turned out to be the right call anyway, since a tool that
"helpfully" reframes a coalesced segment would silently violate the assumptions above.

```
python3 extract_golden.py nfs41-golden.pcap .
```

It reassembles each TCP stream by sequence number, splits it into RPC records by the record
marker, decodes each COMPOUND's operation array, and selects:

- the only COMPOUND in the capture containing a `SETATTR`,
- the `EXCHANGE_ID` call from the `v41probe.py` connection, and its reply matched by xid.

It fails loudly on a gap, an overlap it cannot resolve, or a record it cannot frame, rather
than emitting a partial file.

## `readdir_reply.bin` and `readdir_dense.bin` — captured live, not from the pcap

These two are not extracted by `extract_golden.py` and are not in the pcap. They were
written directly by `TestCaptureReadDirReply` (`capturereaddir_live_test.go`), which issues
`PUTFH` + `READDIR` against a real array and writes the reply body verbatim. They exist
because `fastdecode.go`'s hand-written decoder has to be validated and benchmarked against
bytes a FlashBlade actually sent.

| File | Bytes | Entries | Source |
|---|---:|---:|---|
| `readdir_reply.bin` | 808 | 8 | `198.51.100.54:2049` `/bench-perms/bench-s200`, 2026-08-21 |
| `readdir_dense.bin` | 32,700 | 333 | `198.51.100.54:2049` `/bench-perms/bench-s200/engineering`, same run |

S200, Purity//FB 4.8.0. Both are the reply to a two-operation COMPOUND requesting
`FATTR4_TYPE`, `FATTR4_MODE`, `FATTR4_FILEHANDLE` and `FATTR4_FSID` per entry — the same
four `ReadDir` asks for, so the decoders are measured on the shape the walk really meets.

Two properties worth stating, because both were design decisions rather than accidents:

- **No `SEQUENCE`, so no session state.** The capture COMPOUND is deliberately unsessioned,
  which is why these files carry no session identifier, no slot number and no sequence id.
  They are safe to commit and cannot go stale against a server's session state.
- **Both are needed.** The dense one is the benchmark's input, since 333 entries is what
  makes per-entry decode cost visible; the small one is an 8-entry `eof=true` reply, a
  different terminal shape. A decoder bug in the end-of-list handling shows up in the small
  file and can hide in the dense one.

Regenerate either with:

```
PERMISSIONRESET_TEST_SERVER=host:2049 PERMISSIONRESET_TEST_EXPORT=/export \
PERMISSIONRESET_CAPTURE_DIR=/export/some/dir PERMISSIONRESET_CAPTURE_OUT=./readdir_reply.bin \
  go test ./internal/nfs41/ -run TestCaptureReadDirReply -v
```

The capture test parses what it captured before writing it and refuses to save a reply that
does not decode or whose status is not `NFS4_OK`.
