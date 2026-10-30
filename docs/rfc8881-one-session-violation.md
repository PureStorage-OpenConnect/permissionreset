# RFC 8881 §2.10.5 violation: one session per client ID on FlashBlade

## Summary

FlashBlade permits exactly one NFSv4.1 session per client ID. A second
`CREATE_SESSION` on an existing client ID is refused with `NFS4ERR_INVAL`,
regardless of whether it arrives on the same connection or a different one.
This contradicts a MUST-level requirement in RFC 8881.

## Affected product

- **Platform:** FlashBlade
- **Measured on:** S200 and S500R1, Purity//FB 4.8.0
- **Not affected:** FlashArray (Purity//FA 6.10.6 accepts multiple sessions per
  client ID)

## RFC requirement

RFC 8881 §2.10.5 (Session Trunking and Client ID Trunking):

> Servers MUST support client ID trunking for specific network addresses if
> they support session trunking for those same addresses.

FlashBlade supports session trunking — the Linux kernel NFS client mounts it
daily with `nconnect=16`, multiplexing RPCs across 16 connections on one
session. Client ID trunking, the ability to create additional sessions on an
already-established client ID, is a prerequisite that the RFC requires the
server to support whenever session trunking is available.

## Observed behaviour

A second `CREATE_SESSION` for a client ID that already has a session returns
`NFS4ERR_INVAL` (22). The error code is uninformative — §18.36.3 defines
`NFS4ERR_INVAL` for attribute-based causes (channel attributes out of range),
not for a session-count limit, and no NFS error code exists for "too many
sessions per client ID" because the RFC does not anticipate that limit.

## Reproduction

Four diagnostic arms, measured 2026-08-21 against an S200 (Purity//FB
4.8.0). Test code: `internal/nfs41/trunkprobe_live_test.go`,
`TestClientIDTrunkingProbe`.

```
PERMISSIONRESET_TEST_SERVER=<host>:2049 \
  go test ./internal/nfs41/ -run TestClientIDTrunkingProbe -v
```

### Arm A — one EXCHANGE_ID, CREATE_SESSION on a second connection

1. Dial two TCP connections to the same data VIP.
2. `EXCHANGE_ID` on connection 1, obtaining client ID C.
3. `CREATE_SESSION` on connection 1 for client ID C — succeeds.
4. `CREATE_SESSION` on connection 2 for client ID C — **`NFS4ERR_INVAL`**.

Reproduces the failure a connection-pooling client hits when it tries to add a
session on a new connection for an existing client ID.

### Arm B — EXCHANGE_ID per connection, same owner and verifier

1. Dial two TCP connections.
2. `EXCHANGE_ID` on each with the same `co_ownerid` and `co_verifier`.
3. Both return the **same client ID** — confirming the array advertises client
   ID trunking per §18.35.4.
4. `CREATE_SESSION` on connection 1 — succeeds.
5. `CREATE_SESSION` on connection 2 — **`NFS4ERR_INVAL`**.

The array hands back the same client ID for the same owner (advertising
trunking) and then refuses the session that trunking exists to support.

### Arm C — both CREATE_SESSIONs on the same connection

1. Dial one TCP connection.
2. `EXCHANGE_ID`, obtaining client ID C.
3. `CREATE_SESSION` for C — succeeds.
4. `CREATE_SESSION` for C (incremented `csa_sequence`) — **`NFS4ERR_INVAL`**.

The connection is irrelevant. The limit is one session per client ID.

### Arm D — 16 independent client IDs

1. Dial 16 TCP connections.
2. Each connection gets its own `EXCHANGE_ID` with a distinct `co_ownerid`,
   producing 16 distinct client IDs.
3. `CREATE_SESSION` on each — **all 16 succeed**, yielding 2048 total slots.
4. All 16 sessions are verified usable (`PUTROOTFH+GETFH` returns `NFS4_OK`).

Multiple sessions work when each has its own client ID. The limit is per client
ID, not per connection or per source address.

## Excluded alternative explanations

- **`csa_sequence` misordering.** Arm B sent `csa_sequence = 1`, arms A and C
  sent `csa_sequence = 2`. All three were refused with `NFS4ERR_INVAL`.
  §18.36.4 specifies `NFS4ERR_SEQ_MISORDERED` for a sequencing fault, which is
  a distinct error code from what the array returns.

- **Malformed channel attributes.** Both `CREATE_SESSION` calls in each arm send
  byte-identical `csa_fore_chan_attrs` and `csa_back_chan_attrs`. The first
  succeeds and the second fails. A packet capture of arm C confirms the two
  `CREATE_SESSION4args` differ in exactly one byte (`csa_sequence` 1 vs 2).

- **Connection binding.** Arm C eliminates this by sending both requests on the
  same connection.

## Impact

### On NFS clients

Any NFSv4.1 client that attempts client ID trunking — creating multiple
sessions on one client ID to multiplex across connections — will receive an
opaque `NFS4ERR_INVAL` with no indication of the actual cause. The Linux kernel
NFS client avoids this because its `nconnect` implementation uses session
trunking (multiple connections on one session), not client ID trunking (multiple
sessions on one client ID).

A userspace NFSv4.1 client that wants a pool of N connections must use N
independent `EXCHANGE_ID` registrations with distinct client owners — N clients,
not N sessions — which means locking and open state cannot be shared across the
pool. For a metadata-only client (SETATTR, GETATTR, READDIR) this costs nothing.
For a client that would use OPEN or LOCK, it forecloses cross-connection state
sharing.

### Error reporting

`NFS4ERR_INVAL` is overloaded. §18.36.3 defines it for attribute-based causes
(requested channel attributes out of range), and §18.36.4 defines
`NFS4ERR_SEQ_MISORDERED` for the sequencing case. There is no defined error for
"this client ID already has a session." A client receiving `NFS4ERR_INVAL` on
`CREATE_SESSION` cannot distinguish "my channel attributes are wrong" from "I
already have a session on this client ID" without the kind of multi-arm probing
recorded here.

## Requested resolution

Two items, independent of each other:

1. **Support multiple sessions per client ID**, as §2.10.5 requires. This
   enables client ID trunking, which the array already advertises by returning
   the same client ID for the same owner on different connections (arm B).

2. **Return a more specific error code.** If the one-session limit persists,
   `NFS4ERR_RESOURCE` or a vendor-specific diagnostic (e.g., in the reply's
   `sr_status_flags`) would tell a client why `CREATE_SESSION` failed, instead
   of an `NFS4ERR_INVAL` that reads like a malformed request.

## What NOT to file

The one-mutating-operation-per-COMPOUND constraint (documented separately in
`RFC-Deviations.md` §2) is deliberate and load-bearing for FlashBlade's
end-to-end data-integrity feature. A test in the Purity source
(`data_integrity_nfs4_test.cpp`) exists specifically to enforce it. That
behaviour must not be filed as a defect.

## References

- RFC 8881 §2.10.5 — Session Trunking and Client ID Trunking
- RFC 8881 §18.35 — EXCHANGE_ID
- RFC 8881 §18.36 — CREATE_SESSION
- `RFC-Deviations.md` §1 — internal documentation of this deviation
- `internal/nfs41/trunkprobe_live_test.go` — four-arm reproduction test
- `internal/nfs41/client.go` — workaround (N independent clients per pool)
