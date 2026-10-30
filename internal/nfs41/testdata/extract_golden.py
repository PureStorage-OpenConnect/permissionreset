#!/usr/bin/env python3
"""Extract golden NFSv4.1 wire messages from a pcap.

Standard library only, deliberately. The host this was written on had neither
tshark nor scapy, and hand-rolling the parse is the right call regardless: the
golden bytes must be exactly one RPC record as it appeared on the wire, and a
tool that helpfully reframes a coalesced TCP segment would silently violate the
framing assumptions that compoundPayload, stripRPCReplyHeader and ParseCompound
all depend on.

Usage:
    python3 extract_golden.py nfs41-golden.pcap [outdir]

Writes exchange_id_call.bin, exchange_id_reply.bin and setattr_acl_call.bin.
Fails loudly rather than emitting a partial or mis-framed file.
"""
import collections
import os
import struct
import sys

NFS_PROGRAM, NFS_VERSION, NFSPROC4_COMPOUND = 100003, 4, 1
OP_GETATTR, OP_GETFH, OP_LOOKUP, OP_PUTFH, OP_PUTROOTFH = 9, 10, 15, 22, 24
OP_ACCESS, OP_READDIR, OP_SETATTR, OP_SEQUENCE = 3, 26, 34, 53
OP_EXCHANGE_ID, OP_CREATE_SESSION = 42, 43


class Fatal(Exception):
    pass


def read_pcap(path):
    """Yield (src, sport, dst, dport, seq, payload) for every TCP segment."""
    data = open(path, "rb").read()
    magic = data[:4]
    endian = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }.get(magic)
    if endian is None:
        raise Fatal(f"{path}: not a classic pcap (magic {magic.hex()})")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    # 1 = Ethernet, 101 = raw IP, 113 = Linux cooked, 276 = Linux cooked v2 (SLL2).
    l2len = {1: 14, 101: 0, 113: 16, 276: 20}
    if linktype not in l2len:
        raise Fatal(f"{path}: unhandled pcap linktype {linktype}")

    off = 24
    while off + 16 <= len(data):
        _ts, _us, caplen, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt, off = data[off:off + caplen], off + caplen

        if linktype == 1:
            if len(pkt) < 14:
                continue
            etype, l3 = struct.unpack(">H", pkt[12:14])[0], pkt[14:]
            while etype in (0x8100, 0x88A8):          # VLAN
                etype, l3 = struct.unpack(">H", l3[2:4])[0], l3[4:]
        elif linktype == 101:
            etype, l3 = 0x0800, pkt
        elif linktype == 113:
            etype, l3 = struct.unpack(">H", pkt[14:16])[0], pkt[16:]
        else:                                          # 276, SLL2
            etype, l3 = struct.unpack(">H", pkt[0:2])[0], pkt[20:]

        if etype != 0x0800 or len(l3) < 20 or l3[9] != 6:   # IPv4 / TCP only
            continue
        ihl = (l3[0] & 0x0F) * 4
        total = struct.unpack(">H", l3[2:4])[0]
        src = ".".join(str(b) for b in l3[12:16])
        dst = ".".join(str(b) for b in l3[16:20])
        l4 = l3[ihl:total] if total else l3[ihl:]
        if len(l4) < 20:
            continue
        sport, dport, seq = struct.unpack(">HHI", l4[:8])
        payload = l4[((l4[12] >> 4) & 0xF) * 4:]
        if payload:
            yield src, sport, dst, dport, seq, payload


def reassemble(segs, who):
    """Order segments by sequence number, resolving retransmits and overlaps."""
    out, base = bytearray(), None
    for seq in sorted(segs):
        p = segs[seq]
        if base is None:
            base, out = seq, bytearray(p)
            continue
        want = base + len(out)
        if seq == want:
            out += p
        elif seq < want:                               # retransmit or overlap
            adv = want - seq
            if adv < len(p):
                out += p[adv:]
        else:
            raise Fatal(f"{who}: {seq - want} byte gap in the capture at seq {want}; "
                        f"the pcap is incomplete and cannot yield golden bytes")
    return bytes(out)


def split_records(buf, who):
    """Split an RPC-over-TCP stream into records, each returned WITH its marker."""
    recs, i = [], 0
    while i + 4 <= len(buf):
        mark = struct.unpack(">I", buf[i:i + 4])[0]
        last, ln = mark & 0x80000000, mark & 0x7FFFFFFF
        if ln == 0 or i + 4 + ln > len(buf):
            break
        if not last:
            raise Fatal(f"{who}: multi-fragment record at offset {i}; this extractor "
                        f"only handles single-fragment records, which is all the "
                        f"reference capture contains")
        recs.append(buf[i:i + 4 + ln])
        i += 4 + ln
    if i != len(buf):
        raise Fatal(f"{who}: {len(buf) - i} trailing bytes after the last complete record")
    return recs


def _skip_op(op, b, p):
    """Offset just past this op's arguments. Only ops present in the capture."""
    if op in (OP_PUTROOTFH, OP_GETFH):
        return p
    if op == OP_ACCESS:
        return p + 4
    if op == OP_SEQUENCE:                              # sessionid16 seq4 slot4 high4 cache4
        return p + 32
    if op in (OP_PUTFH, OP_LOOKUP):                    # opaque<> / utf8str
        n = struct.unpack(">I", b[p:p + 4])[0]
        return p + 4 + n + (-n % 4)
    if op == OP_GETATTR:                               # bitmap4
        n = struct.unpack(">I", b[p:p + 4])[0]
        return p + 4 + n * 4
    if op == OP_READDIR:                               # cookie8 verf8 dir4 max4 bitmap
        q = p + 24
        n = struct.unpack(">I", b[q:q + 4])[0]
        return q + 4 + n * 4
    if op == OP_SETATTR:                               # stateid16 bitmap attrlist4
        q = p + 16
        n = struct.unpack(">I", b[q:q + 4])[0]
        q += 4 + n * 4
        ln = struct.unpack(">I", b[q:q + 4])[0]
        return q + 4 + ln + (-ln % 4)
    return None                                        # unknown: stop walking


def compound_call_ops(rec):
    """(xid, [opnum]) for a COMPOUND call record, or (xid, None) if not one."""
    body = rec[4:]
    if len(body) < 24:
        return None, None
    xid, mtype = struct.unpack(">II", body[:8])
    if mtype != 0:                                     # 0 = CALL
        return xid, None
    _rpcv, prog, vers, proc = struct.unpack(">IIII", body[8:24])
    if (prog, vers, proc) != (NFS_PROGRAM, NFS_VERSION, NFSPROC4_COMPOUND):
        return xid, None
    p = 24
    for _ in range(2):                                 # cred, verf
        _flavor, ln = struct.unpack(">II", body[p:p + 8])
        p += 8 + ln + (-ln % 4)
    taglen = struct.unpack(">I", body[p:p + 4])[0]
    p += 4 + taglen + (-taglen % 4)
    _minor, nops = struct.unpack(">II", body[p:p + 8])
    p += 8
    ops = []
    for _ in range(nops):
        if p + 4 > len(body):
            break
        op = struct.unpack(">I", body[p:p + 4])[0]
        ops.append(op)
        nxt = _skip_op(op, body, p + 4)
        if nxt is None:
            break
        p = nxt
    return xid, ops


def reply_xid(rec):
    body = rec[4:]
    if len(body) < 8:
        return None
    xid, mtype = struct.unpack(">II", body[:8])
    return xid if mtype == 1 else None                 # 1 = REPLY


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    pcap = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else "."

    streams = collections.defaultdict(dict)
    for src, sport, dst, dport, seq, payload in read_pcap(pcap):
        streams[(src, sport, dst, dport)][seq] = payload

    calls, replies = [], {}
    for key, segs in sorted(streams.items()):
        who = f"{key[0]}:{key[1]}->{key[2]}:{key[3]}"
        for rec in split_records(reassemble(segs, who), who):
            xid, ops = compound_call_ops(rec)
            if ops:
                calls.append((key, xid, ops, rec))
            else:
                rxid = reply_xid(rec)
                if rxid is not None:
                    replies.setdefault(rxid, rec)

    setattrs = [(k, x, r) for k, x, o, r in calls if OP_SETATTR in o]
    if len(setattrs) != 1:
        raise Fatal(f"expected exactly one COMPOUND containing SETATTR, found {len(setattrs)}")

    # Prefer the shortest EXCHANGE_ID call: the v41probe.py run sends a single-op
    # COMPOUND, where the kernel mount's is padded with a longer client owner.
    eids = sorted(((k, x, r) for k, x, o, r in calls if o and o[0] == OP_EXCHANGE_ID),
                  key=lambda t: len(t[2]))
    if not eids:
        raise Fatal("no EXCHANGE_ID call in the capture")
    _ek, exid, eid_call = eids[0]
    if exid not in replies:
        raise Fatal(f"no reply captured for EXCHANGE_ID xid {exid:#010x}")

    os.makedirs(outdir, exist_ok=True)
    for name, blob in (("exchange_id_call.bin", eid_call),
                       ("exchange_id_reply.bin", replies[exid]),
                       ("setattr_acl_call.bin", setattrs[0][2])):
        mark = struct.unpack(">I", blob[:4])[0]
        if not mark & 0x80000000 or (mark & 0x7FFFFFFF) != len(blob) - 4:
            raise Fatal(f"{name}: record marker {mark:#010x} disagrees with a "
                        f"{len(blob) - 4} byte body; refusing to write a mis-framed golden")
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(blob)
        print(f"{name:26} {len(blob):5} bytes")


if __name__ == "__main__":
    try:
        main()
    except Fatal as e:
        sys.exit(f"error: {e}")
