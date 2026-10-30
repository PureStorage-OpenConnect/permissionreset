#!/usr/bin/env python3
"""Extract every CREATE_SESSION call from a pcap and byte-diff them.

Hand-rolled: no tshark, no scapy. Reads a classic pcap, keeps client->server
TCP payload in order, walks RPC record marks, and finds NFSv4 COMPOUND calls
whose operation array contains OP_CREATE_SESSION (43).
"""
import struct
import sys

OP_CREATE_SESSION = 43


def frames(path):
    with open(path, "rb") as fh:
        data = fh.read()
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xA1B2C3D4:
        endian, nano = "<", False
    elif magic == 0xD4C3B2A1:
        endian, nano = ">", False
    elif magic == 0xA1B23C4D:
        endian, nano = "<", True
    elif magic == 0x4D3CB2A1:
        endian, nano = ">", True
    else:
        raise SystemExit("not a classic pcap: magic %#x" % magic)
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        yield linktype, data[off:off + caplen]
        off += caplen


def tcp_payloads(path):
    """Yield (src_port, dst_port, seq, payload) for IPv4/TCP frames."""
    for linktype, frame in frames(path):
        if linktype == 1:          # Ethernet
            if len(frame) < 14 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
                continue
            ip = frame[14:]
        elif linktype == 101:      # raw IP
            ip = frame
        else:
            continue
        if not ip or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:             # TCP
            continue
        total = struct.unpack("!H", ip[2:4])[0]
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack("!HH", tcp[:4])
        seq = struct.unpack("!I", tcp[4:8])[0]
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if payload:
            yield sport, dport, seq, payload


def client_stream(path, server_port=2049):
    """Reassemble client->server bytes per source port, ordered by TCP seq."""
    streams = {}
    for sport, dport, seq, payload in tcp_payloads(path):
        if dport != server_port:
            continue
        streams.setdefault(sport, {})[seq] = payload
    out = {}
    for sport, chunks in streams.items():
        buf = b""
        for seq in sorted(chunks):
            buf += chunks[seq]
        out[sport] = buf
    return out


def rpc_records(stream):
    """Split an RPC-over-TCP byte stream into complete messages."""
    off = 0
    while off + 4 <= len(stream):
        mark = struct.unpack("!I", stream[off:off + 4])[0]
        length = mark & 0x7FFFFFFF
        off += 4
        if off + length > len(stream):
            break
        yield stream[off:off + length]
        off += length


def find_create_session(msg):
    """Return the CREATE_SESSION argument bytes, or None.

    Walks: xid, msg_type(0=call), rpcvers, prog, vers, proc, cred, verf, then
    the COMPOUND args (tag, minorversion, argarray count, first opcode).
    """
    if len(msg) < 24:
        return None
    xid, mtype = struct.unpack("!II", msg[:8])
    if mtype != 0:
        return None
    off = 8
    rpcvers, prog, vers, proc = struct.unpack("!IIII", msg[off:off + 16])
    off += 16
    if prog != 100003 or vers != 4 or proc != 1:   # NFS COMPOUND
        return None
    for _ in range(2):                             # cred, verf
        flavor, blen = struct.unpack("!II", msg[off:off + 8])
        off += 8 + ((blen + 3) & ~3)
    taglen = struct.unpack("!I", msg[off:off + 4])[0]
    off += 4 + ((taglen + 3) & ~3)
    minor = struct.unpack("!I", msg[off:off + 4])[0]
    off += 4
    nops = struct.unpack("!I", msg[off:off + 4])[0]
    off += 4
    if nops < 1:
        return None
    opcode = struct.unpack("!I", msg[off:off + 4])[0]
    off += 4
    if opcode != OP_CREATE_SESSION:
        return None
    return xid, minor, nops, msg[off:]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cs.pcap"
    found = []
    for sport, stream in sorted(client_stream(path).items()):
        for msg in rpc_records(stream):
            hit = find_create_session(msg)
            if hit:
                xid, minor, nops, args = hit
                found.append((sport, xid, minor, nops, args))

    print("CREATE_SESSION calls found: %d" % len(found))
    for i, (sport, xid, minor, nops, args) in enumerate(found, 1):
        clientid, sequence = struct.unpack("!QI", args[:12])
        print("  #%d sport=%d xid=%#010x minorversion=%d ops=%d "
              "csa_clientid=%#x csa_sequence=%d argbytes=%d"
              % (i, sport, xid, minor, nops, clientid, sequence, len(args)))

    if len(found) < 2:
        print("\nNeed at least two calls to diff.")
        return

    a, b = found[0][4], found[1][4]
    print("\nSame TCP connection: %s" % (found[0][0] == found[1][0]))
    print("Argument lengths: %d vs %d" % (len(a), len(b)))
    if len(a) != len(b):
        print("LENGTHS DIFFER -- the two calls are not structurally identical.")
        return
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    print("Differing byte offsets within CREATE_SESSION4args: %s" % diffs)
    for i in diffs:
        print("  offset %2d: %#04x -> %#04x" % (i, a[i], b[i]))
    # csa_clientid is bytes 0-7, csa_sequence is bytes 8-11.
    only_seq = all(8 <= i < 12 for i in diffs)
    print("\nAll differences confined to csa_sequence (offsets 8-11): %s" % only_seq)


if __name__ == "__main__":
    main()
