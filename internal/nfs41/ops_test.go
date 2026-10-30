package nfs41

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
)

// bitmapHas reports whether attribute number attr is set. RFC 5661 section 3.3.7:
// attribute n is bit n%32 of word n/32, words in ascending order.
func bitmapHas(bits []uint32, attr uint32) bool {
	w, b := attr/32, attr%32
	if int(w) >= len(bits) {
		return false
	}
	return bits[w]&(1<<b) != 0
}

// readDirBitmap pulls the requested-attribute bitmap back out of a READDIR op,
// so a test can assert what the client asked the server for.
func readDirBitmap(op xdr.Nfs_argop4) []uint32 {
	return op.Opreaddir().Attr_request
}

// marshalOp encodes one operation to its wire bytes. goxdr panics with an
// xdr.XdrError rather than returning one, so that is converted here; a test
// asserting on encoding must not die as a panic in an unrelated goroutine.
func marshalOp(op xdr.Nfs_argop4) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			if xe, ok := r.(xdr.XdrError); ok {
				err = xe
				return
			}
			panic(r)
		}
	}()
	var buf bytes.Buffer
	op.XdrMarshal(xdr.XdrOut{Out: &buf}, "op")
	return buf.Bytes(), nil
}

// stripRPCReplyHeader removes the RPC framing from a captured reply, leaving the
// COMPOUND result bytes ParseCompound expects.
//
// The capture format is fixed by Task 4: one reply per file, record marker
// included, exactly as it appeared on the wire. So: 4 bytes of record marker,
// then the six header words acceptedReply builds in Task 6 — xid, mtype,
// reply_stat, verf.flavor, verf.length, accept_stat — for 28 bytes total.
//
// The verifier length is READ rather than assumed. AUTH_NONE makes it zero and
// that is what a FlashBlade sends, but a capture from a Kerberos-enabled server
// would carry a non-empty verifier and silently shift every subsequent field.
func stripRPCReplyHeader(t *testing.T, b []byte) []byte {
	t.Helper()
	if len(b) < 28 {
		t.Fatalf("reply is %d bytes, too short to contain an RPC header", len(b))
	}
	mark := binary.BigEndian.Uint32(b[0:4])
	if mark&0x80000000 == 0 {
		t.Fatal("captured reply is not a single final fragment; readRecord is needed to reassemble it")
	}
	// Word offsets, counting the 4-byte record marker at [0:4]:
	//   [4:8] xid   [8:12] mtype   [12:16] reply_stat
	//   [16:20] verf.flavor   [20:24] verf.length   [24:] verf.body then accept_stat
	//
	// An earlier revision of this helper read reply_stat at [8:12] and the
	// verifier length at [16:20], both one word early. It was never caught
	// because it cannot be: the tests that call it skip until the packet
	// capture arrives. With AUTH_NONE both misread words happen to be zero, so
	// the accept_stat guard passed and the helper returned four extra bytes --
	// but mtype is 1 for every reply in existence, so the reply_stat guard would
	// have fired on the first real capture and blamed the capture.
	if got := binary.BigEndian.Uint32(b[8:12]); got != 1 {
		t.Fatalf("mtype = %d, want 1 (REPLY)", got)
	}
	if got := binary.BigEndian.Uint32(b[12:16]); got != 0 {
		t.Fatalf("reply_stat = %d, want 0 (MSG_ACCEPTED)", got)
	}
	verfLen := binary.BigEndian.Uint32(b[20:24])
	off := 24 + int(verfLen) + (-int(verfLen) & 3) // opaque body, padded to 4
	if off+4 > len(b) {
		t.Fatalf("verifier length %d runs past the end of a %d byte reply", verfLen, len(b))
	}
	if got := binary.BigEndian.Uint32(b[off : off+4]); got != 0 {
		t.Fatalf("accept_stat = %d, want 0 (SUCCESS)", got)
	}
	return b[off+4:]
}

// TestStripRPCReplyHeaderFindsTheBody exists because stripRPCReplyHeader's only
// other callers skip until the packet capture arrives, which made it the one
// helper in this file that could be wrong indefinitely without any test noticing
// -- and it was, by exactly one word, in both the reply_stat read and the
// verifier length read.
//
// It builds its input with the same acceptedReply helper rpc_test.go uses, so the
// header layout is asserted against the layer that produces it rather than
// against a second transcription of RFC 5531.
func TestStripRPCReplyHeaderFindsTheBody(t *testing.T) {
	body := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44}

	t.Run("empty AUTH_NONE verifier", func(t *testing.T) {
		got := stripRPCReplyHeader(t, recordMark(acceptedReply(7, body)))
		if !bytes.Equal(got, body) {
			t.Errorf("body = % x, want % x", got, body)
		}
	})

	// The doc comment's stated reason for reading the length rather than assuming
	// zero. A 5-byte verifier also exercises the padding, which is where an
	// off-by-one-word slip stops being masked by AUTH_NONE's all-zero words.
	t.Run("non-empty verifier with padding", func(t *testing.T) {
		var reply []byte
		for _, w := range []uint32{7 /*xid*/, 1 /*REPLY*/, 0 /*MSG_ACCEPTED*/, 6 /*RPCSEC_GSS*/, 5 /*verf len*/} {
			reply = binary.BigEndian.AppendUint32(reply, w)
		}
		reply = append(reply, 1, 2, 3, 4, 5, 0, 0, 0)   // 5 bytes + 3 pad
		reply = binary.BigEndian.AppendUint32(reply, 0) // accept_stat = SUCCESS
		reply = append(reply, body...)

		got := stripRPCReplyHeader(t, recordMark(reply))
		if !bytes.Equal(got, body) {
			t.Errorf("body = % x, want % x; the verifier length or its padding was mishandled", got, body)
		}
	})
}

// extractOpBytes finds the encoded bytes of a single operation inside a captured
// COMPOUND request, so one op can be compared against what our builder produces
// without requiring the whole COMPOUND to match.
//
// It locates the op by decoding the COMPOUND argument header and then walking
// the op array, rather than by searching for the opnum as a byte pattern: an
// opnum value can occur inside an earlier op's payload, and a pattern search
// would match that and silently compare the wrong bytes.
func extractOpBytes(t *testing.T, compound []byte, opnum uint32) []byte {
	t.Helper()
	ops, err := splitCompoundOps(compound)
	if err != nil {
		t.Fatalf("split captured COMPOUND: %v", err)
	}
	for _, op := range ops {
		if len(op) >= 4 && binary.BigEndian.Uint32(op[:4]) == opnum {
			return op
		}
	}
	t.Fatalf("captured COMPOUND contains no op %d", opnum)
	return nil
}

// TestSetACLCompoundMatchesCapturedBytes asserts against traffic a real server
// accepted. It is deliberately not a round trip: an encoder and a decoder that
// are wrong in the same direction agree with each other perfectly.
func TestSetACLCompoundMatchesCapturedBytes(t *testing.T) {
	want, err := os.ReadFile("testdata/setattr_acl_call.bin")
	if err != nil {
		t.Skipf("golden bytes not captured yet: %v", err)
	}
	// The captured call carries a SEQUENCE and a PUTFH ahead of the SETATTR;
	// extract the SETATTR operation's bytes and compare only those, since the
	// session id and slot in SEQUENCE are per-capture.
	wantSetattr := extractOpBytes(t, want, opSETATTR)

	acl, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwatTnNcCy"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalOp(OpSetACL(acl))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantSetattr) {
		t.Fatalf("SETATTR bytes differ from the capture\n got: %x\nwant: %x", got, wantSetattr)
	}
}

// TestACLTravelsThroughAttrValsUnchanged pins the boundary between nfs4acl and
// the wire path: there isn't a transformation. Both transports must produce
// identical ACE bytes, and EncodeAttrList must not touch them.
//
// CORRECTED. An earlier draft of this plan asserted that EncodeAttrList adds a
// 4-byte length prefix and pads to 4, and used a 5-byte ACL to "force 3 bytes of
// padding". That is wrong twice over, and it is worth spelling out because the
// test that would have caught it on the wire is blocked on Task 4:
//
//   - fattr4_acl is `typedef nfsace4 fattr4_acl<>` (nfs4.x:460) — a COUNTED
//     ARRAY. Its first word is the ACE count, not a byte length. nfs4acl.Encode
//     already emits exactly that: u32 num_aces followed by the ACEs.
//   - attr_vals is `attrlist4`, i.e. `typedef opaque attrlist4<>` (nfs4.x:570),
//     so marshalling xdr.Fattr4 supplies ONE outer opaque length and pad for the
//     whole concatenation.
//
// Adding a per-value prefix therefore double-wraps, and a real server reads that
// byte length as the ACE count — NFS4ERR_BADXDR at best, a misparsed ACL at
// worst. There is also no such thing as a 5-byte fattr4_acl: valid ACL XDR is
// always a multiple of 4, because Encode pads each ACE's `who` string.
//
// So the invariant is: each value is already encoded per its own XDR type,
// EncodeAttrList concatenates them in ascending bit order and nothing else.
func TestACLTravelsThroughAttrValsUnchanged(t *testing.T) {
	// A real ACL, not a synthetic byte string — the point is that what nfs4acl
	// produces is already a valid fattr4_acl.
	raw, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwatTnNcCy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%4 != 0 {
		t.Fatalf("nfs4acl output is %d bytes, not 4-byte aligned; the premise of this test is broken", len(raw))
	}

	bitmap, attrs := EncodeAttrList([]uint32{fattr4ACL}, [][]byte{raw})

	if !bytes.Equal(attrs, raw) {
		t.Errorf("EncodeAttrList altered the ACL bytes\n got: %x\nwant: %x", attrs, raw)
	}
	// The ACE count must still be the first word. If a length prefix crept back
	// in, this reads the byte count instead and the number will be far too large.
	if len(attrs) >= 4 {
		if n := binary.BigEndian.Uint32(attrs[0:4]); n != 1 {
			t.Errorf("first word = %d, want the ACE count of 1; a byte-length prefix was added", n)
		}
	}
	if !bitmapHas(bitmap, fattr4ACL) {
		t.Error("bitmap does not name fattr4ACL")
	}
}

// TestEncodeAttrListConcatenatesInBitOrder is the other half of the same
// invariant: no delimiters, no per-value framing, ascending bit order regardless
// of the order the caller passed them in.
func TestEncodeAttrListConcatenatesInBitOrder(t *testing.T) {
	mode := []byte{0, 0, 1, 0xED} // fattr4Mode, bit 33
	typ := []byte{0, 0, 0, 2}     // fattr4Type, bit 1
	// Passed high bit first, deliberately.
	_, attrs := EncodeAttrList([]uint32{fattr4Mode, fattr4Type}, [][]byte{mode, typ})

	want := append(append([]byte{}, typ...), mode...)
	if !bytes.Equal(attrs, want) {
		t.Errorf("attrs = %x, want %x — values must be emitted in ascending bit order", attrs, want)
	}
}

func TestParseCompoundOnCapturedExchangeIDReply(t *testing.T) {
	b, err := os.ReadFile("testdata/exchange_id_reply.bin")
	if err != nil {
		t.Skipf("golden bytes not captured yet: %v", err)
	}
	status, results, err := ParseCompound(stripRPCReplyHeader(t, b))
	if err != nil {
		t.Fatal(err)
	}
	if status != NFS4_OK {
		t.Fatalf("status = %d, want NFS4_OK", status)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
}

func TestReadDirBitmaskRequestsFilehandleAndFSID(t *testing.T) {
	op := OpReadDir(0, [8]byte{}, 8192, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID)
	bits := readDirBitmap(op)
	for _, want := range []uint32{fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID} {
		if !bitmapHas(bits, want) {
			t.Errorf("bitmap is missing attribute %d", want)
		}
	}
}

func TestDecodeAttrListIsPositional(t *testing.T) {
	// Attributes arrive concatenated with no per-attribute delimiter, in
	// ascending bit order. Decoding out of order silently misreads every field,
	// which is the failure the golden-byte tests exist to catch.
	bitmap, attrs := EncodeAttrList(
		[]uint32{fattr4Type, fattr4Mode},
		[][]byte{{0, 0, 0, 2}, {0, 0, 1, 0xED}},
	)
	got, err := DecodeAttrList(bitmap, attrs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[fattr4Type], []byte{0, 0, 0, 2}) {
		t.Errorf("type = %x", got[fattr4Type])
	}
	if !bytes.Equal(got[fattr4Mode], []byte{0, 0, 1, 0xED}) {
		t.Errorf("mode = %x", got[fattr4Mode])
	}
}
