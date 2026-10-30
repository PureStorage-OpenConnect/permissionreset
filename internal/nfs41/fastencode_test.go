package nfs41

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
)

// encodeCase is one COMPOUND argument shape and what the hand-written encoder is
// expected to do with it.
type encodeCase struct {
	name string
	tag  string
	ops  []xdr.Nfs_argop4
	// decline is true for shapes fastencode.go has deliberately not been taught.
	// Asserting the decline is as important as asserting the bytes: the failure
	// this design is built to prevent is a plausible-looking encoding of an
	// operation nobody verified.
	decline bool
}

// realACL is a genuine fattr4_acl produced by nfs4acl, not a synthetic byte
// string. The ACL is the largest and most error-prone payload the encoder
// carries, and the one place a mistaken length or a mistaken pad would be
// invisible in a smaller test.
func realACL(t testing.TB, lines ...string) []byte {
	t.Helper()
	acl, err := nfs4acl.ParseACLSpec(lines)
	if err != nil {
		t.Fatalf("nfs4acl.ParseACLSpec(%q): %v", lines, err)
	}
	return acl
}

// bytesOfLength returns n distinct bytes. Distinct rather than constant so that
// a transposition or an off-by-one inside the opaque body fails the comparison
// instead of hiding behind a run of identical bytes.
func bytesOfLength(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 1)
	}
	return b
}

func encodeCorpus(t testing.TB) []encodeCase {
	t.Helper()

	var cases []encodeCase

	// XDR pads every opaque out to a four-byte boundary, so lengths 0 through 5
	// exercise all four pad widths plus the wrap. Every variable-length field in
	// the vocabulary gets the full sweep: the filehandle, the LOOKUP name, the
	// tag, and the attrlist4 that carries the ACL.
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8} {
		cases = append(cases,
			encodeCase{
				name: fmt.Sprintf("putfh/fh-len-%d", n),
				tag:  "pad",
				ops:  []xdr.Nfs_argop4{OpPutFH(bytesOfLength(n))},
			},
			encodeCase{
				name: fmt.Sprintf("lookup/name-len-%d", n),
				tag:  "pad",
				ops:  []xdr.Nfs_argop4{OpLookup(strings.Repeat("x", n))},
			},
			encodeCase{
				name: fmt.Sprintf("tag/len-%d", n),
				tag:  strings.Repeat("t", n),
				ops:  []xdr.Nfs_argop4{OpGetFH()},
			},
			encodeCase{
				name: fmt.Sprintf("setattr/acl-blob-len-%d", n),
				tag:  "pad",
				ops:  []xdr.Nfs_argop4{OpSetACL(bytesOfLength(n))},
			},
		)
	}

	// A nil filehandle is not the same Go value as an empty one, and goxdr
	// reaches it by a different path (a nil slice rather than a zero-length
	// one). Both must encode as a bare zero length.
	cases = append(cases,
		encodeCase{name: "putfh/nil-fh", tag: "", ops: []xdr.Nfs_argop4{OpPutFH(nil)}},
		// NFS4_FHSIZE is the declared bound. The generated encoder does not
		// enforce the bound on output -- XdrVecOpaque only checks it in
		// SetByteSlice -- so a filehandle at and beyond the bound must still
		// match rather than diverge.
		encodeCase{name: "putfh/fh-at-fhsize", tag: "max", ops: []xdr.Nfs_argop4{OpPutFH(bytesOfLength(xdr.NFS4_FHSIZE))}},
		encodeCase{name: "putfh/fh-over-fhsize", tag: "max", ops: []xdr.Nfs_argop4{OpPutFH(bytesOfLength(xdr.NFS4_FHSIZE + 3))}},
		encodeCase{name: "putrootfh", tag: "root", ops: []xdr.Nfs_argop4{OpPutRootFH()}},
		encodeCase{name: "getfh", tag: "gfh", ops: []xdr.Nfs_argop4{OpGetFH()}},
	)

	// Attribute bitmaps. FATTR4_TYPE is bit 1 and FATTR4_MODE is bit 33, so a
	// request for both spans two words; FATTR4_MAXFILESIZE (27) with
	// FATTR4_OWNER_GROUP (37) spans two words with a different split, and a
	// request that names only a high bit produces leading zero words that must
	// still be counted and emitted.
	cases = append(cases,
		encodeCase{name: "getattr/empty-bitmap", tag: "bm", ops: []xdr.Nfs_argop4{OpGetAttr()}},
		encodeCase{name: "getattr/one-word", tag: "bm", ops: []xdr.Nfs_argop4{OpGetAttr(fattr4Type, fattr4Size)}},
		encodeCase{name: "getattr/two-words", tag: "bm", ops: []xdr.Nfs_argop4{OpGetAttr(fattr4Type, fattr4Mode)}},
		encodeCase{name: "getattr/two-words-split", tag: "bm", ops: []xdr.Nfs_argop4{OpGetAttr(fattr4MaxFileSize, fattr4OwnerGroup)}},
		encodeCase{name: "getattr/high-bit-only", tag: "bm", ops: []xdr.Nfs_argop4{OpGetAttr(fattr4Owner)}},
		encodeCase{name: "getattr/readdir-set", tag: "bm", ops: []xdr.Nfs_argop4{OpGetAttr(fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID)}},
	)

	// SETATTR, including the real ACLs. The two-ACE ACL is the shape the repair
	// path actually writes; the wide one is long enough that a length written a
	// word early would still land inside the buffer.
	small := realACL(t, "A::OWNER@:rwatTnNcCy")
	wide := realACL(t,
		"A::OWNER@:rwatTnNcCy",
		"A:g:GROUP@:rtncy",
		"A::EVERYONE@:rtncy",
		"D::EVERYONE@:waTC",
		"A::someverylongprincipalname@corp.example.com:rwatTnNcCy",
	)
	cases = append(cases,
		encodeCase{name: "setattr/acl-small", tag: "acl", ops: []xdr.Nfs_argop4{OpSetACL(small)}},
		encodeCase{name: "setattr/acl-wide", tag: "acl", ops: []xdr.Nfs_argop4{OpSetACL(wide)}},
		encodeCase{name: "setattr/mode", tag: "attr", ops: []xdr.Nfs_argop4{
			OpSetAttr([]uint32{fattr4Mode}, [][]byte{{0, 0, 0x01, 0xa4}}),
		}},
		// A SETATTR naming attributes in two different bitmap words, with the
		// ACL's variable-length value between the fixed-width ones.
		encodeCase{name: "setattr/acl-and-mode", tag: "attr", ops: []xdr.Nfs_argop4{
			OpSetAttr([]uint32{fattr4Mode, fattr4ACL}, [][]byte{{0, 0, 0x01, 0xa4}, small}),
		}},
		encodeCase{name: "setattr/empty-attrs", tag: "attr", ops: []xdr.Nfs_argop4{
			OpSetAttr(nil, nil),
		}},
	)

	// A SETATTR with a non-zero stateid. No caller builds one today -- OpSetAttr
	// always uses the anonymous stateid -- so this is the case that proves the
	// encoder reads the struct rather than assuming zeroes.
	stateful := OpSetACL(small)
	stateful.Opsetattr().Stateid.Seqid = 0x11223344
	copy(stateful.Opsetattr().Stateid.Other[:], bytesOfLength(12))
	cases = append(cases, encodeCase{name: "setattr/non-anonymous-stateid", tag: "attr", ops: []xdr.Nfs_argop4{stateful}})

	// READDIR cookies and verifiers. The cookie is the only 64-bit field in the
	// vocabulary, so a byte-order mistake there would show up nowhere else, and
	// the maximum value is the one that catches a signed conversion.
	var zeroVerf [8]byte
	var maxVerf [8]byte
	for i := range maxVerf {
		maxVerf[i] = 0xff
	}
	patternVerf := [8]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	for _, rd := range []struct {
		name   string
		cookie uint64
		verf   [8]byte
	}{
		{"zero", 0, zeroVerf},
		{"one", 1, patternVerf},
		{"high-word-only", 0x0000000100000000, patternVerf},
		{"low-word-only", 0x00000000ffffffff, zeroVerf},
		{"max", ^uint64(0), maxVerf},
	} {
		cases = append(cases, encodeCase{
			name: "readdir/cookie-" + rd.name,
			tag:  "rd",
			ops: []xdr.Nfs_argop4{
				OpReadDir(rd.cookie, rd.verf, 8192, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
			},
		})
	}
	cases = append(cases, encodeCase{
		name: "readdir/no-attrs",
		tag:  "rd",
		ops:  []xdr.Nfs_argop4{OpReadDir(7, patternVerf, 0, 0)},
	})

	// SEQUENCE, whose fields are the ones a wrong encoding would corrupt most
	// expensively: a misplaced slotid puts the request on another slot.
	var sessionID [16]byte
	copy(sessionID[:], bytesOfLength(16))
	seq := OpSequence(sessionID, 0x01020304, 5, 1023)
	cached := OpSequence(sessionID, 1, 0, 0)
	cached.Opsequence().Sa_cachethis = true
	cases = append(cases,
		encodeCase{name: "sequence", tag: "session", ops: []xdr.Nfs_argop4{seq}},
		encodeCase{name: "sequence/cachethis", tag: "session", ops: []xdr.Nfs_argop4{cached}},
		encodeCase{name: "sequence/zero-session", tag: "session", ops: []xdr.Nfs_argop4{OpSequence([16]byte{}, 0, 0, 0)}},
	)

	// The whole-COMPOUND shapes the three hot call sites actually send.
	fh := bytesOfLength(32)
	cases = append(cases,
		encodeCase{name: "hot/readdir-compound", tag: "session", ops: []xdr.Nfs_argop4{
			seq,
			OpPutFH(fh),
			OpReadDir(0x123456789abcdef0, patternVerf, 8192, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		}},
		encodeCase{name: "hot/setacl-compound", tag: "session", ops: []xdr.Nfs_argop4{
			seq,
			OpPutFH(fh),
			OpSetACL(wide),
		}},
		encodeCase{name: "hot/getattr-compound", tag: "session", ops: []xdr.Nfs_argop4{
			seq,
			OpPutFH(fh),
			OpGetAttr(fattr4Type, fattr4Mode, fattr4ACL),
		}},
		encodeCase{name: "hot/resolve-compound", tag: "resolve", ops: []xdr.Nfs_argop4{
			OpPutRootFH(),
			OpLookup("mnt"),
			OpLookup("fb-perms"),
			OpLookup("bigdata_named"),
			OpGetFH(),
			OpGetAttr(fattr4Type, fattr4FSID),
		}},
		encodeCase{name: "empty-compound", tag: "", ops: nil},
	)

	// CREATE, OPEN, CLOSE, REMOVE — the generate-tree hot path.
	acl := realACL(t, "A::OWNER@:rwatTnNcCy")
	mode := make([]byte, 4)
	mode[3] = 0x80 | 0x40 | 0x20 | 0x04 // 0644-ish, doesn't matter for encoding test
	dirMode := make([]byte, 4)
	dirMode[3] = 0xFF // 0755-ish

	cases = append(cases,
		encodeCase{name: "create-dir", tag: "gen", ops: []xdr.Nfs_argop4{
			seq,
			OpPutFH(fh),
			OpCreateDir("newdir", []uint32{fattr4ACL, fattr4Mode}, [][]byte{acl, dirMode}),
			OpGetFH(),
		}},
		encodeCase{name: "create-dir-mode-only", tag: "gen", ops: []xdr.Nfs_argop4{
			seq,
			OpPutFH(fh),
			OpCreateDir("modeonly", []uint32{fattr4Mode}, [][]byte{dirMode}),
			OpGetFH(),
		}},
		encodeCase{name: "open-create-close", tag: "gen", ops: []xdr.Nfs_argop4{
			seq,
			OpPutFH(fh),
			OpOpenCreate("testfile.txt", xdr.Clientid4(0x123456789abcdef0), []byte("owner-test"),
				[]uint32{fattr4ACL, fattr4Mode}, [][]byte{acl, mode}),
			OpGetFH(),
			OpCloseCurrent(),
		}},
		encodeCase{name: "close-explicit-stateid", tag: "gen", ops: []xdr.Nfs_argop4{
			seq,
			OpPutFH(fh),
			OpClose(xdr.Stateid4{Seqid: 42, Other: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}),
		}},
		encodeCase{name: "remove", tag: "gen", ops: []xdr.Nfs_argop4{
			seq,
			OpPutFH(fh),
			OpRemove("deadfile.txt"),
		}},
	)

	// The declines. Every one of these is an operation the client either sends
	// only during session setup or does not send at all, and every one must be
	// refused rather than approximated.
	for _, op := range []xdr.Nfs_opnum4{
		xdr.OP_EXCHANGE_ID,
		xdr.OP_CREATE_SESSION,
		xdr.OP_DESTROY_SESSION,
		xdr.OP_RECLAIM_COMPLETE,
		xdr.OP_ACCESS,
		xdr.OP_LOOKUPP,
		xdr.OP_SECINFO_NO_NAME,
	} {
		cases = append(cases, encodeCase{
			name:    fmt.Sprintf("decline/%d-alone", op),
			tag:     "cold",
			ops:     []xdr.Nfs_argop4{{Argop: op}},
			decline: true,
		})
		// A cold operation buried behind hot ones must decline the whole
		// COMPOUND. Encoding the prefix and then discovering the problem would
		// be the one way this design could put wrong bytes on the wire.
		cases = append(cases, encodeCase{
			name:    fmt.Sprintf("decline/%d-after-hot-ops", op),
			tag:     "cold",
			ops:     []xdr.Nfs_argop4{seq, OpPutFH(fh), {Argop: op}},
			decline: true,
		})
	}

	return cases
}

// TestFastEncodeAgreesWithTheGeneratedEncoder is the whole safety argument for
// fastencode.go. The generated encoder is the reference: it is derived from the
// RFC's own XDR description by a third-party generator, so where the two
// disagree the hand-written one is wrong by definition.
//
// Bytes are a total specification of an encoder. Unlike the decoder, where a
// field this client never reads could disagree unnoticed, there is nowhere here
// for a mistake to hide: a single misplaced word fails the comparison.
func TestFastEncodeAgreesWithTheGeneratedEncoder(t *testing.T) {
	for _, tc := range encodeCorpus(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := encodeCompoundFast(nil, tc.tag, tc.ops)
			if tc.decline {
				if ok {
					t.Fatalf("the fast encoder accepted %q, which it has not been taught; "+
						"it must decline rather than produce bytes nobody has verified", tc.name)
				}
				if got != nil {
					t.Errorf("a declining encode returned %d bytes; a decline must leave the "+
						"caller's buffer untouched", len(got))
				}
				return
			}
			if !ok {
				t.Fatalf("the fast encoder declined %q, a shape it is supposed to handle; a "+
					"decline is safe but it means the hot path is still going through the "+
					"generated encoder", tc.name)
			}

			want, err := buildCompoundGenerated(tc.tag, tc.ops)
			if err != nil {
				t.Fatalf("the generated encoder rejected %q: %v", tc.name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encodings differ for %q\n fast (%d bytes): %x\n  gen (%d bytes): %x\n first difference at byte %d",
					tc.name, len(got), got, len(want), want, firstDifference(got, want))
			}
		})
	}
}

// TestBuildCompoundIsIdenticalOnBothPaths checks the toggle, not the encoder:
// whichever path BuildCompound takes, its callers must see the same bytes. A
// fallback nothing exercises is a fallback that has never been shown to work.
func TestBuildCompoundIsIdenticalOnBothPaths(t *testing.T) {
	for _, tc := range encodeCorpus(t) {
		t.Run(tc.name, func(t *testing.T) {
			fastEncodeEnabled = true
			withFast, err := BuildCompound(tc.tag, tc.ops)
			if err != nil {
				t.Fatalf("BuildCompound with the fast encoder: %v", err)
			}

			fastEncodeEnabled = false
			defer func() { fastEncodeEnabled = true }()
			withGenerated, err := BuildCompound(tc.tag, tc.ops)
			if err != nil {
				t.Fatalf("BuildCompound with the generated encoder: %v", err)
			}

			if !bytes.Equal(withFast, withGenerated) {
				t.Fatalf("BuildCompound differs by toggle for %q\n fast: %x\n  gen: %x\n first difference at byte %d",
					tc.name, withFast, withGenerated, firstDifference(withFast, withGenerated))
			}
		})
	}
}

// TestFastEncodeAppendsToTheCallerBuffer pins the append contract. The encoder
// takes a destination slice so a future caller can build the RPC header and the
// COMPOUND body into one allocation; if it ever overwrote what was already there
// that caller would corrupt its own header.
func TestFastEncodeAppendsToTheCallerBuffer(t *testing.T) {
	prefix := []byte("RPCHEADER")
	dst := make([]byte, len(prefix), len(prefix)+4)
	copy(dst, prefix)

	got, ok := encodeCompoundFast(dst, "append", []xdr.Nfs_argop4{OpPutRootFH(), OpGetFH()})
	if !ok {
		t.Fatal("the fast encoder declined a PUTROOTFH/GETFH COMPOUND")
	}
	if !bytes.HasPrefix(got, prefix) {
		t.Fatalf("the caller's %d prefix bytes were not preserved: %x", len(prefix), got)
	}

	want, err := buildCompoundGenerated("append", []xdr.Nfs_argop4{OpPutRootFH(), OpGetFH()})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[len(prefix):], want) {
		t.Fatalf("appended body differs\n fast: %x\n  gen: %x", got[len(prefix):], want)
	}
}

// TestCompoundSizeHintIsExact guards the single-allocation property. The hint is
// allowed to be wrong -- append would grow the slice -- but if it drifts low the
// encoder silently reacquires the growth chain it was written to remove, and no
// other test would notice.
func TestCompoundSizeHintIsExact(t *testing.T) {
	for _, tc := range encodeCorpus(t) {
		if tc.decline {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			got, ok := encodeCompoundFast(nil, tc.tag, tc.ops)
			if !ok {
				t.Fatalf("declined %q", tc.name)
			}
			if hint := compoundSizeHint(tc.tag, tc.ops); hint != len(got) {
				t.Errorf("size hint is %d but the encoding is %d bytes", hint, len(got))
			}
		})
	}
}

// TestFastEncodeAllocatesOnce records what the exercise was for. One allocation
// per COMPOUND is the floor for an encoder that returns a slice, and the
// generated encoder's measured 51 is what this replaces.
func TestFastEncodeAllocatesOnce(t *testing.T) {
	fh := bytesOfLength(32)
	acl := realACL(t, "A::OWNER@:rwatTnNcCy")
	ops := []xdr.Nfs_argop4{OpPutFH(fh), OpSetACL(acl)}

	n := testing.AllocsPerRun(200, func() {
		b, ok := encodeCompoundFast(nil, "guard", ops)
		if !ok || len(b) == 0 {
			t.Fatal("the fast encoder declined or produced nothing")
		}
	})
	if n > 1 {
		t.Errorf("the fast encoder allocates %.0f times per SETACL COMPOUND, want 1; "+
			"compoundSizeHint has probably drifted below the true size", n)
	}
}

func firstDifference(a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// BenchmarkEncodeCompoundFast and its Generated twin are the before-and-after
// pair. Run both with -benchmem; the ratio is the point, not the absolute
// numbers, which move with the machine.
//
// Measured on linux/amd64, go1.25, AMD Ryzen AI 5 PRO 340, 12 threads:
//
//	BenchmarkEncodeCompoundFastSetACL-12          43.4 ns/op     80 B/op    1 allocs/op
//	BenchmarkEncodeCompoundGeneratedSetACL-12    766.9 ns/op    888 B/op   46 allocs/op
//	BenchmarkEncodeCompoundFastReadDir-12         55.0 ns/op    112 B/op    1 allocs/op
//	BenchmarkEncodeCompoundGeneratedReadDir-12   952.6 ns/op   1064 B/op   60 allocs/op
//
// 17x the speed and one allocation instead of dozens. The one allocation is the
// returned slice itself, which is the floor for this signature; a caller that
// supplies its own buffer reaches zero.
func BenchmarkEncodeCompoundFastSetACL(b *testing.B) {
	fh := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	ops := []xdr.Nfs_argop4{OpPutFH(fh), OpSetACL(benchACL)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, ok := encodeCompoundFast(nil, "bench", ops)
		if !ok || len(buf) == 0 {
			b.Fatal("declined")
		}
	}
}

func BenchmarkEncodeCompoundGeneratedSetACL(b *testing.B) {
	fh := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	ops := []xdr.Nfs_argop4{OpPutFH(fh), OpSetACL(benchACL)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, err := buildCompoundGenerated("bench", ops)
		if err != nil || len(buf) == 0 {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeCompoundFastReadDir(b *testing.B) {
	fh := []byte{0xde, 0xad, 0xbe, 0xef}
	var verf [8]byte
	var sessionID [16]byte
	ops := []xdr.Nfs_argop4{
		OpSequence(sessionID, 1, 0, 1023),
		OpPutFH(fh),
		OpReadDir(0, verf, 8192, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, ok := encodeCompoundFast(nil, "session", ops)
		if !ok || len(buf) == 0 {
			b.Fatal("declined")
		}
	}
}

func BenchmarkEncodeCompoundGeneratedReadDir(b *testing.B) {
	fh := []byte{0xde, 0xad, 0xbe, 0xef}
	var verf [8]byte
	var sessionID [16]byte
	ops := []xdr.Nfs_argop4{
		OpSequence(sessionID, 1, 0, 1023),
		OpPutFH(fh),
		OpReadDir(0, verf, 8192, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, err := buildCompoundGenerated("session", ops)
		if err != nil || len(buf) == 0 {
			b.Fatal(err)
		}
	}
}
