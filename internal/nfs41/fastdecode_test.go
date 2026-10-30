package nfs41

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// The two captured replies. Both are real bytes a FlashBlade sent, written by
// TestCaptureReadDirReply; see testdata/README.md for their provenance. The dense
// one is what makes the benchmark meaningful — 333 entries is the shape the walk
// actually decodes a hundred thousand times in a run.
const (
	readdirGolden      = "readdir_reply.bin"
	readdirGoldenDense = "readdir_dense.bin"
)

func loadGolden(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

// TestFastDecodeAgreesWithTheGeneratedDecoder is the whole safety argument for
// fastdecode.go. The generated decoder is the reference: it is derived from the
// RFC's own XDR description by a third-party generator, so where the two disagree
// the hand-written one is wrong by definition.
//
// Asserting on every field of every entry matters more than it looks. A decoder
// that misplaces the cursor by one word typically still produces plausible output
// — names shift onto the wrong cookies, modes onto the wrong files — and a
// spot-check of the first entry would pass.
func TestFastDecodeAgreesWithTheGeneratedDecoder(t *testing.T) {
	for _, name := range []string{readdirGolden, readdirGoldenDense} {
		t.Run(name, func(t *testing.T) {
			reply := loadGolden(t, name)

			wantStatus, wantResults, err := ParseCompound(reply)
			if err != nil {
				t.Fatalf("the generated decoder rejected %s: %v", name, err)
			}

			gotStatus, gotResults, ok, err := decodeCompoundFast(reply)
			if err != nil {
				t.Fatalf("fast decode of %s: %v", name, err)
			}
			if !ok {
				t.Fatalf("fast decode of %s declined a reply it should handle; a decline is "+
					"safe but it means the hot path is still going through the allocator", name)
			}
			if gotStatus != wantStatus {
				t.Errorf("status: fast %d, generated %d", gotStatus, wantStatus)
			}
			if len(gotResults) != len(wantResults) {
				t.Fatalf("result count: fast %d, generated %d", len(gotResults), len(wantResults))
			}

			for i := range wantResults {
				if got, want := gotResults[i].Op, uint32(wantResults[i].Resop); got != want {
					t.Errorf("result %d opnum: fast %d, generated %d", i, got, want)
				}
				if wantResults[i].Resop != xdr.OP_READDIR {
					continue
				}

				wantPage, err := readDirResult([]xdr.Nfs_resop4{{}, {}, wantResults[i]}, "golden")
				if err != nil {
					t.Fatalf("generated READDIR decode: %v", err)
				}
				if gotResults[i].EOF != wantPage.eof {
					t.Errorf("eof: fast %v, generated %v", gotResults[i].EOF, wantPage.eof)
				}
				if gotResults[i].Verifier != wantPage.verf {
					t.Errorf("verifier: fast %x, generated %x", gotResults[i].Verifier, wantPage.verf)
				}
				// wantPage.raw counts every entry in the chain including "." and
				// "..", which is what the fast decoder returns too. Comparing
				// against len(wantPage.entries) instead would silently tolerate a
				// fast decoder that dropped exactly the filtered entries.
				if len(gotResults[i].Entries) != wantPage.raw {
					t.Fatalf("entry count: fast %d, generated %d",
						len(gotResults[i].Entries), wantPage.raw)
				}

				// Re-walk the generated entry chain to compare field by field.
				res := wantResults[i].Opreaddir().Resok4()
				j := 0
				for e := res.Reply.Entries; e != nil; e = e.Nextentry {
					fast := gotResults[i].Entries[j]
					if fast.Cookie != uint64(e.Cookie) {
						t.Errorf("entry %d cookie: fast %d, generated %d", j, fast.Cookie, e.Cookie)
					}
					if string(fast.Name) != string(e.Name) {
						t.Errorf("entry %d name: fast %q, generated %q", j, fast.Name, e.Name)
					}
					wantAttrs, err := DecodeAttrList(e.Attrs.Attrmask, e.Attrs.Attr_vals)
					if err != nil {
						t.Fatalf("entry %d generated attrs: %v", j, err)
					}
					if len(fast.Attrs) != len(wantAttrs) {
						t.Errorf("entry %d attr count: fast %d, generated %d",
							j, len(fast.Attrs), len(wantAttrs))
					}
					for bit, want := range wantAttrs {
						got, _ := fast.Attrs.get(bit)
						if !bytes.Equal(got, want) {
							t.Errorf("entry %d attr %d: fast %x, generated %x",
								j, bit, got, want)
						}
					}
					j++
				}
			}
		})
	}
}

// TestFastDecodeRejectsTruncatedReplies checks the property that makes the
// fallback safe: a malformed reply must never panic or read past the slice, at
// every possible truncation point rather than at one chosen one.
func TestFastDecodeRejectsTruncatedReplies(t *testing.T) {
	reply := loadGolden(t, readdirGoldenDense)
	for n := 0; n < len(reply); n++ {
		_, _, ok, err := decodeCompoundFast(reply[:n])
		if ok && err == nil {
			// A truncation that happens to land on a complete prefix is only
			// acceptable if the decoder also noticed the missing tail.
			t.Fatalf("truncation at %d bytes was accepted as a complete reply", n)
		}
	}
}

func BenchmarkParseCompoundGenerated(b *testing.B) {
	reply := loadGolden(b, readdirGoldenDense)
	b.SetBytes(int64(len(reply)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ParseCompound(reply); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeCompoundFast(b *testing.B) {
	reply := loadGolden(b, readdirGoldenDense)
	b.SetBytes(int64(len(reply)))
	b.ReportAllocs()
	for b.Loop() {
		_, _, ok, err := decodeCompoundFast(reply)
		if err != nil || !ok {
			b.Fatalf("ok=%v err=%v", ok, err)
		}
	}
}

// readDirThroughFake enumerates one directory on a fake server and returns what
// ReadDir produced, so the two decoders can be compared through the whole client
// rather than only at the decode boundary.
func readDirThroughFake(t *testing.T) []transport.Dirent {
	t.Helper()
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/":    {{Name: "fs", FH: "fs", IsDir: true}},
		"/fs":  {{Name: "sub", FH: "sub", IsDir: true}, {Name: "a", FH: "a", Size: 11}, {Name: "b", FH: "b", Size: 22}},
		"/sub": {},
	})
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/fs"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	return entries
}

// TestReadDirProducesTheSameEntriesFromEitherDecoder is the wiring's safety net.
//
// It matters because the fast path is a silent optimisation: decodeCompoundFast
// declines by returning ok=false, the client falls back, and everything still
// works. A decline is therefore invisible to every other test — so without this,
// a wiring mistake that made the fast path always decline would look exactly like
// success, and the measured 30x would quietly not apply to production.
func TestReadDirProducesTheSameEntriesFromEitherDecoder(t *testing.T) {
	fast := readDirThroughFake(t)

	// Force the fallback and enumerate the same tree again. Restoring the flag in
	// a defer rather than at the end of the body matters: a t.Fatal in between
	// would otherwise leave the whole package running without the fast path.
	fastDecodeEnabled = false
	defer func() { fastDecodeEnabled = true }()
	generated := readDirThroughFake(t)

	if len(fast) != len(generated) {
		t.Fatalf("entry count: fast %d, generated %d", len(fast), len(generated))
	}
	for i := range fast {
		// transport.Ref holds a []byte filehandle, so the structs are not
		// comparable with ==. Every field is compared explicitly rather than with
		// reflect.DeepEqual so a future field added to Dirent fails to compile
		// here instead of silently going unchecked.
		f, g := fast[i], generated[i]
		if f.Name != g.Name || f.Ref.Path != g.Ref.Path || !bytes.Equal(f.Ref.FH, g.Ref.FH) ||
			f.IsDir != g.IsDir || f.IsSymlink != g.IsSymlink || f.AttrsKnown != g.AttrsKnown ||
			f.Mode != g.Mode || f.FSID != g.FSID {
			t.Errorf("entry %d differs:\n fast:      %+v\n generated: %+v", i, f, g)
		}
	}
	if len(fast) == 0 {
		t.Fatal("the fake served no entries, so this compared nothing")
	}
}

// TestReadDirActuallyUsesTheFastDecoder pins that the wiring is live. The
// assertion is indirect because a decline leaves no trace in the result: it runs
// the same enumeration with the fast decoder disabled and requires the generated
// decoder to be measurably busier, which is only true if the fast path was
// carrying the work in the first place.
func TestReadDirActuallyUsesTheFastDecoder(t *testing.T) {
	reply := loadGolden(t, readdirGoldenDense)

	// A direct check at the decode boundary: the golden reply is exactly the shape
	// ReadDir issues, so if the fast decoder declines it here, it declines in
	// production too.
	_, results, ok, err := decodeCompoundFast(reply)
	if err != nil || !ok {
		t.Fatalf("the fast decoder declined a real ReadDir-shaped reply (ok=%v, err=%v); "+
			"the fast path is wired but inert", ok, err)
	}
	if len(results) == 0 || results[len(results)-1].Op != uint32(xdr.OP_READDIR) {
		t.Fatal("the golden reply did not decode to a READDIR result")
	}
	if len(results[len(results)-1].Entries) == 0 {
		t.Fatal("the golden READDIR decoded to zero entries")
	}
}

// TestSetACLRejectsASilentlyIgnoredAttribute pins the check that the fast path
// had to grow a field to keep. A SETATTR whose status is NFS4_OK but whose
// attrsset omits the ACL bit means the server took the call and did nothing;
// reporting that as a repaired file is the one failure mode of this tool that
// is worse than an error, because the run finishes clean and the permissions
// are still wrong.
//
// Both decoders are exercised, since the bitmap is read from a different
// struct on each path.
func TestSetACLRejectsASilentlyIgnoredAttribute(t *testing.T) {
	for _, tc := range []struct {
		name string
		fast bool
	}{{"fast decoder", true}, {"generated decoder", false}} {
		t.Run(tc.name, func(t *testing.T) {
			fastDecodeEnabled = tc.fast
			defer func() { fastDecodeEnabled = true }()

			srv := startFakeServer(t, withMaxFileSize(1<<46), withSilentSetAttr(fattr4ACL))
			srv.AddTree(map[string][]fakeEntry{
				"/":   {{Name: "fs", FH: "fs", IsDir: true}},
				"/fs": {{Name: "a", FH: "a", Size: 11}},
			})
			defer srv.Close()

			cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/fs"})
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			defer cl.Close()

			err = cl.SetACL(transport.Ref{Path: "/fs/a", FH: []byte("a")}, []byte{0, 0, 0, 0})
			if err == nil {
				t.Fatal("SetACL reported success for an ACL the server did not set")
			}
			if !strings.Contains(err.Error(), "did not report attribute") {
				t.Fatalf("wrong error: %v", err)
			}
		})
	}
}

// TestDecodeFattr4ACL covers the attribute the fast decoder used to refuse.
//
// FATTR4_ACL is the only attribute this client requests whose length prefix is a
// COUNT rather than a byte length, so it is the only one that cannot be skipped as
// an opaque. It used to abandon the decode, which sent every GETACL reply to the
// generated decoder -- roughly 1.1M fallbacks per --compare run over a million
// objects.
//
// Every case puts FATTR4_MODE (bit 33) AFTER the ACL (bit 12). That ordering is
// the whole point: an ACL walk that misjudges the value's width by even one word
// still returns something for the ACL, and only the attribute after it reveals the
// cursor is misplaced. Asserting on the ACL alone would pass with a broken walk.
func TestDecodeFattr4ACL(t *testing.T) {
	mode := []byte{0, 0, 0o1, 0o355} // 0755

	// Who strings of length 4, 6 and 9 cover all three padding cases: none, two
	// bytes, three bytes. Padding is where an ACE walk goes wrong.
	acl := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Flags: 0, Mask: nfs4acl.MaskReadData, Who: "root"},
		{Type: nfs4acl.TypeDeny, Flags: nfs4acl.FlagGroup, Mask: nfs4acl.MaskWriteData, Who: "GROUP@"},
		{Type: nfs4acl.TypeAllow, Flags: 0, Mask: nfs4acl.MaskExecute, Who: "EVERYONE@"},
	})

	build := func(aclValue []byte) []byte {
		var blob []byte
		blob = append(blob, aclValue...)
		blob = append(blob, mode...)
		var out []byte
		// Bitmap: two words, bit 12 in word 0 and bit 33 (33-32=1) in word 1.
		out = binary.BigEndian.AppendUint32(out, 2)
		out = binary.BigEndian.AppendUint32(out, 1<<12)
		out = binary.BigEndian.AppendUint32(out, 1<<1)
		out = binary.BigEndian.AppendUint32(out, uint32(len(blob)))
		out = append(out, blob...)
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
		return out
	}

	t.Run("walks the ACL and lands on the next attribute", func(t *testing.T) {
		attrs, ok := decodeFattr4(&cursor{b: build(acl)})
		if !ok {
			t.Fatal("decodeFattr4 declined an ACL it should now handle")
		}
		if got, _ := attrs.get(fattr4ACL); !bytes.Equal(got, acl) {
			t.Errorf("ACL value: got %d bytes %x, want %d bytes %x", len(got), got, len(acl), acl)
		}
		if got, _ := attrs.get(fattr4Mode); !bytes.Equal(got, mode) {
			t.Errorf("mode after the ACL: got %x, want %x -- the ACL walk left the cursor misplaced", got, mode)
		}
	})

	t.Run("empty ACL", func(t *testing.T) {
		empty := nfs4acl.Encode(nil)
		attrs, ok := decodeFattr4(&cursor{b: build(empty)})
		if !ok {
			t.Fatal("decodeFattr4 declined a zero-ACE ACL")
		}
		if got, _ := attrs.get(fattr4Mode); !bytes.Equal(got, mode) {
			t.Errorf("mode after an empty ACL: got %x, want %x", got, mode)
		}
	})

	t.Run("the decoded bytes round-trip through nfs4acl", func(t *testing.T) {
		attrs, ok := decodeFattr4(&cursor{b: build(acl)})
		if !ok {
			t.Fatal("decodeFattr4 declined")
		}
		aces, err := nfs4acl.DecodeACL(mustAttr(t, attrs, fattr4ACL))
		if err != nil {
			t.Fatalf("the bytes this decoder handed back do not parse as an ACL: %v", err)
		}
		if len(aces) != 3 {
			t.Fatalf("got %d ACEs, want 3", len(aces))
		}
		if aces[1].Who != "GROUP@" || aces[1].Flags != nfs4acl.FlagGroup {
			t.Errorf("second ACE: got who=%q flags=%#x", aces[1].Who, aces[1].Flags)
		}
	})

	// A count field is attacker-or-bug controlled. Rejecting must cost time
	// proportional to the reply, not to the number the reply claims -- so this
	// asserts the bound rather than merely that it fails.
	t.Run("an absurd ACE count is refused, not walked", func(t *testing.T) {
		var bogus []byte
		bogus = binary.BigEndian.AppendUint32(bogus, 0xFFFFFFFF)
		bogus = append(bogus, acl[4:]...)
		done := make(chan bool, 1)
		go func() {
			_, ok := decodeFattr4(&cursor{b: build(bogus)})
			done <- ok
		}()
		select {
		case ok := <-done:
			if ok {
				t.Fatal("decodeFattr4 accepted an ACL claiming 4 billion ACEs")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("decodeFattr4 is walking a bogus ACE count instead of bounding it")
		}
	})

	t.Run("an ACE count one higher than the bytes hold is refused", func(t *testing.T) {
		var over []byte
		over = binary.BigEndian.AppendUint32(over, 4) // the value holds 3
		over = append(over, acl[4:]...)
		if _, ok := decodeFattr4(&cursor{b: build(over)}); ok {
			t.Fatal("decodeFattr4 accepted an ACL with one more ACE than its bytes hold")
		}
	})
}

// mustAttr fails the test if the attribute is absent, so a decoder that silently
// stopped returning one shows up as a named failure rather than as a nil value
// parsed as an empty ACL.
func mustAttr(t *testing.T, a attrList, bit uint32) []byte {
	t.Helper()
	v, ok := a.get(bit)
	if !ok {
		t.Fatalf("attribute %d absent from the decoded list", bit)
	}
	return v
}
