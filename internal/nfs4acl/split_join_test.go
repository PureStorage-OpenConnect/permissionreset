package nfs4acl

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// rawACE hand-builds one ACE's wire bytes, bypassing Encode entirely. Tests
// that want to prove SplitACL copies bytes rather than decoding and
// re-encoding them need input that was never built through Encode in the
// first place -- Encode is itself faithful to Who in this codebase today, so a
// test built entirely out of Encode() calls could not tell "copied" from
// "decoded and faithfully re-encoded" apart.
func rawACE(aceType, flags, mask uint32, who string) []byte {
	padded := len(who)
	if padded%4 != 0 {
		padded += 4 - (padded % 4)
	}
	buf := make([]byte, 16+padded)
	binary.BigEndian.PutUint32(buf[0:4], aceType)
	binary.BigEndian.PutUint32(buf[4:8], flags)
	binary.BigEndian.PutUint32(buf[8:12], mask)
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(who)))
	copy(buf[16:], who)
	return buf
}

func rawACL(entries ...[]byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(entries)))
	out := append([]byte{}, header...)
	for _, e := range entries {
		out = append(out, e...)
	}
	return out
}

// TestSplitACLByteForByteDACL is the core requirement: A/D entries, in a
// realistic FA-shaped stream -- a numeric principal, GROUP@ without the g
// flag, a deny entry, and U/L entries interleaved at the start, the middle and
// the tail -- must come back in daclRaw exactly as they went in, and every
// U/L entry must be gone from it, wherever it appeared.
func TestSplitACLByteForByteDACL(t *testing.T) {
	leadingU := rawACE(TypeAudit, FlagSuccessAccess, MaskReadData, "EVERYONE@")               // U, interleaved at start
	denyNumeric := rawACE(TypeDeny, 0, MaskWriteData, "9999")                                 // D, numeric principal
	allowNumeric := rawACE(TypeAllow, 0, MaskReadData|MaskExecute, "1402")                    // A, numeric principal
	midL := rawACE(TypeAlarm, FlagFailedAccess, MaskWriteData, "SOMEBODY@")                   // L, interleaved mid
	allowGroupNoFlag := rawACE(TypeAllow, 0, MaskReadData, "GROUP@")                          // A, GROUP@ with no g flag (FA's own rendering)
	tailU := rawACE(TypeAudit, FlagSuccessAccess|FlagFailedAccess, MaskReadData, "EVERYONE@") // U, tail (FA's usual position)

	raw := rawACL(leadingU, denyNumeric, allowNumeric, midL, allowGroupNoFlag, tailU)

	daclRaw, daclCount, sacl, err := SplitACL(raw)
	if err != nil {
		t.Fatalf("SplitACL: %v", err)
	}
	if daclCount != 3 {
		t.Fatalf("daclCount = %d, want 3", daclCount)
	}

	wantDacl := rawACL(denyNumeric, allowNumeric, allowGroupNoFlag)
	if !bytes.Equal(daclRaw, wantDacl) {
		t.Fatalf("daclRaw = %x\nwant     %x\n(the D/A/A entries, byte-for-byte, with only the header recounted)", daclRaw, wantDacl)
	}

	if len(sacl) != 3 {
		t.Fatalf("sacl = %d entries, want 3 (leadingU, midL, tailU)", len(sacl))
	}
	if sacl[0].Type != TypeAudit || sacl[0].Who != "EVERYONE@" || sacl[0].Flags != FlagSuccessAccess {
		t.Errorf("sacl[0] = %+v, want the interleaved leading U entry", sacl[0])
	}
	if sacl[1].Type != TypeAlarm || sacl[1].Who != "SOMEBODY@" || sacl[1].Flags != FlagFailedAccess {
		t.Errorf("sacl[1] = %+v, want the interleaved mid L entry", sacl[1])
	}
	if sacl[2].Type != TypeAudit || sacl[2].Who != "EVERYONE@" || sacl[2].Flags != FlagSuccessAccess|FlagFailedAccess {
		t.Errorf("sacl[2] = %+v, want the tail U entry", sacl[2])
	}

	// Every U/L entry is gone from the DACL-only output, wherever it appeared.
	daclACEs, err := DecodeACL(daclRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(daclACEs) != 3 {
		t.Fatalf("daclRaw decodes to %d ACEs, want 3", len(daclACEs))
	}
	for i, a := range daclACEs {
		if a.Type != TypeAllow && a.Type != TypeDeny {
			t.Errorf("daclRaw ACE %d has type %d, want only ALLOW/DENY", i, a.Type)
		}
	}
	// And the preserved entries kept their own exact who/flag/mask, including
	// the numeric principals and the no-g-flag GROUP@.
	if daclACEs[0].Who != "9999" || daclACEs[0].Type != TypeDeny {
		t.Errorf("daclACEs[0] = %+v, want the numeric deny entry", daclACEs[0])
	}
	if daclACEs[1].Who != "1402" || daclACEs[1].Type != TypeAllow {
		t.Errorf("daclACEs[1] = %+v, want the numeric allow entry", daclACEs[1])
	}
	if daclACEs[2].Who != "GROUP@" || daclACEs[2].Flags&FlagGroup != 0 {
		t.Errorf("daclACEs[2] = %+v, want GROUP@ with no g flag, exactly as FA returned it", daclACEs[2])
	}
}

// TestSplitACLAllDACLNoSACL covers the plain case: an ACL with no audit
// entries at all splits into a full DACL and an empty sacl.
func TestSplitACLAllDACLNoSACL(t *testing.T) {
	raw := rawACL(
		rawACE(TypeAllow, 0, MaskReadData, "OWNER@"),
		rawACE(TypeDeny, 0, MaskWriteData, "EVERYONE@"),
	)
	daclRaw, daclCount, sacl, err := SplitACL(raw)
	if err != nil {
		t.Fatalf("SplitACL: %v", err)
	}
	if daclCount != 2 {
		t.Fatalf("daclCount = %d, want 2", daclCount)
	}
	if len(sacl) != 0 {
		t.Fatalf("sacl = %+v, want empty", sacl)
	}
	if !bytes.Equal(daclRaw, raw) {
		t.Fatalf("daclRaw = %x, want the whole input back unchanged: %x", daclRaw, raw)
	}
}

// TestSplitACLAllSACLNoDACL covers the refusal case's own data shape: an ACL
// with no ALLOW/DENY entries splits into a header-only (count 0) daclRaw and
// every entry in sacl. Callers (applyNFSv4's KeepDACL path, ProbePreflight)
// detect this from daclCount == 0, not from here -- this test only pins what
// SplitACL itself hands back.
func TestSplitACLAllSACLNoDACL(t *testing.T) {
	raw := rawACL(rawACE(TypeAudit, FlagSuccessAccess, MaskReadData, "EVERYONE@"))
	daclRaw, daclCount, sacl, err := SplitACL(raw)
	if err != nil {
		t.Fatalf("SplitACL: %v", err)
	}
	if daclCount != 0 {
		t.Fatalf("daclCount = %d, want 0", daclCount)
	}
	wantHeader := make([]byte, 4)
	if !bytes.Equal(daclRaw, wantHeader) {
		t.Fatalf("daclRaw = %x, want a bare zero-count header %x", daclRaw, wantHeader)
	}
	if len(sacl) != 1 {
		t.Fatalf("sacl = %+v, want the one audit entry", sacl)
	}
}

// TestSplitACLEmpty covers a zero-ACE ACL (just the header): legal input, no
// entries on either side.
func TestSplitACLEmpty(t *testing.T) {
	raw := rawACL()
	daclRaw, daclCount, sacl, err := SplitACL(raw)
	if err != nil {
		t.Fatalf("SplitACL: %v", err)
	}
	if daclCount != 0 || len(sacl) != 0 {
		t.Fatalf("daclCount=%d sacl=%+v, want both empty", daclCount, sacl)
	}
	if !bytes.Equal(daclRaw, raw) {
		t.Fatalf("daclRaw = %x, want %x", daclRaw, raw)
	}
}

func TestSplitACLMalformedInput(t *testing.T) {
	validEntry := rawACE(TypeAllow, 0, MaskReadData, "OWNER@")

	tests := []struct {
		name string
		raw  []byte
	}{
		{"too short for the count header", []byte{0, 0, 0}},
		{"count says more entries than the stream holds", func() []byte {
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, 2) // claims 2, stream holds 1
			return append(header, validEntry...)
		}()},
		{"truncated ACE header", func() []byte {
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, 1)
			return append(header, validEntry[:10]...) // short of the 16-byte header
		}()},
		{"truncated who field", func() []byte {
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, 1)
			// whoLen says 6 ("OWNER@" is 6 bytes) but only 2 bytes follow.
			entry := append([]byte{}, validEntry[:16]...)
			return append(header, append(entry, validEntry[16:18]...)...)
		}()},
		{"unknown ACE type", func() []byte {
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, 1)
			bad := append([]byte{}, validEntry...)
			binary.BigEndian.PutUint32(bad[0:4], 99) // not Allow/Deny/Audit/Alarm
			return append(header, bad...)
		}()},
		{"empty", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, err := SplitACL(tt.raw); err == nil {
				t.Errorf("SplitACL(%x): want an error", tt.raw)
			}
		})
	}
}

// TestJoinACLRoundTrip proves JoinACL reassembles exactly what SplitACL took
// apart when handed the same SACL back, and that handing it a different SACL
// produces the DACL unchanged with only the tail replaced.
func TestJoinACLRoundTrip(t *testing.T) {
	denyNumeric := rawACE(TypeDeny, 0, MaskWriteData, "9999")
	allowNumeric := rawACE(TypeAllow, 0, MaskReadData, "1402")
	raw := rawACL(denyNumeric, allowNumeric, rawACE(TypeAudit, FlagSuccessAccess, MaskReadData, "EVERYONE@"))

	daclRaw, daclCount, _, err := SplitACL(raw)
	if err != nil {
		t.Fatalf("SplitACL: %v", err)
	}
	if daclCount != 2 {
		t.Fatalf("daclCount = %d, want 2", daclCount)
	}

	newSacl := []ACE{
		{Type: TypeAudit, Flags: FlagSuccessAccess | FlagFailedAccess, Mask: MaskWriteData, Who: "SOMEONE@"},
	}
	joined := JoinACL(daclRaw, newSacl)

	aces, err := DecodeACL(joined)
	if err != nil {
		t.Fatalf("DecodeACL(joined): %v", err)
	}
	if len(aces) != 3 {
		t.Fatalf("joined has %d ACEs, want 3 (2 kept DACL + 1 new SACL)", len(aces))
	}
	if aces[0].Who != "9999" || aces[0].Type != TypeDeny {
		t.Errorf("aces[0] = %+v, want the kept deny entry", aces[0])
	}
	if aces[1].Who != "1402" || aces[1].Type != TypeAllow {
		t.Errorf("aces[1] = %+v, want the kept allow entry", aces[1])
	}
	if aces[2].Who != "SOMEONE@" || aces[2].Type != TypeAudit {
		t.Errorf("aces[2] = %+v, want the new SACL entry at the tail", aces[2])
	}

	// The DACL bytes themselves are untouched -- JoinACL never re-encodes them.
	// Only the leading 4-byte count header differs (it carries the combined
	// total); the entry bytes after it are daclRaw's own, unchanged.
	if !bytes.Equal(joined[4:len(daclRaw)], daclRaw[4:]) {
		t.Errorf("joined's DACL region = %x, want daclRaw's own entry bytes %x unchanged", joined[4:len(daclRaw)], daclRaw[4:])
	}
}

// TestJoinACLNoSaclEqualsInput pins the degenerate case: joining in no SACL
// entries at all reproduces daclRaw exactly.
func TestJoinACLNoSaclEqualsInput(t *testing.T) {
	raw := rawACL(rawACE(TypeAllow, 0, MaskReadData, "OWNER@"), rawACE(TypeDeny, 0, MaskWriteData, "EVERYONE@"))
	daclRaw, _, _, err := SplitACL(raw)
	if err != nil {
		t.Fatalf("SplitACL: %v", err)
	}
	joined := JoinACL(daclRaw, nil)
	if !bytes.Equal(joined, daclRaw) {
		t.Fatalf("JoinACL(daclRaw, nil) = %x, want daclRaw unchanged %x", joined, daclRaw)
	}
}

// TestJoinACLZeroDACL covers the shape ProbePreflight and applyNFSv4 refuse to
// write: JoinACL itself is a dumb reassembler and will happily build a
// SACL-only ACL if asked -- the refusal is the callers' responsibility, not
// this function's, so this just pins that it still encodes correctly.
func TestJoinACLZeroDACL(t *testing.T) {
	daclRaw, _, _, err := SplitACL(rawACL())
	if err != nil {
		t.Fatalf("SplitACL: %v", err)
	}
	sacl := []ACE{{Type: TypeAudit, Flags: FlagSuccessAccess, Mask: MaskReadData, Who: "EVERYONE@"}}
	joined := JoinACL(daclRaw, sacl)
	aces, err := DecodeACL(joined)
	if err != nil {
		t.Fatalf("DecodeACL: %v", err)
	}
	if len(aces) != 1 || aces[0].Type != TypeAudit {
		t.Fatalf("aces = %+v, want the one audit entry", aces)
	}
}
