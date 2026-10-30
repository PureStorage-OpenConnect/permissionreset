package nfs4acl

import (
	"bytes"
	"strings"
	"testing"
)

// TestFormatACETypes verifies every ACE type round-trips through FormatACE/ParseACELine.
func TestFormatACETypes(t *testing.T) {
	for _, tc := range []struct {
		typ  uint32
		char string
	}{
		{TypeAllow, "A"},
		{TypeDeny, "D"},
		{TypeAudit, "U"},
		{TypeAlarm, "L"},
	} {
		ace := ACE{Type: tc.typ, Flags: 0, Mask: MaskReadData, Who: "OWNER@"}
		s, err := FormatACE(ace)
		if err != nil {
			t.Fatalf("FormatACE type=%s: %v", tc.char, err)
		}
		if !strings.HasPrefix(s, tc.char+":") {
			t.Errorf("FormatACE type=%s: got %q, want prefix %q", tc.char, s, tc.char+":")
		}
		got, err := ParseACELine(s)
		if err != nil {
			t.Fatalf("ParseACELine(%q): %v", s, err)
		}
		if got != ace {
			t.Errorf("type=%s: round-trip mismatch: got %+v, want %+v", tc.char, got, ace)
		}
	}
}

// TestFormatACEFlags verifies every individual flag bit round-trips.
func TestFormatACEFlags(t *testing.T) {
	for _, e := range flagBitToChar {
		ace := ACE{Type: TypeAllow, Flags: e.bit, Mask: MaskReadData, Who: "OWNER@"}
		s, err := FormatACE(ace)
		if err != nil {
			t.Fatalf("FormatACE flag=0x%x: %v", e.bit, err)
		}
		got, err := ParseACELine(s)
		if err != nil {
			t.Fatalf("ParseACELine(%q): %v", s, err)
		}
		if got != ace {
			t.Errorf("flag=0x%x: round-trip mismatch: got %+v, want %+v", e.bit, got, ace)
		}
	}
}

// TestFormatACEAllFlagsCombined verifies all flags together round-trip.
func TestFormatACEAllFlagsCombined(t *testing.T) {
	var allFlags uint32
	for _, e := range flagBitToChar {
		allFlags |= e.bit
	}
	ace := ACE{Type: TypeAllow, Flags: allFlags, Mask: MaskReadData, Who: "OWNER@"}
	s, err := FormatACE(ace)
	if err != nil {
		t.Fatalf("FormatACE all flags: %v", err)
	}
	got, err := ParseACELine(s)
	if err != nil {
		t.Fatalf("ParseACELine(%q): %v", s, err)
	}
	if got != ace {
		t.Errorf("all flags: round-trip mismatch: got %+v, want %+v", got, ace)
	}
}

// TestFormatACEEmptyFlags verifies empty flags round-trips (produces "type::who:perms").
func TestFormatACEEmptyFlags(t *testing.T) {
	ace := ACE{Type: TypeAllow, Flags: 0, Mask: MaskReadData, Who: "OWNER@"}
	s, err := FormatACE(ace)
	if err != nil {
		t.Fatalf("FormatACE empty flags: %v", err)
	}
	parts := strings.SplitN(s, ":", 4)
	if len(parts) != 4 || parts[1] != "" {
		t.Errorf("empty flags: expected empty flag field, got %q", s)
	}
	got, err := ParseACELine(s)
	if err != nil {
		t.Fatalf("ParseACELine(%q): %v", s, err)
	}
	if got != ace {
		t.Errorf("empty flags: round-trip mismatch: got %+v, want %+v", got, ace)
	}
}

// TestFormatACEPerms verifies every individual permission bit round-trips.
func TestFormatACEPerms(t *testing.T) {
	for _, e := range maskBitToChar {
		ace := ACE{Type: TypeAllow, Flags: 0, Mask: e.bit, Who: "OWNER@"}
		s, err := FormatACE(ace)
		if err != nil {
			t.Fatalf("FormatACE mask=0x%x: %v", e.bit, err)
		}
		got, err := ParseACELine(s)
		if err != nil {
			t.Fatalf("ParseACELine(%q): %v", s, err)
		}
		if got != ace {
			t.Errorf("mask=0x%x: round-trip mismatch: got %+v, want %+v", e.bit, got, ace)
		}
	}
}

// TestFormatACESpecialPrincipals verifies OWNER@, GROUP@, EVERYONE@ and name@domain.
func TestFormatACESpecialPrincipals(t *testing.T) {
	for _, who := range []string{
		"OWNER@",
		"GROUP@",
		"EVERYONE@",
		"user@domain.com",
		"admin@corp.example.com",
	} {
		ace := ACE{Type: TypeAllow, Flags: 0, Mask: MaskReadData | MaskReadACL, Who: who}
		s, err := FormatACE(ace)
		if err != nil {
			t.Fatalf("FormatACE who=%q: %v", who, err)
		}
		got, err := ParseACELine(s)
		if err != nil {
			t.Fatalf("ParseACELine(%q): %v", s, err)
		}
		if got.Who != who {
			t.Errorf("principal %q: round-trip who mismatch: got %q", who, got.Who)
		}
		if got != ace {
			t.Errorf("principal %q: round-trip mismatch: got %+v, want %+v", who, got, ace)
		}
	}
}

// TestFormatACENumericPrincipals verifies numeric user/group principals.
func TestFormatACENumericPrincipals(t *testing.T) {
	for _, who := range []string{"10010", "10020"} {
		ace := ACE{Type: TypeAllow, Flags: 0, Mask: MaskReadData, Who: who}
		s, err := FormatACE(ace)
		if err != nil {
			t.Fatalf("FormatACE numeric who=%q: %v", who, err)
		}
		got, err := ParseACELine(s)
		if err != nil {
			t.Fatalf("ParseACELine(%q): %v", s, err)
		}
		if got.Who != who {
			t.Errorf("numeric %q: who mismatch: got %q", who, got.Who)
		}
	}
}

// TestFormatACEGroupFlag verifies the g flag is preserved exactly from the Who field,
// not inferred from spelling.
func TestFormatACEGroupFlag(t *testing.T) {
	// GROUP@ without g flag — flag must not be inferred from spelling.
	withoutG := ACE{Type: TypeAllow, Flags: 0, Mask: MaskReadData, Who: "GROUP@"}
	s, err := FormatACE(withoutG)
	if err != nil {
		t.Fatalf("FormatACE GROUP@ without g: %v", err)
	}
	got, err := ParseACELine(s)
	if err != nil {
		t.Fatalf("ParseACELine(%q): %v", s, err)
	}
	if got.Flags != 0 {
		t.Errorf("g flag inferred from spelling: got flags=0x%x, want 0", got.Flags)
	}

	// user@domain with g flag — flag must be preserved.
	withG := ACE{Type: TypeAllow, Flags: FlagGroup, Mask: MaskReadData, Who: "user@domain"}
	s2, err := FormatACE(withG)
	if err != nil {
		t.Fatalf("FormatACE user with g: %v", err)
	}
	got2, err := ParseACELine(s2)
	if err != nil {
		t.Fatalf("ParseACELine(%q): %v", s2, err)
	}
	if got2.Flags&FlagGroup == 0 {
		t.Errorf("g flag lost: got flags=0x%x", got2.Flags)
	}
}

// TestFormatACEDenyBeforeAllow verifies deny-before-allow ordering is preserved
// through a FormatACL/ParseACLSpec round-trip.
func TestFormatACEDenyBeforeAllow(t *testing.T) {
	aces := []ACE{
		{Type: TypeDeny, Flags: 0, Mask: MaskWriteData, Who: "EVERYONE@"},
		{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit, Mask: MaskReadData | MaskExecute, Who: "OWNER@"},
	}
	raw := Encode(aces)
	lines, err := FormatACL(raw)
	if err != nil {
		t.Fatalf("FormatACL: %v", err)
	}
	reencoded, err := ParseACLSpec(lines)
	if err != nil {
		t.Fatalf("ParseACLSpec: %v", err)
	}
	if !bytes.Equal(raw, reencoded) {
		t.Errorf("deny-before-allow round-trip: bytes differ")
	}
}

// TestFormatACEInheritedFlag verifies the I (inherited) flag round-trips.
func TestFormatACEInheritedFlag(t *testing.T) {
	ace := ACE{Type: TypeAllow, Flags: FlagInherited | FlagFileInherit, Mask: MaskReadData, Who: "EVERYONE@"}
	s, err := FormatACE(ace)
	if err != nil {
		t.Fatalf("FormatACE: %v", err)
	}
	got, err := ParseACELine(s)
	if err != nil {
		t.Fatalf("ParseACELine(%q): %v", s, err)
	}
	if got != ace {
		t.Errorf("inherited flag round-trip: got %+v, want %+v", got, ace)
	}
}

// TestFormatACLFullRoundTrip verifies Encode(Parse(FormatACL(raw))) == raw for a
// realistic multi-ACE ACL.
func TestFormatACLFullRoundTrip(t *testing.T) {
	original := []ACE{
		{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit, Mask: MaskReadData | MaskWriteData | MaskAppendData | MaskDeleteChild | MaskExecute | MaskReadAttributes | MaskWriteAttributes | MaskReadACL | MaskWriteACL | MaskWriteOwner | MaskSynchronize, Who: "OWNER@"},
		{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit | FlagGroup, Mask: MaskReadData | MaskExecute | MaskReadAttributes | MaskReadNamedAttrs | MaskReadACL | MaskSynchronize, Who: "GROUP@"},
		{Type: TypeDeny, Flags: 0, Mask: MaskWriteData | MaskAppendData | MaskDeleteChild | MaskDelete, Who: "EVERYONE@"},
		{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit | FlagInheritOnly, Mask: MaskReadData | MaskReadACL, Who: "user@corp.example.com"},
	}
	raw := Encode(original)

	lines, err := FormatACL(raw)
	if err != nil {
		t.Fatalf("FormatACL: %v", err)
	}
	if len(lines) != len(original) {
		t.Fatalf("FormatACL: got %d lines, want %d", len(lines), len(original))
	}

	aces, err := func() ([]ACE, error) {
		var out []ACE
		for _, l := range lines {
			a, err := ParseACELine(l)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
		return out, nil
	}()
	if err != nil {
		t.Fatalf("ParseACELine: %v", err)
	}

	reencoded := Encode(aces)
	if !bytes.Equal(raw, reencoded) {
		t.Errorf("full round-trip: Encode(Parse(FormatACL(raw))) != raw")
	}
}

// TestFormatACLRoundTripViaParseACLSpec verifies the ParseACLSpec convenience path.
func TestFormatACLRoundTripViaParseACLSpec(t *testing.T) {
	original := []ACE{
		{Type: TypeAllow, Flags: 0, Mask: MaskReadData | MaskReadAttributes | MaskReadACL | MaskSynchronize, Who: "OWNER@"},
		{Type: TypeDeny, Flags: FlagNoPropInherit, Mask: MaskDeleteChild, Who: "admin@realm.com"},
	}
	raw := Encode(original)
	lines, err := FormatACL(raw)
	if err != nil {
		t.Fatalf("FormatACL: %v", err)
	}
	reencoded, err := ParseACLSpec(lines)
	if err != nil {
		t.Fatalf("ParseACLSpec: %v", err)
	}
	if !bytes.Equal(raw, reencoded) {
		t.Errorf("ParseACLSpec round-trip: bytes differ")
	}
}

// TestFormatACERejectUnknownType verifies that a type value not in 0-3 is rejected.
func TestFormatACERejectUnknownType(t *testing.T) {
	ace := ACE{Type: 99, Flags: 0, Mask: MaskReadData, Who: "OWNER@"}
	if _, err := FormatACE(ace); err == nil {
		t.Error("FormatACE should reject unknown type value")
	}
}

// TestFormatACERejectUnknownFlagBit verifies that unknown flag bits are rejected.
func TestFormatACERejectUnknownFlagBit(t *testing.T) {
	ace := ACE{Type: TypeAllow, Flags: 0x00000100, Mask: MaskReadData, Who: "OWNER@"}
	if _, err := FormatACE(ace); err == nil {
		t.Error("FormatACE should reject unknown flag bit")
	}
}

// TestFormatACERejectRetentionBits verifies that MaskWriteRetention and MaskWriteRetHold
// are rejected (they have no text grammar equivalent).
func TestFormatACERejectRetentionBits(t *testing.T) {
	for _, mask := range []uint32{MaskWriteRetention, MaskWriteRetHold, MaskWriteRetention | MaskWriteRetHold} {
		ace := ACE{Type: TypeAllow, Flags: 0, Mask: mask, Who: "OWNER@"}
		if _, err := FormatACE(ace); err == nil {
			t.Errorf("FormatACE should reject mask=0x%x (retention bit)", mask)
		}
	}
}

// TestFormatACERejectUnknownMaskBit verifies that an arbitrary unknown mask bit is rejected.
func TestFormatACERejectUnknownMaskBit(t *testing.T) {
	ace := ACE{Type: TypeAllow, Flags: 0, Mask: 0x00001000, Who: "OWNER@"}
	if _, err := FormatACE(ace); err == nil {
		t.Error("FormatACE should reject unknown mask bit 0x1000")
	}
}

// TestFormatACLErrorNamesACEIndex verifies that FormatACL errors name the offending ACE index.
func TestFormatACLErrorNamesACEIndex(t *testing.T) {
	aces := []ACE{
		{Type: TypeAllow, Flags: 0, Mask: MaskReadData, Who: "OWNER@"},
		{Type: TypeAllow, Flags: 0, Mask: MaskWriteRetention, Who: "GROUP@"}, // bad
	}
	raw := Encode(aces)
	_, err := FormatACL(raw)
	if err == nil {
		t.Fatal("FormatACL should fail on retention bit")
	}
	if !strings.Contains(err.Error(), "ACE 1") {
		t.Errorf("error should name ACE index 1, got: %v", err)
	}
}

// TestFormatACLTruncatedWireData verifies that FormatACL rejects truncated binary input.
func TestFormatACLTruncatedWireData(t *testing.T) {
	for _, bad := range [][]byte{
		{},
		{0, 0},
		{0, 0, 0, 1},             // claims 1 ACE but no body
		{0, 0, 0, 1, 0, 0, 0, 0}, // partial ACE header
	} {
		if _, err := FormatACL(bad); err == nil {
			t.Errorf("FormatACL should reject truncated input %x", bad)
		}
	}
}
