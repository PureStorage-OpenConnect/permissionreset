package nfs4acl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestParseACELine(t *testing.T) {
	tests := []struct {
		input string
		want  ACE
	}{
		{
			"A::OWNER@:rwx",
			ACE{Type: TypeAllow, Flags: 0, Who: "OWNER@",
				Mask: MaskReadData | MaskWriteData | MaskExecute},
		},
		{
			"A:fd:OWNER@:rwaDxtTcCoy",
			ACE{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit, Who: "OWNER@",
				Mask: MaskReadData | MaskWriteData | MaskAppendData | MaskDeleteChild |
					MaskExecute | MaskReadAttributes | MaskWriteAttributes |
					MaskReadACL | MaskWriteACL | MaskWriteOwner | MaskSynchronize},
		},
		{
			"A:fdg:GROUP@:rxtncy",
			ACE{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit | FlagGroup, Who: "GROUP@",
				Mask: MaskReadData | MaskExecute | MaskReadAttributes |
					MaskReadNamedAttrs | MaskReadACL | MaskSynchronize},
		},
		{
			"D::EVERYONE@:w",
			ACE{Type: TypeDeny, Flags: 0, Who: "EVERYONE@", Mask: MaskWriteData},
		},
		{
			"A::user@domain.com:rtncy",
			ACE{Type: TypeAllow, Flags: 0, Who: "user@domain.com",
				Mask: MaskReadData | MaskReadAttributes | MaskReadNamedAttrs |
					MaskReadACL | MaskSynchronize},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseACELine(tt.input)
			if err != nil {
				t.Fatalf("ParseACELine(%q) error: %v", tt.input, err)
			}
			if got.Type != tt.want.Type {
				t.Errorf("Type = %d, want %d", got.Type, tt.want.Type)
			}
			if got.Flags != tt.want.Flags {
				t.Errorf("Flags = 0x%x, want 0x%x", got.Flags, tt.want.Flags)
			}
			if got.Mask != tt.want.Mask {
				t.Errorf("Mask = 0x%x, want 0x%x", got.Mask, tt.want.Mask)
			}
			if got.Who != tt.want.Who {
				t.Errorf("Who = %q, want %q", got.Who, tt.want.Who)
			}
		})
	}
}

func TestParseACELineErrors(t *testing.T) {
	bad := []string{
		"",
		"A::",
		"A::OWNER@",
		"X::OWNER@:r",
		"A:z:OWNER@:r",
		"A::OWNER@:Z",
	}
	for _, s := range bad {
		if _, err := ParseACELine(s); err == nil {
			t.Errorf("ParseACELine(%q) should have failed", s)
		}
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	aces := []ACE{
		{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit, Mask: 0x1F01FF, Who: "OWNER@"},
		{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit | FlagGroup, Mask: 0x1201BF, Who: "GROUP@"},
		{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit, Mask: 0x1200A9, Who: "EVERYONE@"},
	}

	buf := Encode(aces)

	numACEs := binary.BigEndian.Uint32(buf[0:4])
	if numACEs != 3 {
		t.Fatalf("header num_aces = %d, want 3", numACEs)
	}

	pos := 4
	for i, want := range aces {
		gotType := binary.BigEndian.Uint32(buf[pos : pos+4])
		gotFlags := binary.BigEndian.Uint32(buf[pos+4 : pos+8])
		gotMask := binary.BigEndian.Uint32(buf[pos+8 : pos+12])
		gotWhoLen := binary.BigEndian.Uint32(buf[pos+12 : pos+16])
		gotWho := string(buf[pos+16 : pos+16+int(gotWhoLen)])
		pos += 16
		padded := int(gotWhoLen)
		if padded%4 != 0 {
			padded += 4 - padded%4
		}
		pos += padded

		if gotType != want.Type {
			t.Errorf("ace[%d] type = %d, want %d", i, gotType, want.Type)
		}
		if gotFlags != want.Flags {
			t.Errorf("ace[%d] flags = 0x%x, want 0x%x", i, gotFlags, want.Flags)
		}
		if gotMask != want.Mask {
			t.Errorf("ace[%d] mask = 0x%x, want 0x%x", i, gotMask, want.Mask)
		}
		if gotWho != want.Who {
			t.Errorf("ace[%d] who = %q, want %q", i, gotWho, want.Who)
		}
	}
}

func TestEncodeWhoPadding(t *testing.T) {
	tests := []struct {
		who    string
		padded int
	}{
		{"AB", 4},
		{"ABCD", 4},
		{"ABCDE", 8},
		{"OWNER@", 8},
		{"EVERYONE@", 12},
	}
	for _, tt := range tests {
		buf := Encode([]ACE{{Who: tt.who}})
		whoLen := binary.BigEndian.Uint32(buf[16:20])
		if int(whoLen) != len(tt.who) {
			t.Errorf("who=%q: encoded who_len=%d, want %d", tt.who, whoLen, len(tt.who))
		}
		expectedSize := 4 + 16 + tt.padded
		if len(buf) != expectedSize {
			t.Errorf("who=%q: buf len=%d, want %d (padded who=%d)", tt.who, len(buf), expectedSize, tt.padded)
		}
	}
}

func TestParseACLSpec(t *testing.T) {
	lines := []string{
		"A::OWNER@:rwaDxtTcCoy",
		"# comment",
		"  ",
		"A:g:GROUP@:rxtncy",
		"A::EVERYONE@:rxtncy",
	}
	data, err := ParseACLSpec(lines)
	if err != nil {
		t.Fatalf("ParseACLSpec error: %v", err)
	}
	numACEs := binary.BigEndian.Uint32(data[0:4])
	if numACEs != 3 {
		t.Errorf("num_aces = %d, want 3 (comments and blanks should be skipped)", numACEs)
	}
}

func TestParseACLSpecError(t *testing.T) {
	lines := []string{"A::OWNER@:r", "INVALID"}
	if _, err := ParseACLSpec(lines); err == nil {
		t.Error("ParseACLSpec should fail on invalid ACE line")
	}
}

func TestParseACLSpecDeterministic(t *testing.T) {
	lines := []string{
		"A:fd:OWNER@:rwaDxtTcCoy",
		"A:fdg:GROUP@:rwaDxtTcCoy",
		"A:fd:EVERYONE@:rxtncy",
	}
	a, _ := ParseACLSpec(lines)
	b, _ := ParseACLSpec(lines)
	if !bytes.Equal(a, b) {
		t.Error("ParseACLSpec not deterministic — breaks --compare")
	}
}

func TestDecodeACLRoundTrip(t *testing.T) {
	aces := []ACE{
		{Type: TypeAllow, Flags: FlagFileInherit | FlagDirInherit, Mask: MaskReadData | MaskExecute, Who: "OWNER@"},
		{Type: TypeDeny, Flags: FlagGroup, Mask: MaskWriteData, Who: "GROUP@"},
		{Type: TypeAllow, Flags: 0, Mask: MaskReadData, Who: "user@REALM.COM"},
	}
	encoded := Encode(aces)
	decoded, err := DecodeACL(encoded)
	if err != nil {
		t.Fatalf("DecodeACL: %v", err)
	}
	if len(decoded) != len(aces) {
		t.Fatalf("decoded %d ACEs, want %d", len(decoded), len(aces))
	}
	for i := range aces {
		if decoded[i].Type != aces[i].Type || decoded[i].Flags != aces[i].Flags ||
			decoded[i].Mask != aces[i].Mask || decoded[i].Who != aces[i].Who {
			t.Errorf("ACE %d: got %+v, want %+v", i, decoded[i], aces[i])
		}
	}
}

func TestACLEqualCaseInsensitiveWho(t *testing.T) {
	acesA := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "user@REALM.COM"}}
	acesB := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "user@realm.com"}}
	a := Encode(acesA)
	b := Encode(acesB)
	if bytes.Equal(a, b) {
		t.Skip("encodings happen to match — test is vacuous")
	}
	if !ACLEqual(a, b) {
		t.Error("ACLEqual should match case-insensitive who fields")
	}
}

func TestACLEqualDifferentMask(t *testing.T) {
	acesA := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "OWNER@"}}
	acesB := []ACE{{Type: TypeAllow, Mask: MaskWriteData, Who: "OWNER@"}}
	if ACLEqual(Encode(acesA), Encode(acesB)) {
		t.Error("ACLEqual should not match different masks")
	}
}

func TestGoldenEncodeDecodeRoundTrip(t *testing.T) {
	lines := []string{
		"A::OWNER@:rwatTcCy",
		"D::EVERYONE@:w",
		"A:g:GROUP@:rtncy",
		"A:fdi:user@corp.example.com:rxtncy",
		"D:n:admin@realm.com:D",
	}
	for _, line := range lines {
		want, err := ParseACELine(line)
		if err != nil {
			t.Fatalf("ParseACELine(%q): %v", line, err)
		}
		encoded := Encode([]ACE{want})
		decoded, err := DecodeACL(encoded)
		if err != nil {
			t.Fatalf("DecodeACL after encoding %q: %v", line, err)
		}
		if len(decoded) != 1 {
			t.Fatalf("%q: decoded %d ACEs, want 1", line, len(decoded))
		}
		got := decoded[0]
		if got.Type != want.Type {
			t.Errorf("%q: Type = %d, want %d", line, got.Type, want.Type)
		}
		if got.Flags != want.Flags {
			t.Errorf("%q: Flags = 0x%x, want 0x%x", line, got.Flags, want.Flags)
		}
		if got.Mask != want.Mask {
			t.Errorf("%q: Mask = 0x%x, want 0x%x", line, got.Mask, want.Mask)
		}
		if got.Who != want.Who {
			t.Errorf("%q: Who = %q, want %q", line, got.Who, want.Who)
		}
	}
}

func TestLargeACLRoundTrip(t *testing.T) {
	var aces []ACE
	for i := 0; i < 64; i++ {
		who := fmt.Sprintf("user%d@domain.example.com", i)
		mask := uint32(MaskReadData | MaskReadAttributes | MaskReadACL)
		if i%3 == 0 {
			mask |= MaskWriteData | MaskAppendData
		}
		if i%5 == 0 {
			mask |= MaskExecute | MaskDeleteChild
		}
		aceType := uint32(TypeAllow)
		if i%7 == 0 {
			aceType = TypeDeny
		}
		flags := uint32(0)
		if i%2 == 0 {
			flags = FlagFileInherit | FlagDirInherit
		}
		aces = append(aces, ACE{Type: aceType, Flags: flags, Mask: mask, Who: who})
	}

	encoded := Encode(aces)
	decoded, err := DecodeACL(encoded)
	if err != nil {
		t.Fatalf("DecodeACL: %v", err)
	}
	if len(decoded) != len(aces) {
		t.Fatalf("decoded %d ACEs, want %d", len(decoded), len(aces))
	}
	for i := range aces {
		if decoded[i].Type != aces[i].Type || decoded[i].Flags != aces[i].Flags ||
			decoded[i].Mask != aces[i].Mask || decoded[i].Who != aces[i].Who {
			t.Errorf("ACE %d: got %+v, want %+v", i, decoded[i], aces[i])
		}
	}
	if !ACLEqual(encoded, Encode(decoded)) {
		t.Error("re-encoding the decoded ACL does not match the original")
	}
}

func TestACLEqualGroupFlagNormalization(t *testing.T) {
	// FlashArray drops the g flag on GROUP@ when it stores an ACL
	// (RFC-Deviations.md §7). RFC 7530 §6.2.1.5 defines GROUP@ as the owning
	// group by definition, so the flag carries no information there, and
	// PS-18 (issue #87) makes ACLEqual -- which is ACLEqualIdent(a, b, nil) --
	// ignore it for that one well-known who. speccapture's --verify-write
	// byte-round-trip check uses ACLEqual, so this also removes a false
	// verify-write failure on FA. A named principal is not covered by the RFC
	// special case, so the flag still matters there; see
	// TestACEsEqualIdentGroupSpecialIgnoresGroupFlag for the named-principal case.
	with := []ACE{{Type: TypeAllow, Flags: FlagGroup, Mask: MaskReadData | MaskReadACL, Who: "GROUP@"}}
	without := []ACE{{Type: TypeAllow, Flags: 0, Mask: MaskReadData | MaskReadACL, Who: "GROUP@"}}
	a := Encode(with)
	b := Encode(without)
	if bytes.Equal(a, b) {
		t.Fatal("encodings should differ — g flag changes the flags field")
	}
	if !ACLEqual(a, b) {
		t.Error("ACLEqual should ignore the g flag on GROUP@ (FA clears it)")
	}
}

// TestACEsEqualIdentGroupSpecialIgnoresGroupFlag covers PS-18 / issue #87: FA
// clears ACE4_IDENTIFIER_GROUP when it stores GROUP@ (RFC-Deviations.md §7).
// RFC 7530 §6.2.1.5 defines GROUP@ as the owning group by definition, so the
// flag carries no information for that one well-known who -- the identity-aware
// comparison should converge on a second run against FA. A named principal is
// not covered by that RFC special case, so the flag must keep mattering there:
// a spec that said "this group" must not silently start matching "this user".
func TestACEsEqualIdentGroupSpecialIgnoresGroupFlag(t *testing.T) {
	want := []ACE{{Type: TypeAllow, Flags: FlagGroup, Mask: 0x1, Who: "GROUP@"}}
	got := []ACE{{Type: TypeAllow, Flags: 0, Mask: 0x1, Who: "GROUP@"}}
	if !ACEsEqualIdent(want, got, nil) {
		t.Error("GROUP@ with and without the g flag must compare equal (FA clears it)")
	}
	if !ACLEqualIdent(Encode(want), Encode(got), nil) {
		t.Error("ACLEqualIdent must agree with ACEsEqualIdent for GROUP@")
	}

	// The flag still matters on a named principal: this is not a blanket
	// "ignore the group flag" change.
	named := []ACE{{Type: TypeAllow, Flags: FlagGroup, Mask: 0x1, Who: "eng@example.com"}}
	namedNoFlag := []ACE{{Type: TypeAllow, Flags: 0, Mask: 0x1, Who: "eng@example.com"}}
	if ACEsEqualIdent(named, namedNoFlag, nil) {
		t.Error("a named principal with and without the g flag must not compare equal")
	}

	// Other flags on GROUP@ (e.g. inheritance) must still be compared exactly;
	// only ACE4_IDENTIFIER_GROUP is special-cased.
	withInherit := []ACE{{Type: TypeAllow, Flags: FlagGroup | FlagDirInherit, Mask: 0x1, Who: "GROUP@"}}
	withoutInherit := []ACE{{Type: TypeAllow, Flags: 0, Mask: 0x1, Who: "GROUP@"}}
	if ACEsEqualIdent(withInherit, withoutInherit, nil) {
		t.Error("a genuine flag difference besides g on GROUP@ must still mismatch")
	}
}

// fakeResolver scripts the numeric/name@domain mapping so these tests never
// touch NSS.
type fakeResolver struct {
	users  map[string]string // numeric id -> name@domain
	groups map[string]string
}

func (f fakeResolver) Forms(who string, isGroup bool) []string {
	table := f.users
	if isGroup {
		table = f.groups
	}
	if name, ok := table[who]; ok {
		return []string{who, name}
	}
	for id, name := range table {
		if strings.EqualFold(name, who) {
			return []string{who, id}
		}
	}
	return []string{who}
}

func corpResolver() fakeResolver {
	return fakeResolver{
		users:  map[string]string{"10001": "jdoe@corp.example.com"},
		groups: map[string]string{"10002": "domain admins@corp.example.com"},
	}
}

func TestACLEqualIdentNumericMatchesResolvedUser(t *testing.T) {
	spec := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "10001"}}
	server := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "jdoe@corp.example.com"}}
	a, b := Encode(spec), Encode(server)
	if ACLEqual(a, b) {
		t.Fatal("strict ACLEqual should not match the two forms; test would be vacuous")
	}
	if !ACLEqualIdent(a, b, corpResolver()) {
		t.Error("ACLEqualIdent should match 10001 against its resolved name@domain")
	}
}

func TestACLEqualIdentNumericMatchesResolvedGroup(t *testing.T) {
	spec := []ACE{{Type: TypeAllow, Flags: FlagGroup, Mask: MaskReadData, Who: "10002"}}
	server := []ACE{{Type: TypeAllow, Flags: FlagGroup, Mask: MaskReadData, Who: "domain admins@corp.example.com"}}
	if !ACLEqualIdent(Encode(spec), Encode(server), corpResolver()) {
		t.Error("ACLEqualIdent should match a group id against its resolved name@domain")
	}
}

func TestACLEqualIdentGroupIDIsNotAUserID(t *testing.T) {
	// 10002 names a group. Without the g flag the resolver is asked for a user,
	// finds nothing, and the comparison must stay strict rather than reaching
	// into the group namespace.
	spec := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "10002"}}
	server := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "domain admins@corp.example.com"}}
	if ACLEqualIdent(Encode(spec), Encode(server), corpResolver()) {
		t.Error("a user-namespace lookup must not match a group identity")
	}
}

// TestACLEqualIdentGroupFlagNormalizationWithResolver covers the combination
// the PS-18 acceptance criteria call out: GROUP@'s g-flag redundancy must
// converge whether or not an identity resolver is also in play, and a
// resolver present for other ACEs in the same ACL must not let it reach past
// GROUP@ into normalizing a genuinely different named group.
func TestACLEqualIdentGroupFlagNormalizationWithResolver(t *testing.T) {
	spec := []ACE{
		{Type: TypeAllow, Flags: FlagGroup, Mask: MaskReadData, Who: "GROUP@"},
		{Type: TypeAllow, Flags: FlagGroup, Mask: MaskReadData, Who: "10002"},
	}
	server := []ACE{
		{Type: TypeAllow, Flags: 0, Mask: MaskReadData, Who: "GROUP@"}, // FA dropped g
		{Type: TypeAllow, Flags: FlagGroup, Mask: MaskReadData, Who: "domain admins@corp.example.com"},
	}
	if !ACLEqualIdent(Encode(spec), Encode(server), corpResolver()) {
		t.Error("GROUP@ g-flag normalization must hold alongside a resolved named-group ACE in the same ACL")
	}

	// A different named group must still mismatch -- the GROUP@ special case
	// must not bleed into ordinary group comparisons.
	differentGroup := []ACE{
		{Type: TypeAllow, Flags: 0, Mask: MaskReadData, Who: "GROUP@"},
		{Type: TypeAllow, Flags: FlagGroup, Mask: MaskReadData, Who: "someoneelsegroup@corp.example.com"},
	}
	if ACLEqualIdent(Encode(spec), Encode(differentGroup), corpResolver()) {
		t.Error("a genuinely different named group must still mismatch")
	}
}

func TestACLEqualIdentUnresolvableDegradesToStrict(t *testing.T) {
	spec := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "3000099976"}}
	server := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "3000099976"}}
	if !ACLEqualIdent(Encode(spec), Encode(server), corpResolver()) {
		t.Error("an unresolvable identity that is byte-identical must still match")
	}

	other := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "3000099977"}}
	if ACLEqualIdent(Encode(spec), Encode(other), corpResolver()) {
		t.Error("two different unresolvable identities must not match")
	}
}

func TestACLEqualIdentDifferentIdentityStillMismatches(t *testing.T) {
	spec := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "10001"}}
	server := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "someoneelse@corp.example.com"}}
	if ACLEqualIdent(Encode(spec), Encode(server), corpResolver()) {
		t.Error("resolution must not make two genuinely different identities equal")
	}
}

func TestACLEqualIdentNilResolverIsStrict(t *testing.T) {
	spec := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "10001"}}
	server := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "jdoe@corp.example.com"}}
	if ACLEqualIdent(Encode(spec), Encode(server), nil) {
		t.Error("a nil resolver must keep the strict comparison")
	}
}

func TestACLEqualIdentWellKnownUnaffected(t *testing.T) {
	spec := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "OWNER@"}}
	server := []ACE{{Type: TypeAllow, Mask: MaskReadData, Who: "EVERYONE@"}}
	if ACLEqualIdent(Encode(spec), Encode(server), corpResolver()) {
		t.Error("OWNER@ must not match EVERYONE@")
	}
}

func TestIsUnmappedWho(t *testing.T) {
	for _, who := range []string{"65534", "4294967294", "-2", "nobody", "nfsnobody", "nobody@example.net", "nfsnobody@x"} {
		if !IsUnmappedWho(who) {
			t.Errorf("IsUnmappedWho(%q) = false, want true", who)
		}
	}
	// Mapped numerics, FB's synthetic 1000000000+RID form, special and named
	// principals are not the nobody sentinel.
	for _, who := range []string{"1402", "0", "1000002776", "OWNER@", "GROUP@", "EVERYONE@", "juser@example.net", "nobodyelse", "655340"} {
		if IsUnmappedWho(who) {
			t.Errorf("IsUnmappedWho(%q) = true, want false", who)
		}
	}
}

// TestUnmappedPrincipalsFAShape uses the who values FA 6.10.6 returned for an
// SMB-written DACL naming two unmapped SIDs plus mapped controls: 65534 is
// reported once even though three ACEs carry it.
func TestUnmappedPrincipalsFAShape(t *testing.T) {
	raw := Encode([]ACE{
		{Type: TypeDeny, Who: "65534", Mask: MaskDeleteChild},
		{Type: TypeAllow, Who: "65534", Mask: MaskReadData},
		{Type: TypeAllow, Who: "1445", Mask: MaskReadData},
		{Type: TypeAllow, Who: "65534", Mask: MaskWriteData},
		{Type: TypeAllow, Who: "1402", Mask: MaskReadData},
	})
	got, err := UnmappedPrincipals(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "65534" {
		t.Fatalf("UnmappedPrincipals = %v, want [65534]", got)
	}

	clean := Encode([]ACE{{Type: TypeAllow, Who: "1445", Mask: MaskReadData}, {Type: TypeAllow, Who: "OWNER@", Mask: MaskReadData}})
	if got, err := UnmappedPrincipals(clean); err != nil || len(got) != 0 {
		t.Fatalf("UnmappedPrincipals(mapped only) = %v, %v; want none", got, err)
	}
}

func TestIsSyntheticRangeWho(t *testing.T) {
	for _, who := range []string{"1000000000", "1000002776", "1000000544", "2000000003", "3000099976", "4294967295"} {
		if !IsSyntheticRangeWho(who) {
			t.Errorf("IsSyntheticRangeWho(%q) = false, want true", who)
		}
	}
	for _, who := range []string{"999999999", "1402", "9224117", "4294967294", "", "OWNER@", "1000000000@example.net", "12345678901", "-1000000000"} {
		if IsSyntheticRangeWho(who) {
			t.Errorf("IsSyntheticRangeWho(%q) = true, want false", who)
		}
	}
}

func TestHasAudit(t *testing.T) {
	plain := Encode([]ACE{{Type: TypeAllow, Who: "OWNER@", Mask: MaskReadData}})
	audited := Encode([]ACE{{Type: TypeAllow, Who: "OWNER@", Mask: MaskReadData}, {Type: TypeAudit, Flags: FlagSuccessAccess, Who: "EVERYONE@", Mask: MaskReadData}})
	if has, err := HasAudit(plain); err != nil || has {
		t.Errorf("HasAudit(plain) = %v, %v; want false", has, err)
	}
	if has, err := HasAudit(audited); err != nil || !has {
		t.Errorf("HasAudit(audited) = %v, %v; want true", has, err)
	}
}

func TestSplitRawJoinRawRoundTrip(t *testing.T) {
	aces := []ACE{
		{Type: TypeAudit, Flags: FlagSuccessAccess | 0x4000, Who: "odd", Mask: MaskReadData}, // unnamed flag bit, unpadded who
		{Type: TypeAllow, Who: "OWNER@", Mask: MaskReadData},
		{Type: TypeAlarm, Flags: FlagFailedAccess, Who: "1402", Mask: MaskWriteData},
		{Type: TypeDeny, Who: "EVERYONE@", Mask: MaskWriteData},
	}
	raw := Encode(aces)
	dacl, sacl, dn, sn, err := SplitRaw(raw)
	if err != nil || dn != 2 || sn != 2 {
		t.Fatalf("SplitRaw = %d, %d, %v", dn, sn, err)
	}
	if want := Encode([]ACE{aces[1], aces[3]}); !bytes.Equal(dacl, want) {
		t.Errorf("dacl = %x, want %x", dacl, want)
	}
	if want := Encode([]ACE{aces[0], aces[2]}); !bytes.Equal(sacl, want) {
		t.Errorf("sacl = %x, want %x", sacl, want)
	}
	if got, want := JoinRaw(dacl, sacl), Encode([]ACE{aces[1], aces[3], aces[0], aces[2]}); !bytes.Equal(got, want) {
		t.Errorf("JoinRaw = %x, want %x", got, want)
	}
	for name, bad := range map[string][]byte{"short": raw[:2], "truncated": raw[:len(raw)-1], "trailing": append(append([]byte(nil), raw...), 0)} {
		if _, _, _, _, err := SplitRaw(bad); err == nil {
			t.Errorf("%s: SplitRaw accepted it", name)
		}
	}
}
