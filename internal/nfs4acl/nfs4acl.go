package nfs4acl

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/idmap"
)

// ACE types (RFC 7530 section 6.2.1.1)
const (
	TypeAllow = 0
	TypeDeny  = 1
	TypeAudit = 2
	TypeAlarm = 3
)

// ACE flags (RFC 7530 section 6.2.1.4)
const (
	FlagFileInherit   = 0x00000001 // f
	FlagDirInherit    = 0x00000002 // d
	FlagNoPropInherit = 0x00000004 // n
	FlagInheritOnly   = 0x00000008 // i
	FlagSuccessAccess = 0x00000010 // S
	FlagFailedAccess  = 0x00000020 // F
	FlagGroup         = 0x00000040 // g
	FlagInherited     = 0x00000080 // I (NFS 4.1)
)

// Access mask bits (linux/nfs4.h, RFC 7530 section 6.2.1.3)
const (
	MaskReadData        = 0x00000001 // r - read-data / list-directory
	MaskWriteData       = 0x00000002 // w - write-data / add-file
	MaskAppendData      = 0x00000004 // a - append-data / add-subdirectory
	MaskReadNamedAttrs  = 0x00000008 // n - read-named-attributes
	MaskWriteNamedAttrs = 0x00000010 // N - write-named-attributes
	MaskExecute         = 0x00000020 // x - execute / change-directory
	MaskDeleteChild     = 0x00000040 // D - delete-child
	MaskReadAttributes  = 0x00000080 // t - read-attributes
	MaskWriteAttributes = 0x00000100 // T - write-attributes
	MaskWriteRetention  = 0x00000200 // no text grammar equivalent
	MaskWriteRetHold    = 0x00000400 // no text grammar equivalent
	MaskDelete          = 0x00010000 // d - delete
	MaskReadACL         = 0x00020000 // c - read-ACL
	MaskWriteACL        = 0x00040000 // C - write-ACL
	MaskWriteOwner      = 0x00080000 // o - write-owner
	MaskSynchronize     = 0x00100000 // y - synchronize
)

// nfs4_setfacl letter-to-mask mapping (from nfs4_acl(5) man page)
var permCharToMask = map[byte]uint32{
	'r': MaskReadData,        // read-data / list-directory
	'w': MaskWriteData,       // write-data / create-file
	'a': MaskAppendData,      // append-data / create-subdirectory
	'x': MaskExecute,         // execute / change-directory
	'd': MaskDelete,          // delete
	'D': MaskDeleteChild,     // delete-child (dirs only)
	't': MaskReadAttributes,  // read-attributes
	'T': MaskWriteAttributes, // write-attributes
	'n': MaskReadNamedAttrs,  // read-named-attributes
	'N': MaskWriteNamedAttrs, // write-named-attributes
	'c': MaskReadACL,         // read-ACL
	'C': MaskWriteACL,        // write-ACL
	'o': MaskWriteOwner,      // write-owner
	'y': MaskSynchronize,     // synchronize
}

var typeCharToVal = map[byte]uint32{
	'A': TypeAllow,
	'D': TypeDeny,
	'U': TypeAudit,
	'L': TypeAlarm,
}

var flagCharToVal = map[byte]uint32{
	'f': FlagFileInherit,
	'd': FlagDirInherit,
	'n': FlagNoPropInherit,
	'i': FlagInheritOnly,
	'S': FlagSuccessAccess,
	'F': FlagFailedAccess,
	'g': FlagGroup,
	'I': FlagInherited,
}

// Ordered tables for formatting — slices guarantee deterministic output regardless
// of Go map iteration order.

// typeValToChar maps ACE type value to its single-character representation.
var typeValToChar = []struct {
	val  uint32
	char byte
}{
	{TypeAllow, 'A'},
	{TypeDeny, 'D'},
	{TypeAudit, 'U'},
	{TypeAlarm, 'L'},
}

// flagBitToChar maps each flag bit to its character, in canonical order.
var flagBitToChar = []struct {
	bit  uint32
	char byte
}{
	{FlagFileInherit, 'f'},
	{FlagDirInherit, 'd'},
	{FlagNoPropInherit, 'n'},
	{FlagInheritOnly, 'i'},
	{FlagSuccessAccess, 'S'},
	{FlagFailedAccess, 'F'},
	{FlagGroup, 'g'},
	{FlagInherited, 'I'},
}

// maskBitToChar maps each expressible mask bit to its character, in canonical order.
// MaskWriteRetention and MaskWriteRetHold are intentionally absent — they have no
// text grammar equivalent and FormatACE rejects any ACE that carries them.
var maskBitToChar = []struct {
	bit  uint32
	char byte
}{
	{MaskReadData, 'r'},
	{MaskWriteData, 'w'},
	{MaskAppendData, 'a'},
	{MaskReadNamedAttrs, 'n'},
	{MaskWriteNamedAttrs, 'N'},
	{MaskExecute, 'x'},
	{MaskDeleteChild, 'D'},
	{MaskReadAttributes, 't'},
	{MaskWriteAttributes, 'T'},
	{MaskDelete, 'd'},
	{MaskReadACL, 'c'},
	{MaskWriteACL, 'C'},
	{MaskWriteOwner, 'o'},
	{MaskSynchronize, 'y'},
}

// ACE represents a parsed NFSv4 ACE.
type ACE struct {
	Type  uint32
	Flags uint32
	Mask  uint32
	Who   string
}

// ParseACELine parses "A:fg:OWNER@:rwaDxtTcCoy" format.
func ParseACELine(line string) (ACE, error) {
	parts := strings.SplitN(line, ":", 4)
	if len(parts) != 4 {
		return ACE{}, fmt.Errorf("invalid ACE format: %q (need type:flags:who:perms)", line)
	}

	var ace ACE

	// Type
	if len(parts[0]) != 1 {
		return ACE{}, fmt.Errorf("invalid ACE type: %q", parts[0])
	}
	t, ok := typeCharToVal[parts[0][0]]
	if !ok {
		return ACE{}, fmt.Errorf("unknown ACE type: %q", parts[0])
	}
	ace.Type = t

	// Flags
	for _, ch := range []byte(parts[1]) {
		f, ok := flagCharToVal[ch]
		if !ok {
			return ACE{}, fmt.Errorf("unknown ACE flag: %c", ch)
		}
		ace.Flags |= f
	}

	// Who
	ace.Who = parts[2]

	// Permissions
	for _, ch := range []byte(parts[3]) {
		m, ok := permCharToMask[ch]
		if !ok {
			return ACE{}, fmt.Errorf("unknown permission char: %c", ch)
		}
		ace.Mask |= m
	}

	return ace, nil
}

// FormatACE formats a single ACE as a "type:flags:who:perms" string.
// It is the exact inverse of ParseACELine.
//
// Returns an error if the ACE contains an unknown type, an unrecognised flag bit,
// or any mask bit that has no text grammar equivalent (e.g. MaskWriteRetention,
// MaskWriteRetHold). Unknown bits are never silently dropped.
func FormatACE(ace ACE) (string, error) {
	return formatACEIndexed(ace, -1)
}

// formatACEIndexed is the shared implementation; idx >= 0 is included in errors
// raised by FormatACL so callers know which ACE triggered the failure.
func formatACEIndexed(ace ACE, idx int) (string, error) {
	idxTag := func(msg string) string {
		if idx >= 0 {
			return fmt.Sprintf("ACE %d: %s", idx, msg)
		}
		return msg
	}

	// Type
	var typeCh byte
	for _, e := range typeValToChar {
		if ace.Type == e.val {
			typeCh = e.char
			break
		}
	}
	if typeCh == 0 {
		return "", fmt.Errorf("%s", idxTag(fmt.Sprintf("unknown ACE type value %d", ace.Type)))
	}

	// Flags — consume all known bits, reject leftovers
	remaining := ace.Flags
	var flagBuf [8]byte
	nFlags := 0
	for _, e := range flagBitToChar {
		if remaining&e.bit != 0 {
			flagBuf[nFlags] = e.char
			nFlags++
			remaining &^= e.bit
		}
	}
	if remaining != 0 {
		return "", fmt.Errorf("%s", idxTag(fmt.Sprintf("unknown flag bit(s) 0x%x", remaining)))
	}

	// Mask — consume all known bits, reject leftovers
	remaining = ace.Mask
	var permBuf [14]byte
	nPerms := 0
	for _, e := range maskBitToChar {
		if remaining&e.bit != 0 {
			permBuf[nPerms] = e.char
			nPerms++
			remaining &^= e.bit
		}
	}
	if remaining != 0 {
		return "", fmt.Errorf("%s", idxTag(fmt.Sprintf("unknown or unexpressible mask bit(s) 0x%x (e.g. retention bits)", remaining)))
	}

	return fmt.Sprintf("%c:%s:%s:%s",
		typeCh,
		string(flagBuf[:nFlags]),
		ace.Who,
		string(permBuf[:nPerms]),
	), nil
}

// FormatACL decodes raw binary NFSv4 ACL bytes and formats each ACE as a string.
// It is the exact inverse of ParseACLSpec/Encode for ACLs whose mask bits are all
// expressible in the text grammar.
//
// Returns an error (naming the ACE index and the offending bit) if any ACE contains
// an unknown type, flag bit, or inexpressible mask bit.
func FormatACL(raw []byte) ([]string, error) {
	aces, err := DecodeACL(raw)
	if err != nil {
		return nil, err
	}
	lines := make([]string, len(aces))
	for i, ace := range aces {
		s, err := formatACEIndexed(ace, i)
		if err != nil {
			return nil, err
		}
		lines[i] = s
	}
	return lines, nil
}

// Encode serializes ACEs into the binary format expected by system.nfs4_acl xattr.
func Encode(aces []ACE) []byte {
	// Header: u32 num_aces
	// Each ACE: u32 type, u32 flags, u32 mask, u32 who_len, who (padded to 4 bytes)
	size := 4 // num_aces header
	for _, ace := range aces {
		padded := len(ace.Who)
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		size += 16 + padded // 4 u32s + padded who
	}

	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(aces)))
	pos := 4
	for _, ace := range aces {
		binary.BigEndian.PutUint32(buf[pos:pos+4], ace.Type)
		binary.BigEndian.PutUint32(buf[pos+4:pos+8], ace.Flags)
		binary.BigEndian.PutUint32(buf[pos+8:pos+12], ace.Mask)
		binary.BigEndian.PutUint32(buf[pos+12:pos+16], uint32(len(ace.Who)))
		pos += 16
		copy(buf[pos:], ace.Who)
		padded := len(ace.Who)
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		pos += padded
	}
	return buf
}

// ParseACLSpec parses multiple ACE lines (as from YAML acl list) and returns encoded bytes.
func ParseACLSpec(aclLines []string) ([]byte, error) {
	var aces []ACE
	for _, line := range aclLines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		ace, err := ParseACELine(line)
		if err != nil {
			return nil, err
		}
		aces = append(aces, ace)
	}
	return Encode(aces), nil
}

// DecodeACL decodes binary NFSv4 ACL data into a slice of ACEs.
func DecodeACL(data []byte) ([]ACE, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ACL data too short: %d bytes", len(data))
	}
	numACEs := binary.BigEndian.Uint32(data[0:4])
	pos := 4
	aces := make([]ACE, 0, numACEs)
	for i := uint32(0); i < numACEs; i++ {
		if pos+16 > len(data) {
			return nil, fmt.Errorf("ACE %d: truncated header at offset %d", i, pos)
		}
		aceType := binary.BigEndian.Uint32(data[pos : pos+4])
		flags := binary.BigEndian.Uint32(data[pos+4 : pos+8])
		mask := binary.BigEndian.Uint32(data[pos+8 : pos+12])
		whoLen := binary.BigEndian.Uint32(data[pos+12 : pos+16])
		pos += 16
		if pos+int(whoLen) > len(data) {
			return nil, fmt.Errorf("ACE %d: truncated who at offset %d", i, pos)
		}
		who := string(data[pos : pos+int(whoLen)])
		padded := int(whoLen)
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		pos += padded
		aces = append(aces, ACE{Type: aceType, Flags: flags, Mask: mask, Who: who})
	}
	return aces, nil
}

// ACLEqual compares two binary ACLs structurally. Type, flags and mask are
// compared exactly and the who field case-insensitively. It does not reconcile
// the numeric and the name@domain form of one identity: a spec naming a
// principal as "10001" will not match a server that resolved it to
// "jdoe@example.com". Callers that want that reconciliation pass a resolver to
// ACLEqualIdent; callers verifying that bytes round-trip literally, such as
// speccapture, want this strict form.
func ACLEqual(a, b []byte) bool {
	return ACLEqualIdent(a, b, nil)
}

// ACLEqualIdent is ACLEqual with an identity resolver applied to the who field,
// so the two forms of one identity compare equal. A nil resolver, or an identity
// the resolver cannot resolve, degrades to the strict comparison rather than
// failing the call.
func ACLEqualIdent(a, b []byte, r idmap.Resolver) bool {
	acesA, errA := DecodeACL(a)
	acesB, errB := DecodeACL(b)
	if errA != nil || errB != nil {
		return false
	}
	return ACEsEqualIdent(acesA, acesB, r)
}

// ACEsEqualIdent is ACLEqualIdent for callers that already have one or both
// sides decoded -- SplitACL's sacl return, for instance -- and would otherwise
// have to re-encode them just to call ACLEqualIdent. It is the same
// comparison: type/flags/mask exactly, who through the resolver.
func ACEsEqualIdent(a, b []ACE, r idmap.Resolver) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		fa, fb := a[i].Flags, b[i].Flags
		// FlashArray clears ACE4_IDENTIFIER_GROUP on GROUP@ when it stores an
		// ACL (RFC-Deviations.md §7). RFC 7530 §6.2.1.5 defines GROUP@ as the
		// owning group by definition, so the flag carries no information for
		// that one well-known who -- ignore it there only, so a named
		// principal's group flag still mismatches as before.
		if a[i].Who == "GROUP@" && b[i].Who == "GROUP@" {
			fa &^= FlagGroup
			fb &^= FlagGroup
		}
		if a[i].Type != b[i].Type ||
			fa != fb ||
			a[i].Mask != b[i].Mask {
			return false
		}
		// whoEqual only needs flags to pick the user/group namespace for a
		// resolver lookup; GROUP@ short-circuits on string equality before
		// that, so passing the original (possibly g-flagged) value here is
		// correct either way.
		if !whoEqual(a[i].Who, b[i].Who, a[i].Flags, r) {
			return false
		}
	}
	return true
}

// SplitACL splits a raw NFSv4 ACL -- the count-prefixed nfsace4 stream GetACL
// returns -- into its DACL region and its SACL entries.
//
// daclRaw is every A (allow) or D (deny) entry in raw, in the order they
// appeared, sliced directly out of raw and never decoded and re-encoded --
// the point of this function, since a who field FA chose to render oddly (a
// numeric principal, GROUP@ with no g flag, a non-canonical ordering, ...)
// must come back exactly as read. daclRaw carries its own 4-byte num_aces
// header, counting only the entries it kept, so it is itself a complete,
// valid ACL in the same encoding Encode/DecodeACL use -- the only state
// JoinACL needs besides the ACEs to add, and what daclCount is read from
// without a second decode.
//
// sacl is every U (audit) or L (alarm) entry in raw, decoded, in the order
// they appeared -- wherever they appeared. FA is only ever seen to put them at
// the tail, but this makes no assumption about position: a caller that is
// about to discard the object's old SACL (plan v3's "remove every U/L entry,
// wherever it is") must not depend on one. sacl exists for a caller to see
// what was there -- confirming it is gone from daclRaw, or logging it -- not
// to build the replacement: the SACL a DACL-keeping rule writes comes from the
// spec (RulePerms.SaclACEs()), passed to JoinACL directly, never from here.
//
// daclCount is len of the A/D entries folded into daclRaw -- equivalently,
// the num_aces daclRaw's own header carries. Returning it saves every caller
// that only wants to know "is there anything to keep" a second decode of
// daclRaw just to count it.
//
// Returns an error, naming the ACE index, on anything DecodeACL itself would
// reject: a truncated header, a truncated who field, too few bytes overall --
// and on any ACE type value outside the four RFC 7530 defines (0-3), since an
// unrecognized type cannot be safely classified as DACL or SACL.
func SplitACL(raw []byte) (daclRaw []byte, daclCount int, sacl []ACE, err error) {
	if len(raw) < 4 {
		return nil, 0, nil, fmt.Errorf("ACL data too short: %d bytes", len(raw))
	}
	numACEs := binary.BigEndian.Uint32(raw[0:4])
	pos := 4
	daclEntries := make([]byte, 0, len(raw))
	var count int
	for i := uint32(0); i < numACEs; i++ {
		if pos+16 > len(raw) {
			return nil, 0, nil, fmt.Errorf("ACE %d: truncated header at offset %d", i, pos)
		}
		entryStart := pos
		aceType := binary.BigEndian.Uint32(raw[pos : pos+4])
		flags := binary.BigEndian.Uint32(raw[pos+4 : pos+8])
		mask := binary.BigEndian.Uint32(raw[pos+8 : pos+12])
		whoLen := binary.BigEndian.Uint32(raw[pos+12 : pos+16])
		pos += 16
		if pos+int(whoLen) > len(raw) {
			return nil, 0, nil, fmt.Errorf("ACE %d: truncated who at offset %d", i, pos)
		}
		who := string(raw[pos : pos+int(whoLen)])
		padded := int(whoLen)
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		pos += padded
		entryEnd := pos

		switch aceType {
		case TypeAllow, TypeDeny:
			daclEntries = append(daclEntries, raw[entryStart:entryEnd]...)
			count++
		case TypeAudit, TypeAlarm:
			sacl = append(sacl, ACE{Type: aceType, Flags: flags, Mask: mask, Who: who})
		default:
			return nil, 0, nil, fmt.Errorf("ACE %d: unknown ACE type value %d", i, aceType)
		}
	}

	daclRaw = make([]byte, 4, 4+len(daclEntries))
	binary.BigEndian.PutUint32(daclRaw[0:4], uint32(count))
	daclRaw = append(daclRaw, daclEntries...)
	return daclRaw, count, sacl, nil
}

// SplitRaw is SplitACL with the audit/alarm region kept as raw bytes too: both
// regions come back count-prefixed, every entry copied byte-for-byte in its
// original order. It is what a DACL reset that keeps the object's existing
// SACL needs: nothing about those entries -- who form, flag bits this package
// has no name for, padding -- may change on the way back to the array.
func SplitRaw(raw []byte) (daclRaw, saclRaw []byte, daclCount, saclCount int, err error) {
	if len(raw) < 4 {
		return nil, nil, 0, 0, fmt.Errorf("ACL data too short: %d bytes", len(raw))
	}
	numACEs := binary.BigEndian.Uint32(raw[0:4])
	pos := 4
	daclRaw, saclRaw = make([]byte, 4, len(raw)), make([]byte, 4, len(raw))
	for i := uint32(0); i < numACEs; i++ {
		if pos+16 > len(raw) {
			return nil, nil, 0, 0, fmt.Errorf("ACE %d: truncated header at offset %d", i, pos)
		}
		start := pos
		aceType := binary.BigEndian.Uint32(raw[pos : pos+4])
		whoLen := int(binary.BigEndian.Uint32(raw[pos+12 : pos+16]))
		pos += 16
		if whoLen > len(raw)-pos {
			return nil, nil, 0, 0, fmt.Errorf("ACE %d: truncated who at offset %d", i, pos)
		}
		pos += (whoLen + 3) &^ 3
		if pos > len(raw) {
			return nil, nil, 0, 0, fmt.Errorf("ACE %d: truncated padding at offset %d", i, start)
		}
		switch aceType {
		case TypeAllow, TypeDeny:
			daclRaw = append(daclRaw, raw[start:pos]...)
			daclCount++
		case TypeAudit, TypeAlarm:
			saclRaw = append(saclRaw, raw[start:pos]...)
			saclCount++
		default:
			return nil, nil, 0, 0, fmt.Errorf("ACE %d: unknown ACE type value %d", i, aceType)
		}
	}
	if pos != len(raw) {
		return nil, nil, 0, 0, fmt.Errorf("%d trailing bytes after %d ACEs", len(raw)-pos, numACEs)
	}
	binary.BigEndian.PutUint32(daclRaw[0:4], uint32(daclCount))
	binary.BigEndian.PutUint32(saclRaw[0:4], uint32(saclCount))
	return daclRaw, saclRaw, daclCount, saclCount, nil
}

// JoinRaw concatenates two count-prefixed ACE streams (SplitRaw's output, or
// an Encode result) into one ACL, a's entries first. Neither is decoded.
func JoinRaw(a, b []byte) []byte {
	out := make([]byte, 4, len(a)+len(b)-4)
	binary.BigEndian.PutUint32(out[0:4], binary.BigEndian.Uint32(a[0:4])+binary.BigEndian.Uint32(b[0:4]))
	out = append(out, a[4:]...)
	return append(out, b[4:]...)
}

// IsUnmappedWho reports whether who is the form an array renders a principal
// it has no POSIX id for: the nobody uid/gid as a number (65534, its 32-bit
// two's-complement 4294967294, or -2) or by name (nobody, nfsnobody, or
// nobody@domain).
//
// Such a who is lossy, not merely odd. On Purity//FA 6.10.6 every SID with no
// RFC 2307 id reads back as 65534 -- distinct users, groups, and well-known
// SIDs alike -- and writing 65534 back stores the array's own local nobody
// SID in place of every one of them (benchmarks/sacl-unmapped-sid-20261020).
// No write-back of an ACL carrying one can preserve the DACL.
func IsUnmappedWho(who string) bool {
	switch who {
	case "65534", "4294967294", "-2", "nobody", "nfsnobody":
		return true
	}
	return strings.HasPrefix(who, "nobody@") || strings.HasPrefix(who, "nfsnobody@")
}

// SyntheticIDFloor is where FlashBlade's synthetic ids start. FB renders a SID
// that has no RFC 2307 id as 1000000000 + RID, and on an NFS ACL write it decodes
// every numeric who at or above this value back that way, whatever the number
// meant. A real uidNumber/gidNumber of 2000000003 comes back as <domain>-1000000003,
// and the synthetic id of BUILTIN\Administrators (1000000544) comes back as
// <domain>-544. Measured on Purity//FB 4.8.0 (benchmarks/sacl-unmapped-sid-20261020, #52).
const SyntheticIDFloor = 1000000000

// IsSyntheticRangeWho reports whether who is a plain decimal id at or above
// SyntheticIDFloor. The nobody sentinel 4294967294 is IsUnmappedWho's, not this.
func IsSyntheticRangeWho(who string) bool {
	if who == "" || len(who) > 10 {
		return false
	}
	var n uint64
	for _, c := range who {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + uint64(c-'0')
	}
	return n >= SyntheticIDFloor && n != 4294967294
}

// HasAudit reports whether a raw ACL carries any audit (U) or alarm (L) ACE.
func HasAudit(raw []byte) (bool, error) {
	_, _, sacl, err := SplitACL(raw)
	if err != nil {
		return false, err
	}
	return len(sacl) > 0, nil
}

// SyntheticRangePrincipals returns every distinct who in a raw ACL for which
// IsSyntheticRangeWho holds, in first-seen order.
func SyntheticRangePrincipals(raw []byte) ([]string, error) {
	aces, err := DecodeACL(raw)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range aces {
		if IsSyntheticRangeWho(a.Who) && !seen[a.Who] {
			seen[a.Who] = true
			out = append(out, a.Who)
		}
	}
	return out, nil
}

// UnmappedPrincipals returns every distinct who in a raw ACL (SplitACL's
// daclRaw, or a whole ACL) for which IsUnmappedWho holds, in first-seen order.
// An empty result means no ACE names an unmapped principal.
func UnmappedPrincipals(raw []byte) ([]string, error) {
	aces, err := DecodeACL(raw)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range aces {
		if IsUnmappedWho(a.Who) && !seen[a.Who] {
			seen[a.Who] = true
			out = append(out, a.Who)
		}
	}
	return out, nil
}

// JoinACL reassembles a full raw NFSv4 ACL from a DACL region -- as SplitACL
// returns it, header included -- and a set of SACL ACEs to encode and append
// at the tail (plan v3's "add the rule's SACL at the end"). The DACL bytes are
// copied through unchanged; only the new SACL ACEs are encoded, which is the
// one piece that comes from the spec rather than the object itself.
//
// daclRaw must be a well-formed count-prefixed stream carrying at least its
// own 4-byte header, such as SplitACL's own output; passing anything shorter
// panics on the slice index below, the same contract Encode's "acl must be
// non-empty" has elsewhere in this package.
func JoinACL(daclRaw []byte, saclACEs []ACE) []byte {
	daclCount := binary.BigEndian.Uint32(daclRaw[0:4])
	saclEncoded := Encode(saclACEs) // count-prefixed; its own header is dropped below

	total := daclCount + uint32(len(saclACEs))
	out := make([]byte, 4, len(daclRaw)+len(saclEncoded)-4)
	binary.BigEndian.PutUint32(out[0:4], total)
	out = append(out, daclRaw[4:]...)
	out = append(out, saclEncoded[4:]...)
	return out
}

func whoEqual(a, b string, flags uint32, r idmap.Resolver) bool {
	// Tried before any resolution: the overwhelmingly common case is an ACL that
	// already matches, and resolving identities to discover that would put an
	// NSS lookup on the hottest path in the program.
	if a == b || strings.EqualFold(a, b) {
		return true
	}
	if r == nil {
		return false
	}
	// Flags are already known equal here -- ACLEqual compares them before the
	// who field -- so either ACE answers which namespace the identity lives in.
	isGroup := flags&FlagGroup != 0
	for _, fa := range r.Forms(a, isGroup) {
		for _, fb := range r.Forms(b, isGroup) {
			if strings.EqualFold(fa, fb) {
				return true
			}
		}
	}
	return false
}
