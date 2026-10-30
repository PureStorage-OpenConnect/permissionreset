package nfs41

// A hand-written decoder for the COMPOUND replies this client actually receives.
//
// WHY THIS EXISTS. The phase 3 benchmark found the userspace transport's cost is
// dominated by allocation inside the vendored XDR decoder, not by the network. A
// CPU profile of a 1,135,009-object run put 37% cumulative in runtime.mallocgc,
// 22.5% in xdrReadN -> io.CopyN -> io.Copy, and only 10.2% in syscalls. The cause
// is one generated helper:
//
//	func xdrReadN(in io.Reader, n uint32) []byte {
//		var b bytes.Buffer
//		if _, err := io.CopyN(&b, in, int64(n)); err != nil {
//
// xdrGet32 calls that for every 32-bit field, so each 4-byte integer costs a
// bytes.Buffer, an io.CopyN through ReadFrom, and at least one allocation. A
// READDIR reply of 333 entries, each with a four-attribute fattr4, costs
// thousands.
//
// WHY NOT FIX THE GENERATED FILE. internal/nfs41/xdr/PROVENANCE.md requires that
// `make regen-xdr` leave the tree clean, and says that byte-stability is the only
// evidence the 506 KB generated file was never hand-edited. A patch to xdrReadN
// would be reverted by the next regeneration and would spend that guarantee. The
// four existing modifications are all edits to the .x inputs, and no .x construct
// changes how goxdr emits its reader, so that route does not exist either.
//
// WHAT THIS DECODES. Only the reply shapes this client issues, and it reports
// rather than guesses when it meets anything else: decodeCompoundFast returns
// ok=false and the caller falls back to ParseCompound. That keeps the generated
// decoder as the reference implementation for every cold path, and means a reply
// this file has never seen is slow, never wrong.
//
// It reads from the reply slice directly. Every []byte it returns — filehandles,
// names, attribute values — aliases that slice rather than copying it, which is
// the other half of the win. Callers that retain one past the reply's lifetime
// must clone it; ReadDir already does, via cloneRef.

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// errShortReply is returned when the reply ends mid-field. It is not an error
// worth distinguishing from any other malformed reply: the caller falls back to
// the generated decoder, which will produce its own diagnosis.
var errShortReply = errors.New("nfs41: COMPOUND reply ended mid-field")

// cursor is a bounds-checked reader over the reply body. Every method leaves the
// cursor unchanged and reports false on underflow, so a truncated reply can never
// read past the slice or panic.
type cursor struct {
	b []byte
	i int
}

func (c *cursor) remaining() int { return len(c.b) - c.i }

func (c *cursor) uint32() (uint32, bool) {
	if c.remaining() < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(c.b[c.i:])
	c.i += 4
	return v, true
}

func (c *cursor) uint64() (uint64, bool) {
	if c.remaining() < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(c.b[c.i:])
	c.i += 8
	return v, true
}

// opaque reads an XDR variable-length opaque: a length, the bytes, then padding
// to a four-byte boundary. The returned slice aliases the reply.
func (c *cursor) opaque() ([]byte, bool) {
	n, ok := c.uint32()
	if !ok {
		return nil, false
	}
	padded := (int(n) + 3) & ^3
	// The padded length is checked, not just n: a reply whose final opaque omits
	// its padding is malformed, and accepting it here would leave the cursor
	// misaligned for everything after it.
	if padded < 0 || c.remaining() < padded {
		return nil, false
	}
	v := c.b[c.i : c.i+int(n)]
	c.i += padded
	return v, true
}

// fixedOpaque reads n bytes with no length prefix, for the fixed-width fields
// XDR declares as `opaque x[n]` — sessionid4 and verifier4.
func (c *cursor) fixedOpaque(n int) ([]byte, bool) {
	if c.remaining() < n {
		return nil, false
	}
	v := c.b[c.i : c.i+n]
	c.i += n
	return v, true
}

// skip advances without reading, for the fields of operations whose results this
// client never inspects.
func (c *cursor) skip(n int) bool {
	if n < 0 || c.remaining() < n {
		return false
	}
	c.i += n
	return true
}

// skipChangeInfo skips a change_info4: bool(4) + before(8) + after(8) = 20 bytes.
func (c *cursor) skipChangeInfo() bool { return c.skip(20) }

// skipDelegation skips an Open_delegation4 union. OPEN_DELEGATE_NONE is the
// common case from FlashBlade (4 bytes). READ and WRITE delegations carry a
// stateid(16) + recall(4) + ACE, but FlashBlade never grants them; declining
// (returning false) falls back to the generated decoder for safety.
func (c *cursor) skipDelegation() bool {
	dt, ok := c.uint32()
	if !ok {
		return false
	}
	if dt == uint32(xdr.OPEN_DELEGATE_NONE) {
		return true
	}
	return false
}

// fastResult is one operation's result, decoded only as far as this client reads
// it. It is deliberately not xdr.Nfs_resop4: constructing those is most of what
// the generated decoder spends its time on.
type fastResult struct {
	Op     uint32
	Status uint32

	// FH is set by GETFH. Aliases the reply.
	FH []byte

	// Attrs is set by GETATTR: requested bit -> raw value bytes, each aliasing
	// the reply. Nil when the operation was not a GETATTR.
	Attrs attrList

	// SetBits is the attribute bitmap a SETATTR reports it set.
	SetBits []uint32

	// Stateid is set by OPEN and CLOSE.
	Stateid [16]byte

	// The READDIR fields. Entries aliases the reply throughout.
	Verifier [8]byte
	Entries  []fastDirent
	EOF      bool

	// The SEQUENCE fields, all of them, so session.do can validate the reply
	// against the slot it sent.
	SessionID           [16]byte
	SequenceID          uint32
	SlotID              uint32
	HighestSlotID       uint32
	TargetHighestSlotID uint32
	SequenceFlags       uint32
}

// fastDirent is one READDIR entry, with its attributes left as raw bytes for the
// caller to interpret exactly as the generated path does.
type fastDirent struct {
	Cookie uint64
	Name   []byte
	Attrs  attrList
}

// decodeCompoundFast decodes a COMPOUND reply body.
//
// ok=false means "this reply contains something this decoder does not handle";
// the caller must fall back to ParseCompound. An error means the reply is
// malformed and the fallback will say so more precisely.
func decodeCompoundFast(b []byte) (status uint32, results []fastResult, ok bool, err error) {
	c := &cursor{b: b}

	status, got := c.uint32()
	if !got {
		return 0, nil, false, errShortReply
	}
	// The tag, echoed back from the request.
	if _, got := c.opaque(); !got {
		return 0, nil, false, errShortReply
	}
	count, got := c.uint32()
	if !got {
		return 0, nil, false, errShortReply
	}
	// A reply claiming more operations than the remaining bytes could describe is
	// malformed. Four bytes is the smallest possible result (an opnum with a
	// non-OK status truncates there), so this bounds the allocation below without
	// rejecting any well-formed reply.
	if int(count) > c.remaining()/4 {
		return 0, nil, false, errShortReply
	}

	results = make([]fastResult, 0, count)
	for i := uint32(0); i < count; i++ {
		opnum, got := c.uint32()
		if !got {
			return 0, nil, false, errShortReply
		}
		opStatus, got := c.uint32()
		if !got {
			return 0, nil, false, errShortReply
		}
		r := fastResult{Op: opnum, Status: opStatus}

		// A failed operation carries no result body, and the COMPOUND stops at
		// the first failure. Both are RFC 8881 section 15.2 behaviour, and the
		// generated decoder relies on the same rule.
		if opStatus != NFS4_OK {
			results = append(results, r)
			return status, results, true, nil
		}

		switch opnum {
		case uint32(xdr.OP_PUTFH), uint32(xdr.OP_PUTROOTFH):
			// Status only.
		case uint32(xdr.OP_SETATTR):
			// The bitmap of attributes the server reports it set is CAPTURED, not
			// skipped: setAttributes rejects a reply that omits an attribute it
			// asked for, and a fast path that could not see the bitmap would have
			// to drop that check. Silently succeeding on a SETATTR the server
			// partly ignored is the worst failure this client could have.
			bits, got := decodeBitmap(c)
			if !got {
				return 0, nil, false, errShortReply
			}
			r.SetBits = bits
		case uint32(xdr.OP_LOOKUP):
			// LOOKUP4res is status only.
		case uint32(xdr.OP_GETFH):
			fh, got := c.opaque()
			if !got {
				return 0, nil, false, errShortReply
			}
			r.FH = fh
		case uint32(xdr.OP_GETATTR):
			attrs, got := decodeFattr4(c)
			if !got {
				return 0, nil, false, errShortReply
			}
			r.Attrs = attrs
		case uint32(xdr.OP_SEQUENCE):
			// Every field is captured, not skipped. session.do must verify that
			// the reply's sessionid, slotid and sequenceid match what it sent --
			// that check is what detects a reply delivered to the wrong slot --
			// and a fast path that could not supply them would have to duplicate
			// the slot bookkeeping instead of sharing it.
			sid, got := c.fixedOpaque(16)
			if !got {
				return 0, nil, false, errShortReply
			}
			copy(r.SessionID[:], sid)
			for _, field := range []*uint32{&r.SequenceID, &r.SlotID, &r.HighestSlotID, &r.TargetHighestSlotID, &r.SequenceFlags} {
				v, got := c.uint32()
				if !got {
					return 0, nil, false, errShortReply
				}
				*field = v
			}
		case uint32(xdr.OP_READDIR):
			verf, got := c.fixedOpaque(8)
			if !got {
				return 0, nil, false, errShortReply
			}
			copy(r.Verifier[:], verf)
			entries, eof, got := decodeDirlist(c)
			if !got {
				return 0, nil, false, errShortReply
			}
			r.Entries = entries
			r.EOF = eof
		case uint32(xdr.OP_CREATE):
			// CREATE4resok: change_info(bool+2*uint64) + attrset bitmap.
			if !c.skipChangeInfo() {
				return 0, nil, false, errShortReply
			}
			if _, got := decodeBitmap(c); !got {
				return 0, nil, false, errShortReply
			}
		case uint32(xdr.OP_OPEN):
			// OPEN4resok: stateid(seqid+other) + change_info + rflags + attrset + delegation.
			sid, got := c.fixedOpaque(16)
			if !got {
				return 0, nil, false, errShortReply
			}
			copy(r.Stateid[:], sid)
			if !c.skipChangeInfo() {
				return 0, nil, false, errShortReply
			}
			if _, got := c.uint32(); !got { // rflags
				return 0, nil, false, errShortReply
			}
			if _, got := decodeBitmap(c); !got { // attrset
				return 0, nil, false, errShortReply
			}
			if !c.skipDelegation() {
				return 0, nil, false, errShortReply
			}
		case uint32(xdr.OP_CLOSE):
			// CLOSE4resok: stateid.
			sid, got := c.fixedOpaque(16)
			if !got {
				return 0, nil, false, errShortReply
			}
			copy(r.Stateid[:], sid)
		case uint32(xdr.OP_REMOVE):
			// REMOVE4resok: change_info.
			if !c.skipChangeInfo() {
				return 0, nil, false, errShortReply
			}
		default:
			// An operation this decoder has not been taught. Not an error: the
			// generated decoder handles it.
			return 0, nil, false, nil
		}
		results = append(results, r)
	}

	if c.remaining() != 0 {
		return 0, nil, false, fmt.Errorf("nfs41: COMPOUND reply has %d trailing bytes", c.remaining())
	}
	return status, results, true, nil
}

// decodeFattr4 decodes a bitmap plus its packed attribute values into a map of
// attribute bit to raw bytes, matching what getAttrResult produces from the
// generated structs.
//
// The attribute values arrive as one opaque blob whose internal layout is implied
// by the bitmap, in increasing bit order. Every attribute this client requests has
// to be walked to find the end of the one after it, which is why an unrecognised
// attribute has to abandon the whole decode rather than skip a field: its width is
// unknown, so nothing after it can be located.
// attrPair is one decoded fattr4 attribute: the requested bit and its raw value,
// which aliases the reply.
type attrPair struct {
	bit   uint32
	value []byte
}

// attrList is a decoded fattr4. It replaces the map this used to build, for one
// reason that only shows up at scale: a map was allocated PER DIRECTORY ENTRY,
// and a READDIR reply carries hundreds. A run over 1.1M objects spent 382 MB
// here, and hashed a uint32 four times per entry to read back four keys.
//
// A linear scan is faster than hashing at these lengths -- the client requests
// four attributes and the decoder understands seven, so the scan is over single
// digits and the whole list fits in a cache line or two. The win is the
// allocation, not the lookup: one exactly-sized slice instead of an hmap plus its
// bucket.
type attrList []attrPair

// get returns the raw value for bit. The second result distinguishes "absent"
// from "present and empty", which callers rely on to tell a server that omitted
// an attribute from one that sent a zero-length value.
func (a attrList) get(bit uint32) ([]byte, bool) {
	for _, p := range a {
		if p.bit == bit {
			return p.value, true
		}
	}
	return nil, false
}

func decodeFattr4(c *cursor) (attrList, bool) {
	bits, ok := decodeBitmap(c)
	if !ok {
		return nil, false
	}
	blob, ok := c.opaque()
	if !ok {
		return nil, false
	}
	if len(bits) == 0 {
		return nil, true
	}

	inner := &cursor{b: blob}
	attrs := make(attrList, 0, len(bits))
	for _, bit := range bits {
		start := inner.i
		switch bit {
		case fattr4Type, fattr4Mode:
			if !inner.skip(4) {
				return nil, false
			}
		case fattr4MaxFileSize, fattr4Size:
			if !inner.skip(8) {
				return nil, false
			}
		case fattr4FSID:
			// fsid4 is two uint64s.
			if !inner.skip(16) {
				return nil, false
			}
		case fattr4Filehandle:
			if _, ok := inner.opaque(); !ok {
				return nil, false
			}
		case fattr4ACL:
			// Not an opaque: the length prefix counts ACEs, not bytes, so the
			// end of the attribute can only be found by walking every ACE.
			if !skipACEs(inner) {
				return nil, false
			}
		default:
			// Unknown width: nothing after this attribute can be located.
			return nil, false
		}
		attrs = append(attrs, attrPair{bit: bit, value: inner.b[start:inner.i]})
	}
	if inner.remaining() != 0 {
		return nil, false
	}
	return attrs, true
}

// skipACEs advances the cursor past a FATTR4_ACL value, leaving it positioned on
// whatever attribute follows.
//
// RFC 7530 section 6.2.1: the value is an nfsace4 array -- a uint32 count, then
// per ACE a type, a flag and an access mask (three uint32s), then who as a
// variable-length opaque. So the count is a number of ACEs, not a byte length,
// and the only way to find the end is to walk them. That is why this attribute
// used to abandon the whole decode: an attribute of unknown width means nothing
// after it can be located.
//
// The value is left as raw bytes rather than parsed into ACEs, matching every
// other attribute here. Callers that want the ACEs decode them from the bytes --
// nfs4acl.DecodeACL already does, and comparing raw bytes is what the ACL cache
// wants anyway. Parsing here would move work onto the hot path to no purpose.
//
// The count is bounded against the remaining bytes before looping. A malformed
// reply claiming four billion ACEs would otherwise spin through four billion
// failing reads before giving up, and the whole point of the bound is that the
// cost of rejecting a bad reply stays proportional to its size.
func skipACEs(c *cursor) bool {
	count, ok := c.uint32()
	if !ok {
		return false
	}
	// The smallest possible ACE is 16 bytes: three uint32s plus a zero-length
	// who, whose own length prefix is another four.
	const minACESize = 16
	if int(count) > c.remaining()/minACESize {
		return false
	}
	for i := uint32(0); i < count; i++ {
		// type, flag, access_mask.
		if !c.skip(12) {
			return false
		}
		if _, ok := c.opaque(); !ok {
			return false
		}
	}
	return true
}

// decodeBitmap returns the set attribute bits in increasing order, which is the
// order their values are packed in.
func decodeBitmap(c *cursor) ([]uint32, bool) {
	words, ok := c.uint32()
	if !ok {
		return nil, false
	}
	if int(words) > c.remaining()/4 {
		return nil, false
	}
	var bits []uint32
	for w := uint32(0); w < words; w++ {
		word, ok := c.uint32()
		if !ok {
			return nil, false
		}
		for b := uint32(0); b < 32; b++ {
			if word&(1<<b) != 0 {
				bits = append(bits, w*32+b)
			}
		}
	}
	return bits, true
}

// decodeDirlist walks the entry4 chain. XDR encodes it as a linked list: each
// entry is preceded by a "value follows" boolean, and the list is terminated by a
// false followed by the eof flag.
func decodeDirlist(c *cursor) ([]fastDirent, bool, bool) {
	var entries []fastDirent
	for {
		follows, ok := c.uint32()
		if !ok {
			return nil, false, false
		}
		if follows == 0 {
			eof, ok := c.uint32()
			if !ok {
				return nil, false, false
			}
			return entries, eof != 0, true
		}
		cookie, ok := c.uint64()
		if !ok {
			return nil, false, false
		}
		name, ok := c.opaque()
		if !ok {
			return nil, false, false
		}
		attrs, ok := decodeFattr4(c)
		if !ok {
			return nil, false, false
		}
		entries = append(entries, fastDirent{Cookie: cookie, Name: name, Attrs: attrs})
	}
}
