package nfs41

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// NFSv4 attribute numbers. Aliased from the generated XDR, which declares them
// as FATTR4_* constants; do not hand-write the numbers.
const (
	fattr4Type        = uint32(xdr.FATTR4_TYPE)        // 1
	fattr4Size        = uint32(xdr.FATTR4_SIZE)        // 4
	fattr4FSID        = uint32(xdr.FATTR4_FSID)        // 8
	fattr4ACL         = uint32(xdr.FATTR4_ACL)         // 12
	fattr4Filehandle  = uint32(xdr.FATTR4_FILEHANDLE)  // 19
	fattr4MaxFileSize = uint32(xdr.FATTR4_MAXFILESIZE) // 27
	fattr4Mode        = uint32(xdr.FATTR4_MODE)        // 33
	fattr4Owner       = uint32(xdr.FATTR4_OWNER)       // 36
	fattr4OwnerGroup  = uint32(xdr.FATTR4_OWNER_GROUP) // 37
)

const nfsMinorVersion = uint32(1)

// Operation and status numbers are aliased from the generated XDR, never
// re-typed. internal/nfs41/xdr/PROVENANCE.md records their RFC verification.
const (
	opGETATTR = uint32(xdr.OP_GETATTR)
	opLOOKUP  = uint32(xdr.OP_LOOKUP)
	opREADDIR = uint32(xdr.OP_READDIR)
	opSETATTR = uint32(xdr.OP_SETATTR)

	NFS4_OK                = uint32(xdr.NFS4_OK)
	NFS4ERR_PERM           = uint32(xdr.NFS4ERR_PERM)
	NFS4ERR_NOENT          = uint32(xdr.NFS4ERR_NOENT)
	NFS4ERR_ACCESS         = uint32(xdr.NFS4ERR_ACCESS)
	NFS4ERR_INVAL          = uint32(xdr.NFS4ERR_INVAL)
	NFS4ERR_STALE          = uint32(xdr.NFS4ERR_STALE)
	NFS4ERR_NOTSUPP        = uint32(xdr.NFS4ERR_NOTSUPP)
	NFS4ERR_OP_ILLEGAL     = uint32(xdr.NFS4ERR_OP_ILLEGAL)
	NFS4ERR_DELAY          = uint32(xdr.NFS4ERR_DELAY)
	NFS4ERR_GRACE          = uint32(xdr.NFS4ERR_GRACE)
	NFS4ERR_BADHANDLE      = uint32(xdr.NFS4ERR_BADHANDLE)
	NFS4ERR_RESOURCE       = uint32(xdr.NFS4ERR_RESOURCE)
	NFS4ERR_TOOSMALL       = uint32(xdr.NFS4ERR_TOOSMALL)
	NFS4ERR_REP_TOO_BIG    = uint32(xdr.NFS4ERR_REP_TOO_BIG)
	NFS4ERR_NOT_SAME       = uint32(xdr.NFS4ERR_NOT_SAME)
	NFS4ERR_BADSESSION     = uint32(xdr.NFS4ERR_BADSESSION)
	NFS4ERR_DEADSESSION    = uint32(xdr.NFS4ERR_DEADSESSION)
	NFS4ERR_BADSLOT        = uint32(xdr.NFS4ERR_BADSLOT)
	NFS4ERR_SEQ_MISORDERED = uint32(xdr.NFS4ERR_SEQ_MISORDERED)

	// NFS4ERR_RETRY_UNCACHED_REP is what a server sends when it will not answer
	// a replay from its duplicate-reply cache. Every request this client makes
	// sets sa_cachethis false, so this is the expected answer to any replay and
	// classify treats it as retryable.
	NFS4ERR_RETRY_UNCACHED_REP = uint32(xdr.NFS4ERR_RETRY_UNCACHED_REP)

	// The rest are statuses the fake server models and production code needs to
	// name. NFS4ERR_STALE_CLIENTID in particular is the one that tells the pool a
	// registration is gone rather than just a session, and NFS4ERR_BADXDR is what
	// a real server returns for a malformed attrlist4 — the exact failure the
	// golden capture caught in an earlier revision of the encoder, so it is worth
	// naming and logging clearly rather than folding into a generic failure.
	NFS4ERR_NOFILEHANDLE   = uint32(xdr.NFS4ERR_NOFILEHANDLE)
	NFS4ERR_NOTDIR         = uint32(xdr.NFS4ERR_NOTDIR)
	NFS4ERR_ATTRNOTSUPP    = uint32(xdr.NFS4ERR_ATTRNOTSUPP)
	NFS4ERR_BAD_COOKIE     = uint32(xdr.NFS4ERR_BAD_COOKIE)
	NFS4ERR_STALE_CLIENTID = uint32(xdr.NFS4ERR_STALE_CLIENTID)
	NFS4ERR_BADXDR         = uint32(xdr.NFS4ERR_BADXDR)
	NFS4ERR_EXIST          = uint32(xdr.NFS4ERR_EXIST)
)

// BuildCompound marshals an NFSv4.1 COMPOUND request.
//
// It tries the hand-written encoder first and falls back to the generated one
// for any operation fastencode.go has not been taught. A decline is not an
// error and must not be reported as one: the generated encoder is the reference
// implementation and handles every request this client can build, so declining
// costs speed and nothing else.
func BuildCompound(tag string, ops []xdr.Nfs_argop4) (b []byte, err error) {
	if fastEncodeEnabled {
		if fast, ok := encodeCompoundFast(nil, tag, ops); ok {
			return fast, nil
		}
	}
	return buildCompoundGenerated(tag, ops)
}

// buildCompoundGenerated is the reference encoder, kept separate so the
// differential test can use it as an oracle without going through the toggle.
func buildCompoundGenerated(tag string, ops []xdr.Nfs_argop4) (b []byte, err error) {
	defer recoverXDR(&err)

	args := xdr.COMPOUND4args{
		Tag:          []byte(tag),
		Minorversion: nfsMinorVersion,
		Argarray:     ops,
	}
	var buf bytes.Buffer
	args.XdrMarshal(xdr.XdrOut{Out: &buf}, "")
	return buf.Bytes(), nil
}

// ParseCompound unmarshals an NFSv4 COMPOUND reply body.
func ParseCompound(b []byte) (status uint32, results []xdr.Nfs_resop4, err error) {
	defer recoverXDR(&err)

	r := bytes.NewReader(b)
	var reply xdr.COMPOUND4res
	reply.XdrMarshal(xdr.XdrIn{In: r}, "")
	if r.Len() != 0 {
		return 0, nil, fmt.Errorf("nfs41: COMPOUND reply has %d trailing bytes", r.Len())
	}
	return uint32(reply.Status), reply.Resarray, nil
}

func recoverXDR(errp *error) {
	if r := recover(); r != nil {
		if err, ok := r.(xdr.XdrError); ok {
			*errp = err
			return
		}
		if err, ok := r.(error); ok && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			// XdrIn normally wraps read failures in XdrError, but its fixed-array
			// path panics with io.ReadFull's EOF error directly.
			*errp = fmt.Errorf("xdr: %w", err)
			return
		}
		panic(r)
	}
}

// OpPutFH selects fh as the current filehandle.
func OpPutFH(fh []byte) xdr.Nfs_argop4 {
	op := xdr.Nfs_argop4{Argop: xdr.OP_PUTFH}
	op.Opputfh().Object = fh
	return op
}

// OpPutRootFH selects the server's root filehandle.
func OpPutRootFH() xdr.Nfs_argop4 {
	return xdr.Nfs_argop4{Argop: xdr.OP_PUTROOTFH}
}

// OpLookup selects name relative to the current directory filehandle.
func OpLookup(name string) xdr.Nfs_argop4 {
	op := xdr.Nfs_argop4{Argop: xdr.OP_LOOKUP}
	op.Oplookup().Objname = []byte(name)
	return op
}

// OpGetFH asks the server to return the current filehandle.
func OpGetFH() xdr.Nfs_argop4 {
	return xdr.Nfs_argop4{Argop: xdr.OP_GETFH}
}

// OpGetAttr asks for the named attributes of the current object.
func OpGetAttr(bits ...uint32) xdr.Nfs_argop4 {
	op := xdr.Nfs_argop4{Argop: xdr.OP_GETATTR}
	op.Opgetattr().Attr_request = attributeBitmap(bits)
	return op
}

// OpSetAttr sets attributes using the anonymous stateid.
//
// The anonymous stateid is legal for every attribute except FATTR4_SIZE. Since
// Nfs_argop4 constructors cannot return an error, an attempt to set SIZE fails
// immediately rather than putting a request on the wire that the server must
// reject.
func OpSetAttr(bits []uint32, values [][]byte) xdr.Nfs_argop4 {
	for _, bit := range bits {
		if bit == fattr4Size {
			panic("nfs41: FATTR4_SIZE requires a non-anonymous stateid")
		}
	}
	bitmap, attrs := EncodeAttrList(bits, values)
	op := xdr.Nfs_argop4{Argop: xdr.OP_SETATTR}
	op.Opsetattr().Obj_attributes = xdr.Fattr4{
		Attrmask:  bitmap,
		Attr_vals: attrs,
	}
	return op
}

// OpSetACL sets FATTR4_ACL using the anonymous stateid.
//
// acl is already the complete XDR encoding of fattr4_acl. It is passed through
// byte-for-byte; marshaling xdr.Fattr4 supplies the single outer attrlist4
// opaque wrapper.
func OpSetACL(acl []byte) xdr.Nfs_argop4 {
	return OpSetAttr([]uint32{fattr4ACL}, [][]byte{acl})
}

// OpCreateDir creates a directory relative to the current filehandle with
// createattrs. Returns the new directory's change info and attrset.
func OpCreateDir(name string, bits []uint32, values [][]byte) xdr.Nfs_argop4 {
	bitmap, attrs := EncodeAttrList(bits, values)
	op := xdr.Nfs_argop4{Argop: xdr.OP_CREATE}
	ca := op.Opcreate()
	ca.Objtype.Type = xdr.NF4DIR
	ca.Objname = xdr.Component4(name)
	ca.Createattrs = xdr.Fattr4{Attrmask: bitmap, Attr_vals: attrs}
	return op
}

// OpOpenCreate creates a regular file relative to the current filehandle using
// OPEN(CREATE, GUARDED4) with the given createattrs. The GUARDED4 mode fails
// with NFS4ERR_EXIST if the file already exists.
//
// clientID and owner identify the open-owner; seqid is 0 per RFC 5661 §8.13.
func OpOpenCreate(name string, clientID xdr.Clientid4, owner []byte, bits []uint32, values [][]byte) xdr.Nfs_argop4 {
	bitmap, attrs := EncodeAttrList(bits, values)
	op := xdr.Nfs_argop4{Argop: xdr.OP_OPEN}
	oa := op.Opopen()
	oa.Seqid = 0
	oa.Share_access = xdr.OPEN4_SHARE_ACCESS_WRITE
	oa.Share_deny = xdr.OPEN4_SHARE_DENY_NONE
	oa.Owner = xdr.Open_owner4{Clientid: clientID, Owner: owner}
	oa.Openhow.Opentype = xdr.OPEN4_CREATE
	how := oa.Openhow.How()
	how.Mode = xdr.GUARDED4
	*how.Createattrs() = xdr.Fattr4{Attrmask: bitmap, Attr_vals: attrs}
	oa.Claim.Claim = xdr.CLAIM_NULL
	*oa.Claim.File() = xdr.Component4(name)
	return op
}

// OpClose closes an open stateid. Pass the current stateid (seqid=1, other=0)
// to close the OPEN from the same COMPOUND without knowing its stateid in advance.
func OpClose(stateid xdr.Stateid4) xdr.Nfs_argop4 {
	op := xdr.Nfs_argop4{Argop: xdr.OP_CLOSE}
	ca := op.Opclose()
	ca.Seqid = 0
	ca.Open_stateid = stateid
	return op
}

// OpCloseCurrent closes the COMPOUND's current stateid — set by the
// preceding OPEN in the same COMPOUND.
func OpCloseCurrent() xdr.Nfs_argop4 {
	return OpClose(xdr.Stateid4{Seqid: 1})
}

// OpRemove removes a file or empty directory relative to the current filehandle.
func OpRemove(name string) xdr.Nfs_argop4 {
	op := xdr.Nfs_argop4{Argop: xdr.OP_REMOVE}
	op.Opremove().Target = xdr.Component4(name)
	return op
}

// OpReadDir reads a page of the current directory and requests bits for each
// returned entry.
func OpReadDir(cookie uint64, verf [8]byte, dircount, maxcount uint32, bits ...uint32) xdr.Nfs_argop4 {
	op := xdr.Nfs_argop4{Argop: xdr.OP_READDIR}
	*op.Opreaddir() = xdr.READDIR4args{
		Cookie:       cookie,
		Cookieverf:   verf,
		Dircount:     dircount,
		Maxcount:     maxcount,
		Attr_request: attributeBitmap(bits),
	}
	return op
}

// OpSequence starts a session-bound COMPOUND. Reply caching is disabled because
// every operation this client issues is idempotent.
func OpSequence(sessionID [16]byte, seqID uint32, slotID, highestSlotID uint32) xdr.Nfs_argop4 {
	op := xdr.Nfs_argop4{Argop: xdr.OP_SEQUENCE}
	*op.Opsequence() = xdr.SEQUENCE4args{
		Sa_sessionid:      sessionID,
		Sa_sequenceid:     seqID,
		Sa_slotid:         slotID,
		Sa_highest_slotid: highestSlotID,
		Sa_cachethis:      false,
	}
	return op
}

// EncodeAttrList packs attribute values into the fattr4 wire form: a bitmap
// naming which attributes are present, and their values concatenated in
// ascending attribute order with no delimiter between them.
//
// Each value must already be its complete XDR field encoding. The single
// attrlist4 length and pad are added later when xdr.Fattr4 is marshaled.
func EncodeAttrList(bits []uint32, values [][]byte) (bitmap []uint32, attrs []byte) {
	if len(bits) != len(values) {
		panic(fmt.Sprintf("nfs41: %d attribute bits but %d values", len(bits), len(values)))
	}

	type attribute struct {
		bit   uint32
		value []byte
	}
	ordered := make([]attribute, len(bits))
	for i, bit := range bits {
		ordered[i] = attribute{bit: bit, value: values[i]}
	}
	slices.SortFunc(ordered, func(a, b attribute) int {
		if a.bit < b.bit {
			return -1
		}
		if a.bit > b.bit {
			return 1
		}
		return 0
	})

	bitmap = attributeBitmap(bits)
	total := 0
	for _, attr := range ordered {
		total += len(attr.value)
	}
	attrs = make([]byte, 0, total)
	for i, attr := range ordered {
		if i > 0 && ordered[i-1].bit == attr.bit {
			panic(fmt.Sprintf("nfs41: duplicate attribute %d", attr.bit))
		}
		attrs = append(attrs, attr.value...)
	}
	return bitmap, attrs
}

func attributeBitmap(bits []uint32) []uint32 {
	if len(bits) == 0 {
		return nil
	}
	maxBit := slices.Max(bits)
	bitmap := make([]uint32, maxBit/32+1)
	for _, bit := range bits {
		bitmap[bit/32] |= uint32(1) << (bit % 32)
	}
	return bitmap
}

// DecodeAttrList unpacks a fattr4 into complete XDR field encodings keyed by
// attribute number. It walks the bitmap in ascending order because attr_vals
// carries no per-attribute delimiter. Variable-width values retain their own
// framing; for example, a filehandle includes its length prefix and padding.
func DecodeAttrList(bitmap []uint32, attrs []byte) (map[uint32][]byte, error) {
	decoded := make(map[uint32][]byte)
	off := 0
	for word, mask := range bitmap {
		for bit := uint32(0); bit < 32; bit++ {
			if mask&(uint32(1)<<bit) == 0 {
				continue
			}
			attr := uint32(word)*32 + bit
			n, err := encodedAttributeLength(attr, attrs[off:])
			if err != nil {
				return nil, err
			}
			decoded[attr] = slices.Clone(attrs[off : off+n])
			off += n
		}
	}
	if off != len(attrs) {
		return nil, fmt.Errorf("nfs41: attrlist4 has %d trailing bytes after its bitmap", len(attrs)-off)
	}
	return decoded, nil
}

func encodedAttributeLength(attr uint32, b []byte) (int, error) {
	switch attr {
	case uint32(xdr.FATTR4_TYPE),
		uint32(xdr.FATTR4_FH_EXPIRE_TYPE),
		uint32(xdr.FATTR4_LINK_SUPPORT),
		uint32(xdr.FATTR4_SYMLINK_SUPPORT),
		uint32(xdr.FATTR4_NAMED_ATTR),
		uint32(xdr.FATTR4_UNIQUE_HANDLES),
		uint32(xdr.FATTR4_LEASE_TIME),
		uint32(xdr.FATTR4_RDATTR_ERROR),
		uint32(xdr.FATTR4_ACLSUPPORT),
		uint32(xdr.FATTR4_ARCHIVE),
		uint32(xdr.FATTR4_CANSETTIME),
		uint32(xdr.FATTR4_CASE_INSENSITIVE),
		uint32(xdr.FATTR4_CASE_PRESERVING),
		uint32(xdr.FATTR4_CHOWN_RESTRICTED),
		uint32(xdr.FATTR4_HIDDEN),
		uint32(xdr.FATTR4_HOMOGENEOUS),
		uint32(xdr.FATTR4_MAXLINK),
		uint32(xdr.FATTR4_MAXNAME),
		uint32(xdr.FATTR4_MODE),
		uint32(xdr.FATTR4_NO_TRUNC),
		uint32(xdr.FATTR4_NUMLINKS),
		uint32(xdr.FATTR4_SYSTEM):
		return requireAttributeBytes(attr, b, 4)

	case uint32(xdr.FATTR4_CHANGE),
		uint32(xdr.FATTR4_SIZE),
		uint32(xdr.FATTR4_FILEID),
		uint32(xdr.FATTR4_FILES_AVAIL),
		uint32(xdr.FATTR4_FILES_FREE),
		uint32(xdr.FATTR4_FILES_TOTAL),
		uint32(xdr.FATTR4_MAXFILESIZE),
		uint32(xdr.FATTR4_MAXREAD),
		uint32(xdr.FATTR4_MAXWRITE),
		uint32(xdr.FATTR4_MOUNTED_ON_FILEID),
		uint32(xdr.FATTR4_QUOTA_AVAIL_HARD),
		uint32(xdr.FATTR4_QUOTA_AVAIL_SOFT),
		uint32(xdr.FATTR4_QUOTA_USED),
		uint32(xdr.FATTR4_SPACE_AVAIL),
		uint32(xdr.FATTR4_SPACE_FREE),
		uint32(xdr.FATTR4_SPACE_TOTAL),
		uint32(xdr.FATTR4_SPACE_USED),
		uint32(xdr.FATTR4_RAWDEV):
		return requireAttributeBytes(attr, b, 8)

	case uint32(xdr.FATTR4_FSID):
		return requireAttributeBytes(attr, b, 16)

	case uint32(xdr.FATTR4_TIME_ACCESS),
		uint32(xdr.FATTR4_TIME_BACKUP),
		uint32(xdr.FATTR4_TIME_CREATE),
		uint32(xdr.FATTR4_TIME_DELTA),
		uint32(xdr.FATTR4_TIME_METADATA),
		uint32(xdr.FATTR4_TIME_MODIFY):
		return requireAttributeBytes(attr, b, 12)

	case uint32(xdr.FATTR4_SUPPORTED_ATTRS):
		return encodedBitmapLength(attr, b)

	case uint32(xdr.FATTR4_FILEHANDLE),
		uint32(xdr.FATTR4_MIMETYPE),
		uint32(xdr.FATTR4_OWNER),
		uint32(xdr.FATTR4_OWNER_GROUP):
		return encodedOpaqueLength(attr, b)

	case uint32(xdr.FATTR4_ACL):
		return encodedACLLength(attr, b)

	case uint32(xdr.FATTR4_TIME_ACCESS_SET),
		uint32(xdr.FATTR4_TIME_MODIFY_SET):
		return encodedSettimeLength(attr, b)

	default:
		return 0, fmt.Errorf("nfs41: cannot determine the XDR length of attribute %d", attr)
	}
}

func requireAttributeBytes(attr uint32, b []byte, n int) (int, error) {
	if len(b) < n {
		return 0, fmt.Errorf("nfs41: attribute %d is truncated: need %d bytes, have %d", attr, n, len(b))
	}
	return n, nil
}

func xdrPadding(n uint64) uint64 {
	return (4 - n%4) % 4
}

func encodedOpaqueLength(attr uint32, b []byte) (int, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("nfs41: attribute %d is truncated before its length", attr)
	}
	n := uint64(binary.BigEndian.Uint32(b[:4]))
	total := uint64(4) + n + xdrPadding(n)
	if total > uint64(len(b)) {
		return 0, fmt.Errorf("nfs41: attribute %d is truncated: encoded length %d, have %d", attr, total, len(b))
	}
	return int(total), nil
}

func encodedBitmapLength(attr uint32, b []byte) (int, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("nfs41: attribute %d is truncated before its bitmap word count", attr)
	}
	count := uint64(binary.BigEndian.Uint32(b[:4]))
	total := uint64(4) + count*4
	if total > uint64(len(b)) {
		return 0, fmt.Errorf("nfs41: attribute %d is truncated: encoded length %d, have %d", attr, total, len(b))
	}
	return int(total), nil
}

func encodedACLLength(attr uint32, b []byte) (int, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("nfs41: attribute %d is truncated before its ACE count", attr)
	}
	count := binary.BigEndian.Uint32(b[:4])
	off := 4
	for i := uint32(0); i < count; i++ {
		if len(b)-off < 16 {
			return 0, fmt.Errorf("nfs41: attribute %d ACE %d is truncated", attr, i)
		}
		whoLen := uint64(binary.BigEndian.Uint32(b[off+12 : off+16]))
		aceLen := uint64(16) + whoLen + xdrPadding(whoLen)
		if aceLen > uint64(len(b)-off) {
			return 0, fmt.Errorf("nfs41: attribute %d ACE %d is truncated", attr, i)
		}
		off += int(aceLen)
	}
	return off, nil
}

func encodedSettimeLength(attr uint32, b []byte) (int, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("nfs41: attribute %d is truncated before settime4", attr)
	}
	switch int32(binary.BigEndian.Uint32(b[:4])) {
	case int32(xdr.SET_TO_SERVER_TIME4):
		return 4, nil
	case int32(xdr.SET_TO_CLIENT_TIME4):
		return requireAttributeBytes(attr, b, 16)
	default:
		return 0, fmt.Errorf("nfs41: attribute %d has invalid settime4 discriminant %d", attr, binary.BigEndian.Uint32(b[:4]))
	}
}

// splitCompoundOps returns raw operation encodings from a captured COMPOUND
// request. It decodes each operation body with goxdr so op numbers inside a
// preceding payload cannot be mistaken for operation boundaries.
func splitCompoundOps(b []byte) (ops [][]byte, err error) {
	defer recoverXDR(&err)

	payload, err := compoundPayload(b)
	if err != nil {
		return nil, err
	}
	d := wireDecoder{b: payload}
	if _, err := d.opaque("COMPOUND tag"); err != nil {
		return nil, err
	}
	minor, err := d.word("COMPOUND minor version")
	if err != nil {
		return nil, err
	}
	if minor != nfsMinorVersion {
		return nil, fmt.Errorf("nfs41: COMPOUND minor version is %d, want %d", minor, nfsMinorVersion)
	}
	count, err := d.word("COMPOUND operation count")
	if err != nil {
		return nil, err
	}
	if uint64(count)*4 > uint64(len(payload)-d.off) {
		return nil, fmt.Errorf("nfs41: COMPOUND operation count %d exceeds its %d-byte payload", count, len(payload)-d.off)
	}
	ops = make([][]byte, 0, count)
	for range count {
		start := d.off
		var op xdr.Nfs_argop4
		op.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: &d}}, "")
		ops = append(ops, payload[start:d.off])
	}
	if d.off != len(payload) {
		return nil, fmt.Errorf("nfs41: COMPOUND request has %d trailing bytes", len(payload)-d.off)
	}
	return ops, nil
}

func compoundPayload(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, errors.New("nfs41: captured COMPOUND is truncated")
	}
	// BuildCompound output starts directly with the XDR tag length. A Task 4 call
	// capture starts at the record marker and includes the RPC call header. A
	// record marker is unambiguous only when its final bit and length both match.
	//
	// The two disagreement cases are distinguished rather than both falling
	// through to "assume it is a bare COMPOUND". A capture is the likely source
	// of either: `tshark -e tcp.payload` emits a TCP segment, and servers
	// routinely coalesce two RPC records into one segment or split one across
	// two. Falling through would then report "COMPOUND minor version is
	// <garbage>, want 1", which reads as "our XDR is wrong" rather than "the
	// capture is framed differently than you assumed" -- and that is a long way
	// to chase for a three-line diagnostic.
	mark := binary.BigEndian.Uint32(b[:4])
	if mark&lastFragment != 0 && mark&fragmentLengthMask != uint32(len(b)-4) {
		return nil, fmt.Errorf("nfs41: record marker declares a %d byte final fragment but the input holds %d; "+
			"a capture containing more or less than exactly one RPC record needs readRecord to reframe it",
			mark&fragmentLengthMask, len(b)-4)
	}
	if mark&lastFragment == 0 {
		return b, nil
	}

	d := wireDecoder{b: b, off: 4}
	header := []struct {
		field string
		want  uint32
		check bool
	}{
		{field: "xid"},
		{field: "message type", want: uint32(xdr.CALL), check: true},
		{field: "RPC version", want: rpcVersion, check: true},
		{field: "program", want: nfsProgram, check: true},
		{field: "program version", want: nfsProgramVersion, check: true},
		{field: "procedure", want: nfsProcCompound, check: true},
	}
	for _, field := range header {
		got, err := d.word(field.field)
		if err != nil {
			return nil, err
		}
		if field.check && got != field.want {
			return nil, fmt.Errorf("nfs41: captured RPC %s is %d, want %d", field.field, got, field.want)
		}
	}
	if _, err := d.word("credential flavor"); err != nil {
		return nil, err
	}
	if _, err := d.opaque("credential body"); err != nil {
		return nil, err
	}
	if _, err := d.word("verifier flavor"); err != nil {
		return nil, err
	}
	if _, err := d.opaque("verifier body"); err != nil {
		return nil, err
	}
	return b[d.off:], nil
}

type wireDecoder struct {
	b   []byte
	off int
}

func (d *wireDecoder) word(field string) (uint32, error) {
	if len(d.b)-d.off < 4 {
		return 0, fmt.Errorf("nfs41: truncated %s", field)
	}
	v := binary.BigEndian.Uint32(d.b[d.off : d.off+4])
	d.off += 4
	return v, nil
}

func (d *wireDecoder) opaque(field string) ([]byte, error) {
	n, err := d.word(field + " length")
	if err != nil {
		return nil, err
	}
	length := uint64(n)
	total := length + xdrPadding(length)
	if total > uint64(len(d.b)-d.off) {
		return nil, fmt.Errorf("nfs41: truncated %s: need %d bytes, have %d", field, total, len(d.b)-d.off)
	}
	value := d.b[d.off : d.off+int(n)]
	d.off += int(total)
	return value, nil
}

type decoderReader struct {
	d *wireDecoder
}

func (r *decoderReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.d.off >= len(r.d.b) {
		return 0, io.EOF
	}
	n := copy(p, r.d.b[r.d.off:])
	r.d.off += n
	return n, nil
}
