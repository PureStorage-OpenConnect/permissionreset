package nfs41

// A hand-written encoder for the COMPOUND requests this client actually sends.
//
// WHY THIS EXISTS. The same reason as fastdecode.go, one layer over. With the
// decoder off the critical path, a CPU profile of the tool put 11.7% in the
// generated encoder -- xdr.XdrOut.Marshal and the XdrRecurse chain beneath it.
// The pathology is the decoder's in mirror image: goxdr marshals through an
// interface, allocates a four- or eight-byte slice for every scalar it writes
// (xdrPut32, xdrPut64), and grows a bytes.Buffer underneath all of it. At
// --workers 1024 the lab client runs 84% busy, so this is on the critical path.
//
// SAME CONTRACT AS THE DECODER. encodeCompoundFast handles only the operations
// this client sends on its hot paths and reports rather than guesses: an
// operation it has not been taught returns ok=false, and BuildCompound falls
// back to the generated encoder. Session setup -- EXCHANGE_ID, CREATE_SESSION,
// DESTROY_SESSION, RECLAIM_COMPLETE -- deliberately stays on the generated path.
// Those are a handful of calls per connection, they carry the fiddliest
// structures in the protocol (two channel_attrs4 with their RDMA vectors), and
// there is no measurable time in them. Never approximate an encoding to avoid a
// decline: slow, never wrong.
//
// HOW IT IS KEPT HONEST. The generated encoder is the oracle, and bytes are a
// total specification of an encoder, so unlike the decoder there is no room for
// a subtle disagreement to hide. TestFastEncodeAgreesWithTheGeneratedEncoder
// requires the two to produce byte-identical output for every shape this file
// claims to handle, and requires a decline -- not plausible bytes -- for every
// shape it does not.

import (
	"encoding/binary"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// fastEncodeEnabled is the kill switch for the hand-written encoder, the twin of
// fastDecodeEnabled. It is a variable rather than a constant so a test can force
// the generated path and prove it still serves every caller -- a fallback
// nothing exercises is a fallback that has never been shown to work.
var fastEncodeEnabled = true

// xdrZeroPad supplies the padding bytes for an opaque whose length is not a
// multiple of four, indexed by len&3. It mirrors goxdr's xdrZerofill, which is
// what makes the padding bytes zero rather than whatever was in the buffer.
var xdrZeroPad = [4][]byte{{}, {0, 0, 0}, {0, 0}, {0}}

// encodeCompoundFast appends a COMPOUND4args body to dst and returns the grown
// slice.
//
// ok=false means an operation in ops is not handled here and the caller must use
// the generated encoder. dst is returned unmodified in that case: every
// operation is vetted before a single byte is written, so a decline never leaves
// a partly built buffer behind.
func encodeCompoundFast(dst []byte, tag string, ops []xdr.Nfs_argop4) (b []byte, ok bool) {
	for i := range ops {
		switch ops[i].Argop {
		case xdr.OP_PUTFH, xdr.OP_PUTROOTFH, xdr.OP_LOOKUP, xdr.OP_GETFH,
			xdr.OP_GETATTR, xdr.OP_SETATTR, xdr.OP_READDIR, xdr.OP_SEQUENCE,
			xdr.OP_CREATE, xdr.OP_OPEN, xdr.OP_CLOSE, xdr.OP_REMOVE:
		default:
			return dst, false
		}
	}

	out := dst
	if cap(out)-len(out) < compoundSizeHint(tag, ops) {
		grown := make([]byte, len(out), len(out)+compoundSizeHint(tag, ops))
		copy(grown, out)
		out = grown
	}

	// COMPOUND4args is tag, then minorversion, then the operation array with its
	// own count -- in that order, which is not the order the reply uses.
	out = appendString(out, tag)
	out = binary.BigEndian.AppendUint32(out, nfsMinorVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(ops)))

	for i := range ops {
		op := &ops[i]
		out = binary.BigEndian.AppendUint32(out, uint32(op.Argop))
		switch op.Argop {
		case xdr.OP_PUTFH:
			out = appendOpaque(out, op.Opputfh().Object)
		case xdr.OP_PUTROOTFH, xdr.OP_GETFH:
			// Both are void: the opnum is the whole operation.
		case xdr.OP_LOOKUP:
			out = appendOpaque(out, op.Oplookup().Objname)
		case xdr.OP_GETATTR:
			out = appendBitmap(out, op.Opgetattr().Attr_request)
		case xdr.OP_SETATTR:
			args := op.Opsetattr()
			// stateid4 is a seqid followed by twelve opaque bytes -- a fixed
			// array, so no length prefix and no padding. This client sets
			// attributes with the anonymous stateid, which is all zeroes, and
			// OpSetAttr refuses FATTR4_SIZE, the one attribute that would need a
			// real one. The struct is still read rather than assumed zero, so a
			// future caller that fills it in is encoded correctly instead of
			// silently sending zeroes.
			out = binary.BigEndian.AppendUint32(out, args.Stateid.Seqid)
			out = append(out, args.Stateid.Other[:]...)
			// fattr4 is a bitmap plus one attrlist4 opaque. The ACL blob arrives
			// here already encoded, as OpSetACL's contract says; the single outer
			// length and pad are added right here and nowhere else.
			out = appendBitmap(out, args.Obj_attributes.Attrmask)
			out = appendOpaque(out, args.Obj_attributes.Attr_vals)
		case xdr.OP_READDIR:
			args := op.Opreaddir()
			out = binary.BigEndian.AppendUint64(out, args.Cookie)
			// verifier4 is opaque[8], a fixed array: raw bytes, no prefix.
			out = append(out, args.Cookieverf[:]...)
			out = binary.BigEndian.AppendUint32(out, args.Dircount)
			out = binary.BigEndian.AppendUint32(out, args.Maxcount)
			out = appendBitmap(out, args.Attr_request)
		case xdr.OP_SEQUENCE:
			args := op.Opsequence()
			out = append(out, args.Sa_sessionid[:]...)
			out = binary.BigEndian.AppendUint32(out, args.Sa_sequenceid)
			out = binary.BigEndian.AppendUint32(out, args.Sa_slotid)
			out = binary.BigEndian.AppendUint32(out, args.Sa_highest_slotid)
			out = appendBool(out, args.Sa_cachethis)
		case xdr.OP_CREATE:
			args := op.Opcreate()
			// createtype4: type discriminant. Only NF4DIR supported.
			out = binary.BigEndian.AppendUint32(out, uint32(args.Objtype.Type))
			out = appendOpaque(out, []byte(args.Objname))
			out = appendFattr4(out, args.Createattrs)
		case xdr.OP_OPEN:
			args := op.Opopen()
			out = binary.BigEndian.AppendUint32(out, args.Seqid)
			out = binary.BigEndian.AppendUint32(out, uint32(args.Share_access))
			out = binary.BigEndian.AppendUint32(out, uint32(args.Share_deny))
			// open_owner4: clientid + owner opaque
			out = binary.BigEndian.AppendUint64(out, uint64(args.Owner.Clientid))
			out = appendOpaque(out, args.Owner.Owner)
			// openflag4: opentype discriminant
			out = binary.BigEndian.AppendUint32(out, uint32(args.Openhow.Opentype))
			if args.Openhow.Opentype == xdr.OPEN4_CREATE {
				how := args.Openhow.How()
				out = binary.BigEndian.AppendUint32(out, uint32(how.Mode))
				// UNCHECKED4 and GUARDED4 carry createattrs
				out = appendFattr4(out, *how.Createattrs())
			}
			// open_claim4: claim discriminant
			out = binary.BigEndian.AppendUint32(out, uint32(args.Claim.Claim))
			if args.Claim.Claim == xdr.CLAIM_NULL {
				out = appendOpaque(out, []byte(*args.Claim.File()))
			}
		case xdr.OP_CLOSE:
			args := op.Opclose()
			out = binary.BigEndian.AppendUint32(out, args.Seqid)
			// stateid4: seqid + 12 bytes other
			out = binary.BigEndian.AppendUint32(out, args.Open_stateid.Seqid)
			out = append(out, args.Open_stateid.Other[:]...)
		case xdr.OP_REMOVE:
			out = appendOpaque(out, []byte(op.Opremove().Target))
		}
	}
	return out, true
}

func appendFattr4(out []byte, attrs xdr.Fattr4) []byte {
	out = appendBitmap(out, attrs.Attrmask)
	return appendOpaque(out, attrs.Attr_vals)
}

// compoundSizeHint is the exact encoded size of the operations this encoder
// handles, so the buffer is allocated once instead of doubling its way up. It is
// allowed to be wrong -- append would grow the slice -- but being right is what
// turns a growth chain into a single allocation, and that is most of the win.
func compoundSizeHint(tag string, ops []xdr.Nfs_argop4) int {
	// The tag opaque, then minorversion and the operation count.
	size := 4 + len(tag) + xdrPad(len(tag)) + 8
	for i := range ops {
		op := &ops[i]
		size += 4 // the opnum
		switch op.Argop {
		case xdr.OP_PUTFH:
			fh := op.Opputfh().Object
			size += 4 + len(fh) + xdrPad(len(fh))
		case xdr.OP_LOOKUP:
			name := op.Oplookup().Objname
			size += 4 + len(name) + xdrPad(len(name))
		case xdr.OP_GETATTR:
			size += 4 + 4*len(op.Opgetattr().Attr_request)
		case xdr.OP_SETATTR:
			args := op.Opsetattr()
			vals := args.Obj_attributes.Attr_vals
			size += 16 // the stateid
			size += 4 + 4*len(args.Obj_attributes.Attrmask)
			size += 4 + len(vals) + xdrPad(len(vals))
		case xdr.OP_READDIR:
			// cookie, verifier, dircount, maxcount, then the bitmap.
			size += 8 + 8 + 4 + 4
			size += 4 + 4*len(op.Opreaddir().Attr_request)
		case xdr.OP_SEQUENCE:
			size += 16 + 4 + 4 + 4 + 4
		case xdr.OP_CREATE:
			args := op.Opcreate()
			name := []byte(args.Objname)
			size += 4 // type
			size += 4 + len(name) + xdrPad(len(name))
			size += encodedFattr4Size(args.Createattrs)
		case xdr.OP_OPEN:
			args := op.Opopen()
			size += 4 + 4 + 4 // seqid, share_access, share_deny
			size += 8         // clientid
			size += 4 + len(args.Owner.Owner) + xdrPad(len(args.Owner.Owner))
			size += 4 // opentype
			if args.Openhow.Opentype == xdr.OPEN4_CREATE {
				size += 4 // createmode
				size += encodedFattr4Size(*args.Openhow.How().Createattrs())
			}
			size += 4 // claim
			if args.Claim.Claim == xdr.CLAIM_NULL {
				f := []byte(*args.Claim.File())
				size += 4 + len(f) + xdrPad(len(f))
			}
		case xdr.OP_CLOSE:
			size += 4 + 4 + 12 // seqid + stateid(seqid + other)
		case xdr.OP_REMOVE:
			t := []byte(op.Opremove().Target)
			size += 4 + len(t) + xdrPad(len(t))
		}
	}
	return size
}

func encodedFattr4Size(attrs xdr.Fattr4) int {
	return 4 + 4*len(attrs.Attrmask) + 4 + len(attrs.Attr_vals) + xdrPad(len(attrs.Attr_vals))
}

// appendOpaque writes an XDR variable-length opaque: a length, the bytes, then
// zero padding to a four-byte boundary.
func appendOpaque(out []byte, v []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
	out = append(out, v...)
	return append(out, xdrZeroPad[len(v)&3]...)
}

// appendString is appendOpaque for a Go string, which avoids the []byte
// conversion allocating a copy of the tag on every request.
func appendString(out []byte, v string) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
	out = append(out, v...)
	return append(out, xdrZeroPad[len(v)&3]...)
}

// appendBitmap writes a bitmap4: a word count followed by the words.
func appendBitmap(out []byte, words []uint32) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(words)))
	for _, word := range words {
		out = binary.BigEndian.AppendUint32(out, word)
	}
	return out
}

// appendBool writes an XDR bool, which is a four-byte integer.
func appendBool(out []byte, v bool) []byte {
	if v {
		return binary.BigEndian.AppendUint32(out, 1)
	}
	return binary.BigEndian.AppendUint32(out, 0)
}
