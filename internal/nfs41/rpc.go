package nfs41

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

const (
	// maxRecordSize bounds a single reassembled RPC record. A server that
	// claims more than this is either broken or hostile, and the alternative
	// is an allocation sized by the peer.
	maxRecordSize = 8 << 20

	lastFragment       = uint32(1 << 31)
	fragmentLengthMask = lastFragment - 1

	rpcVersion = uint32(2)

	// The NFSv4 RPC program triple, from xdr/nfs4.x:2245-2252:
	//
	//	program NFS4_PROGRAM { version NFS_V4 { ... } = 4; } = 100003;
	//	NFSPROC4_COMPOUND(COMPOUND4args) = 1;
	//
	// Named here rather than aliased because goxdr emits these only as methods
	// on the unexported xdrProc_NFSPROC4_COMPOUND, so there is no xdr.* symbol
	// to alias -- the one place in this package where the
	// alias-don't-transcribe rule cannot be satisfied literally. Naming them
	// once is the next best thing: hand-typing 100003 at each Conn.Call site is
	// how a wrong program number becomes a connection that fails with
	// PROG_UNAVAIL for no visible reason.
	nfsProgram        = uint32(100003)
	nfsProgramVersion = uint32(4)
	nfsProcCompound   = uint32(1)

	// These bounds come from opaque_auth.body and authsys_parms in xdr/rpc.x
	// and xdr/nfs4.x. The generated package does not expose bound constants.
	maxOpaqueAuth  = 400
	maxMachineName = 255
	maxAuxGIDs     = 16
)

// TLS INJECTION POINT 1 of 2 — see docs/superpowers/specs/
// 2026-08-20-nfsv41-userspace-transport-design.md section 12.
// Dialer is the only route by which this package creates a net.Conn. RFC 9289
// support can wrap the connection with its AUTH_TLS probe and TLS handshake in
// another Dialer without changing the RPC or NFS layers.
type Dialer func(ctx context.Context) (net.Conn, error)

// TCPDialer returns a plain TCP Dialer. A TLS Dialer will join it in phase 6.
func TCPDialer(addr string) Dialer {
	var d net.Dialer
	return func(ctx context.Context) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	}
}

// AuthSys is the AUTH_SYS credential sent with every call. NFS servers use
// these values when making permission decisions.
type AuthSys struct {
	Stamp   uint32
	Machine string
	UID     uint32
	GID     uint32
	AuxGIDs []uint32
}

// recordMark prefixes payload with an ONC RPC record marker. We send each call
// as one fragment, so the last-fragment bit is always set.
func recordMark(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	copy(out[4:], payload)
	markRecord(out)
	return out
}

// markRecord fills the marker slot reserved by buildCall without copying the
// payload. recordMark remains separate because tests and the fake server frame
// replies that were not built by buildCall.
func markRecord(record []byte) {
	length := len(record) - 4
	if length < 0 || uint64(length) > uint64(fragmentLengthMask) {
		panic(fmt.Sprintf("nfs41: cannot mark a %d-byte RPC record", length))
	}
	binary.BigEndian.PutUint32(record[:4], lastFragment|uint32(length))
}

// readRecord reassembles one complete ONC RPC record. Servers may split a
// reply into multiple fragments even though this client sends one fragment per
// call. The limit applies to the complete record as well as each fragment.
func readRecord(r io.Reader) ([]byte, error) {
	var out []byte
	for {
		var marker [4]byte
		if _, err := io.ReadFull(r, marker[:]); err != nil {
			return nil, fmt.Errorf("rpc: read record marker: %w", err)
		}

		word := binary.BigEndian.Uint32(marker[:])
		last := word&lastFragment != 0
		n := int(word & fragmentLengthMask)
		if !last && n == 0 {
			return nil, errors.New("rpc: non-final record fragment has zero length")
		}
		if n > maxRecordSize-len(out) {
			return nil, fmt.Errorf(
				"rpc: record exceeds the %d-byte limit (have %d, next fragment %d)",
				maxRecordSize, len(out), n,
			)
		}

		start := len(out)
		if start == 0 {
			out = make([]byte, n)
		} else {
			out = append(out, make([]byte, n)...)
		}
		if _, err := io.ReadFull(r, out[start:]); err != nil {
			return nil, fmt.Errorf("rpc: read %d-byte record fragment: %w", n, err)
		}
		if last {
			return out, nil
		}
	}
}

// ErrConnClosed identifies a connection that can no longer carry calls. The
// retry classifier treats it as a rebuild-the-session condition.
var ErrConnClosed = errors.New("nfs41: connection closed")

// ErrNotSent marks a Call that failed BEFORE the record reached the writer, so
// the server provably never saw it. Callers test for it with errors.Is.
//
// This distinction is not cosmetic, and a caller holding sequence state cannot
// work without it. A slot's seqid is consumed at acquire, so:
//
//   - not sent: the server never observed that seqid. Reusing the slot for the
//     next request sends seqid+1 where the server still expects seqid, and the
//     reply is NFS4ERR_SEQ_MISORDERED. The slot must not simply be released for
//     reuse — either the seqid is reclaimed, or the slot is quarantined and the
//     session rebuilt.
//   - sent, then cancelled: the seqid was legitimately consumed and ordering is
//     intact. Only the outcome is unknown, and because every operation this
//     client issues is idempotent, that is recoverable by retrying.
//
// Without the distinction a caller must assume the worse case on every timeout,
// which under load means rebuilding the session on every NFS4ERR_DELAY.
var ErrNotSent = errors.New("nfs41: request not sent")

// ErrGarbageArgs is the RPC layer's refusal of a call's arguments: the server
// could not decode them, so it never entered the NFS layer and never executed
// the COMPOUND's first operation.
//
// It exists as a sentinel because two callers need to branch on it and neither
// can do so by matching the message text.
//
// The first is sequence accounting. GARBAGE_ARGS is decided during RPC argument
// decoding, which precedes operation execution, so SEQUENCE cannot have run and
// the slot's sequence ID cannot have been consumed. A caller that releases the
// slot instead of reclaiming it leaves its next request one ahead of the
// server's expectation and earns NFS4ERR_SEQ_MISORDERED.
//
// The second is shape refusal. RFC-Deviations.md section 4 records that
// FlashBlade refuses an over-length COMPOUND this way rather than with
// NFS4ERR_TOO_MANY_OPS, so on that platform GARBAGE_ARGS does not reliably mean
// "this client encoded something malformed" -- it may mean "that shape is not
// accepted here". Retrying the identical bytes cannot fix either reading, and
// rebuilding the session cannot either.
var ErrGarbageArgs = errors.New("rpc: server could not decode procedure arguments")

type callResult struct {
	record []byte
	err    error
}

// Conn carries concurrent RPC calls over one TCP connection.
//
// A single writer goroutine preserves record boundaries without making a
// caller wait on an uncancellable mutex or socket write. A separate reader
// goroutine reassembles records and routes replies by xid; replies need not
// arrive in call order.
//
// Each reply is a fresh allocation, so Call's result is never overwritten, but a
// retained sub-slice pins the whole record; decoders that keep bytes must copy them.
type Conn struct {
	conn net.Conn

	// reader wraps conn for readLoop only. Safe because readLoop is the sole
	// reader and the writer goroutine writes to conn directly, bypassing it.
	// Without it every reply costs at least two read(2) calls: one for the
	// 4-byte record marker, one for the body. readRecord still takes an
	// io.Reader, so the spec tests that feed it a bytes.Buffer are unaffected.
	reader *bufio.Reader

	credential []byte // encoded opaque_auth, immutable after construction

	writes chan []byte
	done   chan struct{}
	wg     sync.WaitGroup

	closeOnce sync.Once

	// Write-gathering counters, for the tests. A gathered write is invisible from
	// the outside -- net.Buffers falls back to one Write per buffer on a
	// connection that cannot do writev, so counting writes on the connection
	// cannot tell a batch of eight from eight separate records. Counting where
	// the batching decision is made can.
	batches        atomic.Uint64
	recordsWritten atomic.Uint64

	// queuedForWrite counts senders that have reached the hand-off select below.
	// Gathering is a race by construction -- writeLoop gathers whatever is parked
	// on an unbuffered channel at the instant it looks -- so a test that merely
	// starts N callers and hopes cannot assert it. This lets a test hold the first
	// write until the other senders have arrived, making the gather deterministic
	// instead of scheduler-dependent.
	queuedForWrite atomic.Uint64

	mu          sync.Mutex
	nextXID     uint32
	pending     map[uint32]chan callResult
	terminalErr error
}

// NewConn dials through d and starts the RPC reader and writer.
func NewConn(ctx context.Context, d Dialer, cred AuthSys) (*Conn, error) {
	if ctx == nil {
		return nil, errors.New("nfs41: nil context")
	}
	if d == nil {
		return nil, errors.New("nfs41: nil Dialer")
	}
	credential, err := encodeAuthSys(cred)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	nc, err := d(ctx)
	if err != nil {
		return nil, fmt.Errorf("nfs41: dial RPC server: %w", err)
	}
	if nc == nil {
		return nil, errors.New("nfs41: Dialer returned a nil connection")
	}
	return startConn(nc, credential), nil
}

// newConnOnWire wraps an already-established connection. NewConn is its only
// production caller; tests use it with net.Pipe. The tests pass a credential
// that is valid by construction; fail fast if that invariant changes.
func newConnOnWire(nc net.Conn, cred AuthSys) *Conn {
	credential, err := encodeAuthSys(cred)
	if err != nil {
		panic(err)
	}
	return startConn(nc, credential)
}

func startConn(nc net.Conn, credential []byte) *Conn {
	c := &Conn{
		conn:       nc,
		reader:     bufio.NewReader(nc),
		credential: credential,
		writes:     make(chan []byte),
		done:       make(chan struct{}),
		nextXID:    1,
		pending:    make(map[uint32]chan callResult),
	}
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		c.writeLoop()
	}()
	go func() {
		defer c.wg.Done()
		c.readLoop()
	}()
	return c
}

// writeBatchMax bounds how many records one write(2) carries.
//
// The point of a bound is latency, not memory: a record already handed to
// writeLoop is a request some worker is blocked on, and gathering without limit
// would let a busy connection keep deferring the first record in favour of
// newer arrivals. 32 is enough to fold the syscall cost by an order of magnitude
// at the concurrency this client runs at, and small enough that the head of the
// batch waits on at most 31 memory copies.
const writeBatchMax = 32

// WriteBatchMax exposes the gather bound so a caller reporting achieved depth can
// say what the ceiling was. A depth at the ceiling and a depth well under it call
// for opposite responses.
const WriteBatchMax = writeBatchMax

func (c *Conn) writeLoop() {
	// Records that are already queued are written together.
	//
	// MEASURED: one write(2) per RPC put 20% of a repair run's CPU in the write
	// path -- 1.1M syscalls for 1.1M objects. The sends are concurrent (one per
	// in-flight worker) and c.writes is unbuffered, so at any moment there are
	// usually several senders parked; taking all of them before writing turns
	// those syscalls into one writev(2).
	//
	// Reordering is not a hazard here. Replies are matched by XID, and RFC 8881
	// sequencing is per slot with one request outstanding per slot at a time, so
	// two records in the same batch are always for different slots and carry no
	// ordering relationship to each other.
	batch := make([][]byte, 0, writeBatchMax)
	for {
		select {
		case <-c.done:
			return
		case record := <-c.writes:
			batch = append(batch[:0], record)
		gather:
			for len(batch) < writeBatchMax {
				select {
				case more := <-c.writes:
					batch = append(batch, more)
				default:
					break gather
				}
			}
			if err := c.writeRecords(batch); err != nil {
				c.terminate(err)
				return
			}
		}
	}
}

// writeRecords writes a gathered batch, using writev when there is more than
// one record. net.Buffers falls back to sequential writes on connections that
// cannot do writev -- net.Pipe in the tests -- so this is a performance
// difference only, never a behavioural one.
func (c *Conn) writeRecords(batch [][]byte) error {
	c.batches.Add(1)
	c.recordsWritten.Add(uint64(len(batch)))
	if len(batch) == 1 {
		if _, err := c.conn.Write(batch[0]); err != nil {
			return fmt.Errorf("rpc: write record: %w", err)
		}
		return nil
	}
	// WriteTo consumes the Buffers it is given, re-slicing entries as it drains
	// them. It is handed the batch directly because writeLoop rebuilds the batch
	// from scratch on the next iteration and no caller retains these records.
	buffers := net.Buffers(batch)
	if _, err := buffers.WriteTo(c.conn); err != nil {
		return fmt.Errorf("rpc: write %d records: %w", len(batch), err)
	}
	return nil
}

func (c *Conn) readLoop() {
	for {
		record, err := readRecord(c.reader)
		if err != nil {
			c.terminate(err)
			return
		}
		if len(record) < 4 {
			c.terminate(fmt.Errorf("rpc: reply is %d bytes; need an xid", len(record)))
			return
		}

		xid := binary.BigEndian.Uint32(record[:4])
		c.mu.Lock()
		waiter, ok := c.pending[xid]
		if ok {
			delete(c.pending, xid)
		}
		c.mu.Unlock()
		if ok {
			// The channel is buffered so cancellation after the map lookup cannot
			// stall the only reader and therefore every other in-flight call.
			waiter <- callResult{record: record}
		}
		// An unmatched xid belongs to a call whose context expired, or is a
		// duplicate. Its caller is gone, so dropping it is the only useful action.
	}
}

// terminate records a terminal connection error and releases every waiter.
func (c *Conn) terminate(cause error) {
	terminal := connectionClosedError(cause)
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.terminalErr = terminal
		waiters := c.pending
		c.pending = nil
		close(c.done)
		c.mu.Unlock()

		// Non-blocking. Every waiter channel is 1-deep and empty here, because
		// readLoop deletes from pending under the same mutex this function used
		// to steal the map, so no waiter can already hold a value. That makes a
		// plain send safe today — but these sends precede c.conn.Close(), so if a
		// future change ever left a value queued, terminate would block forever,
		// the socket would never close, readLoop would never unblock, and
		// Close's wg.Wait would hang permanently. The default costs nothing and
		// removes an unstated invariant whose violation is unrecoverable.
		for _, waiter := range waiters {
			select {
			case waiter <- callResult{err: terminal}:
			default:
			}
		}
		c.conn.Close()
	})
}

func connectionClosedError(cause error) error {
	if cause == nil {
		return ErrConnClosed
	}
	if errors.Is(cause, ErrConnClosed) {
		return cause
	}
	return fmt.Errorf("%w: %w", ErrConnClosed, cause)
}

func (c *Conn) connectionError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminalErr
}

// Call sends one RPC and waits for its matching reply. The returned bytes are
// the procedure-specific body after a successful accepted-reply header.
//
// After writer handoff, cancellation cannot unsend the record: the server may
// still receive it. Callers with sequence state must therefore treat ctx.Err as
// indeterminate — the request may have been executed.
//
// Which of the two cases occurred is reported, and a caller holding sequence
// state MUST branch on it: an error satisfying errors.Is(err, ErrNotSent) means
// the record never reached the writer, so the slot's consumed seqid has to be
// reclaimed or the slot quarantined. Any other error here means the request may
// have executed, the seqid was legitimately consumed, and a retry is safe. See
// ErrNotSent.
//
// An earlier revision of this comment claimed a cancelled Call always leaves the
// seqid "exactly what the server expects" and so never needs a rebuild. That is
// true only of the sent case. In the not-sent case the server never saw the
// seqid, so the next request on that slot skips one — which makes
// NFS4ERR_SEQ_MISORDERED reachable despite exclusive slot ownership, contrary to
// what the implementation plan asserts.
func (c *Conn) Call(ctx context.Context, prog, vers, proc uint32, args []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nfs41: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	xid, waiter, err := c.registerCall()
	if err != nil {
		return nil, err
	}

	record, err := c.buildCall(xid, prog, vers, proc, args)
	if err != nil {
		c.unregisterCall(xid, waiter)
		return nil, fmt.Errorf("%w: %w", ErrNotSent, err)
	}

	// This select is the sent/not-sent boundary. Its success case hands the
	// record to the writer; its failure cases provably did not.
	c.queuedForWrite.Add(1)
	select {
	case c.writes <- record:
	case <-ctx.Done():
		c.unregisterCall(xid, waiter)
		return nil, fmt.Errorf("%w: %w", ErrNotSent, ctx.Err())
	case <-c.done:
		c.unregisterCall(xid, waiter)
		return nil, fmt.Errorf("%w: %w", ErrNotSent, c.connectionError())
	}

	select {
	case result := <-waiter:
		if result.err != nil {
			return nil, result.err
		}
		return parseAcceptedReply(result.record)
	case <-ctx.Done():
		c.unregisterCall(xid, waiter)
		return nil, ctx.Err()
	}
}

func (c *Conn) registerCall() (uint32, chan callResult, error) {
	waiter := make(chan callResult, 1)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.terminalErr; err != nil {
		return 0, nil, err
	}

	// Do not reuse an xid that is still in flight when the counter wraps.
	for {
		xid := c.nextXID
		c.nextXID++
		if _, exists := c.pending[xid]; exists {
			continue
		}
		c.pending[xid] = waiter
		return xid, waiter, nil
	}
}

func (c *Conn) unregisterCall(xid uint32, waiter chan callResult) {
	c.mu.Lock()
	if c.pending[xid] == waiter {
		delete(c.pending, xid)
	}
	c.mu.Unlock()
}

// Close shuts down the wire and unblocks every in-flight Call. It is safe to
// call repeatedly and waits for the connection's reader and writer to exit.
//
// Because it waits for them, it must NOT be called from the reader or writer
// goroutine — that self-deadlocks. Nothing does today; the note is for Task 8's
// session Destroy and Task 14's connection pool, which will call it from places
// this file cannot see.
func (c *Conn) Close() error {
	c.terminate(ErrConnClosed)
	c.wg.Wait()
	return nil
}

// encodeAuthSys returns the complete opaque_auth credential (flavor, length,
// and body), ready to append to an RPC call header.
func encodeAuthSys(cred AuthSys) ([]byte, error) {
	if len(cred.Machine) > maxMachineName {
		return nil, fmt.Errorf(
			"rpc: AUTH_SYS machine name is %d bytes; maximum is %d",
			len(cred.Machine), maxMachineName,
		)
	}
	if len(cred.AuxGIDs) > maxAuxGIDs {
		return nil, fmt.Errorf(
			"rpc: AUTH_SYS has %d auxiliary gids; maximum is %d",
			len(cred.AuxGIDs), maxAuxGIDs,
		)
	}

	machinePad := xdrPad(len(cred.Machine))
	bodyLen := 4 + 4 + len(cred.Machine) + machinePad + 4 + 4 + 4 + 4*len(cred.AuxGIDs)
	if bodyLen > maxOpaqueAuth {
		return nil, fmt.Errorf("rpc: AUTH_SYS credential is %d bytes; maximum is %d", bodyLen, maxOpaqueAuth)
	}

	out := make([]byte, 0, 8+bodyLen)
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.AUTH_SYS))
	out = binary.BigEndian.AppendUint32(out, uint32(bodyLen))
	out = binary.BigEndian.AppendUint32(out, cred.Stamp)
	out = binary.BigEndian.AppendUint32(out, uint32(len(cred.Machine)))
	out = append(out, cred.Machine...)
	out = append(out, make([]byte, machinePad)...)
	out = binary.BigEndian.AppendUint32(out, cred.UID)
	out = binary.BigEndian.AppendUint32(out, cred.GID)
	out = binary.BigEndian.AppendUint32(out, uint32(len(cred.AuxGIDs)))
	for _, gid := range cred.AuxGIDs {
		out = binary.BigEndian.AppendUint32(out, gid)
	}
	return out, nil
}

func xdrPad(n int) int {
	return (-n) & 3
}

// buildCall hand-encodes the small fixed RPC header, then appends the already
// XDR-encoded procedure arguments verbatim. It reserves and fills the record
// marker in the same allocation so the complete call is copied only once.
func (c *Conn) buildCall(xid, prog, vers, proc uint32, args []byte) ([]byte, error) {
	const fixedBytes = 6*4 + 2*4 // six call words plus AUTH_NONE verifier
	baseSize := fixedBytes + len(c.credential)
	if len(args) > maxRecordSize-baseSize {
		return nil, fmt.Errorf("rpc: call exceeds the %d-byte record limit", maxRecordSize)
	}
	messageSize := baseSize + len(args)

	out := make([]byte, 4, 4+messageSize)
	for _, word := range []uint32{xid, uint32(xdr.CALL), rpcVersion, prog, vers, proc} {
		out = binary.BigEndian.AppendUint32(out, word)
	}
	out = append(out, c.credential...)
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.AUTH_NONE))
	out = binary.BigEndian.AppendUint32(out, 0)
	out = append(out, args...)
	markRecord(out)
	return out, nil
}

type rpcDecoder struct {
	buf []byte
	off int
	xid uint32
}

func (d *rpcDecoder) word(field string) (uint32, error) {
	if len(d.buf)-d.off < 4 {
		return 0, fmt.Errorf("rpc: xid %d: truncated %s", d.xid, field)
	}
	value := binary.BigEndian.Uint32(d.buf[d.off : d.off+4])
	d.off += 4
	return value, nil
}

func (d *rpcDecoder) opaque(field string, max uint32) ([]byte, error) {
	// The length word is read inline rather than through word(field + " length").
	// That concatenation ran on the success path of every reply -- once per RPC,
	// 1.1M times in a repair run -- to build a string used only in an error that
	// almost never fires. MEASURED: it was 5.9% of the whole profile and 35% of
	// every allocation the tool made, via concatstring2 -> rawstring -> mallocgc.
	// Four duplicated lines are worth that.
	if len(d.buf)-d.off < 4 {
		return nil, fmt.Errorf("rpc: xid %d: truncated %s length", d.xid, field)
	}
	n := binary.BigEndian.Uint32(d.buf[d.off : d.off+4])
	d.off += 4
	if n > max {
		return nil, fmt.Errorf("rpc: xid %d: %s is %d bytes; maximum is %d", d.xid, field, n, max)
	}
	padded := uint64(n) + uint64(xdrPad(int(n)))
	if padded > uint64(len(d.buf)-d.off) {
		return nil, fmt.Errorf("rpc: xid %d: truncated %s: need %d bytes", d.xid, field, padded)
	}
	value := d.buf[d.off : d.off+int(n)]
	d.off += int(padded)
	return value, nil
}

// parseAcceptedReply validates an RFC 5531 reply and returns the procedure
// result from a successful accepted reply. Rejected replies and accepted RPC
// failures are translated to descriptive errors here, before any NFS decoder
// sees them.
func parseAcceptedReply(record []byte) ([]byte, error) {
	d := rpcDecoder{buf: record}
	xid, err := d.word("xid")
	if err != nil {
		return nil, err
	}
	d.xid = xid

	messageType, err := d.word("message type")
	if err != nil {
		return nil, err
	}
	if messageType != uint32(xdr.REPLY) {
		return nil, fmt.Errorf("rpc: xid %d: message type %d is not REPLY", xid, messageType)
	}

	replyStatus, err := d.word("reply status")
	if err != nil {
		return nil, err
	}
	switch xdr.Reply_stat(replyStatus) {
	case xdr.MSG_ACCEPTED:
		return d.acceptedResult(record)
	case xdr.MSG_DENIED:
		return nil, d.deniedError()
	default:
		return nil, fmt.Errorf("rpc: xid %d: unknown reply status %d", xid, replyStatus)
	}
}

func (d *rpcDecoder) acceptedResult(record []byte) ([]byte, error) {
	if _, err := d.word("verifier flavor"); err != nil {
		return nil, err
	}
	if _, err := d.opaque("verifier", maxOpaqueAuth); err != nil {
		return nil, err
	}

	status, err := d.word("accept status")
	if err != nil {
		return nil, err
	}
	switch xdr.Accept_stat(status) {
	case xdr.SUCCESS:
		return record[d.off:], nil
	case xdr.PROG_UNAVAIL:
		return nil, fmt.Errorf("rpc: xid %d: program unavailable", d.xid)
	case xdr.PROG_MISMATCH:
		low, high, err := d.versionRange("program mismatch")
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(
			"rpc: xid %d: program version mismatch (server supports %d through %d)",
			d.xid, low, high,
		)
	case xdr.PROC_UNAVAIL:
		return nil, fmt.Errorf("rpc: xid %d: procedure unavailable", d.xid)
	case xdr.GARBAGE_ARGS:
		return nil, fmt.Errorf("rpc: xid %d: %w", d.xid, ErrGarbageArgs)
	case xdr.SYSTEM_ERR:
		return nil, fmt.Errorf("rpc: xid %d: remote system error", d.xid)
	default:
		return nil, fmt.Errorf("rpc: xid %d: unknown accept status %d", d.xid, status)
	}
}

func (d *rpcDecoder) deniedError() error {
	rejectStatus, err := d.word("reject status")
	if err != nil {
		return err
	}
	switch xdr.Reject_stat(rejectStatus) {
	case xdr.RPC_MISMATCH:
		low, high, err := d.versionRange("RPC mismatch")
		if err != nil {
			return err
		}
		return fmt.Errorf(
			"rpc: xid %d: RPC version mismatch (server supports %d through %d)",
			d.xid, low, high,
		)
	case xdr.AUTH_ERROR:
		status, err := d.word("authentication status")
		if err != nil {
			return err
		}
		return fmt.Errorf(
			"rpc: xid %d: authentication error: %s (%d)",
			d.xid, xdr.Auth_stat(status), status,
		)
	default:
		return fmt.Errorf("rpc: xid %d: unknown reject status %d", d.xid, rejectStatus)
	}
}

func (d *rpcDecoder) versionRange(field string) (uint32, uint32, error) {
	low, err := d.word(field + " low version")
	if err != nil {
		return 0, 0, err
	}
	high, err := d.word(field + " high version")
	if err != nil {
		return 0, 0, err
	}
	return low, high, nil
}

// WriteStats reports how many write(2) calls the gather loop made and how many
// records they carried. records/batches is the achieved gather depth.
//
// This is a diagnostic, not an invariant: the gather is a race by construction,
// so the ratio reflects how much the senders happened to overlap. It is exported
// because "is the gathering working" is otherwise unanswerable from outside the
// package, and the write path has now twice measured as the largest single
// consumer of client CPU.
func (c *Conn) WriteStats() (batches, records uint64) {
	return c.batches.Load(), c.recordsWritten.Load()
}
