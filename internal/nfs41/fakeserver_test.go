package nfs41

// fakeserver_test.go is the in-process NFSv4.1 server the rest of this
// package's tests run against. It exists because the error taxonomy this
// client has to survive — NFS4ERR_DELAY, NFS4ERR_BADSESSION,
// NFS4ERR_SEQ_MISORDERED, a mid-stream TCP reset, NFS4ERR_TOOSMALL, a changed
// READDIR cookie verifier — is not reliably reproducible against real
// hardware, and is a millisecond here.
//
// It implements exactly the operations the client sends: EXCHANGE_ID,
// CREATE_SESSION, DESTROY_SESSION, SEQUENCE, READDIR, SETATTR, plus
// PUTROOTFH, PUTFH, LOOKUP, GETFH and GETATTR as the plumbing those need.
//
// Deliberately NOT implemented: OPEN, CLOSE, LOCK, delegations, the back
// channel, BIND_CONN_TO_SESSION. A fake that answered an op the client cannot
// send would let a regression through unnoticed, so every other op is refused
// with NFS4ERR_NOTSUPP or NFS4ERR_OP_ILLEGAL and never NFS4_OK.
// TestFakeServerRejectsAnUnknownOp pins that.
//
// Being a _test.go file, none of this ships.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// opBindConnToSession is RFC 5661 operation 41. The generated XDR in
// internal/nfs41/xdr covers the subset of NFSv4.1 this client speaks and has
// no BIND_CONN_TO_SESSION arm at all, so the constant cannot be aliased from
// it the way ops.go aliases the rest. The fake dispatches on the raw opnum
// word precisely so it can still recognise and count this one: Task 14 asserts
// BindConnToSessionCount() stayed 0, and that assertion is worthless if an
// unrecognised opnum is indistinguishable from any other.
const opBindConnToSession = uint32(41)

// Statuses the fake returns that ops.go does not alias, because the production
// client has no reason to name them. They are given fake-local names rather
// than the NFS4ERR_* spelling so that adding a production alias later cannot
// collide with this file.
const (
	errNoFilehandle  = uint32(xdr.NFS4ERR_NOFILEHANDLE)
	errNotDir        = uint32(xdr.NFS4ERR_NOTDIR)
	errAttrNotSupp   = uint32(xdr.NFS4ERR_ATTRNOTSUPP)
	errBadCookie     = uint32(xdr.NFS4ERR_BAD_COOKIE)
	errStaleClientID = uint32(xdr.NFS4ERR_STALE_CLIENTID)
	errBadXDR        = uint32(xdr.NFS4ERR_BADXDR)

	// errOpNotInSession and errSequencePos are the two statuses a real server
	// uses to police SEQUENCE placement: a COMPOUND that carries session-bound
	// operations without a leading SEQUENCE, and a SEQUENCE anywhere but first.
	errOpNotInSession = uint32(xdr.NFS4ERR_OP_NOT_IN_SESSION)
	errSequencePos    = uint32(xdr.NFS4ERR_SEQUENCE_POS)
)

const (
	// fakeRootFH is the filehandle string PUTROOTFH selects. A filehandle in the
	// fake defaults to its tree path, which makes ACLFor("/dir/file") readable
	// at a test's call site; fakeEntry.FH overrides it per entry.
	fakeRootFH = "/"

	// defaultGrantedSlots is the fore-channel ca_maxrequests the fake grants
	// when withSlots is not supplied.
	defaultGrantedSlots = 8

	// defaultMaxFileSize is the FATTR4_MAXFILESIZE the fake reports when
	// withMaxFileSize is not supplied: 32 TiB. The Task 11 gate uses exact
	// membership in the accepted set, not a threshold, so 32 TiB is refused;
	// non-gate tests use newTestClient, which explicitly enables the override.
	defaultMaxFileSize = uint64(32) << 40

	// minReaddirMaxcount is the smallest rd_maxcount the fake will honour.
	// Below it there is no room for even one entry plus the dirlist4 framing,
	// which is exactly the condition NFS4ERR_TOOSMALL names.
	minReaddirMaxcount = 128

	// procNull is the only RPC procedure number the fake needs that production
	// code does not: nfsProgram, nfsProgramVersion and nfsProcCompound are
	// declared in rpc.go, and duplicating them here once collided with it.
	procNull = uint32(0)
)

// fakeEntry is one child of a directory in the fake's tree.
type fakeEntry struct {
	Name  string
	IsDir bool
	// ACL is the complete XDR encoding of fattr4_acl, as OpSetACL takes and
	// ACLFor returns. Nil means "no ACL set yet", reported as an empty ACL.
	ACL []byte
	// Size is reported as FATTR4_SIZE.
	Size uint64

	// FH is the entry's filehandle. Empty means "use the entry's tree path",
	// which is what every test written before Tasks 11 and 12 assumes and is
	// why ACLFor("/dir/file") reads well. A non-empty FH overrides the path
	// entirely: the path is then no longer a filehandle the fake will accept.
	//
	// Do not "simplify" this into always-derive-from-path. The asymmetry is
	// load-bearing. While a filehandle *is* its path, a client that
	// string-builds a filehandle out of Ref.Path passes this entire suite
	// while issuing a LOOKUP per object — it looks correct and is merely slow,
	// the failure mode hardest to catch later. Eliminating exactly that bug is
	// the whole reason READDIR asks for FATTR4_FILEHANDLE, so the tests that
	// police it set FH to values deliberately unequal to the path.
	FH string
	// Mode is the initial FATTR4_MODE. Zero falls back to 0o755. A SETATTR
	// that writes mode still wins over it: this is the starting value, not an
	// override of observed writes.
	Mode uint32
	// FSID is reported as FATTR4_FSID major, with minor 0. Zero preserves the
	// fake's historical (major=1, minor=2) so no older test changes meaning.
	FSID uint64
	// IsSymlink reports FATTR4_TYPE as NF4LNK. It is deliberately not
	// mutually exclusive with IsDir: a consumer test sets both to prove the
	// client never descends a link, and NF4LNK wins in that case.
	IsSymlink bool
}

// fhTarget is what an effective filehandle resolves to. The fake keeps one
// index from filehandle to target so filehandle and tree path cannot drift
// into two competing notions of identity: the tree, cookies and READDIR are
// keyed by path, while PUTFH, GETFH, GETATTR, SETATTR, the acls and modes side
// maps and ACLFor are keyed by filehandle.
type fhTarget struct {
	path  string
	entry fakeEntry
}

// fakeOpt configures a fakeServer before it starts accepting.
type fakeOpt func(*fakeServer)

// withSlots sets the fore-channel slot count the fake grants in
// CREATE_SESSION, and the value GrantedSlots reports.
func withSlots(n int) fakeOpt {
	return func(s *fakeServer) { s.grantedSlots = n }
}

// withMaxFileSize sets the FATTR4_MAXFILESIZE the fake reports. Task 11's gate
// tests drive the refusal path with it.
func withMaxFileSize(v uint64) fakeOpt {
	return func(s *fakeServer) { s.maxFileSize = v }
}

// withRequiredBackChannelAttrs makes CREATE_SESSION refuse a zeroed
// csa_back_chan_attrs with NFS4ERR_TOOSMALL, which is what a Purity//FA does and
// a FlashBlade does not.
//
// MEASURED 2026-08-22 on fa-lab-01 (6.10.6). This is modelled because its
// absence hid the real cause for a day: the client shipped a zeroed back channel,
// FA refused the session, and the refusal was attributed to
// ca_maxresponsesize_cached instead -- a field the probe later swept from 0 to
// 1 MiB with every value refused. A fake that accepts a zeroed back channel lets
// that misdiagnosis be made again.
func withRequiredBackChannelAttrs() fakeOpt {
	return func(s *fakeServer) { s.requireBackChannelAttrs = true }
}

// withSilentSetAttr makes SETATTR report success while omitting the named
// attribute from its attrsset bitmap -- a server that accepted the request and
// ignored the attribute. Real servers are permitted to set fewer attributes
// than asked, so the client must catch it rather than report a repair that did
// not happen.
func withSilentSetAttr(attr uint32) fakeOpt {
	return func(s *fakeServer) { s.silentSetAttrs = append(s.silentSetAttrs, attr) }
}

// withImplID makes the fake return an eir_server_impl_id in its EXCHANGE_ID
// reply. Without it the array is empty, which is what a server that declines
// to identify itself sends.
func withImplID(domain, name string) fakeOpt {
	return func(s *fakeServer) {
		s.implID = &xdr.Nfs_impl_id4{
			Nii_domain: []byte(domain),
			Nii_name:   []byte(name),
		}
	}
}

// withExchangeSequence sets the eir_sequenceid returned by EXCHANGE_ID. A
// non-default start makes tests prove the client retained the negotiated value
// rather than coincidentally hardcoding 1.
func withExchangeSequence(sequence uint32) fakeOpt {
	return func(s *fakeServer) { s.exchangeSequence = sequence }
}

// withMaxChannelSizes overrides the CREATE_SESSION request/response-size grant.
// It lets session tests exercise the client's local maxRecordSize clamp without
// changing the fake's normal echo-the-offer behavior.
func withMaxChannelSizes(request, response uint32) fakeOpt {
	return func(s *fakeServer) {
		s.maxRequestSize = request
		s.maxResponseSize = response
	}
}

// withZeroForeChannelLimitOnce makes the next accepted CREATE_SESSION answer
// NFS4_OK while granting ca_maxoperations 0, and every one after it grant
// normally.
//
// This is the only shape of failure that reaches the client's post-success
// rejection list: the COMPOUND status is NFS4_OK, so the server HAS created a
// session and HAS recorded csa_sequence in its replay cache, and the client then
// refuses the session on a purely local judgement. Every other injection point
// the fake has fails the COMPOUND status instead, which is the opposite
// transaction — "the server refused, so the reservation stands".
func withZeroForeChannelLimitOnce() fakeOpt {
	return func(s *fakeServer) { s.zeroForeChannelGrants = 1 }
}

// withForgetClientIDAfter destroys the registration after n successful
// CREATE_SESSIONs, modelling a server that reports NFS4ERR_STALE_CLIENTID during
// a later rebuild.
func withForgetClientIDAfter(n int) fakeOpt {
	return func(s *fakeServer) { s.forgetClientIDAfter = n }
}

// withManySessionsPerClientID makes the fake accept more than one session on a
// clientid, which is what RFC 8881 section 2.10.5 requires and what no
// FlashBlade tested so far actually does. The default is the hardware behaviour;
// this opts out.
func withManySessionsPerClientID() fakeOpt {
	return func(s *fakeServer) { s.oneSessionPerClientID = false }
}

// withChainedLookupsAcrossRoot lets a COMPOUND keep looking up components after
// it has crossed out of the pseudo-filesystem, which is what the fake did
// unconditionally before Defect 1 was found and what a Linux server does.
func withChainedLookupsAcrossRoot() fakeOpt {
	return func(s *fakeServer) { s.oneLookupAfterPseudoRootCrossing = false }
}

// withDropReplyAfter runs the next n occurrences of op normally and then throws
// the whole COMPOUND reply away, so the client sees a request that was executed
// and never answered.
//
// This is the opposite injection point from InjectOnce, which fires BEFORE the
// operation runs and therefore leaves the server in the "never saw it" state. A
// lost reply is the other half of RFC 8881 section 18.36.4 — "the server already
// recorded it" — and it is the only way to drive the client's
// retry-the-same-csa_sequence path end to end. The client is expected to give up
// on its own deadline; the connection stays open.
//
//lint:ignore U1000 wired into fakeServer.dropReplyAfter, waiting for a retry-path test
func withDropReplyAfter(op uint32, n int) fakeOpt {
	return func(s *fakeServer) { s.dropReplyAfter[op] = n }
}

// fakeConn is one accepted connection. Its write mutex serialises reply
// records, because each request is handled on its own goroutine so that
// concurrent calls on one Conn are concurrent here too — without that,
// HoldRepliesUntilSignalled could never accumulate more than one in flight.
type fakeConn struct {
	id  int
	nc  net.Conn
	wmu sync.Mutex
}

type injection struct {
	status    uint32
	remaining int
}

type fakeServer struct {
	ln net.Listener

	closeOnce sync.Once
	stop      chan struct{}
	wg        sync.WaitGroup

	mu sync.Mutex

	// changed is closed and replaced whenever inFlight or held changes. It is
	// the broadcast primitive WaitForInFlight and the reply hold wait on,
	// because sync.Cond cannot wait with a deadline.
	changed chan struct{}

	grantedSlots            int
	requireBackChannelAttrs bool
	silentSetAttrs          []uint32
	maxFileSize             uint64
	implID                  *xdr.Nfs_impl_id4
	exchangeSequence        uint32
	maxRequestSize          uint32
	maxResponseSize         uint32
	forgetClientIDAfter     int
	// oneSessionPerClientID models FlashBlade's refusal of a second session on a
	// clientid. It defaults to TRUE in startFakeServer because that is what the
	// hardware does; withManySessionsPerClientID opts out for the one test that
	// needs to prove the fake can express the RFC-conformant behaviour too.
	oneSessionPerClientID bool
	// oneLookupAfterPseudoRootCrossing models FlashBlade's refusal of a second
	// LOOKUP in a COMPOUND that has crossed out of the pseudo-filesystem. Defaults
	// to TRUE for the same reason; withChainedLookupsAcrossRoot opts out.
	oneLookupAfterPseudoRootCrossing bool
	// zeroForeChannelGrants counts how many more accepted CREATE_SESSIONs grant an
	// unusable zero ca_maxoperations. See withZeroForeChannelLimitOnce.
	zeroForeChannelGrants int

	// tree maps a directory filehandle to its children. ACLFor reads acls,
	// which SETATTR writes.
	tree map[string][]fakeEntry
	// byFH indexes every entry AddTree has seen by its effective filehandle,
	// which is fakeEntry.FH when set and the entry's tree path otherwise.
	byFH map[string]fhTarget
	// fhOverridden records the tree paths of entries that supplied an explicit
	// FH. Those paths are not filehandles any more, so PUTFH of one must be
	// stale — otherwise a client that string-builds filehandles from paths
	// would still be accepted and the override would prove nothing.
	fhOverridden map[string]bool
	acls         map[string][]byte
	// modes records FATTR4_MODE writes, so a SETATTR of mode is observable
	// through GETATTR rather than silently dropped.
	modes map[string]uint32

	conns   map[int]*fakeConn
	nextID  int
	connSum int
	perConn map[int]int

	callCounts    map[uint32]int
	lookupCounts  map[string]int
	sessionCount  int
	bindConnCount int
	// clientIDs keys a clientid by co_ownerid, which is how a real server
	// behaves: a repeated EXCHANGE_ID from the same client owner returns the
	// same clientid. ClientIDCount is len(clientIDs) for that reason.
	clientIDs    map[string]uint64
	nextClientID uint64

	// createSessionSeq records every csa_sequence received, in wire order,
	// including the ones that were refused or replayed.
	createSessionSeq []uint32
	// createSessionArgs records every CREATE_SESSION4args received, so a test can
	// assert on what the client actually offered rather than only on what it did
	// with the grant.
	createSessionArgs []xdr.CREATE_SESSION4args
	// lastCreateSeq is the last csa_sequence ACCEPTED per clientid, and
	// lastCreateReply is the reply that was sent for it. Together they are the
	// one-entry-per-clientid CREATE_SESSION replay cache RFC 8881 section 18.36.4
	// requires: the same value again replays, one higher creates, anything else is
	// NFS4ERR_SEQ_MISORDERED.
	lastCreateSeq   map[uint64]uint32
	lastCreateReply map[uint64]xdr.CREATE_SESSION4resok
	reclaimComplete map[uint64]bool

	sessions      map[[16]byte]*fakeSession
	nextSessionID uint64

	sawCachethis bool

	injections map[uint32]*injection
	// dropReplyAfter counts, per opnum, how many more COMPOUND replies to throw
	// away after the operation has already run. See withDropReplyAfter.
	dropReplyAfter map[uint32]int

	readdirPageSize int
	readdirReplies  int
	changeVerfAfter int
	readdirVerf     [8]byte
	// readdirMaxcounts is the rd_maxcount of every READDIR the fake decoded, in
	// order, including ones it then refused with NFS4ERR_TOOSMALL.
	readdirMaxcounts []uint32
	// readdirMinOK/readdirMaxOK bound the rd_maxcount the fake will honour; zero
	// means unbounded on that side. See SetReaddirSizeWindow.
	readdirMinOK uint32
	readdirMaxOK uint32
	// omitReaddirAttrs are attribute numbers stripped from rd_attr_request
	// before the per-entry fattr4 is built, so the reply describes each entry
	// without them. See OmitReaddirAttrs.
	omitReaddirAttrs map[uint32]bool

	held     bool
	inFlight int

	// holdAfterSeq parks a COMPOUND after its SEQUENCE has acquired a slot, and
	// seqHeld counts how many are parked there. This is a separate hold from
	// held: that one fires before the COMPOUND runs at all, so it cannot keep a
	// slot occupied, which is exactly what a slot-contention test needs.
	holdAfterSeq bool
	seqHeld      int
}

// slotState is one fore-channel slot's server-side state.
//
// A bare "last accepted seqid" cannot model a slot table, and modelling it that
// way hid two real client bugs. It cannot distinguish a slot that has never been
// used from one whose last accepted seqid happens to be 0, so sa_sequenceid == 0
// on a fresh slot looks like a replay and the COMPOUND executes — where a real
// server, and knfsd via NFSD4_SLOT_INITIALIZED, answers NFS4ERR_SEQ_MISORDERED.
// And it carries no notion of a slot currently in use, so two concurrent
// requests could share a slot and both succeed, which is precisely the
// double-allocation bug a slot table is most likely to have.
type slotState struct {
	// seqid is the last accepted sa_sequenceid, meaningful only when
	// initialized is true.
	seqid uint32
	// initialized is false until the slot has accepted its first request. The
	// first request on a slot must carry sa_sequenceid 1; there is no earlier
	// reply to replay, so the replay arm is unreachable while this is false.
	initialized bool
	// inUse is true from the SEQUENCE that acquired the slot until the COMPOUND
	// carrying it finishes. A second request naming the same slot meanwhile is
	// NFS4ERR_DELAY, per RFC 8881 section 2.10.6.2.
	inUse bool
}

type fakeSession struct {
	clientID     uint64
	grantedSlots uint32
	// slots is the fore-channel slot table, keyed by slotid. An absent key is a
	// slot that has never been used.
	slots map[uint32]*slotState
}

// startFakeServer listens on 127.0.0.1:0 and serves until the test ends.
//
// It registers its own teardown with t.Cleanup, so a failing test cannot leak
// the accept goroutine into the rest of the suite, and Close is idempotent so
// the conventional `defer srv.Close()` at a call site is also fine.
func startFakeServer(t *testing.T, opts ...fakeOpt) *fakeServer {
	t.Helper()

	s := &fakeServer{
		stop:             make(chan struct{}),
		changed:          make(chan struct{}),
		grantedSlots:     defaultGrantedSlots,
		maxFileSize:      defaultMaxFileSize,
		exchangeSequence: 1,
		tree:             map[string][]fakeEntry{fakeRootFH: nil},
		byFH:             make(map[string]fhTarget),
		fhOverridden:     make(map[string]bool),
		acls:             make(map[string][]byte),
		modes:            make(map[string]uint32),
		conns:            make(map[int]*fakeConn),
		perConn:          make(map[int]int),
		callCounts:       make(map[uint32]int),
		lookupCounts:     make(map[string]int),
		clientIDs:        make(map[string]uint64),
		nextClientID:     1,
		lastCreateSeq:    make(map[uint64]uint32),
		lastCreateReply:  make(map[uint64]xdr.CREATE_SESSION4resok),
		reclaimComplete:  make(map[uint64]bool),
		sessions:         make(map[[16]byte]*fakeSession),
		nextSessionID:    1,
		// Default to the measured hardware restrictions, not to the RFC's
		// permissiveness. A fake more forgiving than the array is how Defects 1 and
		// 3 both reached hardware.
		oneSessionPerClientID:            true,
		oneLookupAfterPseudoRootCrossing: true,
		injections:                       make(map[uint32]*injection),
		dropReplyAfter:                   make(map[uint32]int),
		readdirVerf:                      [8]byte{'f', 'a', 'k', 'e', 'v', 0, 0, 1},
	}
	for _, opt := range opts {
		opt(s)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake server: listen: %v", err)
	}
	s.ln = ln

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop()
	}()

	t.Cleanup(s.Close)
	return s
}

// Dialer returns the only route by which a test may reach the fake. Production
// code creates every connection through a Dialer, so routing tests through one
// too is what keeps the RFC 9289 TLS injection point from being bypassed by a
// test-only path that hands a net.Conn straight to newConnOnWire.
func (s *fakeServer) Dialer() Dialer {
	addr := s.ln.Addr().String()
	return TCPDialer(addr)
}

// Close stops the listener, drops every open connection and releases any
// goroutine parked in the reply hold. Safe to call more than once.
func (s *fakeServer) Close() {
	s.closeOnce.Do(func() {
		close(s.stop)
		s.ln.Close()

		s.mu.Lock()
		conns := s.conns
		s.conns = make(map[int]*fakeConn)
		s.notifyLocked()
		s.mu.Unlock()

		for _, c := range conns {
			c.nc.Close()
		}
		s.wg.Wait()
	})
}

func (s *fakeServer) acceptLoop() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}

		s.mu.Lock()
		s.nextID++
		c := &fakeConn{id: s.nextID, nc: nc}
		s.conns[c.id] = c
		s.connSum++
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(c)
		}()
	}
}

// serve reads records off one connection and dispatches each on its own
// goroutine, so that concurrent calls from a single Conn are concurrent here.
func (s *fakeServer) serve(c *fakeConn) {
	defer func() {
		c.nc.Close()
		s.mu.Lock()
		delete(s.conns, c.id)
		s.mu.Unlock()
	}()

	r := bufio.NewReader(c.nc)
	var reqs sync.WaitGroup
	defer reqs.Wait()

	for {
		record, err := readRecord(r)
		if err != nil {
			return
		}
		select {
		case <-s.stop:
			return
		default:
		}

		reqs.Add(1)
		go func() {
			defer reqs.Done()
			s.handleRecord(c, record)
		}()
	}
}

// handleRecord decodes one RPC call, runs it, and frames the reply.
func (s *fakeServer) handleRecord(c *fakeConn, record []byte) {
	xid, proc, body, err := parseFakeCall(record)
	if err != nil {
		// A call we cannot even parse gets no reply. The client's readLoop will
		// eventually time out or see the connection drop, which is the same
		// thing a real server's GARBAGE_ARGS-then-hangup looks like from here.
		return
	}

	s.enterRequest()
	defer s.exitRequest()

	// The hold is applied after the request is counted as in flight, so
	// WaitForInFlight sees calls pile up rather than racing the hold.
	if !s.awaitRelease() {
		return
	}

	var payload []byte
	switch proc {
	case procNull:
		payload = nil
	case nfsProcCompound:
		s.mu.Lock()
		s.perConn[c.id]++
		s.mu.Unlock()
		var drop bool
		payload, drop = s.compoundReply(body)
		if drop {
			// The reply is lost in the network. The connection stays up, so the
			// client sees a call that never gets answered rather than a hangup.
			return
		}
	default:
		// Procedure the fake does not implement. Refuse at the RPC layer.
		s.writeRecord(c, encodeAcceptedFailure(xid, xdr.PROC_UNAVAIL))
		return
	}

	s.writeRecord(c, encodeAcceptedReply(xid, payload))
}

func (s *fakeServer) writeRecord(c *fakeConn, payload []byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.nc.Write(recordMark(payload))
}

// ---------------------------------------------------------------------------
// In-flight accounting and the reply hold
// ---------------------------------------------------------------------------

// notifyLocked wakes everything waiting on a state change. Callers hold mu.
func (s *fakeServer) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *fakeServer) enterRequest() {
	s.mu.Lock()
	s.inFlight++
	s.notifyLocked()
	s.mu.Unlock()
}

func (s *fakeServer) exitRequest() {
	s.mu.Lock()
	s.inFlight--
	s.notifyLocked()
	s.mu.Unlock()
}

// awaitRelease blocks while replies are held. It returns false if the server
// shut down while holding, so the caller abandons the reply instead of writing
// to a closed connection.
func (s *fakeServer) awaitRelease() bool {
	for {
		s.mu.Lock()
		if !s.held {
			s.mu.Unlock()
			return true
		}
		ch := s.changed
		s.mu.Unlock()

		select {
		case <-ch:
		case <-s.stop:
			return false
		}
	}
}

// HoldRepliesUntilSignalled stops the fake answering. Requests are still read
// and counted as in flight, so calls accumulate instead of completing serially
// — which is the only way to prove the client really has several outstanding
// at once rather than being fast.
func (s *fakeServer) HoldRepliesUntilSignalled() {
	s.mu.Lock()
	s.held = true
	s.notifyLocked()
	s.mu.Unlock()
}

// ReleaseReplies resumes answering.
func (s *fakeServer) ReleaseReplies() {
	s.mu.Lock()
	s.held = false
	s.notifyLocked()
	s.mu.Unlock()
}

// HoldAfterSequence parks every COMPOUND immediately after its SEQUENCE has
// validated and acquired a slot, before any later operation runs. The slot stays
// marked in use for as long as the COMPOUND is parked, which is the only way to
// present the fake with two live requests naming the same slot deterministically
// rather than hoping a race lands the right way.
func (s *fakeServer) HoldAfterSequence() {
	s.mu.Lock()
	s.holdAfterSeq = true
	s.notifyLocked()
	s.mu.Unlock()
}

// ReleaseAfterSequence resumes every COMPOUND parked by HoldAfterSequence.
func (s *fakeServer) ReleaseAfterSequence() {
	s.mu.Lock()
	s.holdAfterSeq = false
	s.notifyLocked()
	s.mu.Unlock()
}

// WaitForSequenceHeld blocks until n COMPOUNDs are parked after their SEQUENCE
// or d elapses, and reports whether it reached n.
func (s *fakeServer) WaitForSequenceHeld(n int, d time.Duration) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()

	for {
		s.mu.Lock()
		if s.seqHeld >= n {
			s.mu.Unlock()
			return true
		}
		ch := s.changed
		s.mu.Unlock()

		select {
		case <-ch:
		case <-deadline.C:
			s.mu.Lock()
			reached := s.seqHeld >= n
			s.mu.Unlock()
			return reached
		case <-s.stop:
			return false
		}
	}
}

// awaitSequenceRelease implements the HoldAfterSequence park. It returns false
// if the server shut down while parked.
func (s *fakeServer) awaitSequenceRelease() bool {
	s.mu.Lock()
	if !s.holdAfterSeq {
		s.mu.Unlock()
		return true
	}
	s.seqHeld++
	s.notifyLocked()

	for {
		if !s.holdAfterSeq {
			s.seqHeld--
			s.notifyLocked()
			s.mu.Unlock()
			return true
		}
		ch := s.changed
		s.mu.Unlock()

		select {
		case <-ch:
		case <-s.stop:
			s.mu.Lock()
			s.seqHeld--
			s.notifyLocked()
			s.mu.Unlock()
			return false
		}
		s.mu.Lock()
	}
}

// InFlight reports calls received but not yet answered.
func (s *fakeServer) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inFlight
}

// WaitForInFlight blocks until n calls are in flight or d elapses, and reports
// whether it reached n.
//
// It returns a bool rather than failing the test itself on purpose: the caller
// owns the assertion message, and the parallelism claim it proves is the whole
// point of Task 14's test.
func (s *fakeServer) WaitForInFlight(n int, d time.Duration) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()

	for {
		s.mu.Lock()
		if s.inFlight >= n {
			s.mu.Unlock()
			return true
		}
		ch := s.changed
		s.mu.Unlock()

		select {
		case <-ch:
		case <-deadline.C:
			s.mu.Lock()
			reached := s.inFlight >= n
			s.mu.Unlock()
			return reached
		case <-s.stop:
			return false
		}
	}
}

// ---------------------------------------------------------------------------
// Configuration and observation
// ---------------------------------------------------------------------------

// GrantedSlots reports the fore-channel slot count the fake grants. The fake
// grants exactly this many regardless of what CREATE_SESSION asked for, so a
// test can compare a negotiated slot table against a single known number.
func (s *fakeServer) GrantedSlots() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grantedSlots
}

// SetGrantedSlots changes the fore-channel slot count later CREATE_SESSIONs
// grant. It exists so a test can make a retry succeed where the first attempt
// was refused for an unusable grant.
func (s *fakeServer) SetGrantedSlots(n int) {
	s.mu.Lock()
	s.grantedSlots = n
	s.mu.Unlock()
}

// SetMaxFileSize changes the FATTR4_MAXFILESIZE the fake reports.
func (s *fakeServer) SetMaxFileSize(v uint64) {
	s.mu.Lock()
	s.maxFileSize = v
	s.mu.Unlock()
}

// MaxFileSize reports the value SetMaxFileSize or withMaxFileSize configured.
func (s *fakeServer) MaxFileSize() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxFileSize
}

// SawCachethis reports whether any SEQUENCE arrived with sa_cachethis set.
// Every operation this client issues is idempotent, so the answer must stay
// false; a true means someone started asking the server to cache replies.
func (s *fakeServer) SawCachethis() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sawCachethis
}

// InjectOnce makes the next occurrence of op fail with status.
func (s *fakeServer) InjectOnce(op uint32, status uint32) {
	s.InjectN(op, status, 1)
}

// InjectN makes the next n occurrences of op fail with status. A second call
// for the same op replaces the pending injection rather than stacking, so a
// test cannot accidentally inherit leftovers from its own earlier setup.
func (s *fakeServer) InjectN(op uint32, status uint32, n int) {
	s.mu.Lock()
	if n <= 0 {
		delete(s.injections, op)
	} else {
		s.injections[op] = &injection{status: status, remaining: n}
	}
	s.mu.Unlock()
}

// takeInjection reports the injected status for op, if one is pending, and
// consumes it.
func (s *fakeServer) takeInjection(op uint32) (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inj, ok := s.injections[op]
	if !ok || inj.remaining <= 0 {
		return 0, false
	}
	inj.remaining--
	if inj.remaining == 0 {
		delete(s.injections, op)
	}
	return inj.status, true
}

// takeReplyDrop reports whether this occurrence of op should have its COMPOUND
// reply thrown away, and consumes the budget.
func (s *fakeServer) takeReplyDrop(op uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining, ok := s.dropReplyAfter[op]
	if !ok || remaining <= 0 {
		return false
	}
	remaining--
	if remaining == 0 {
		delete(s.dropReplyAfter, op)
	} else {
		s.dropReplyAfter[op] = remaining
	}
	return true
}

// DropConnection closes every open connection without a clean shutdown, which
// is what a mid-stream TCP reset looks like to the client. The listener stays
// up, so the client can reconnect through the same Dialer.
func (s *fakeServer) DropConnection() {
	s.mu.Lock()
	conns := make([]*fakeConn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		if tcp, ok := c.nc.(*net.TCPConn); ok {
			// A zero linger makes the close a reset rather than a FIN, so the
			// client sees the abrupt failure the retry classifier has to handle.
			tcp.SetLinger(0)
		}
		c.nc.Close()
	}
}

// AddTree merges directories and their children into the served tree. Keys are
// directory tree paths; the root is "/". A key is also that directory's
// filehandle unless the entry naming it in its parent set an explicit FH.
func (s *fakeServer) AddTree(t map[string][]fakeEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for dir, entries := range t {
		s.tree[dir] = append(s.tree[dir], entries...)
		for _, e := range entries {
			p := path.Join(dir, e.Name)
			fh := effectiveFH(p, e)
			if e.FH != "" {
				s.fhOverridden[p] = true
			}
			s.byFH[fh] = fhTarget{path: p, entry: e}
			// The side maps are keyed by filehandle, so ACLFor takes whatever
			// the entry's effective filehandle is.
			if e.ACL != nil {
				s.acls[fh] = bytes.Clone(e.ACL)
			}
			if e.IsDir {
				if _, ok := s.tree[p]; !ok {
					s.tree[p] = nil
				}
			}
		}
	}
}

// effectiveFH is the single definition of an entry's filehandle: its own FH if
// it set one, its tree path otherwise.
func effectiveFH(entryPath string, e fakeEntry) string {
	if e.FH != "" {
		return e.FH
	}
	return entryPath
}

// ACLFor returns the fattr4_acl SETATTR last stored for fh, or nil.
func (s *fakeServer) ACLFor(fh string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	acl, ok := s.acls[fh]
	if !ok {
		return nil
	}
	return bytes.Clone(acl)
}

// CallCount reports how many times op was attempted. It counts attempts, not
// successes, including the ones an injection failed, which is what makes it
// usable for asserting a retry budget was spent exactly.
func (s *fakeServer) CallCount(op uint32) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callCounts[op]
}

// LookupCount reports how many times LOOKUP resolved name. Task 10 uses it to
// prove stale-filehandle recovery re-resolved the path, and Task 12 uses it to
// prove READDIR did not need a lookup per entry.
func (s *fakeServer) LookupCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookupCounts[name]
}

// ConnectionCount reports TCP connections accepted over the fake's lifetime,
// including ones since closed.
func (s *fakeServer) ConnectionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connSum
}

// SessionCount reports sessions created. One per connection is the design.
//
// It stays 0 until something drives CREATE_SESSION, which nothing before
// Task 8 does; Task 8's session tests are the first to move it.
func (s *fakeServer) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionCount
}

// ClientIDCount reports distinct clientids issued. It must be 1: EXCHANGE_ID
// runs once and every session reuses its clientid, so a repeated EXCHANGE_ID
// from the same co_ownerid returns the same clientid here as it would on a
// real server.
func (s *fakeServer) ClientIDCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clientIDs)
}

// CreateSessionSequences reports every csa_sequence the fake received, in wire
// order, refused and replayed ones included. It returns a copy so callers cannot
// race or mutate server state.
func (s *fakeServer) CreateSessionSequences() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint32(nil), s.createSessionSeq...)
}

// CreateSessionArgs reports every CREATE_SESSION4args the fake received, in wire
// order, so a test can assert on what the client offered. The channel attributes
// and the sec parms are the interesting part: an offer the server silently cuts
// down is invisible in the grant.
func (s *fakeServer) CreateSessionArgs() []xdr.CREATE_SESSION4args {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]xdr.CREATE_SESSION4args(nil), s.createSessionArgs...)
}

// ClassifyCreateSessionSequence drives the fake's per-clientid CREATE_SESSION
// sequence classifier without creating a wire session. It exists for the fake's
// own mutation tests: a conforming client sends neither a regression nor a
// repeat of a value it has already had answered, so end-to-end tests alone
// cannot prove those arms are present.
//
// An unknown clientid classifies as misordered here. Over the wire it is
// NFS4ERR_STALE_CLIENTID, which createSession checks before classifying.
func (s *fakeServer) ClassifyCreateSessionSequence(clientID uint64, sequence uint32) createSeqDisposition {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.knownClientIDLocked(clientID) {
		return createSeqMisordered
	}
	return s.classifyCreateSequenceLocked(clientID, sequence)
}

// CreateSessionDirect runs the fake's CREATE_SESSION handler without a wire
// round trip, so a test can drive the replay cache with a csa_sequence no
// conforming client would send. It returns the resok and the status.
func (s *fakeServer) CreateSessionDirect(clientID uint64, sequence uint32) (xdr.CREATE_SESSION4resok, uint32) {
	res, status := s.createSession(xdr.CREATE_SESSION4args{
		Csa_clientid: xdr.Clientid4(clientID),
		Csa_sequence: xdr.Sequenceid4(sequence),
	})
	if status != NFS4_OK {
		return xdr.CREATE_SESSION4resok{}, status
	}
	return *res.Opcreatesession().Csr_resok4(), status
}

// BindConnToSessionCount reports BIND_CONN_TO_SESSION operations received. It
// must be 0. Trunking is deliberately not implemented, so a nonzero count
// means someone added it and this fake is no longer modelling the server the
// client actually talks to.
func (s *fakeServer) BindConnToSessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bindConnCount
}

// CallsPerConnection reports COMPOUND calls keyed by connection number, in
// accept order starting at 1, for asserting a connection pool spreads load.
func (s *fakeServer) CallsPerConnection() map[int]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]int, len(s.perConn))
	for id, n := range s.perConn {
		out[id] = n
	}
	return out
}

// ReaddirMaxcounts returns the rd_maxcount of every READDIR the fake decoded, in
// order. It is the only way to observe what the client asked the server to fit a
// reply into, which is what ca_maxresponsesize headroom is a claim about.
func (s *fakeServer) ReaddirMaxcounts() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.readdirMaxcounts)
}

// SetReaddirSizeWindow makes the fake refuse any rd_maxcount outside
// [minOK, maxOK]: NFS4ERR_TOOSMALL below minOK, NFS4ERR_REP_TOO_BIG above maxOK.
// Zero disables that side of the window.
//
// An INVERTED window (minOK > maxOK) is the case worth having a hook for: a
// server that refuses every size, one way below the crossover and the other way
// above it. ReadDir's two recoveries then push against each other -- grow on
// TOOSMALL, shrink on REP_TOO_BIG -- and each one's own hard exit (the cap, the
// floor) sits outside the interval the pair oscillates in, so neither is reached.
// InjectOnce cannot express this: it fires once, and the bug needs a server that
// keeps answering.
func (s *fakeServer) SetReaddirSizeWindow(minOK, maxOK uint32) {
	s.mu.Lock()
	s.readdirMinOK, s.readdirMaxOK = minOK, maxOK
	s.mu.Unlock()
}

// SetReaddirPageSize caps entries per READDIR reply, to force the cookie chain
// across several pages. Zero means no cap.
func (s *fakeServer) SetReaddirPageSize(n int) {
	s.mu.Lock()
	s.readdirPageSize = n
	s.mu.Unlock()
}

// OmitReaddirAttrs makes every subsequent READDIR reply describe its entries
// without the named attributes, which is what a server that does not support
// them looks like: RFC 8881 section 18.23.3 lets a READDIR reply carry a subset
// of rd_attr_request, and only FATTR4_RDATTR_ERROR is ever mandatory.
//
// It exists because "the server answered with less than we asked for" is not
// reachable any other way, and it is the only condition under which
// Dirent.AttrsKnown may be false on this transport. Without it, a ReadDir that
// hardcodes AttrsKnown = true is indistinguishable from one that derives it,
// and the walk would then trust a zero mode as though it were 0000.
//
// Only the READDIR path is affected. GETATTR keeps answering in full, because
// the point is a partial enumeration reply followed by a Stat that succeeds.
func (s *fakeServer) OmitReaddirAttrs(bits ...uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.omitReaddirAttrs == nil {
		s.omitReaddirAttrs = make(map[uint32]bool, len(bits))
	}
	for _, b := range bits {
		s.omitReaddirAttrs[b] = true
	}
}

// clearBitmapBits returns bitmap without the attributes in drop. The input is
// never mutated: it belongs to the decoded call arguments, and the fake's
// replies are built from it more than once.
func clearBitmapBits(bitmap []uint32, drop map[uint32]bool) []uint32 {
	if len(drop) == 0 {
		return bitmap
	}
	out := slices.Clone(bitmap)
	for attr := range drop {
		word := int(attr / 32)
		if word < len(out) {
			out[word] &^= uint32(1) << (attr % 32)
		}
	}
	return out
}

// ChangeVerifierAfter changes the cookie verifier after n READDIR replies, so
// a continuation arrives with a stale rd_cookieverf and gets NFS4ERR_NOT_SAME.
// That is the READDIR restart path, and it is not reproducible on demand
// against real hardware.
func (s *fakeServer) ChangeVerifierAfter(n int) {
	s.mu.Lock()
	s.changeVerfAfter = n
	s.readdirReplies = 0
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// RPC framing
// ---------------------------------------------------------------------------

// parseFakeCall decodes the RFC 5531 call header and returns the procedure
// arguments. It reuses wireDecoder from ops.go rather than reimplementing
// opaque framing.
func parseFakeCall(record []byte) (xid, proc uint32, body []byte, err error) {
	d := wireDecoder{b: record}

	if xid, err = d.word("xid"); err != nil {
		return 0, 0, nil, err
	}
	messageType, err := d.word("message type")
	if err != nil {
		return 0, 0, nil, err
	}
	if messageType != uint32(xdr.CALL) {
		return 0, 0, nil, fmt.Errorf("fake: message type %d is not CALL", messageType)
	}
	version, err := d.word("RPC version")
	if err != nil {
		return 0, 0, nil, err
	}
	if version != rpcVersion {
		return 0, 0, nil, fmt.Errorf("fake: RPC version %d is not %d", version, rpcVersion)
	}
	program, err := d.word("program")
	if err != nil {
		return 0, 0, nil, err
	}
	programVersion, err := d.word("program version")
	if err != nil {
		return 0, 0, nil, err
	}
	if program != nfsProgram || programVersion != nfsProgramVersion {
		return 0, 0, nil, fmt.Errorf("fake: call is for program %d version %d", program, programVersion)
	}
	if proc, err = d.word("procedure"); err != nil {
		return 0, 0, nil, err
	}
	if _, err = d.word("credential flavor"); err != nil {
		return 0, 0, nil, err
	}
	if _, err = d.opaque("credential body"); err != nil {
		return 0, 0, nil, err
	}
	if _, err = d.word("verifier flavor"); err != nil {
		return 0, 0, nil, err
	}
	if _, err = d.opaque("verifier body"); err != nil {
		return 0, 0, nil, err
	}
	return xid, proc, record[d.off:], nil
}

// encodeAcceptedReply frames a successful accepted reply around payload.
func encodeAcceptedReply(xid uint32, payload []byte) []byte {
	out := make([]byte, 0, 6*4+len(payload))
	out = binary.BigEndian.AppendUint32(out, xid)
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.REPLY))
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.MSG_ACCEPTED))
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.AUTH_NONE)) // verifier flavor
	out = binary.BigEndian.AppendUint32(out, 0)                     // verifier length
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.SUCCESS))
	return append(out, payload...)
}

// encodeAcceptedFailure frames an accepted reply carrying an RPC-level failure.
// PROG_MISMATCH is not produced here, so no version range follows the status.
func encodeAcceptedFailure(xid uint32, status xdr.Accept_stat) []byte {
	out := make([]byte, 0, 6*4)
	out = binary.BigEndian.AppendUint32(out, xid)
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.REPLY))
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.MSG_ACCEPTED))
	out = binary.BigEndian.AppendUint32(out, uint32(xdr.AUTH_NONE))
	out = binary.BigEndian.AppendUint32(out, 0)
	return binary.BigEndian.AppendUint32(out, uint32(status))
}

// ---------------------------------------------------------------------------
// COMPOUND
// ---------------------------------------------------------------------------

// compoundReply runs one COMPOUND and returns its encoded COMPOUND4res. A
// request the fake cannot decode becomes errBadXDR with no results, which
// is what a real server does with a garbled argarray.
//
// The second return value reports that the reply must be thrown away
// (withDropReplyAfter). It is distinct from an encoding failure: the operation
// ran and the server state changed, and the caller must send nothing at all.
func (s *fakeServer) compoundReply(body []byte) ([]byte, bool) {
	res, drop, err := s.runCompound(body)
	if err != nil {
		res = xdr.COMPOUND4res{Status: xdr.NFS4ERR_BADXDR}
	}
	if drop {
		return nil, true
	}

	encoded, err := marshalCompoundRes(res)
	if err != nil {
		// The reply the fake built cannot be encoded, which is a bug in the
		// fake rather than a server behaviour worth modelling. Fall back to a
		// bare status so the client gets a decodable answer and the test fails
		// on the status rather than on a hang.
		encoded, err = marshalCompoundRes(xdr.COMPOUND4res{Status: xdr.NFS4ERR_SERVERFAULT})
		if err != nil {
			return nil, false
		}
	}
	return encoded, false
}

func marshalCompoundRes(res xdr.COMPOUND4res) (b []byte, err error) {
	defer recoverXDR(&err)
	var buf bytes.Buffer
	res.XdrMarshal(xdr.XdrOut{Out: &buf}, "")
	return buf.Bytes(), nil
}

// compoundState is the per-COMPOUND current filehandle, as RFC 8881 defines it,
// plus the slot this COMPOUND's SEQUENCE acquired, if any.
type compoundState struct {
	fh     string
	haveFH bool
	// crossedPseudoRoot records that a LOOKUP in THIS COMPOUND has already walked
	// out of the pseudo-filesystem and into an export. A FlashBlade refuses the
	// next LOOKUP after that crossing with NFS4ERR_NOENT; see
	// oneLookupAfterPseudoRootCrossing.
	crossedPseudoRoot bool
	// sessionID is populated by a successful leading SEQUENCE. Session-bound ops
	// such as RECLAIM_COMPLETE use it to find the clientid they apply to.
	sessionID [16]byte
	// acquired is the slot held for the duration of this COMPOUND. runCompound
	// releases it; nothing else may.
	acquired *slotState
}

// runCompound decodes and executes the argarray one operation at a time.
//
// It dispatches on the raw opnum word rather than unmarshalling xdr.Nfs_argop4,
// for two reasons. First, an opnum the generated XDR has no arm for — including
// BIND_CONN_TO_SESSION, which this subset omits entirely — would panic the
// whole-argarray decode, leaving the fake unable to say which op it choked on;
// dispatching by number lets it answer NFS4ERR_OP_ILLEGAL and count what it
// saw. Second, it makes the "deliberately not implemented" list a single
// default case that cannot accidentally return NFS4_OK.
//
// goxdr signals a decode failure by panicking with xdr.XdrError rather than
// returning an error, so this function recovers exactly the way ops.go does.
// Without it one malformed request would take down the whole test binary
// instead of failing a single test.
// The drop return value is set when a successful operation's reply is to be
// discarded (withDropReplyAfter). Everything the operation did to server state
// stands; only the answer is lost.
// isForwardRequiredOp reports whether an operation is one a FlashBlade will only
// accept once per COMPOUND.
//
// MEASURED against an S200 on Purity 4.8.0: a COMPOUND carrying two SETATTRs is
// refused with NFS4ERR_INVAL and an EMPTY result array, whether the two address
// the same filehandle or different ones, and whether they carry an ACL or a mode.
// Four operations are fine, and multiple GETATTRs are fine; it is the second
// SETATTR itself. See internal/nfs41/traverseorder_live_test.go.
//
// The mechanism, from the Purity source (pure-fb/iridium, kernel/root/nfs.cpp --
// NOT nfs_exa.cpp, which is the EXA HPC product): the SETATTR case sets
// is_mutable_ and calls forward_required(op_idx), which fails when one is already
// claimed because the compound holds a SINGLE forward index rather than a list.
// The compound then returns INVALID with the response reset. It is deliberate:
// kernel/root/test/data_integrity_nfs4_test.cpp records that the server supports
// one mutable operation per compound "due to the forwarding architecture" and that
// the data integrity feature depends on it.
//
// WRITE, LOCK, LOCKT, LOCKU and LINK go through the same gate on the array. Only
// SETATTR is listed here because it is the only one of them this fake implements;
// add them here if it ever grows them.
func isForwardRequiredOp(opnum uint32) bool {
	return opnum == uint32(xdr.OP_SETATTR)
}

func (s *fakeServer) runCompound(body []byte) (res xdr.COMPOUND4res, drop bool, err error) {
	defer recoverXDR(&err)

	d := wireDecoder{b: body}
	tag, err := d.opaque("COMPOUND tag")
	if err != nil {
		return res, false, err
	}
	minor, err := d.word("COMPOUND minor version")
	if err != nil {
		return res, false, err
	}
	if minor != nfsMinorVersion {
		return xdr.COMPOUND4res{
			Status: xdr.NFS4ERR_MINOR_VERS_MISMATCH,
			Tag:    bytes.Clone(tag),
		}, false, nil
	}
	count, err := d.word("COMPOUND operation count")
	if err != nil {
		return res, false, err
	}
	if uint64(count)*4 > uint64(len(d.b)-d.off) {
		return res, false, fmt.Errorf("fake: operation count %d exceeds the %d-byte argarray", count, len(d.b)-d.off)
	}

	res.Tag = bytes.Clone(tag)
	res.Status = xdr.NFS4_OK
	var st compoundState

	// One forward-required operation per COMPOUND; see isForwardRequiredOp.
	//
	// The count is taken in a scan BEFORE anything executes, because that is
	// where the array takes it: a refused COMPOUND has no side effects, and a
	// fake that executed the first SETATTR and then reported failure would hand
	// callers a partially-applied bundle the hardware never produces -- the one
	// difference that would make a retry unsafe.
	//
	// The scan is only trusted when it walks the argarray exactly to its end. An
	// operation skipArgs does not know leaves the offset where it was, and a
	// desynchronised scan would count garbage; in that case the count is
	// discarded and the ordinary loop runs, which is the behaviour that existed
	// before this check and fails in the ways the other tests already cover.
	if forwardRequiredOps(s, d, int(count)) > 1 {
		// Empty Resarray, not a result per operation: the array resets the
		// response before writing the error, so a client sees a status and
		// nothing else. Any test asserting an operation trace on a refused
		// COMPOUND is asserting a shape the hardware will not produce.
		return xdr.COMPOUND4res{
			Status: xdr.Nfsstat4(NFS4ERR_INVAL),
			Tag:    res.Tag,
		}, false, nil
	}

	// A slot acquired by this COMPOUND's SEQUENCE is held until the COMPOUND
	// ends, however it ends — including the recoverXDR path, since this defer
	// runs before that one returns.
	defer func() {
		if st.acquired != nil {
			s.releaseSlot(st.acquired)
		}
	}()

	// Once any session exists, this fake polices SEQUENCE placement the way a
	// real server does. Before that it cannot: the fake's own tests, which run
	// before Task 8's session layer exists, have to be able to speak COMPOUND
	// with no session at all. Gating on sessionCount keeps that escape hatch
	// open for exactly those tests and closes it for everything afterwards, so
	// the hole cannot silently widen as later tasks add operations.
	s.mu.Lock()
	requireSequence := s.sessionCount > 0
	s.mu.Unlock()

	for i := range int(count) {
		opnum, err := d.word("operation number")
		if err != nil {
			return res, false, err
		}

		s.mu.Lock()
		s.callCounts[opnum]++
		if opnum == opBindConnToSession {
			s.bindConnCount++
		}
		s.mu.Unlock()

		// RFC 8881: SEQUENCE, when present, must be the first operation, and
		// with the exception of the operations that establish or tear down
		// session state it must be present.
		if isSequence := opnum == uint32(xdr.OP_SEQUENCE); isSequence && i != 0 {
			res.Resarray = append(res.Resarray, errResult(opnum, errSequencePos))
			res.Status = xdr.Nfsstat4(errSequencePos)
			return res, false, nil
		} else if !isSequence && i == 0 && requireSequence && !allowedWithoutSequence(opnum) {
			res.Resarray = append(res.Resarray, errResult(opnum, errOpNotInSession))
			res.Status = xdr.Nfsstat4(errOpNotInSession)
			return res, false, nil
		}

		result, status := s.runOp(opnum, &d, &st)
		res.Resarray = append(res.Resarray, result)
		// The drop is taken only for an operation that succeeded, and only
		// after it ran. That is the whole point of the knob: an injection
		// models a server that refused, this models one that acted and whose
		// answer never arrived.
		if status == NFS4_OK && s.takeReplyDrop(opnum) {
			drop = true
		}
		if status != NFS4_OK {
			// RFC 8881: the results array ends with the failing operation and
			// the COMPOUND status is that operation's status.
			res.Status = xdr.Nfsstat4(status)
			return res, drop, nil
		}
	}
	return res, drop, nil
}

// forwardRequiredOps counts the forward-required operations in an argarray
// without executing any of them, on a copy of the decoder so the caller's
// position is untouched. It returns 0 when the scan cannot be trusted -- see the
// call site.
func forwardRequiredOps(s *fakeServer, d wireDecoder, count int) (n int) {
	defer func() {
		if recover() != nil {
			n = 0
		}
	}()
	for range count {
		opnum, err := d.word("operation number")
		if err != nil {
			return 0
		}
		if isForwardRequiredOp(opnum) {
			n++
		}
		s.skipArgs(opnum, &d)
	}
	if d.off != len(d.b) {
		return 0
	}
	return n
}

// runOp decodes one operation's arguments and produces its result. It returns
// the result and its status; a non-OK status ends the COMPOUND.
func (s *fakeServer) runOp(opnum uint32, d *wireDecoder, st *compoundState) (xdr.Nfs_resop4, uint32) {
	// An injection fires before the operation runs, so it models a server that
	// refused rather than one that acted and then lied about it.
	if status, ok := s.takeInjection(opnum); ok {
		// The arguments still have to be consumed or the rest of the argarray
		// cannot be decoded. Nothing after the failing op is executed, but the
		// bytes must be skipped to keep the decoder honest about trailing data.
		s.skipArgs(opnum, d)
		return errResult(opnum, status), status
	}

	switch opnum {
	case uint32(xdr.OP_PUTROOTFH):
		st.fh, st.haveFH = fakeRootFH, true
		// Positioned in the pseudo-filesystem: the next LOOKUP is the crossing.
		st.crossedPseudoRoot = false
		r := xdr.Nfs_resop4{Resop: xdr.OP_PUTROOTFH}
		r.Opputrootfh().Status = xdr.NFS4_OK
		return r, NFS4_OK

	case uint32(xdr.OP_PUTFH):
		var args xdr.PUTFH4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		fh := string(args.Object)
		if !s.exists(fh) {
			return errResult(opnum, NFS4ERR_STALE), NFS4ERR_STALE
		}
		st.fh, st.haveFH = fh, true
		// A PUTFH lands inside a filesystem, so no crossing happens in this
		// COMPOUND and LOOKUPs from here may chain freely. This is the whole reason
		// the fix works: resolving from the export root's filehandle never crosses.
		st.crossedPseudoRoot = false
		r := xdr.Nfs_resop4{Resop: xdr.OP_PUTFH}
		r.Opputfh().Status = xdr.NFS4_OK
		return r, NFS4_OK

	case uint32(xdr.OP_LOOKUP):
		var args xdr.LOOKUP4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		name := string(args.Objname)
		s.mu.Lock()
		s.lookupCounts[name]++
		s.mu.Unlock()
		if !st.haveFH {
			return errResult(opnum, errNoFilehandle), errNoFilehandle
		}
		// MEASURED 2026-08-21 on an S200 (Purity 4.8.0): a FlashBlade refuses the
		// LOOKUP that follows the pseudo-filesystem crossing within one COMPOUND.
		//
		//   PUTROOTFH + LOOKUP fs + GETFH                  -> NFS4_OK
		//   PUTROOTFH + LOOKUP fs + LOOKUP child + GETFH   -> NFS4ERR_NOENT
		//   PUTFH(export root) + 4 chained LOOKUPs + GETFH -> NFS4_OK
		//
		// So chaining is fine WITHIN a filesystem; only the crossing cannot be
		// chained past. Modelled because its absence is the entire reason Defect 1
		// shipped: this fake chained LOOKUPs across its own root happily, so
		// resolvePath passed every test and then could not address a single object
		// below the export root on real hardware.
		if s.oneLookupAfterPseudoRootCrossing && st.crossedPseudoRoot {
			return errResult(opnum, NFS4ERR_NOENT), NFS4ERR_NOENT
		}
		fromPseudoRoot := st.fh == fakeRootFH
		child, ok := s.lookup(st.fh, name)
		if !ok {
			return errResult(opnum, NFS4ERR_NOENT), NFS4ERR_NOENT
		}
		st.fh = child
		if fromPseudoRoot {
			st.crossedPseudoRoot = true
		}
		r := xdr.Nfs_resop4{Resop: xdr.OP_LOOKUP}
		r.Oplookup().Status = xdr.NFS4_OK
		return r, NFS4_OK

	case uint32(xdr.OP_GETFH):
		if !st.haveFH {
			return errResult(opnum, errNoFilehandle), errNoFilehandle
		}
		r := xdr.Nfs_resop4{Resop: xdr.OP_GETFH}
		r.Opgetfh().Status = xdr.NFS4_OK
		*r.Opgetfh().Resok4() = xdr.GETFH4resok{Object: []byte(st.fh)}
		return r, NFS4_OK

	case uint32(xdr.OP_GETATTR):
		var args xdr.GETATTR4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		if !st.haveFH {
			return errResult(opnum, errNoFilehandle), errNoFilehandle
		}
		r := xdr.Nfs_resop4{Resop: xdr.OP_GETATTR}
		r.Opgetattr().Status = xdr.NFS4_OK
		*r.Opgetattr().Resok4() = xdr.GETATTR4resok{
			Obj_attributes: s.attrsFor(st.fh, args.Attr_request),
		}
		return r, NFS4_OK

	case uint32(xdr.OP_SETATTR):
		var args xdr.SETATTR4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		if !st.haveFH {
			return errResult(opnum, errNoFilehandle), errNoFilehandle
		}
		return s.setAttr(st.fh, args)

	case uint32(xdr.OP_READDIR):
		var args xdr.READDIR4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		if !st.haveFH {
			return errResult(opnum, errNoFilehandle), errNoFilehandle
		}
		return s.readDir(st.fh, args)

	case uint32(xdr.OP_EXCHANGE_ID):
		var args xdr.EXCHANGE_ID4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		return s.exchangeID(args)

	case uint32(xdr.OP_CREATE_SESSION):
		var args xdr.CREATE_SESSION4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		return s.createSession(args)

	case uint32(xdr.OP_DESTROY_SESSION):
		var args xdr.DESTROY_SESSION4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		return s.destroySession(args)

	case uint32(xdr.OP_RECLAIM_COMPLETE):
		var args xdr.RECLAIM_COMPLETE4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		return s.reclaimCompleteOp(st, args)

	case uint32(xdr.OP_SEQUENCE):
		var args xdr.SEQUENCE4args
		args.XdrMarshal(xdr.XdrIn{In: &decoderReader{d: d}}, "")
		r, status, slot := s.sequence(args)
		if slot != nil {
			st.sessionID = args.Sa_sessionid
		}
		// The acquired slot is recorded on the COMPOUND rather than returned,
		// so runCompound can release it in a defer without every other
		// operation's return statement having to carry a nil through.
		st.acquired = slot
		if slot != nil {
			// Parked here, the slot is held while the rest of the COMPOUND
			// waits, so a second request naming it meets a busy slot.
			s.awaitSequenceRelease()
		}
		return r, status

	default:
		// Everything the client does not send: OPEN, CLOSE, LOCK, delegations,
		// the back channel, BIND_CONN_TO_SESSION, and any opnum outside the
		// protocol. Answering one of these successfully would hide a
		// regression, so the fake never returns NFS4_OK here.
		//
		// The arguments cannot be skipped, because their encoding is unknown
		// once the fake stops modelling the op — so the COMPOUND ends here.
		// That is legal: NFS4ERR_OP_ILLEGAL terminates an argarray.
		status := NFS4ERR_NOTSUPP
		if !knownOpnum(opnum) {
			status = NFS4ERR_OP_ILLEGAL
		}
		return illegalResult(status), status
	}
}

// skipArgs consumes the arguments of an operation whose execution was replaced
// by an injected error. Only the ops the fake models can be skipped; the
// injection API is not reachable for the others.
func (s *fakeServer) skipArgs(opnum uint32, d *wireDecoder) {
	r := xdr.XdrIn{In: &decoderReader{d: d}}
	switch opnum {
	case uint32(xdr.OP_PUTFH):
		var a xdr.PUTFH4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_LOOKUP):
		var a xdr.LOOKUP4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_GETATTR):
		var a xdr.GETATTR4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_SETATTR):
		var a xdr.SETATTR4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_READDIR):
		var a xdr.READDIR4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_EXCHANGE_ID):
		var a xdr.EXCHANGE_ID4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_CREATE_SESSION):
		var a xdr.CREATE_SESSION4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_DESTROY_SESSION):
		var a xdr.DESTROY_SESSION4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_RECLAIM_COMPLETE):
		var a xdr.RECLAIM_COMPLETE4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_SEQUENCE):
		var a xdr.SEQUENCE4args
		a.XdrMarshal(r, "")
	case uint32(xdr.OP_PUTROOTFH), uint32(xdr.OP_GETFH):
		// void arguments
	}
}

// allowedWithoutSequence reports whether opnum may begin a COMPOUND that has no
// SEQUENCE. RFC 8881 section 18.46.3 lists exactly the operations that create or
// destroy the state SEQUENCE depends on, so requiring a SEQUENCE ahead of them
// would be circular. BIND_CONN_TO_SESSION is in the RFC's list but not here:
// this fake refuses it as unimplemented, and leaving it out means an accidental
// send is answered with a session error rather than being quietly permitted.
func allowedWithoutSequence(opnum uint32) bool {
	switch opnum {
	case uint32(xdr.OP_EXCHANGE_ID),
		uint32(xdr.OP_CREATE_SESSION),
		uint32(xdr.OP_DESTROY_SESSION),
		uint32(xdr.OP_DESTROY_CLIENTID):
		return true
	}
	return false
}

// knownOpnum reports whether opnum names an operation in the NFSv4.1 argarray
// union at all. It separates "recognised but not implemented here", which is
// NFS4ERR_NOTSUPP, from "not an operation", which is NFS4ERR_OP_ILLEGAL.
func knownOpnum(opnum uint32) bool {
	return (opnum >= uint32(xdr.OP_ACCESS) && opnum <= uint32(xdr.OP_RECLAIM_COMPLETE)) ||
		opnum == uint32(xdr.OP_ILLEGAL)
}

// illegalResult builds an OP_ILLEGAL result carrying status.
func illegalResult(status uint32) xdr.Nfs_resop4 {
	r := xdr.Nfs_resop4{Resop: xdr.OP_ILLEGAL}
	r.Opillegal().Status = xdr.Nfsstat4(status)
	return r
}

// errResult builds the correctly-typed failing result for op, so a client that
// inspects results[i] by operation still finds the arm it expects.
func errResult(opnum uint32, status uint32) xdr.Nfs_resop4 {
	s := xdr.Nfsstat4(status)
	switch opnum {
	case uint32(xdr.OP_PUTROOTFH):
		r := xdr.Nfs_resop4{Resop: xdr.OP_PUTROOTFH}
		r.Opputrootfh().Status = s
		return r
	case uint32(xdr.OP_PUTFH):
		r := xdr.Nfs_resop4{Resop: xdr.OP_PUTFH}
		r.Opputfh().Status = s
		return r
	case uint32(xdr.OP_LOOKUP):
		r := xdr.Nfs_resop4{Resop: xdr.OP_LOOKUP}
		r.Oplookup().Status = s
		return r
	case uint32(xdr.OP_GETFH):
		r := xdr.Nfs_resop4{Resop: xdr.OP_GETFH}
		r.Opgetfh().Status = s
		return r
	case uint32(xdr.OP_GETATTR):
		r := xdr.Nfs_resop4{Resop: xdr.OP_GETATTR}
		r.Opgetattr().Status = s
		return r
	case uint32(xdr.OP_SETATTR):
		r := xdr.Nfs_resop4{Resop: xdr.OP_SETATTR}
		r.Opsetattr().Status = s
		return r
	case uint32(xdr.OP_READDIR):
		r := xdr.Nfs_resop4{Resop: xdr.OP_READDIR}
		r.Opreaddir().Status = s
		return r
	case uint32(xdr.OP_EXCHANGE_ID):
		r := xdr.Nfs_resop4{Resop: xdr.OP_EXCHANGE_ID}
		r.Opexchange_id().Eir_status = s
		return r
	case uint32(xdr.OP_CREATE_SESSION):
		r := xdr.Nfs_resop4{Resop: xdr.OP_CREATE_SESSION}
		r.Opcreatesession().Csr_status = s
		return r
	case uint32(xdr.OP_DESTROY_SESSION):
		r := xdr.Nfs_resop4{Resop: xdr.OP_DESTROY_SESSION}
		r.Opdestroysession().Dsr_status = s
		return r
	case uint32(xdr.OP_SEQUENCE):
		r := xdr.Nfs_resop4{Resop: xdr.OP_SEQUENCE}
		r.Opsequence().Sr_status = s
		return r
	case uint32(xdr.OP_RECLAIM_COMPLETE):
		r := xdr.Nfs_resop4{Resop: xdr.OP_RECLAIM_COMPLETE}
		r.Opreclaimcomplete().Rcr_status = s
		return r
	default:
		return illegalResult(status)
	}
}

// ---------------------------------------------------------------------------
// Session operations
// ---------------------------------------------------------------------------

func (s *fakeServer) exchangeID(args xdr.EXCHANGE_ID4args) (xdr.Nfs_resop4, uint32) {
	owner := string(args.Eia_clientowner.Co_ownerid)

	s.mu.Lock()
	clientID, ok := s.clientIDs[owner]
	if !ok {
		clientID = s.nextClientID
		s.nextClientID++
		s.clientIDs[owner] = clientID
	}
	implID := s.implID
	exchangeSequence := s.exchangeSequence
	s.mu.Unlock()

	r := xdr.Nfs_resop4{Resop: xdr.OP_EXCHANGE_ID}
	r.Opexchange_id().Eir_status = xdr.NFS4_OK
	resok := r.Opexchange_id().Eir_resok4()
	*resok = xdr.EXCHANGE_ID4resok{
		Eir_clientid:      clientID,
		Eir_sequenceid:    xdr.Sequenceid4(exchangeSequence),
		Eir_flags:         xdr.EXCHGID4_FLAG_USE_NON_PNFS,
		Eir_state_protect: xdr.State_protect4_r{Spr_how: xdr.SP4_NONE},
		Eir_server_owner: xdr.Server_owner4{
			So_minor_id: 1,
			So_major_id: []byte("permissionreset-fakeserver"),
		},
		Eir_server_scope: []byte("permissionreset-fakeserver"),
	}
	if implID != nil {
		// The array is bound to 1 in the XDR, and a server that declines to
		// identify itself sends it empty. Both shapes matter: whether a real
		// FlashBlade populates eir_server_impl_id is an open lab question, so
		// the fake can produce either answer on demand.
		resok.Eir_server_impl_id = []xdr.Nfs_impl_id4{*implID}
	}
	return r, NFS4_OK
}

func (s *fakeServer) knownClientIDLocked(clientID uint64) bool {
	for _, id := range s.clientIDs {
		if id == clientID {
			return true
		}
	}
	return false
}

// createSeqDisposition is what the fake decides to do with a csa_sequence.
type createSeqDisposition int

const (
	// createSeqNext is the expected value: run CREATE_SESSION for real.
	createSeqNext createSeqDisposition = iota
	// createSeqReplay is the value most recently answered for this clientid.
	// RFC 8881 section 18.36.4 requires the cached reply, not an error: the
	// client's retry after a lost reply must not create a second session.
	createSeqReplay
	// createSeqMisordered is anything else — a regression, or a jump ahead.
	createSeqMisordered
)

// classifyCreateSequenceLocked decides how to answer csa_sequence for a
// clientid, and advances the per-clientid watermark when the value is the
// expected next one.
//
// The three-way split is the whole point. A server that answers
// NFS4ERR_SEQ_MISORDERED to a repeat, as this fake used to, cannot express the
// one case the client's transactional csa_sequence handling exists for: the
// server created the session and the reply was lost. Under the old behaviour a
// correct client looked broken and a client that never retried looked correct.
func (s *fakeServer) classifyCreateSequenceLocked(clientID uint64, sequence uint32) createSeqDisposition {
	// Record attempts, including refused and replayed ones: the accessor
	// describes what the client sent, while lastCreateSeq describes what the
	// server accepted.
	s.createSessionSeq = append(s.createSessionSeq, sequence)
	last, initialized := s.lastCreateSeq[clientID]
	if !initialized {
		if sequence != s.exchangeSequence {
			return createSeqMisordered
		}
		s.lastCreateSeq[clientID] = sequence
		return createSeqNext
	}
	switch sequence {
	case last:
		return createSeqReplay
	case last + 1:
		s.lastCreateSeq[clientID] = sequence
		return createSeqNext
	default:
		return createSeqMisordered
	}
}

func (s *fakeServer) createSession(args xdr.CREATE_SESSION4args) (xdr.Nfs_resop4, uint32) {
	s.mu.Lock()
	s.createSessionArgs = append(s.createSessionArgs, args)
	clientID := uint64(args.Csa_clientid)
	if !s.knownClientIDLocked(clientID) {
		s.mu.Unlock()
		return errResult(uint32(xdr.OP_CREATE_SESSION), errStaleClientID), errStaleClientID
	}
	// Refused BEFORE the sequence is classified, and therefore before the
	// watermark moves. That ordering is the whole point: a real server that
	// refuses CREATE_SESSION creates no session and records no csa_sequence, so
	// the client's retry with the SAME sequence must look like a first attempt
	// rather than a replay. Placing this after classifyCreateSequenceLocked made
	// the retry fail with NFS4ERR_SEQ_MISORDERED and would have sent us looking
	// for a client bug that did not exist.
	if s.requireBackChannelAttrs && args.Csa_back_chan_attrs.Ca_maxrequests == 0 {
		s.mu.Unlock()
		return errResult(uint32(xdr.OP_CREATE_SESSION), NFS4ERR_TOOSMALL), NFS4ERR_TOOSMALL
	}

	switch s.classifyCreateSequenceLocked(clientID, uint32(args.Csa_sequence)) {
	case createSeqNext:
		// Fall through and create a session.
	case createSeqReplay:
		cached, ok := s.lastCreateReply[clientID]
		s.mu.Unlock()
		if !ok {
			// The watermark moved without a reply being cached, which only
			// happens when ClassifyCreateSessionSequence was driven directly.
			// There is nothing to replay, so refuse rather than invent a reply.
			return errResult(uint32(xdr.OP_CREATE_SESSION), NFS4ERR_SEQ_MISORDERED), NFS4ERR_SEQ_MISORDERED
		}
		r := xdr.Nfs_resop4{Resop: xdr.OP_CREATE_SESSION}
		r.Opcreatesession().Csr_status = xdr.NFS4_OK
		*r.Opcreatesession().Csr_resok4() = cached
		return r, NFS4_OK
	default:
		s.mu.Unlock()
		return errResult(uint32(xdr.OP_CREATE_SESSION), NFS4ERR_SEQ_MISORDERED), NFS4ERR_SEQ_MISORDERED
	}

	// One session per clientid, which is what a FlashBlade does. MEASURED
	// 2026-08-21 on an S200 running Purity 4.8.0: the second CREATE_SESSION for a
	// clientid is refused with NFS4ERR_INVAL whether it arrives on a fresh
	// connection or on the one that carried the first, and the two calls differ on
	// the wire in exactly the four bytes of csa_sequence. See
	// trunkprobe_live_test.go.
	//
	// This is modelled because its absence hid a release blocker. The fake used to
	// grant a second session happily, so the connection pool's shared-registration
	// design passed the whole suite and then failed at startup on real hardware for
	// every --connections >= 2. It sits AFTER the replay arm on purpose: a replayed
	// csa_sequence must still be answered from the cache per RFC 8881 section
	// 18.36.4, and answering INVAL there would break the lost-reply retry instead.
	if s.oneSessionPerClientID {
		for _, session := range s.sessions {
			if session.clientID == clientID {
				s.mu.Unlock()
				return errResult(uint32(xdr.OP_CREATE_SESSION), NFS4ERR_INVAL), NFS4ERR_INVAL
			}
		}
	}

	slots := s.grantedSlots
	if slots < 0 || uint64(slots) > uint64(^uint32(0)) {
		s.mu.Unlock()
		return errResult(uint32(xdr.OP_CREATE_SESSION), NFS4ERR_RESOURCE), NFS4ERR_RESOURCE
	}

	var sessionID [16]byte
	binary.BigEndian.PutUint64(sessionID[0:8], args.Csa_clientid)
	binary.BigEndian.PutUint64(sessionID[8:16], s.nextSessionID)
	s.nextSessionID++
	s.sessions[sessionID] = &fakeSession{
		clientID:     args.Csa_clientid,
		grantedSlots: uint32(slots),
		slots:        make(map[uint32]*slotState),
	}
	s.sessionCount++
	if s.forgetClientIDAfter > 0 && s.sessionCount >= s.forgetClientIDAfter {
		for owner, id := range s.clientIDs {
			if id == args.Csa_clientid {
				delete(s.clientIDs, owner)
			}
		}
	}
	s.mu.Unlock()

	// The fake grants exactly the configured slot count regardless of what the
	// client asked for, so GrantedSlots() is a single known number a test can
	// compare a negotiated slot table against.
	fore := args.Csa_fore_chan_attrs
	fore.Ca_maxrequests = uint32(slots)
	s.mu.Lock()
	maxRequestSize := s.maxRequestSize
	maxResponseSize := s.maxResponseSize
	zeroForeChannel := s.zeroForeChannelGrants > 0
	if zeroForeChannel {
		s.zeroForeChannelGrants--
	}
	s.mu.Unlock()
	if maxRequestSize != 0 {
		fore.Ca_maxrequestsize = maxRequestSize
	}
	if maxResponseSize != 0 {
		fore.Ca_maxresponsesize = maxResponseSize
	}
	if zeroForeChannel {
		fore.Ca_maxoperations = 0
	}
	fore.Ca_rdma_ird = nil

	resok := xdr.CREATE_SESSION4resok{
		Csr_sessionid: sessionID,
		Csr_sequence:  args.Csa_sequence,
		// No CREATE_SESSION4_FLAG_CONN_BACK_CHAN: there is no back channel,
		// and claiming one would let a client start expecting callbacks the
		// fake will never make.
		Csr_flags:           0,
		Csr_fore_chan_attrs: fore,
		Csr_back_chan_attrs: xdr.Channel_attrs4{},
	}
	// The one-entry-per-clientid CREATE_SESSION replay cache of RFC 8881
	// section 18.36.4. It is stored before the reply is handed back precisely
	// because the reply may never reach the client.
	s.mu.Lock()
	s.lastCreateReply[clientID] = resok
	s.mu.Unlock()

	r := xdr.Nfs_resop4{Resop: xdr.OP_CREATE_SESSION}
	r.Opcreatesession().Csr_status = xdr.NFS4_OK
	*r.Opcreatesession().Csr_resok4() = resok
	return r, NFS4_OK
}

func (s *fakeServer) destroySession(args xdr.DESTROY_SESSION4args) (xdr.Nfs_resop4, uint32) {
	s.mu.Lock()
	_, ok := s.sessions[args.Dsa_sessionid]
	delete(s.sessions, args.Dsa_sessionid)
	s.mu.Unlock()

	if !ok {
		return errResult(uint32(xdr.OP_DESTROY_SESSION), NFS4ERR_BADSESSION), NFS4ERR_BADSESSION
	}
	r := xdr.Nfs_resop4{Resop: xdr.OP_DESTROY_SESSION}
	r.Opdestroysession().Dsr_status = xdr.NFS4_OK
	return r, NFS4_OK
}

func (s *fakeServer) reclaimCompleteOp(st *compoundState, _ xdr.RECLAIM_COMPLETE4args) (xdr.Nfs_resop4, uint32) {
	if st.acquired == nil {
		return errResult(uint32(xdr.OP_RECLAIM_COMPLETE), errOpNotInSession), errOpNotInSession
	}

	// The leading SEQUENCE identifies the session and therefore its clientid.
	s.mu.Lock()
	session, ok := s.sessions[st.sessionID]
	if !ok {
		s.mu.Unlock()
		return errResult(uint32(xdr.OP_RECLAIM_COMPLETE), NFS4ERR_BADSESSION), NFS4ERR_BADSESSION
	}
	clientID := session.clientID
	if s.reclaimComplete[clientID] {
		s.mu.Unlock()
		status := uint32(xdr.NFS4ERR_COMPLETE_ALREADY)
		return errResult(uint32(xdr.OP_RECLAIM_COMPLETE), status), status
	}
	s.reclaimComplete[clientID] = true
	s.mu.Unlock()

	r := xdr.Nfs_resop4{Resop: xdr.OP_RECLAIM_COMPLETE}
	r.Opreclaimcomplete().Rcr_status = xdr.NFS4_OK
	return r, NFS4_OK
}

// sequence validates one SEQUENCE and, on success, acquires the named slot.
//
// The returned *slotState is non-nil exactly when the slot was acquired, and
// the caller must release it once the COMPOUND finishes. runCompound does that
// in a defer, so a failing later operation cannot leak a slot marked in use.
func (s *fakeServer) sequence(args xdr.SEQUENCE4args) (xdr.Nfs_resop4, uint32, *slotState) {
	fail := func(status uint32) (xdr.Nfs_resop4, uint32, *slotState) {
		return errResult(uint32(xdr.OP_SEQUENCE), status), status, nil
	}

	s.mu.Lock()
	if args.Sa_cachethis {
		s.sawCachethis = true
	}
	session, ok := s.sessions[args.Sa_sessionid]
	if !ok {
		s.mu.Unlock()
		return fail(NFS4ERR_BADSESSION)
	}
	slots := session.grantedSlots
	if args.Sa_slotid >= slots {
		s.mu.Unlock()
		return fail(NFS4ERR_BADSLOT)
	}

	slot := session.slots[args.Sa_slotid]
	if slot == nil {
		slot = &slotState{}
		session.slots[args.Sa_slotid] = slot
	}

	// A slot already executing a COMPOUND cannot accept another request,
	// whether the second one is a retry of the first or a fresh seqid. Both
	// mean the client allocated one slot twice.
	if slot.inUse {
		s.mu.Unlock()
		return fail(NFS4ERR_DELAY)
	}

	switch {
	case !slot.initialized:
		// First use of this slot. Only seqid 1 is legal: there is no cached
		// reply to replay, so seqid 0 is misordered rather than a replay.
		if args.Sa_sequenceid != 1 {
			s.mu.Unlock()
			return fail(NFS4ERR_SEQ_MISORDERED)
		}
		slot.initialized = true
		slot.seqid = 1
	case args.Sa_sequenceid == slot.seqid+1:
		slot.seqid = args.Sa_sequenceid
	case args.Sa_sequenceid == slot.seqid:
		// A replay. sa_cachethis is false for every operation this client
		// issues, so there is no cached reply to return and the request simply
		// runs again — legal for the idempotent operations the fake models.
		// A stricter server may answer NFS4ERR_RETRY_UNCACHED_REP (10068)
		// instead; that status is missing from Task 10's classification table,
		// so switching to it is Task 10's call, not this file's.
	default:
		s.mu.Unlock()
		return fail(NFS4ERR_SEQ_MISORDERED)
	}
	slot.inUse = true
	s.mu.Unlock()

	r := xdr.Nfs_resop4{Resop: xdr.OP_SEQUENCE}
	r.Opsequence().Sr_status = xdr.NFS4_OK
	*r.Opsequence().Sr_resok4() = xdr.SEQUENCE4resok{
		Sr_sessionid:             args.Sa_sessionid,
		Sr_sequenceid:            args.Sa_sequenceid,
		Sr_slotid:                args.Sa_slotid,
		Sr_highest_slotid:        slots - 1,
		Sr_target_highest_slotid: slots - 1,
		Sr_status_flags:          0,
	}
	return r, NFS4_OK, slot
}

// releaseSlot marks a slot free again. Called once per acquired slot, from
// runCompound's defer.
func (s *fakeServer) releaseSlot(slot *slotState) {
	s.mu.Lock()
	slot.inUse = false
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Filesystem operations
// ---------------------------------------------------------------------------

func (s *fakeServer) exists(fh string) bool {
	_, ok := s.pathFor(fh)
	return ok
}

// pathFor turns a filehandle into the tree path the tree, cookies and READDIR
// are keyed by. It is the one place the two identities are related.
func (s *fakeServer) pathFor(fh string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pathForLocked(fh)
}

func (s *fakeServer) pathForLocked(fh string) (string, bool) {
	if fh == fakeRootFH {
		return fakeRootFH, true
	}
	if t, ok := s.byFH[fh]; ok {
		return t.path, true
	}
	// The entry naming this path handed out a different filehandle, so the
	// path is not one.
	if s.fhOverridden[fh] {
		return "", false
	}
	// A bare directory AddTree created as a key without any parent listing
	// naming it. Its filehandle is still its path.
	if _, ok := s.tree[fh]; ok {
		return fh, true
	}
	return "", false
}

// lookup resolves name inside the directory named by the filehandle dir, and
// returns the child's filehandle.
func (s *fakeServer) lookup(dir, name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirPath, ok := s.pathForLocked(dir)
	if !ok {
		return "", false
	}
	for _, e := range s.tree[dirPath] {
		if e.Name == name {
			return effectiveFH(path.Join(dirPath, name), e), true
		}
	}
	return "", false
}

// entryFor returns the tree entry describing fh, and whether fh is a directory.
func (s *fakeServer) entryFor(fh string) (fakeEntry, bool) {
	if fh == fakeRootFH {
		return fakeEntry{Name: "/", IsDir: true}, true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.byFH[fh]; ok {
		// A path that is a key in tree is a directory even if the entry did
		// not say so, which is what AddTree of a bare directory produces.
		_, isDirKey := s.tree[t.path]
		return t.entry, t.entry.IsDir || isDirKey
	}
	if s.fhOverridden[fh] {
		return fakeEntry{Name: path.Base(fh)}, false
	}
	_, isDir := s.tree[fh]
	return fakeEntry{Name: path.Base(fh), IsDir: isDir}, isDir
}

// attrsFor builds a fattr4 answering the requested bits the fake supports.
// Unsupported bits are omitted, which RFC 8881 permits: a GETATTR reply
// carries a subset of what was asked for.
func (s *fakeServer) attrsFor(fh string, request []uint32) xdr.Fattr4 {
	entry, isDir := s.entryFor(fh)

	s.mu.Lock()
	acl := s.acls[fh]
	mode, haveMode := s.modes[fh]
	maxFileSize := s.maxFileSize
	s.mu.Unlock()

	// A SETATTR that wrote mode wins; the entry's Mode is only the initial
	// value, and 0o755 remains the fallback when neither says anything.
	if !haveMode {
		mode = entry.Mode
		if mode == 0 {
			mode = 0o755
		}
	}

	requested := make(map[uint32]bool)
	for word, mask := range request {
		for bit := uint32(0); bit < 32; bit++ {
			if mask&(uint32(1)<<bit) != 0 {
				requested[uint32(word)*32+bit] = true
			}
		}
	}

	var bits []uint32
	var values [][]byte
	add := func(bit uint32, value []byte) {
		if requested[bit] {
			bits = append(bits, bit)
			values = append(values, value)
		}
	}

	// IsSymlink is checked first and is not exclusive with IsDir: an entry that
	// sets both is a directory-looking link, which is how a test proves the
	// client refuses to descend one.
	fileType := uint32(xdr.NF4REG)
	switch {
	case entry.IsSymlink:
		fileType = uint32(xdr.NF4LNK)
	case isDir:
		fileType = uint32(xdr.NF4DIR)
	}
	add(fattr4Type, be32(fileType))
	add(fattr4Size, be64(entry.Size))
	// A zero FSID keeps the fake's historical (major=1, minor=2) so no test
	// written before per-entry FSIDs changes meaning.
	fsidMajor, fsidMinor := uint64(1), uint64(2)
	if entry.FSID != 0 {
		fsidMajor, fsidMinor = entry.FSID, 0
	}
	add(fattr4FSID, append(be64(fsidMajor), be64(fsidMinor)...))
	add(fattr4ACL, aclValue(acl))
	add(fattr4Filehandle, xdrOpaque([]byte(fh)))
	add(fattr4MaxFileSize, be64(maxFileSize))
	add(fattr4Mode, be32(mode))
	add(fattr4Owner, xdrOpaque([]byte("nobody@fakeserver")))
	add(fattr4OwnerGroup, xdrOpaque([]byte("nogroup@fakeserver")))

	if len(bits) == 0 {
		return xdr.Fattr4{}
	}
	bitmap, attrs := EncodeAttrList(bits, values)
	return xdr.Fattr4{Attrmask: bitmap, Attr_vals: attrs}
}

func (s *fakeServer) setAttr(fh string, args xdr.SETATTR4args) (xdr.Nfs_resop4, uint32) {
	decoded, err := DecodeAttrList(args.Obj_attributes.Attrmask, args.Obj_attributes.Attr_vals)
	if err != nil {
		return errResult(uint32(xdr.OP_SETATTR), errBadXDR), errBadXDR
	}

	var set []uint32
	s.mu.Lock()
	for attr, value := range decoded {
		switch attr {
		case fattr4ACL:
			s.acls[fh] = bytes.Clone(value)
			set = append(set, attr)
		case fattr4Mode:
			if len(value) >= 4 {
				s.modes[fh] = binary.BigEndian.Uint32(value[:4])
				set = append(set, attr)
			}
		default:
			// An attribute the fake does not model. Refusing is the honest
			// answer; silently reporting it as set would hide a client that
			// started sending attributes the array may not support.
			s.mu.Unlock()
			return errResult(uint32(xdr.OP_SETATTR), errAttrNotSupp), errAttrNotSupp
		}
	}
	s.mu.Unlock()

	set = slices.DeleteFunc(set, func(attr uint32) bool {
		return slices.Contains(s.silentSetAttrs, attr)
	})

	r := xdr.Nfs_resop4{Resop: xdr.OP_SETATTR}
	r.Opsetattr().Status = xdr.NFS4_OK
	r.Opsetattr().Attrsset = attributeBitmap(set)
	return r, NFS4_OK
}

// readDir pages through a directory.
//
// Cookies are entry index plus firstReaddirCookie, because RFC 8881 reserves
// 0, 1 and 2. Cookie 0 means "from the beginning"; any other value must name
// an entry the fake handed out.
const firstReaddirCookie = uint64(3)

func (s *fakeServer) readDir(fh string, args xdr.READDIR4args) (xdr.Nfs_resop4, uint32) {
	// Recorded before the TOOSMALL check so a rejected request is still visible:
	// what the client ASKED for is the subject of the maxcount tests, and a
	// request the fake refuses is exactly the one whose size is in question.
	s.mu.Lock()
	s.readdirMaxcounts = append(s.readdirMaxcounts, args.Maxcount)
	s.mu.Unlock()

	if args.Maxcount < minReaddirMaxcount {
		return errResult(uint32(xdr.OP_READDIR), NFS4ERR_TOOSMALL), NFS4ERR_TOOSMALL
	}

	s.mu.Lock()
	winMin, winMax := s.readdirMinOK, s.readdirMaxOK
	s.mu.Unlock()
	if winMin != 0 && args.Maxcount < winMin {
		return errResult(uint32(xdr.OP_READDIR), NFS4ERR_TOOSMALL), NFS4ERR_TOOSMALL
	}
	if winMax != 0 && args.Maxcount > winMax {
		return errResult(uint32(xdr.OP_READDIR), NFS4ERR_REP_TOO_BIG), NFS4ERR_REP_TOO_BIG
	}

	s.mu.Lock()
	dirPath, known := s.pathForLocked(fh)
	entries, isDir := s.tree[dirPath]
	isDir = isDir && known
	pageSize := s.readdirPageSize
	verf := s.readdirVerf
	omitted := s.omitReaddirAttrs
	s.mu.Unlock()

	// A server is entitled to answer with a subset of the requested attributes,
	// and clearing the bit from the request is exactly how that looks on the
	// wire: attrsFor only emits bits the request asked for, so the reply's
	// attrmask comes back without them. See OmitReaddirAttrs.
	attrRequest := clearBitmapBits(args.Attr_request, omitted)

	if !isDir {
		return errResult(uint32(xdr.OP_READDIR), errNotDir), errNotDir
	}

	// A continuation carrying a verifier from before ChangeVerifierAfter fired
	// must restart, which is what NFS4ERR_NOT_SAME tells the client.
	if args.Cookie != 0 && args.Cookieverf != verf {
		return errResult(uint32(xdr.OP_READDIR), NFS4ERR_NOT_SAME), NFS4ERR_NOT_SAME
	}

	start := 0
	if args.Cookie != 0 {
		if args.Cookie < firstReaddirCookie ||
			args.Cookie > firstReaddirCookie+uint64(len(entries))-1 {
			return errResult(uint32(xdr.OP_READDIR), errBadCookie), errBadCookie
		}
		start = int(args.Cookie-firstReaddirCookie) + 1
	}

	end := len(entries)
	if pageSize > 0 && start+pageSize < end {
		end = start + pageSize
	}

	// Build the linked list back to front, which is the only direction an
	// Entry4 chain can be assembled.
	var head *xdr.Entry4
	for i := end - 1; i >= start; i-- {
		// attrsFor is keyed by filehandle, so the child's effective one — not
		// its path — is what FATTR4_FILEHANDLE must report.
		child := effectiveFH(path.Join(dirPath, entries[i].Name), entries[i])
		head = &xdr.Entry4{
			Cookie:    firstReaddirCookie + uint64(i),
			Name:      []byte(entries[i].Name),
			Attrs:     s.attrsFor(child, attrRequest),
			Nextentry: head,
		}
	}

	s.mu.Lock()
	s.readdirReplies++
	if s.changeVerfAfter > 0 && s.readdirReplies >= s.changeVerfAfter {
		s.readdirVerf[7]++
		s.changeVerfAfter = 0
	}
	s.mu.Unlock()

	r := xdr.Nfs_resop4{Resop: xdr.OP_READDIR}
	r.Opreaddir().Status = xdr.NFS4_OK
	*r.Opreaddir().Resok4() = xdr.READDIR4resok{
		Cookieverf: verf,
		Reply: xdr.Dirlist4{
			Entries: head,
			Eof:     end == len(entries),
		},
	}
	return r, NFS4_OK
}

// ---------------------------------------------------------------------------
// Small XDR value helpers
// ---------------------------------------------------------------------------

func be32(v uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, v)
}

func be64(v uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, v)
}

func xdrOpaque(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	out = append(out, b...)
	return append(out, make([]byte, xdrPad(len(b)))...)
}

// aclValue returns a complete fattr4_acl encoding. A file with no stored ACL
// reports an empty one, which is a zero ACE count, not a zero-length value.
func aclValue(acl []byte) []byte {
	if len(acl) == 0 {
		return be32(0)
	}
	return acl
}

// ---------------------------------------------------------------------------
// The tests that test the fake
// ---------------------------------------------------------------------------
//
// These stop at the RPC and COMPOUND layers deliberately. ExchangeID and
// NewSession are Task 8's and do not exist yet; this task runs first precisely
// so a test double is verified before the code under test depends on it.

func TestFakeServerAnswersExchangeID(t *testing.T) {
	srv := startFakeServer(t, withSlots(6))
	defer srv.Close()

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Hand-built EXCHANGE_ID: no session layer exists yet. co_verifier is
	// arbitrary, co_ownerid identifies this client, and SP4_NONE means we are
	// not negotiating state protection.
	args := xdr.EXCHANGE_ID4args{
		Eia_clientowner: xdr.Client_owner4{
			Co_verifier: xdr.Verifier4{1, 2, 3, 4, 5, 6, 7, 8},
			Co_ownerid:  []byte("permissionreset-faketest"),
		},
		Eia_flags:         xdr.EXCHGID4_FLAG_USE_NON_PNFS,
		Eia_state_protect: xdr.State_protect4_a{Spa_how: xdr.SP4_NONE},
	}
	op := xdr.Nfs_argop4{Argop: xdr.OP_EXCHANGE_ID}
	*op.Opexchange_id() = args

	req, err := BuildCompound("faketest", []xdr.Nfs_argop4{op})
	if err != nil {
		t.Fatal(err)
	}
	// NFS program 100003, version 4, procedure 1 (COMPOUND).
	reply, err := c.Call(context.Background(), 100003, 4, 1, req)
	if err != nil {
		t.Fatal(err)
	}
	status, results, err := ParseCompound(reply)
	if err != nil {
		t.Fatal(err)
	}
	if status != NFS4_OK {
		t.Fatalf("COMPOUND status = %d, want NFS4_OK", status)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	ok := results[0].Opexchange_id().Eir_resok4()
	if ok.Eir_clientid == 0 {
		t.Error("eir_clientid = 0; the fake did not allocate a clientid")
	}
	// The slot grant is not visible until CREATE_SESSION, so assert the
	// configured value through the accessor Task 8's tests will compare against.
	if srv.GrantedSlots() != 6 {
		t.Errorf("GrantedSlots() = %d, want 6 from withSlots(6)", srv.GrantedSlots())
	}

	// The observation counters the later tasks assert on must move for a call
	// that really crossed a socket, and must not move for anything else.
	if got := srv.ConnectionCount(); got != 1 {
		t.Errorf("ConnectionCount() = %d, want 1", got)
	}
	if got := srv.CallCount(uint32(xdr.OP_EXCHANGE_ID)); got != 1 {
		t.Errorf("CallCount(OP_EXCHANGE_ID) = %d, want 1", got)
	}
	if got := srv.ClientIDCount(); got != 1 {
		t.Errorf("ClientIDCount() = %d, want 1", got)
	}
	if got := srv.CallsPerConnection(); len(got) != 1 || got[1] != 1 {
		t.Errorf("CallsPerConnection() = %v, want one connection with one call", got)
	}
	if got := srv.BindConnToSessionCount(); got != 0 {
		t.Errorf("BindConnToSessionCount() = %d, want 0; trunking is deliberately absent", got)
	}
	if got := srv.SessionCount(); got != 0 {
		t.Errorf("SessionCount() = %d, want 0; nothing sent CREATE_SESSION", got)
	}
	if srv.SawCachethis() {
		t.Error("SawCachethis() = true without any SEQUENCE")
	}
}

func TestFakeServerSetsMaxFileSize(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	defer srv.Close()
	// exercised fully by the gate tests in Task 11
	if srv.MaxFileSize() != 1<<46 {
		t.Fatal("withMaxFileSize did not take effect")
	}
}

// TestFakeServerRejectsAnUnknownOp pins the "deliberately not implemented" list
// in Step 3. A fake that quietly succeeds on an op the client cannot send would
// hide a regression rather than surface it, so the fake must answer
// NFS4ERR_NOTSUPP or NFS4ERR_OP_ILLEGAL instead of NFS4_OK.
func TestFakeServerRejectsAnUnknownOp(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	op := xdr.Nfs_argop4{Argop: xdr.OP_OPEN}
	req, err := BuildCompound("illegal", []xdr.Nfs_argop4{op})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := c.Call(context.Background(), 100003, 4, 1, req)
	if err != nil {
		// A transport-level failure is an acceptable refusal too.
		return
	}
	status, _, err := ParseCompound(reply)
	if err != nil {
		return
	}
	if status == NFS4_OK {
		t.Fatal("the fake answered OP_OPEN successfully; an unimplemented op must not return NFS4_OK")
	}
}

// TestFakeServerServesATreeAndStoresAnACL covers the filesystem plumbing the
// later tasks lean on — PUTROOTFH, LOOKUP, GETFH, GETATTR, SETATTR, READDIR —
// over a real socket, without a session. It is not in the plan's Step 1 list;
// it is here because AddTree and ACLFor are two of the twelve methods Step 1
// otherwise leaves entirely unexercised, and an unexercised test double is the
// exact failure mode this task's review exists to catch.
func TestFakeServerServesATreeAndStoresAnACL(t *testing.T) {
	// The subject is tree serving and ACL storage, and it resolves /dir/a with two
	// chained LOOKUPs from the pseudo-root — the shape a FlashBlade refuses. Opting
	// out keeps this test about what it is about instead of restructuring it into
	// two COMPOUNDs; the crossing restriction has its own tests.
	srv := startFakeServer(t, withChainedLookupsAcrossRoot())
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "dir", IsDir: true}},
		"/dir": {
			{Name: "a", Size: 11},
			{Name: "b", Size: 22},
		},
	})

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	call := func(ops ...xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4) {
		t.Helper()
		req, err := BuildCompound("tree", ops)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := c.Call(context.Background(), nfsProgram, nfsProgramVersion, nfsProcCompound, req)
		if err != nil {
			t.Fatal(err)
		}
		status, results, err := ParseCompound(reply)
		if err != nil {
			t.Fatal(err)
		}
		return status, results
	}

	// Resolve /dir/a and read its filehandle back.
	status, results := call(OpPutRootFH(), OpLookup("dir"), OpLookup("a"), OpGetFH())
	if status != NFS4_OK {
		t.Fatalf("lookup COMPOUND status = %d, want NFS4_OK", status)
	}
	fh := string(results[3].Opgetfh().Resok4().Object)
	if fh != "/dir/a" {
		t.Fatalf("GETFH returned %q, want %q", fh, "/dir/a")
	}
	if got := srv.LookupCount("a"); got != 1 {
		t.Errorf("LookupCount(\"a\") = %d, want 1", got)
	}

	// Store an ACL and read it back through the accessor.
	acl := []byte{0, 0, 0, 0}
	status, _ = call(OpPutFH([]byte(fh)), OpSetACL(acl))
	if status != NFS4_OK {
		t.Fatalf("SETATTR COMPOUND status = %d, want NFS4_OK", status)
	}
	if got := srv.ACLFor(fh); !bytes.Equal(got, acl) {
		t.Errorf("ACLFor(%q) = %v, want %v", fh, got, acl)
	}

	// A missing name is NFS4ERR_NOENT, and the results array ends with it.
	status, results = call(OpPutRootFH(), OpLookup("nope"), OpGetFH())
	if status != NFS4ERR_NOENT {
		t.Fatalf("lookup of a missing name = %d, want NFS4ERR_NOENT", status)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: the array ends with the failing op", len(results))
	}

	// READDIR pages through the directory and the cookies chain.
	srv.SetReaddirPageSize(1)
	status, results = call(
		OpPutRootFH(), OpLookup("dir"),
		OpReadDir(0, [8]byte{}, 4096, 4096, fattr4Type, fattr4Size),
	)
	if status != NFS4_OK {
		t.Fatalf("READDIR status = %d, want NFS4_OK", status)
	}
	page := results[2].Opreaddir().Resok4()
	if page.Reply.Entries == nil || page.Reply.Entries.Nextentry != nil {
		t.Fatal("READDIR returned the wrong number of entries for a page size of 1")
	}
	if page.Reply.Eof {
		t.Fatal("READDIR reported eof on the first of two pages")
	}
	if got := string(page.Reply.Entries.Name); got != "a" {
		t.Fatalf("first entry = %q, want %q", got, "a")
	}

	// The continuation with the right verifier succeeds and reaches eof.
	status, results = call(
		OpPutRootFH(), OpLookup("dir"),
		OpReadDir(page.Reply.Entries.Cookie, page.Cookieverf, 4096, 4096, fattr4Type),
	)
	if status != NFS4_OK {
		t.Fatalf("READDIR continuation status = %d, want NFS4_OK", status)
	}
	next := results[2].Opreaddir().Resok4()
	if !next.Reply.Eof || next.Reply.Entries == nil || string(next.Reply.Entries.Name) != "b" {
		t.Fatal("READDIR continuation did not return the second entry at eof")
	}

	// A too-small maxcount is NFS4ERR_TOOSMALL, and a stale cookie verifier is
	// NFS4ERR_NOT_SAME. Neither is reproducible on demand against hardware.
	status, _ = call(OpPutRootFH(), OpLookup("dir"), OpReadDir(0, [8]byte{}, 8, 8, fattr4Type))
	if status != NFS4ERR_TOOSMALL {
		t.Errorf("READDIR with maxcount 8 = %d, want NFS4ERR_TOOSMALL", status)
	}
	status, _ = call(
		OpPutRootFH(), OpLookup("dir"),
		OpReadDir(firstReaddirCookie, [8]byte{'w', 'r', 'o', 'n', 'g'}, 4096, 4096, fattr4Type),
	)
	if status != NFS4ERR_NOT_SAME {
		t.Errorf("READDIR with a stale cookieverf = %d, want NFS4ERR_NOT_SAME", status)
	}

	if got := srv.LookupCount("dir"); got != 5 {
		t.Errorf("LookupCount(\"dir\") = %d, want 5", got)
	}
}

// TestFakeServerInjectionAndHoldRepliesWork exercises the injection and
// concurrency machinery at the COMPOUND layer, so the pieces Task 8 and
// Task 14 depend on are not shipped entirely untested. The session-layer
// version of the injection test lives in Task 8, where ExchangeID and
// NewSession exist.
func TestFakeServerInjectionAndHoldRepliesWork(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f"}}})

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	do := func() uint32 {
		t.Helper()
		req, err := BuildCompound("inject", []xdr.Nfs_argop4{
			OpPutRootFH(), OpLookup("f"), OpSetACL([]byte{0, 0, 0, 0}),
		})
		if err != nil {
			t.Fatal(err)
		}
		reply, err := c.Call(context.Background(), nfsProgram, nfsProgramVersion, nfsProcCompound, req)
		if err != nil {
			t.Fatal(err)
		}
		status, _, err := ParseCompound(reply)
		if err != nil {
			t.Fatal(err)
		}
		return status
	}

	srv.InjectOnce(opSETATTR, NFS4ERR_DELAY)
	if got := do(); got != NFS4ERR_DELAY {
		t.Fatalf("first call status = %d, want NFS4ERR_DELAY", got)
	}
	if got := do(); got != NFS4_OK {
		t.Fatalf("second call status = %d, want NFS4_OK — the injection must fire once", got)
	}

	srv.InjectN(opSETATTR, NFS4ERR_GRACE, 2)
	for i := range 2 {
		if got := do(); got != NFS4ERR_GRACE {
			t.Fatalf("call %d status = %d, want NFS4ERR_GRACE", i+1, got)
		}
	}
	if got := do(); got != NFS4_OK {
		t.Fatalf("call after InjectN(2) status = %d, want NFS4_OK", got)
	}

	// CallCount counts attempts, including the ones an injection failed: five
	// SETATTRs went out — one injected DELAY, one success, two injected GRACE,
	// one success.
	if got := srv.CallCount(opSETATTR); got != 5 {
		t.Errorf("CallCount(opSETATTR) = %d, want 5", got)
	}

	// Hold replies and prove several calls are genuinely in flight at once
	// rather than completing one at a time.
	srv.HoldRepliesUntilSignalled()
	const parallel = 4
	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			do()
		}()
	}
	if !srv.WaitForInFlight(parallel, 5*time.Second) {
		srv.ReleaseReplies()
		wg.Wait()
		t.Fatalf("only %d calls reached the server; want %d in flight at once", srv.InFlight(), parallel)
	}
	srv.ReleaseReplies()
	wg.Wait()
	if got := srv.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d after release, want 0", got)
	}
}

// fakeCompoundCaller returns a helper that runs one COMPOUND over conn and
// returns its status and results, failing the test on a transport or decode
// error. It exists because the slot-table and SEQUENCE-placement tests below
// have to speak COMPOUND directly: they are testing the fake's own policing,
// so routing through the session layer would test the client instead.
func fakeCompoundCaller(t *testing.T, c *Conn) func(tag string, ops ...xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4) {
	call := fakeCompoundCallerE(c)
	return func(tag string, ops ...xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4) {
		t.Helper()
		status, results, err := call(tag, ops...)
		if err != nil {
			t.Fatal(err)
		}
		return status, results
	}
}

// fakeCompoundCallerE is fakeCompoundCaller without the test dependency, for the
// one caller that runs on its own goroutine — t.Fatal may only be called from
// the goroutine running the test.
//
// The per-call deadline matters: a fake that fails to police a busy slot parks
// the second request forever, and a bounded call turns that into a named failure
// in one test instead of a package-wide timeout panic.
func fakeCompoundCallerE(c *Conn) func(tag string, ops ...xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4, error) {
	return func(tag string, ops ...xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4, error) {
		req, err := BuildCompound(tag, ops)
		if err != nil {
			return 0, nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		reply, err := c.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, req)
		if err != nil {
			return 0, nil, err
		}
		status, results, err := ParseCompound(reply)
		if err != nil {
			return 0, nil, err
		}
		return status, results, nil
	}
}

// establishFakeSession drives EXCHANGE_ID and CREATE_SESSION by hand and returns
// the session id. It asks for one slot so that a slot-contention test has no
// second slot to escape onto.
func establishFakeSession(t *testing.T, c *Conn) [16]byte {
	t.Helper()
	call := fakeCompoundCaller(t, c)

	eid := xdr.Nfs_argop4{Argop: xdr.OP_EXCHANGE_ID}
	*eid.Opexchange_id() = xdr.EXCHANGE_ID4args{
		Eia_clientowner: xdr.Client_owner4{
			Co_verifier: xdr.Verifier4{9, 8, 7, 6, 5, 4, 3, 2},
			Co_ownerid:  []byte("permissionreset-slottest"),
		},
		Eia_flags:         xdr.EXCHGID4_FLAG_USE_NON_PNFS,
		Eia_state_protect: xdr.State_protect4_a{Spa_how: xdr.SP4_NONE},
	}
	status, results := call("eid", eid)
	if status != NFS4_OK {
		t.Fatalf("EXCHANGE_ID status = %d, want NFS4_OK", status)
	}
	clientID := results[0].Opexchange_id().Eir_resok4().Eir_clientid

	cs := xdr.Nfs_argop4{Argop: xdr.OP_CREATE_SESSION}
	*cs.Opcreatesession() = xdr.CREATE_SESSION4args{
		Csa_clientid: clientID,
		Csa_sequence: 1,
		Csa_fore_chan_attrs: xdr.Channel_attrs4{
			Ca_maxrequestsize:  1 << 16,
			Ca_maxresponsesize: 1 << 16,
			Ca_maxoperations:   8,
			Ca_maxrequests:     1,
		},
	}
	status, results = call("cs", cs)
	if status != NFS4_OK {
		t.Fatalf("CREATE_SESSION status = %d, want NFS4_OK", status)
	}
	return results[0].Opcreatesession().Csr_resok4().Csr_sessionid
}

// TestFakeServerRequiresSequenceOnceASessionExists pins the SEQUENCE-placement
// policing. Without it a client could send session-bound operations with no
// SEQUENCE at all, or with the SEQUENCE somewhere other than first, and the fake
// would execute them — where a real server refuses. The fake's own earlier tests
// speak sessionless COMPOUND deliberately, so the rule only arms once a session
// has been created.
func TestFakeServerRequiresSequenceOnceASessionExists(t *testing.T) {
	srv := startFakeServer(t, withSlots(1))
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f"}}})

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	call := fakeCompoundCaller(t, c)

	// Before any session exists, a bare PUTROOTFH is accepted. That escape
	// hatch is what lets this file's other tests work at all.
	if status, _ := call("presession", OpPutRootFH()); status != NFS4_OK {
		t.Fatalf("sessionless PUTROOTFH before any session = %d, want NFS4_OK", status)
	}

	sessionID := establishFakeSession(t, c)

	// Now the same COMPOUND must be refused.
	status, results := call("nosequence", OpPutRootFH(), OpLookup("f"))
	if status != errOpNotInSession {
		t.Fatalf("COMPOUND without SEQUENCE = %d, want NFS4ERR_OP_NOT_IN_SESSION (%d)", status, errOpNotInSession)
	}
	if len(results) != 1 {
		t.Errorf("got %d results, want 1: the array ends with the refused op", len(results))
	}

	// A SEQUENCE that is not the first operation is NFS4ERR_SEQUENCE_POS. Note
	// the leading SEQUENCE here: operations are policed in order, so a COMPOUND
	// that opens with an ordinary operation is refused with
	// NFS4ERR_OP_NOT_IN_SESSION before any later SEQUENCE is ever reached,
	// which is what the assertion above covers.
	status, _ = call("latesequence", OpSequence(sessionID, 1, 0, 0), OpSequence(sessionID, 2, 0, 0))
	if status != errSequencePos {
		t.Fatalf("SEQUENCE at position 2 = %d, want NFS4ERR_SEQUENCE_POS (%d)", status, errSequencePos)
	}

	// With SEQUENCE first, the same work succeeds. Seqid 2 because the refused
	// COMPOUND above still had a legal leading SEQUENCE, which consumed 1.
	status, _ = call("ok", OpSequence(sessionID, 2, 0, 0), OpPutRootFH(), OpLookup("f"))
	if status != NFS4_OK {
		t.Fatalf("SEQUENCE-led COMPOUND = %d, want NFS4_OK", status)
	}

	// EXCHANGE_ID and DESTROY_SESSION stay reachable without a SEQUENCE, or a
	// client could never recover a session it has lost.
	ds := xdr.Nfs_argop4{Argop: xdr.OP_DESTROY_SESSION}
	ds.Opdestroysession().Dsa_sessionid = sessionID
	if status, _ := call("destroy", ds); status != NFS4_OK {
		t.Fatalf("sessionless DESTROY_SESSION = %d, want NFS4_OK", status)
	}
}

// TestFakeServerRejectsSequenceIDZeroOnAFreshSlot pins the slot-initialisation
// rule. A slot table that starts its sequence ids at 0 rather than 1 is a real
// and easy client bug; with the slot modelled as a bare last-accepted seqid, a
// zero looked identical to a replay of a reply that never existed, so the whole
// suite would pass and every first call would fail against the array.
func TestFakeServerRejectsSequenceIDZeroOnAFreshSlot(t *testing.T) {
	srv := startFakeServer(t, withSlots(2))
	defer srv.Close()

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	call := fakeCompoundCaller(t, c)
	sessionID := establishFakeSession(t, c)

	// Slot 0 has never been used, so seqid 0 is misordered, not a replay.
	if status, _ := call("zero", OpSequence(sessionID, 0, 0, 1), OpPutRootFH()); status != NFS4ERR_SEQ_MISORDERED {
		t.Fatalf("first use of a slot with seqid 0 = %d, want NFS4ERR_SEQ_MISORDERED", status)
	}
	// A skipped seqid on a fresh slot is refused for the same reason.
	if status, _ := call("skip", OpSequence(sessionID, 2, 0, 1), OpPutRootFH()); status != NFS4ERR_SEQ_MISORDERED {
		t.Fatalf("first use of a slot with seqid 2 = %d, want NFS4ERR_SEQ_MISORDERED", status)
	}
	// A rejected SEQUENCE must not have initialised the slot: seqid 1 still
	// works afterwards.
	if status, _ := call("one", OpSequence(sessionID, 1, 0, 1), OpPutRootFH()); status != NFS4_OK {
		t.Fatalf("first use of a slot with seqid 1 = %d, want NFS4_OK", status)
	}
	// Once initialised, the next seqid advances and a replay of the last one is
	// still accepted, because sa_cachethis is false and the operations are
	// idempotent.
	if status, _ := call("two", OpSequence(sessionID, 2, 0, 1), OpPutRootFH()); status != NFS4_OK {
		t.Fatalf("seqid 2 after 1 = %d, want NFS4_OK", status)
	}
	if status, _ := call("replay", OpSequence(sessionID, 2, 0, 1), OpPutRootFH()); status != NFS4_OK {
		t.Fatalf("replay of seqid 2 = %d, want NFS4_OK", status)
	}
	if status, _ := call("back", OpSequence(sessionID, 1, 0, 1), OpPutRootFH()); status != NFS4ERR_SEQ_MISORDERED {
		t.Fatalf("seqid 1 after 2 = %d, want NFS4ERR_SEQ_MISORDERED", status)
	}
	// A slotid past the grant is NFS4ERR_BADSLOT rather than a silently
	// created slot.
	if status, _ := call("badslot", OpSequence(sessionID, 1, 2, 1), OpPutRootFH()); status != NFS4ERR_BADSLOT {
		t.Fatalf("slotid 2 with 2 slots granted = %d, want NFS4ERR_BADSLOT", status)
	}
}

// TestFakeServerRefusesTwoRequestsOnOneSlot pins the in-use half of the slot
// model. A slot table that hands the same slot to two callers at once is the
// classic bug in that code and the thing Task 14's parallelism claim rests on;
// with no per-slot in-use state the loser simply took the replay arm and got
// NFS4_OK, so the fake could not see it at all.
func TestFakeServerRefusesTwoRequestsOnOneSlot(t *testing.T) {
	srv := startFakeServer(t, withSlots(1))
	defer srv.Close()

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	call := fakeCompoundCaller(t, c)
	sessionID := establishFakeSession(t, c)

	// Park a COMPOUND after its SEQUENCE so slot 0 is provably occupied when
	// the second request arrives, rather than relying on a race.
	srv.HoldAfterSequence()

	var firstStatus uint32
	var firstErr error
	done := make(chan struct{})
	holder := fakeCompoundCallerE(c)
	go func() {
		defer close(done)
		firstStatus, _, firstErr = holder("holder", OpSequence(sessionID, 1, 0, 0), OpPutRootFH())
	}()

	if !srv.WaitForSequenceHeld(1, 5*time.Second) {
		srv.ReleaseAfterSequence()
		<-done
		t.Fatal("no COMPOUND parked after its SEQUENCE; the hold did not engage")
	}

	// A second request on the same slot, whether it looks like a retry of the
	// held one or a fresh seqid, meets a busy slot.
	c2, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	call2 := fakeCompoundCaller(t, c2)

	if status, _ := call2("retry", OpSequence(sessionID, 1, 0, 0), OpPutRootFH()); status != NFS4ERR_DELAY {
		srv.ReleaseAfterSequence()
		<-done
		t.Fatalf("retry of an in-flight slot = %d, want NFS4ERR_DELAY", status)
	}
	if status, _ := call2("fresh", OpSequence(sessionID, 2, 0, 0), OpPutRootFH()); status != NFS4ERR_DELAY {
		srv.ReleaseAfterSequence()
		<-done
		t.Fatalf("second seqid on an in-flight slot = %d, want NFS4ERR_DELAY", status)
	}

	srv.ReleaseAfterSequence()
	<-done
	if firstErr != nil {
		t.Fatalf("the held COMPOUND: %v", firstErr)
	}
	if firstStatus != NFS4_OK {
		t.Fatalf("the held COMPOUND finished with %d, want NFS4_OK", firstStatus)
	}

	// The slot is free again, and the refused requests did not advance it: the
	// next legal seqid is still 2.
	if status, _ := call("after", OpSequence(sessionID, 2, 0, 0), OpPutRootFH()); status != NFS4_OK {
		t.Fatalf("seqid 2 after the hold released = %d, want NFS4_OK", status)
	}
}

// TestFakeServerClassifiesCreateSessionSequences pins the three-way split the
// fake needs to be RFC 8881 section 18.36.4 conformant: only the expected next
// value runs, the value most recently answered is a replay, and everything else
// is NFS4ERR_SEQ_MISORDERED. A conforming client produces none of the last two
// on its own, so an end-to-end test alone cannot prove they are distinguished.
func TestFakeServerClassifiesCreateSessionSequences(t *testing.T) {
	srv := startFakeServer(t, withExchangeSequence(41))
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-fake-create-seq"))
	if err != nil {
		t.Fatal(err)
	}

	if got := srv.ClassifyCreateSessionSequence(reg.ID(), 41); got != createSeqNext {
		t.Fatalf("initial csa_sequence 41 classified %d, want createSeqNext", got)
	}
	if got := srv.ClassifyCreateSessionSequence(reg.ID(), 41); got != createSeqReplay {
		t.Fatalf("repeated csa_sequence 41 classified %d, want createSeqReplay", got)
	}
	if got := srv.ClassifyCreateSessionSequence(reg.ID(), 40); got != createSeqMisordered {
		t.Fatalf("regressing csa_sequence 40 classified %d, want createSeqMisordered", got)
	}
	// A jump ahead is also misordered: the server has no reply for 43 and must
	// not skip 42.
	if got := srv.ClassifyCreateSessionSequence(reg.ID(), 43); got != createSeqMisordered {
		t.Fatalf("csa_sequence 43 classified %d, want createSeqMisordered", got)
	}
	if got := srv.ClassifyCreateSessionSequence(reg.ID(), 42); got != createSeqNext {
		t.Fatalf("csa_sequence 42 after refusals classified %d, want createSeqNext", got)
	}
	// An unknown clientid never reaches the classifier over the wire, but the
	// direct entry point must still refuse it rather than seed a watermark.
	if got := srv.ClassifyCreateSessionSequence(reg.ID()^1, 41); got != createSeqMisordered {
		t.Fatalf("unknown clientid classified %d, want createSeqMisordered", got)
	}
	// Every attempt was recorded, refused ones included.
	if got := srv.CreateSessionSequences(); len(got) != 5 {
		t.Fatalf("CreateSessionSequences() = %v, want all five direct attempts recorded", got)
	}
}

// TestFakeServerReplaysACachedCreateSessionReply is the wire-level half: the
// same csa_sequence arriving twice must produce the same session, not a second
// one, and not an error.
func TestFakeServerReplaysACachedCreateSessionReply(t *testing.T) {
	// Exercises csa_sequence replay bookkeeping, which is protocol-general and must
	// stay correct for RFC-conformant servers, so it opts out of the FlashBlade
	// one-session-per-clientid default.
	srv := startFakeServer(t, withExchangeSequence(7), withManySessionsPerClientID())
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-fake-create-replay"))
	if err != nil {
		t.Fatal(err)
	}

	first, status := srv.CreateSessionDirect(reg.ID(), 7)
	if status != NFS4_OK {
		t.Fatalf("first CREATE_SESSION status = %d, want NFS4_OK", status)
	}
	second, status := srv.CreateSessionDirect(reg.ID(), 7)
	if status != NFS4_OK {
		t.Fatalf("replayed CREATE_SESSION status = %d, want NFS4_OK — RFC 8881 18.36.4 caches the reply", status)
	}
	if second.Csr_sessionid != first.Csr_sessionid {
		t.Fatalf("replay returned session %x, want the cached %x", second.Csr_sessionid, first.Csr_sessionid)
	}
	if got := srv.SessionCount(); got != 1 {
		t.Fatalf("SessionCount() = %d after a replay, want 1: a replay must create nothing", got)
	}
	if _, status := srv.CreateSessionDirect(reg.ID(), 9); status != NFS4ERR_SEQ_MISORDERED {
		t.Fatalf("a skipped csa_sequence status = %d, want NFS4ERR_SEQ_MISORDERED", status)
	}
	if _, status := srv.CreateSessionDirect(reg.ID(), 8); status != NFS4_OK {
		t.Fatalf("csa_sequence 8 status = %d, want NFS4_OK", status)
	}
	if got := srv.SessionCount(); got != 2 {
		t.Fatalf("SessionCount() = %d, want 2", got)
	}
}

func TestCreateSessionSequenceAdvancesOnlyAfterSuccess(t *testing.T) {
	srv := startFakeServer(t, withExchangeSequence(17))
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-create-transaction"))
	if err != nil {
		t.Fatal(err)
	}

	// An injected refusal runs before CREATE_SESSION accepts the sequence. The
	// next attempt must therefore reserve 17 again, not advance to 18.
	srv.InjectOnce(uint32(xdr.OP_CREATE_SESSION), NFS4ERR_DELAY)
	if _, err := NewSession(context.Background(), c, reg, 0, nil); err == nil {
		t.Fatal("injected CREATE_SESSION refusal returned nil")
	}
	s, err := NewSession(context.Background(), c, reg, 0, nil)
	if err != nil {
		t.Fatalf("retry after refused CREATE_SESSION: %v", err)
	}
	defer s.Destroy(context.Background())
	if got := srv.CreateSessionSequences(); len(got) != 1 || got[0] != 17 {
		t.Fatalf("accepted csa_sequence values = %v, want [17] after retrying the reservation", got)
	}
}

func TestSessionChannelAttrsClampToRPCRecordCap(t *testing.T) {
	srv := startFakeServer(t, withMaxChannelSizes(maxRecordSize+4096, maxRecordSize+8192))
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-channel-clamp"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	s, err := NewSession(context.Background(), c, reg, 0, func(msg string) {
		lines = append(lines, msg)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy(context.Background())
	attrs := s.ChannelAttrs()
	if attrs.MaxRequestSize != maxRecordSize || attrs.MaxResponseSize != maxRecordSize {
		t.Fatalf("ChannelAttrs() = %+v, want request and response clamped to %d", attrs, maxRecordSize)
	}
	if len(lines) < 2 {
		t.Fatalf("channel-size clamp logged %d lines, want request and response warnings: %v", len(lines), lines)
	}
}

func TestFakeServerRefusesRepeatedReclaimComplete(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-reclaim-repeat"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(context.Background(), c, reg, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy(context.Background())

	op := xdr.Nfs_argop4{Argop: xdr.OP_RECLAIM_COMPLETE}
	op.Opreclaimcomplete().Rca_one_fs = false
	status, _, err := s.Do(context.Background(), []xdr.Nfs_argop4{op})
	if err != nil {
		t.Fatal(err)
	}
	if status != uint32(xdr.NFS4ERR_COMPLETE_ALREADY) {
		t.Fatalf("second RECLAIM_COMPLETE status = %d, want NFS4ERR_COMPLETE_ALREADY", status)
	}
}

func TestSessionRebuildUsesSameConnectionAndNextCreateSequence(t *testing.T) {
	srv := startFakeServer(t, withExchangeSequence(9))
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-rebuild"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(context.Background(), c, reg, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy(context.Background())

	if err := s.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := srv.ConnectionCount(); got != 1 {
		t.Fatalf("ConnectionCount() = %d after Rebuild, want the original connection only", got)
	}
	if got := srv.CreateSessionSequences(); len(got) != 2 || got[0] != 9 || got[1] != 10 {
		t.Fatalf("csa_sequence values = %v after Rebuild, want [9 10]", got)
	}
}

func TestSessionRebuildSurfacesStaleClientIDDistinctly(t *testing.T) {
	srv := startFakeServer(t, withForgetClientIDAfter(1))
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-rebuild-stale-client"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(context.Background(), c, reg, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Rebuild(context.Background())
	var createErr *SessionCreateError
	if !errors.As(err, &createErr) {
		t.Fatalf("Rebuild() error = %v, want *SessionCreateError", err)
	}
	if createErr.Status != uint32(xdr.NFS4ERR_STALE_CLIENTID) {
		t.Fatalf("CREATE_SESSION status = %d, want NFS4ERR_STALE_CLIENTID", createErr.Status)
	}
}

func TestSessionRebuildOnClosedConnectionWrapsErrConnClosed(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-rebuild-closed"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(context.Background(), c, reg, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Rebuild(context.Background()); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("Rebuild() error = %v, want it to wrap ErrConnClosed", err)
	}
}

// TestFakeServerDropConnection covers the mid-stream reset. The client must see
// a terminal connection error rather than hanging, and the listener must stay
// up so a reconnect through the same Dialer succeeds.
func TestFakeServerDropConnection(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req, err := BuildCompound("drop", []xdr.Nfs_argop4{OpPutRootFH()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(context.Background(), nfsProgram, nfsProgramVersion, nfsProcCompound, req); err != nil {
		t.Fatalf("first call: %v", err)
	}

	srv.DropConnection()

	// The reset is asynchronous, so retry until the connection reports it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err = c.Call(context.Background(), nfsProgram, nfsProgramVersion, nfsProcCompound, req)
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("calls kept succeeding after DropConnection")
		}
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("after DropConnection, Call err = %v, want ErrConnClosed", err)
	}

	// The listener survives, so a second connection works and is counted.
	c2, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatalf("reconnect after DropConnection: %v", err)
	}
	defer c2.Close()
	if _, err := c2.Call(context.Background(), nfsProgram, nfsProgramVersion, nfsProcCompound, req); err != nil {
		t.Fatalf("call on the reconnected Conn: %v", err)
	}
	if got := srv.ConnectionCount(); got != 2 {
		t.Errorf("ConnectionCount() = %d, want 2", got)
	}
}

// TestNewSessionHonoursItsOwnDeadlineWhileACreateSessionIsInFlight pins the
// createGate fix. RFC 8881 allows one CREATE_SESSION in flight per clientid, so
// the second caller on a shared *ClientRegistration must wait — but the WAIT is
// the caller's own, and must end when the caller's context does. When the gate
// was a sync.Mutex the wait could not be abandoned, so a second NewSession
// silently ignored its deadline for as long as the first round trip took:
// forever against a peer that accepts the connection and never answers, which is
// what the proxy in front of a lab array VIF does.
//
// The first NewSession runs on its own goroutine, so its error is captured and
// asserted after the join — t.Fatal may only be called from the test goroutine.
// The second one runs on a goroutine too, bounded by a select, so that a
// regression here fails this test by name instead of hanging the package until
// the go test timeout panic.
func TestNewSessionHonoursItsOwnDeadlineWhileACreateSessionIsInFlight(t *testing.T) {
	// Retries CREATE_SESSION on one clientid after abandoning a wait, so it needs a
	// server that allows more than one session per clientid.
	srv := startFakeServer(t, withManySessionsPerClientID())
	defer srv.Close()

	c1, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// One registration, shared by both connections: that sharing is what makes
	// the gate contended, and is exactly what Task 14's pool does.
	reg, err := ExchangeID(context.Background(), c1, []byte("permissionreset-create-gate-ctx"))
	if err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		s   *Session
		err error
	}

	// Stall the fake so the first CREATE_SESSION parks server-side with the gate
	// held. WaitForInFlight below makes that deterministic rather than a race.
	srv.HoldRepliesUntilSignalled()
	firstDone := make(chan outcome, 1)
	go func() {
		s, err := NewSession(context.Background(), c1, reg, 0, nil)
		firstDone <- outcome{s, err}
	}()

	if !srv.WaitForInFlight(1, 5*time.Second) {
		srv.ReleaseReplies()
		first := <-firstDone
		if first.s != nil {
			first.s.Destroy(context.Background())
		}
		t.Fatal("the first NewSession's CREATE_SESSION never reached the fake")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	secondDone := make(chan outcome, 1)
	start := time.Now()
	go func() {
		s, err := NewSession(ctx, c2, reg, 0, nil)
		secondDone <- outcome{s, err}
	}()

	var second outcome
	var elapsed time.Duration
	select {
	case second = <-secondDone:
		elapsed = time.Since(start)
	case <-time.After(5 * time.Second):
		// The wait on the gate is uncancellable again. Unwedge everything so the
		// failure is this one named test rather than a package-wide timeout.
		srv.ReleaseReplies()
		second = <-secondDone
		if second.s != nil {
			second.s.Destroy(context.Background())
		}
		first := <-firstDone
		if first.s != nil {
			first.s.Destroy(context.Background())
		}
		t.Fatal("the second NewSession did not return within 5s despite a 100ms deadline: the wait for the in-flight CREATE_SESSION is not cancellable")
	}

	if second.s != nil {
		second.s.Destroy(context.Background())
		t.Error("the second NewSession returned a session while another CREATE_SESSION was in flight")
	}
	if !errors.Is(second.err, context.DeadlineExceeded) {
		t.Errorf("second NewSession() error = %v, want it to wrap context.DeadlineExceeded", second.err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("second NewSession() returned after %v, want promptly after its 100ms deadline", elapsed)
	}

	srv.ReleaseReplies()
	first := <-firstDone
	if first.err != nil {
		t.Fatalf("first NewSession() error = %v, want it to succeed once replies resume", first.err)
	}
	if first.s == nil {
		t.Fatal("first NewSession() returned no session and no error")
	}
	defer first.s.Destroy(context.Background())

	// The abandoned wait sent nothing, so the clientid's CREATE_SESSION sequence
	// is untouched by it: exactly one attempt reached the server.
	if got := srv.CreateSessionSequences(); len(got) != 1 {
		t.Errorf("CreateSessionSequences() = %v, want the abandoned caller to have sent nothing", got)
	}
	// And nothing is left parked on the fake or holding the gate: a third
	// session on the same registration succeeds immediately.
	third, err := NewSession(context.Background(), c2, reg, 0, nil)
	if err != nil {
		t.Fatalf("NewSession() after the abandoned wait: %v", err)
	}
	third.Destroy(context.Background())
	// The fake decrements inFlight after it has written the reply, so the
	// client can return first; wait for the count to settle rather than
	// reading it once.
	deadline := time.Now().Add(2 * time.Second)
	for srv.InFlight() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := srv.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d at the end of the test, want 0", got)
	}
}

// TestCreateSessionSequenceAdvancesAfterALocalRejection pins the one thing
// TestCreateSessionSequenceAdvancesOnlyAfterSuccess cannot: where in create the
// csa_sequence counter advances relative to the LOCAL attribute checks.
//
// That test injects NFS4ERR_DELAY, which fails the COMPOUND-status check sitting
// above the advance under any ordering, so it only proves the reservation stands
// when the SERVER refused. The other half is a CREATE_SESSION the server answers
// NFS4_OK and the client then rejects itself. Past NFS4_OK the server HAS created
// a session and HAS recorded csa_sequence in its per-clientid replay cache (RFC
// 8881 section 18.36.4), so a client that returns without advancing resends the
// same value, is answered from that cache with the identical reply, fails the
// identical local check, and wedges the clientid for the life of the
// registration. Moving the advance below the attribute checks reproduces exactly
// that, and the recovery asserted here is what dies when it moves.
func TestCreateSessionSequenceAdvancesAfterALocalRejection(t *testing.T) {
	srv := startFakeServer(t, withExchangeSequence(31), withZeroForeChannelLimitOnce())
	defer srv.Close()

	// Every call is bounded, so a wedge fails this test by name instead of
	// running the package into its timeout panic.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := NewConn(ctx, srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(ctx, c, []byte("permissionreset-create-local-reject"))
	if err != nil {
		t.Fatal(err)
	}

	first, err := NewSession(ctx, c, reg, 0, nil)
	if err == nil {
		first.Destroy(ctx)
		t.Fatal("NewSession() accepted a session granted ca_maxoperations 0")
	}

	// The session the client refused was created on the server, so refusing it
	// without a DESTROY_SESSION leaks it until its lease expires.
	if got := srv.CallCount(uint32(xdr.OP_DESTROY_SESSION)); got != 1 {
		t.Errorf("CallCount(OP_DESTROY_SESSION) = %d after a local rejection, want 1: the abandoned session must be torn down", got)
	}

	second, err := NewSession(ctx, c, reg, 0, nil)
	if err != nil {
		t.Fatalf("NewSession() after a locally rejected session: %v — the clientid is wedged, so csa_sequence did not advance past the rejected attempt", err)
	}
	defer second.Destroy(context.Background())

	// The recovery attempt must carry 32, not another 31. A repeat is answered
	// from the replay cache and can never succeed.
	want := []uint32{31, 32}
	got := srv.CreateSessionSequences()
	if len(got) != len(want) {
		t.Fatalf("CreateSessionSequences() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CreateSessionSequences() = %v, want %v", got, want)
		}
	}
	if second.Slots() != srv.GrantedSlots() {
		t.Errorf("Slots() = %d after recovery, want the fake's grant of %d", second.Slots(), srv.GrantedSlots())
	}
}

// TestCreateSessionOffersNoReplyCacheAndNoBackChannel pins what goes out on the
// wire in csa_fore_chan_attrs, which is where the consequence lives. The fake
// echoes the offer back rather than inspecting it, so nothing else in the package
// notices if the offer changes.
//
// ca_maxresponsesize_cached must be 0. sa_cachethis is false on every SEQUENCE
// this client sends, so a non-zero value reserves per-slot duplicate-reply cache
// that is never used — 128 slots times the RPC layer's 8 MiB record cap asks the
// array for roughly a gigabyte of DRC — and RFC 8881 section 18.36.3 lets a
// server that budgets its cache reduce ca_maxrequests to fit the ask instead of
// refusing it. The failure is silent: the session comes up with a fraction of its
// intended concurrency and looks perfectly healthy.
func TestCreateSessionOffersNoReplyCacheAndNoBackChannel(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-create-offer"))
	if err != nil {
		t.Fatal(err)
	}
	const wantSlots = 64
	s, err := NewSession(context.Background(), c, reg, wantSlots, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy(context.Background())

	args := srv.CreateSessionArgs()
	if len(args) != 1 {
		t.Fatalf("CreateSessionArgs() recorded %d attempts, want 1", len(args))
	}
	offer := args[0].Csa_fore_chan_attrs
	if offer.Ca_maxresponsesize_cached != 0 {
		t.Errorf("offered ca_maxresponsesize_cached = %d, want 0: sa_cachethis is always false, so any reply cache reserved here is unusable and invites the server to cut ca_maxrequests to fit it",
			offer.Ca_maxresponsesize_cached)
	}
	if offer.Ca_maxrequests != wantSlots {
		t.Errorf("offered ca_maxrequests = %d, want the requested %d", offer.Ca_maxrequests, wantSlots)
	}
	if offer.Ca_maxrequestsize != requestedChannelSize || offer.Ca_maxresponsesize != requestedChannelSize {
		t.Errorf("offered ca_maxrequestsize/ca_maxresponsesize = %d/%d, want %d for both",
			offer.Ca_maxrequestsize, offer.Ca_maxresponsesize, requestedChannelSize)
	}
	if offer.Ca_maxoperations != maxSessionOperations {
		t.Errorf("offered ca_maxoperations = %d, want %d", offer.Ca_maxoperations, maxSessionOperations)
	}
	// There is no back channel and no callback server, so requesting one would be
	// a real regression: the server would start making callbacks nothing answers.
	if uint32(args[0].Csa_flags)&xdr.CREATE_SESSION4_FLAG_CONN_BACK_CHAN != 0 {
		t.Errorf("csa_flags = %#x, want CREATE_SESSION4_FLAG_CONN_BACK_CHAN clear: this client accepts no callbacks", args[0].Csa_flags)
	}
}

// TestDefaultSlotRequestLogsAGrantBelowTheDefault pins the reporting arm
// effectiveSlots grew for the want <= 0 path. TestSessionChannelAttrsClampToRPCRecordCap
// only covers the two record-cap warnings, and the explicit-request arm of
// effectiveSlots is the one every other slot test drives, so a session that
// silently comes up with a handful of slots where 128 were offered — the loss
// that costs this transport most of its reason to exist — went unreported.
func TestDefaultSlotRequestLogsAGrantBelowTheDefault(t *testing.T) {
	const grant = 8
	srv := startFakeServer(t, withSlots(grant))
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-default-slot-shortfall"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	// wantSlots 0 is the default-request path: no explicit local ceiling, so the
	// shortfall is only visible by comparing the grant against defaultRequestedSlots.
	s, err := NewSession(context.Background(), c, reg, 0, func(msg string) {
		mu.Lock()
		lines = append(lines, msg)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy(context.Background())
	if s.Slots() != grant {
		t.Fatalf("Slots() = %d, want the grant of %d", s.Slots(), grant)
	}

	mu.Lock()
	defer mu.Unlock()
	wantDefault := fmt.Sprintf("%d", defaultRequestedSlots)
	wantGrant := fmt.Sprintf("%d", grant)
	for _, line := range lines {
		if strings.Contains(line, "slots") && strings.Contains(line, wantDefault) && strings.Contains(line, wantGrant) {
			return
		}
	}
	t.Fatalf("no log line reported the slot shortfall (default %s, granted %s); lines = %v", wantDefault, wantGrant, lines)
}

// TestFakeRefusesChainedLookupAcrossThePseudoRoot pins the fake's model of the
// FlashBlade restriction behind Defect 1, and pins the three shapes that were
// measured on an S200 rather than only the one that fails.
//
// It asserts the FAKE, not the client, for the same reason the second-session
// test does: the fake being more permissive than the array is what let Defect 1
// pass the whole suite and then fail against hardware on every subtree target.
func TestFakeRefusesChainedLookupAcrossThePseudoRoot(t *testing.T) {
	srv := startFakeServer(t)
	srv.AddTree(map[string][]fakeEntry{
		"/":       {{Name: "fs", FH: "fs", IsDir: true}},
		"/fs":     {{Name: "sub", FH: "sub", IsDir: true}},
		"/fs/sub": {{Name: "leaf", FH: "leaf", IsDir: true}},
	})
	defer srv.Close()

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	call := func(ops ...xdr.Nfs_argop4) uint32 {
		t.Helper()
		req, err := BuildCompound("cross", ops)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := c.Call(context.Background(), nfsProgram, nfsProgramVersion, nfsProcCompound, req)
		if err != nil {
			t.Fatal(err)
		}
		status, _, err := ParseCompound(reply)
		if err != nil {
			t.Fatal(err)
		}
		return status
	}

	if got := call(OpPutRootFH(), OpLookup("fs"), OpGetFH()); got != NFS4_OK {
		t.Errorf("one LOOKUP from the pseudo-root: status = %d, want NFS4_OK — the "+
			"crossing itself must succeed", got)
	}
	if got := call(OpPutRootFH(), OpLookup("fs"), OpLookup("sub"), OpGetFH()); got != NFS4ERR_NOENT {
		t.Errorf("chained LOOKUP across the crossing: status = %d, want NFS4ERR_NOENT", got)
	}
	if got := call(OpPutFH([]byte("fs")), OpLookup("sub"), OpLookup("leaf"), OpGetFH()); got != NFS4_OK {
		t.Errorf("chained LOOKUPs from a PUTFH inside the filesystem: status = %d, want "+
			"NFS4_OK — chaining within a filesystem is not restricted, and the fix relies "+
			"on exactly that", got)
	}
}

// TestChainedLookupsAcrossRootCanBeModelled proves withChainedLookupsAcrossRoot
// flips the behaviour, so the default is a choice rather than the only thing the
// fake can express.
func TestChainedLookupsAcrossRootCanBeModelled(t *testing.T) {
	srv := startFakeServer(t, withChainedLookupsAcrossRoot())
	srv.AddTree(map[string][]fakeEntry{
		"/":       {{Name: "fs", FH: "fs", IsDir: true}},
		"/fs":     {{Name: "sub", FH: "sub", IsDir: true}},
		"/fs/sub": {},
	})
	defer srv.Close()

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req, err := BuildCompound("cross", []xdr.Nfs_argop4{
		OpPutRootFH(), OpLookup("fs"), OpLookup("sub"), OpGetFH(),
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := c.Call(context.Background(), nfsProgram, nfsProgramVersion, nfsProcCompound, req)
	if err != nil {
		t.Fatal(err)
	}
	status, _, err := ParseCompound(reply)
	if err != nil {
		t.Fatal(err)
	}
	if status != NFS4_OK {
		t.Fatalf("with the opt-out set, chaining across the crossing must succeed: status = %d", status)
	}
}

// TestFakeServerRefusesASecondSetattrInOneCompound pins the array's one-mutating-
// operation rule into the fake.
//
// This exists because the fake was, for a while, MORE PERMISSIVE than the
// hardware on exactly this point: it would execute seven SETATTRs in one COMPOUND
// happily, so a batch of seven passed here and was refused by the array. A fake
// that blesses an unsendable shape is worse than no fake, because every test
// above it reports success for something that cannot be sent.
//
// The arms are the ones measured on the array, so this test fails if the fake
// drifts back toward permissiveness in any of the directions the array refuses.
func TestFakeServerRefusesASecondSetattrInOneCompound(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "a", Size: 1}, {Name: "b", Size: 2}},
	})

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	call := func(ops ...xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4) {
		t.Helper()
		req, err := BuildCompound("mutable", ops)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := c.Call(context.Background(), nfsProgram, nfsProgramVersion, nfsProcCompound, req)
		if err != nil {
			t.Fatal(err)
		}
		status, results, err := ParseCompound(reply)
		if err != nil {
			t.Fatal(err)
		}
		return status, results
	}

	acl := []byte{0, 0, 0, 0}
	fhA, fhB := []byte("/a"), []byte("/b")
	mode := OpSetAttr([]uint32{fattr4Mode}, [][]byte{{0, 0, 1, 0xa4}})

	// Accepted on the array, so they must be accepted here. A fake that refuses
	// these has over-corrected, which would be just as misleading in the other
	// direction.
	for _, ok := range []struct {
		name string
		ops  []xdr.Nfs_argop4
	}{
		{"PUTFH+SETACL", []xdr.Nfs_argop4{OpPutFH(fhA), OpSetACL(acl)}},
		{"PUTFH+SETACL+GETATTR", []xdr.Nfs_argop4{OpPutFH(fhA), OpSetACL(acl), OpGetAttr(fattr4Mode)}},
		{"PUTFH+SETACL+PUTFH+GETATTR", []xdr.Nfs_argop4{
			OpPutFH(fhA), OpSetACL(acl), OpPutFH(fhB), OpGetAttr(fattr4Mode)}},
		{"PUTFH+GETATTR+PUTFH+GETATTR", []xdr.Nfs_argop4{
			OpPutFH(fhA), OpGetAttr(fattr4Mode), OpPutFH(fhB), OpGetAttr(fattr4Mode)}},
	} {
		if status, results := call(ok.ops...); status != NFS4_OK {
			t.Errorf("%s: status = %d, want NFS4_OK (%d results)", ok.name, status, len(results))
		}
	}

	// Refused on the array, all with NFS4ERR_INVAL and an EMPTY result array.
	for _, bad := range []struct {
		name string
		ops  []xdr.Nfs_argop4
	}{
		{"two SETACLs, same filehandle", []xdr.Nfs_argop4{
			OpPutFH(fhA), OpSetACL(acl), OpPutFH(fhA), OpSetACL(acl)}},
		{"two SETACLs, distinct filehandles", []xdr.Nfs_argop4{
			OpPutFH(fhA), OpSetACL(acl), OpPutFH(fhB), OpSetACL(acl)}},
		{"SETACL then SETATTR mode", []xdr.Nfs_argop4{
			OpPutFH(fhA), OpSetACL(acl), OpPutFH(fhB), mode}},
		{"three SETACLs", []xdr.Nfs_argop4{
			OpPutFH(fhA), OpSetACL(acl), OpPutFH(fhB), OpSetACL(acl), OpPutFH(fhA), OpSetACL(acl)}},
	} {
		status, results := call(bad.ops...)
		if status != NFS4ERR_INVAL {
			t.Errorf("%s: status = %d, want NFS4ERR_INVAL (%d)", bad.name, status, NFS4ERR_INVAL)
		}
		if len(results) != 0 {
			t.Errorf("%s: %d results, want 0 -- the array resets the response, so a "+
				"client sees a status and nothing else", bad.name, len(results))
		}
	}

	// The first SETATTR of a refused COMPOUND must not have taken effect: the
	// array rejects before any operation runs, so a partially-applied bundle is
	// the one outcome that would make a caller's retry unsafe.
	if got := srv.ACLFor("/b"); len(got) != 0 {
		t.Errorf("ACLFor(/b) = %v after refused COMPOUNDs, want nothing stored", got)
	}
}
