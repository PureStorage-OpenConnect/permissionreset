package nfs41

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

var processClientVerifier = newClientVerifier()

const (
	// S500R1's measured grant. This is an offer, not an assumption: the
	// server's CREATE_SESSION reply remains authoritative.
	defaultRequestedSlots = 128
	// S500R1's measured ca_maxoperations and the phase-1 client maximum.
	maxSessionOperations = 16
	// requestedChannelSize is the ca_maxrequestsize and ca_maxresponsesize this
	// client offers. It is deliberately not the RPC layer's 8 MiB maxRecordSize.
	// An S500R1 grants 526336 whatever is asked, so the extra 7.5 MiB buys
	// nothing on the hardware this transport exists for, and RFC 8881 section
	// 18.36.3 lets a server that budgets its fore channel as ca_maxrequests
	// times a per-request size reduce ca_maxrequests to fit an inflated ask —
	// paying for unusable bytes with the concurrency that is the whole point.
	// 1 MiB is comfortably above every grant measured here and comfortably below
	// maxRecordSize, so a server that honours the offer literally still cannot
	// produce a legal reply that rpc.go tears the connection down over.
	requestedChannelSize = 1 << 20

	// The back channel this client offers but never uses.
	//
	// It declines callbacks -- no CREATE_SESSION4_FLAG_CONN_BACK_CHAN, no callback
	// program -- so nothing will ever travel on this channel, and for a long time
	// the client sent csa_back_chan_attrs entirely zeroed to say so.
	//
	// MEASURED 2026-08-22 against fa-lab-01 (Purity//FA 6.10.6): a zeroed
	// back channel is refused with NFS4ERR_TOOSMALL, and populating it is the
	// whole fix. FlashBlade accepts either. A zeroed structure is, read literally,
	// a set of values that are all too small, so the error is defensible; what was
	// not defensible was this client's earlier diagnosis, which blamed
	// ca_maxresponsesize_cached. The probe swept that field from 0 to 1 MiB and
	// every value was refused, while merely populating these five made a zero
	// cached size acceptable -- see cachedsizeprobe_live_test.go.
	//
	// The values are deliberately modest. One slot is what Linux offers for a
	// callback channel, and two operations covers the CB_COMPOUND shapes a server
	// could send. Asking for more would reserve resources on the server for a
	// channel that will never carry a request.
	backChannelSize       = 4 << 10
	backChannelOperations = 2
	backChannelSlots      = 1
	// Six RPC call words, an AUTH_NONE verifier, and a maximally sized
	// opaque_auth credential. The record marker is deliberately excluded by the
	// ca_maxrequestsize definition.
	maxRPCCallOverhead = 6*4 + 2*4 + 8 + maxOpaqueAuth
	// RFC 1831 bounds authsys_parms.machinename at 255 bytes, and the generated
	// XDR panics rather than truncating.
	maxAuthSysMachineName = 255
)

// slot is one entry in a session's slot table. A slot is held exclusively
// between acquire and release (or reclaim). That exclusive ownership supplies
// the per-slot ordering required by RFC 8881 section 2.10.6; delivery still has
// to be handled separately by choosing release or reclaim after the call result.
type slot struct {
	id    uint32
	seqID uint32
	inUse bool
}

// slotTable owns one NFSv4.1 session's fore-channel slots.
//
// The mutex protects slot ownership, sequence IDs, and growth as one invariant.
// A notification channel is closed and replaced whenever a slot becomes
// available, which gives acquire a context-aware condition wait without tying
// table capacity to a fixed-size channel buffer.
type slotTable struct {
	mu      sync.Mutex
	slots   []*slot
	changed chan struct{}
}

func newSlotTable(n int) *slotTable {
	if n < 0 {
		n = 0
	}
	t := &slotTable{changed: make(chan struct{})}
	t.addSlotsLocked(n)
	return t
}

// acquire waits for exclusive ownership of a slot and reserves its next
// sequence ID. New sessions initialize every slot's stored sequence ID to zero,
// so the first acquire increments it to one, as RFC 8881 requires.
func (t *slotTable) acquire(ctx context.Context) (*slot, error) {
	if ctx == nil {
		return nil, errors.New("nfs41: nil context")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("nfs41: acquire session slot: %w", err)
		}
		t.mu.Lock()
		for _, s := range t.slots {
			if !s.inUse {
				s.inUse = true
				s.seqID++
				t.mu.Unlock()
				return s, nil
			}
		}
		changed := t.changed
		t.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			return nil, fmt.Errorf("nfs41: acquire session slot: %w", ctx.Err())
		}
	}
}

// release returns a slot after a request whose SEQUENCE may have succeeded. The
// sequence ID reserved by acquire remains consumed.
func (t *slotTable) release(s *slot) {
	t.finish(s, false)
}

// reclaim returns a slot whose sequence ID was provably not consumed: either the
// request never reached Conn's writer, or SEQUENCE itself returned an error. It
// undoes acquire's increment so the same sequence ID is sent on the next use.
func (t *slotTable) reclaim(s *slot) {
	t.finish(s, true)
}

func (t *slotTable) finish(s *slot, reclaim bool) {
	if s == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !s.inUse {
		return
	}
	if reclaim {
		s.seqID--
	}
	s.inUse = false
	t.notifyLocked()
}

// growTo raises the table to target slots, bounded by cap. Growth is one-way;
// shrinking could strand a slot that is already in flight.
func (t *slotTable) growTo(target, cap int) {
	if target < 0 || cap <= 0 {
		return
	}
	if target > cap {
		target = cap
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if target <= len(t.slots) {
		return
	}
	t.addSlotsLocked(target - len(t.slots))
	t.notifyLocked()
}

func (t *slotTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.slots)
}

func (t *slotTable) addSlotsLocked(n int) {
	for range n {
		t.slots = append(t.slots, &slot{id: uint32(len(t.slots))})
	}
}

func (t *slotTable) notifyLocked() {
	close(t.changed)
	t.changed = make(chan struct{})
}

// effectiveSlots applies the caller's optional slot cap to the server's grant.
// A zero request means use the grant. The server's grant is always the ceiling.
func effectiveSlots(want, grant int, log func(string)) int {
	if grant <= 0 {
		return 0
	}
	if want <= 0 {
		// A grant below the default request is reported too, not only one below
		// an explicit request. Nothing downstream treats it as an error — the
		// grant is always the ceiling — but a session that quietly comes up with
		// 8 slots where 128 were available has lost most of the concurrency that
		// justifies this transport, and an unlogged loss that size is precisely
		// the one nobody notices.
		if grant < defaultRequestedSlots && log != nil {
			log(fmt.Sprintf("nfs41: requested the default %d session slots; server granted %d; using %d",
				defaultRequestedSlots, grant, grant))
		}
		return grant
	}
	if want > grant {
		if log != nil {
			log(fmt.Sprintf("nfs41: requested %d session slots; server granted %d; using %d", want, grant, grant))
		}
		return grant
	}
	return want
}

// ServerIdentity is the peer identity this client retains from EXCHANGE_ID. An
// absent implementation ID is normal on FlashBlade, which does not populate it:
// measured empty on an S500R1 (Purity//FB 4.3.x) and on an S200 (4.8.0), with
// eir_server_owner and eir_server_scope both carrying only the data VIP.
//
// FlashArray DOES populate it. Measured 2026-08-21 against fa-lab-01:
//
//	Owner      "fa-lab-01"
//	Scope      "domain"
//	ImplName   "PureStorage FlashArray 6.10.6 202604291817+1e21401674a1-610jackfruit"
//	ImplDomain "purestorage.com"
//
// That is a real product identifier and a better gate than the max-file-size
// heuristic, because it does not move with the release while FA's max file size
// does. The gate reads it first and refuses a FlashArray by name; the size table
// is the fallback for servers that supply nothing here, which is FlashBlade. See
// isFlashArrayIdentity and pureMaxFileSizes in client.go.
//
// The field is OPTIONAL per RFC 8881 section 18.35, so an empty one is conforming
// and means "not asked", never "not a Pure array".
type ServerIdentity struct {
	Owner      string
	Scope      string
	ImplDomain string
	ImplName   string
	ImplDate   time.Time
}

// ClientRegistration is one EXCHANGE_ID result: everything that is per-clientid
// rather than per-session. Every Session on this clientid shares one of these,
// and it outlives any of them.
type ClientRegistration struct {
	id       uint64
	identity *ServerIdentity
	owner    []byte
	verifier [8]byte

	// createGate serializes the complete CREATE_SESSION exchange: RFC 8881
	// allows only one in flight per clientid.
	//
	// It is a 1-deep semaphore rather than a sync.Mutex because its holder keeps
	// it across a network round trip, and a waiter must be able to abandon the
	// wait when its own context expires. sync.Mutex.Lock cannot be abandoned, so
	// with a mutex here a second NewSession silently ignored its own deadline for
	// as long as the first exchange took — unbounded against a peer that accepts
	// the connection and never answers, which is what a corporate proxy in front
	// of an array VIF does. Under Task 14's pool, where one registration is
	// shared by every connection, that stalls every other connection's setup
	// past all of their deadlines.
	//
	// Lock ordering: Session.lifecycle, then this gate, then Session.stateMu.
	// Nothing waits on this gate while holding stateMu, and nothing waits on the
	// RECLAIM_COMPLETE gate below while holding this one.
	createGate chan struct{}

	// nextCreateSeq is the csa_sequence for the next CREATE_SESSION on this
	// clientid. It starts at the eir_sequenceid EXCHANGE_ID returned and is read
	// and written only by the holder of createGate.
	nextCreateSeq uint32

	// RECLAIM_COMPLETE with rca_one_fs=false is scoped to the clientid, not a
	// session, so all sessions share one attempt. This is a gate rather than a
	// sync.Once for the same reason as createGate: Once.Do makes a second caller
	// wait out the first caller's round trip with no way to give up.
	reclaimMu   sync.Mutex
	reclaimDone bool
	// reclaimBusy is non-nil while an attempt is in flight and is closed when
	// that attempt finishes, whatever its outcome.
	reclaimBusy chan struct{}
}

// acquireCreateGate reserves the right to send this clientid's next
// CREATE_SESSION, or returns ctx's error rather than waiting past it.
func (r *ClientRegistration) acquireCreateGate(ctx context.Context) error {
	if r.createGate == nil {
		return errors.New("nfs41: client registration was not produced by ExchangeID")
	}
	// The uncontended case must not race ctx.Done: a select with both cases
	// ready picks at random, which would fail a call whose gate was free.
	select {
	case r.createGate <- struct{}{}:
		return nil
	default:
	}
	select {
	case r.createGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("nfs41: waiting for the CREATE_SESSION in flight on this client ID: %w", ctx.Err())
	}
}

func (r *ClientRegistration) releaseCreateGate() {
	<-r.createGate
}

// beginReclaimComplete reports whether this caller owns the one
// RECLAIM_COMPLETE attempt for this clientid. It returns false with a nil error
// when the attempt has already been made, and ctx's error rather than waiting
// past it for an attempt in flight.
func (r *ClientRegistration) beginReclaimComplete(ctx context.Context) (bool, error) {
	for {
		r.reclaimMu.Lock()
		if r.reclaimDone {
			r.reclaimMu.Unlock()
			return false, nil
		}
		if r.reclaimBusy == nil {
			r.reclaimBusy = make(chan struct{})
			r.reclaimMu.Unlock()
			return true, nil
		}
		busy := r.reclaimBusy
		r.reclaimMu.Unlock()

		select {
		case <-busy:
			// The in-flight attempt finished; loop to observe its outcome.
		case <-ctx.Done():
			return false, fmt.Errorf("nfs41: waiting for the RECLAIM_COMPLETE in flight on this client ID: %w", ctx.Err())
		}
	}
}

// endReclaimComplete records the attempt as made, successful or not. A failed
// RECLAIM_COMPLETE is deliberately not retried by a later session: the operation
// is an optimization that avoids grace-period ambiguity, not a correctness gate,
// and a server that answers NFS4ERR_COMPLETE_ALREADY to a second one is strictly
// conforming.
func (r *ClientRegistration) endReclaimComplete() {
	r.reclaimMu.Lock()
	r.reclaimDone = true
	busy := r.reclaimBusy
	r.reclaimBusy = nil
	r.reclaimMu.Unlock()
	if busy != nil {
		close(busy)
	}
}

// ID returns the shorthand client ID allocated by the server.
func (r *ClientRegistration) ID() uint64 {
	if r == nil {
		return 0
	}
	return r.id
}

// Identity returns the immutable server identity from EXCHANGE_ID.
func (r *ClientRegistration) Identity() *ServerIdentity {
	if r == nil {
		return nil
	}
	return r.identity
}

func newClientVerifier() (verifier [8]byte) {
	if _, err := rand.Read(verifier[:]); err != nil {
		// crypto/rand failing means the process cannot safely distinguish this
		// incarnation from a prior one. There is no honest fallback derived from
		// owner or time, both of which concurrent processes can reproduce.
		panic(fmt.Sprintf("nfs41: generate client incarnation verifier: %v", err))
	}
	return verifier
}

// ExchangeID establishes a client owner. EXCHANGE_ID is the sole operation in
// its COMPOUND because no session exists yet.
func ExchangeID(ctx context.Context, c *Conn, clientOwner []byte) (*ClientRegistration, error) {
	if ctx == nil {
		return nil, errors.New("nfs41: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("nfs41: nil RPC connection")
	}
	if len(clientOwner) == 0 {
		return nil, errors.New("nfs41: empty client owner")
	}
	if len(clientOwner) > xdr.NFS4_OPAQUE_LIMIT {
		return nil, fmt.Errorf("nfs41: client owner is %d bytes; maximum is %d", len(clientOwner), xdr.NFS4_OPAQUE_LIMIT)
	}

	verifier := processClientVerifier
	owner := append([]byte(nil), clientOwner...)
	op := xdr.Nfs_argop4{Argop: xdr.OP_EXCHANGE_ID}
	*op.Opexchange_id() = xdr.EXCHANGE_ID4args{
		Eia_clientowner: xdr.Client_owner4{
			Co_verifier: verifier,
			Co_ownerid:  owner,
		},
		Eia_flags:         xdr.EXCHGID4_FLAG_USE_NON_PNFS,
		Eia_state_protect: xdr.State_protect4_a{Spa_how: xdr.SP4_NONE},
	}

	status, results, err := callCompound(ctx, c, "exchange-id", []xdr.Nfs_argop4{op})
	if err != nil {
		return nil, fmt.Errorf("nfs41: EXCHANGE_ID: %w", err)
	}
	if status != NFS4_OK {
		return nil, fmt.Errorf("nfs41: EXCHANGE_ID status %d", status)
	}
	if len(results) != 1 || results[0].Resop != xdr.OP_EXCHANGE_ID {
		return nil, fmt.Errorf("nfs41: EXCHANGE_ID returned %d unexpected results", len(results))
	}
	res := results[0].Opexchange_id()
	if uint32(res.Eir_status) != NFS4_OK {
		return nil, fmt.Errorf("nfs41: EXCHANGE_ID result status %d", res.Eir_status)
	}
	ok := res.Eir_resok4()
	if ok.Eir_clientid == 0 {
		return nil, errors.New("nfs41: EXCHANGE_ID returned a zero client ID")
	}

	identity := &ServerIdentity{
		Owner: string(ok.Eir_server_owner.So_major_id),
		Scope: string(ok.Eir_server_scope),
	}
	if len(ok.Eir_server_impl_id) != 0 {
		impl := ok.Eir_server_impl_id[0]
		identity.ImplDomain = string(impl.Nii_domain)
		identity.ImplName = string(impl.Nii_name)
		if impl.Nii_date.Nseconds < uint32(time.Second) {
			identity.ImplDate = time.Unix(impl.Nii_date.Seconds, int64(impl.Nii_date.Nseconds)).UTC()
		}
	}
	return &ClientRegistration{
		id:            uint64(ok.Eir_clientid),
		identity:      identity,
		owner:         owner,
		verifier:      verifier,
		createGate:    make(chan struct{}, 1),
		nextCreateSeq: uint32(ok.Eir_sequenceid),
	}, nil
}

// ChannelAttrs is the granted fore-channel attributes after clamping to the RPC
// layer's record cap.
type ChannelAttrs struct {
	MaxRequestSize  uint32
	MaxResponseSize uint32
	MaxOperations   uint32
	MaxRequests     uint32
}

// SessionCreateError reports a server refusal of CREATE_SESSION. Callers can use
// errors.As and Status to distinguish NFS4ERR_STALE_CLIENTID from a stale
// session, which requires a new client registration rather than another rebuild.
type SessionCreateError struct {
	Status uint32
}

func (e *SessionCreateError) Error() string {
	return fmt.Sprintf("nfs41: CREATE_SESSION status %s (%d)", xdr.Nfsstat4(e.Status), e.Status)
}

// Session owns one connection's NFSv4.1 session and slot table.
type Session struct {
	c   *Conn
	reg *ClientRegistration
	log func(string)

	want int

	lifecycle sync.RWMutex
	stateMu   sync.RWMutex
	id        [16]byte
	slots     *slotTable
	attrs     ChannelAttrs
	destroyed bool
}

// NewSession creates one fore-channel session on c. wantSlots is an optional
// local ceiling; zero requests the measured default and uses the full grant.
func NewSession(ctx context.Context, c *Conn, reg *ClientRegistration, wantSlots uint32, log func(string)) (*Session, error) {
	if ctx == nil {
		return nil, errors.New("nfs41: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("nfs41: nil RPC connection")
	}
	if reg == nil {
		return nil, errors.New("nfs41: nil client registration")
	}
	if reg.id == 0 {
		return nil, errors.New("nfs41: zero client ID")
	}
	want := int(wantSlots)
	if uint32(want) != wantSlots {
		return nil, fmt.Errorf("nfs41: requested slot count %d does not fit int", wantSlots)
	}
	if log == nil {
		log = func(string) {}
	}
	s := &Session{c: c, reg: reg, log: log, want: want}
	if err := s.create(ctx); err != nil {
		return nil, err
	}
	s.sendReclaimCompleteOnce(ctx)
	return s, nil
}

// create serializes CREATE_SESSION with every other session sharing reg. The
// sequence is reserved under reg.mu and committed only after a successful reply,
// so a failed exchange leaves the same value available for retry.
func (s *Session) create(ctx context.Context) error {
	if s.c == nil {
		return errors.New("nfs41: nil RPC connection")
	}
	if err := s.c.connectionError(); err != nil {
		return fmt.Errorf("nfs41: CREATE_SESSION on closed connection: %w", err)
	}

	if err := s.reg.acquireCreateGate(ctx); err != nil {
		return err
	}
	defer s.reg.releaseCreateGate()

	sequence := s.reg.nextCreateSeq
	if sequence == 0 {
		return errors.New("nfs41: CREATE_SESSION has a zero sequence ID")
	}
	requestedSlots := s.want
	if requestedSlots <= 0 {
		requestedSlots = defaultRequestedSlots
	}

	fore := xdr.Channel_attrs4{
		Ca_maxrequestsize:  requestedChannelSize,
		Ca_maxresponsesize: requestedChannelSize,
		// ca_maxresponsesize_cached is zero because the client has no use for a
		// duplicate-reply cache: sa_cachethis is false on every SEQUENCE it sends
		// and by design always will be, since every operation it issues is
		// idempotent. A non-zero value would reserve per-slot reply cache that is
		// never read. That reason stands on its own and does not depend on how any
		// particular server responds.
		//
		// MEASURED 2026-08-21 against an S500R1 (see the probe in
		// slotprobe_live_test.go): asking for 8 MiB here changed nothing. Both
		// arms were granted ca_maxrequests 128, ca_maxresponsesize 526336 and
		// ca_maxoperations 16 — identical channel attributes. An earlier revision
		// of this comment asserted that a non-zero value "invites a grant of a
		// handful of slots in return"; on this array it does not, and that claim
		// is retracted.
		//
		// The concern remains legitimate rather than imaginary: RFC 8881 section
		// 18.36.3 explicitly permits a server to reduce ca_maxrequests to fit the
		// requested cache in its budget, and Linux's nfs4_init_channel_attrs
		// leaves max_resp_sz_cached at zero for that reason. One firmware on one
		// model declining to exercise that latitude is not licence to start
		// asking for cache we would not read — and if a future firmware does
		// enforce it, the symptom is silent, because a small grant looks exactly
		// like normal operation.
		//
		// MEASURED 2026-08-22: Purity//FA 6.10.6 accepts zero here, once the back
		// channel is populated. An earlier revision of this client believed FA
		// refused zero and retried with a non-zero size; that was a misdiagnosis of
		// the zeroed back channel, and the retry is gone. See backChannelSize.
		Ca_maxresponsesize_cached: 0,
		Ca_maxoperations:          maxSessionOperations,
		Ca_maxrequests:            uint32(requestedSlots),
	}

	// One callback_sec_parms4 element, even though this client declines the back
	// channel. A zero-length array is legal and knfsd tolerates it, but every
	// real client sends at least one element — Linux emits a single AUTH_SYS
	// entry — so one element is the only path server implementations are known to
	// exercise. The credential itself is inert: without
	// CREATE_SESSION4_FLAG_CONN_BACK_CHAN there is no callback for it to
	// authenticate.
	machine := string(s.reg.owner)
	if len(machine) > maxAuthSysMachineName {
		machine = machine[:maxAuthSysMachineName]
	}
	sec := xdr.Callback_sec_parms4{Cb_secflavor: xdr.Uint32_t(xdr.AUTH_SYS)}
	*sec.Cbsp_sys_cred() = xdr.Authsys_parms{
		Stamp:       uint32(time.Now().Unix()),
		Machinename: machine,
	}

	op := xdr.Nfs_argop4{Argop: xdr.OP_CREATE_SESSION}
	*op.Opcreatesession() = xdr.CREATE_SESSION4args{
		Csa_clientid:        s.reg.id,
		Csa_sequence:        sequence,
		Csa_fore_chan_attrs: fore,
		// No back-channel FLAG and no callback program: this client never accepts
		// callbacks. The attributes are populated all the same, because a
		// Purity//FA refuses a zeroed structure outright; see backChannelSize.
		Csa_back_chan_attrs: xdr.Channel_attrs4{
			Ca_maxrequestsize:         backChannelSize,
			Ca_maxresponsesize:        backChannelSize,
			Ca_maxresponsesize_cached: 0,
			Ca_maxoperations:          backChannelOperations,
			Ca_maxrequests:            backChannelSlots,
		},
		Csa_sec_parms: []xdr.Callback_sec_parms4{sec},
	}

	status, results, err := callCompound(ctx, s.c, "create-session", []xdr.Nfs_argop4{op})
	if err != nil {
		// No reply was parsed, so the server either never saw this csa_sequence or
		// saw it and lost the reply. Both retry the SAME value: RFC 8881 section
		// 18.36.4 answers the second case from the per-clientid replay cache, and
		// advancing past a value the server never saw leaves a gap that refuses
		// every later CREATE_SESSION on this clientid.
		return fmt.Errorf("nfs41: CREATE_SESSION sequence %d: %w", sequence, err)
	}
	if status != NFS4_OK {
		// The server refused, so it created no session and recorded no sequence.
		// The reservation stands for the next attempt.
		return &SessionCreateError{Status: status}
	}

	// Past this line the server HAS created a session and HAS recorded
	// csa_sequence in its per-clientid CREATE_SESSION replay cache (RFC 8881
	// section 18.36.4) — a COMPOUND status of NFS4_OK means every operation in it
	// succeeded, and CREATE_SESSION is the only one. Everything below is a LOCAL
	// judgement about a session that already exists, so the counter advances
	// first and unconditionally. Returning without advancing would resend the
	// same value, earn a replay of the identical reply, fail the identical local
	// check, and wedge this clientid for the life of the registration.
	//
	// Assigning from the echoed reservation rather than incrementing in place
	// also makes a uint32 wrap visible on the next attempt.
	s.reg.nextCreateSeq = sequence + 1

	if len(results) != 1 || results[0].Resop != xdr.OP_CREATE_SESSION {
		// No decodable session ID, so the session cannot even be torn down. It
		// leaks until its lease expires; nothing better is available.
		return fmt.Errorf("nfs41: CREATE_SESSION returned %d unexpected results", len(results))
	}
	res := results[0].Opcreatesession()
	if uint32(res.Csr_status) != NFS4_OK {
		// Unreachable against a server that follows RFC 8881 section 15.2: with
		// one operation in the COMPOUND, csr_status IS the COMPOUND status already
		// checked above. Kept as a decoding guard, not as a reachable path.
		return &SessionCreateError{Status: uint32(res.Csr_status)}
	}
	ok := res.Csr_resok4()
	if ok.Csr_sequence != sequence {
		s.abandonSession(ctx, ok.Csr_sessionid,
			fmt.Sprintf("CREATE_SESSION echoed sequence %d, want %d", ok.Csr_sequence, sequence))
		return fmt.Errorf("nfs41: CREATE_SESSION sequence %d, want %d", ok.Csr_sequence, sequence)
	}

	granted := ok.Csr_fore_chan_attrs
	attrs := ChannelAttrs{
		MaxRequestSize:  min(uint32(granted.Ca_maxrequestsize), uint32(maxRecordSize)),
		MaxResponseSize: min(uint32(granted.Ca_maxresponsesize), uint32(maxRecordSize)),
		MaxOperations:   uint32(granted.Ca_maxoperations),
		MaxRequests:     uint32(granted.Ca_maxrequests),
	}
	if granted.Ca_maxrequestsize > maxRecordSize {
		s.log(fmt.Sprintf("nfs41: server granted ca_maxrequestsize %d above the RPC record cap %d; using %d", granted.Ca_maxrequestsize, maxRecordSize, attrs.MaxRequestSize))
	}
	if granted.Ca_maxresponsesize > maxRecordSize {
		s.log(fmt.Sprintf("nfs41: server granted ca_maxresponsesize %d above the RPC record cap %d; using %d", granted.Ca_maxresponsesize, maxRecordSize, attrs.MaxResponseSize))
	}
	if granted.Ca_maxrequestsize == 0 || granted.Ca_maxresponsesize == 0 || granted.Ca_maxoperations == 0 {
		s.abandonSession(ctx, ok.Csr_sessionid, "CREATE_SESSION granted an unusable zero fore-channel limit")
		return errors.New("nfs41: CREATE_SESSION granted an unusable zero fore-channel limit")
	}
	if granted.Ca_maxoperations > maxSessionOperations {
		attrs.MaxOperations = maxSessionOperations
	}
	grant := int(granted.Ca_maxrequests)
	if uint64(granted.Ca_maxrequests) > uint64(requestedSlots) {
		// An over-grant is clamped, not refused. Linux's
		// nfs4_verify_channel_attrs clamps max_reqs the same way. Refusing turned
		// a server being harmlessly generous into a permanent wedge: the session
		// is already created, so the retry is answered from the replay cache with
		// the identical over-grant and fails identically, forever.
		s.log(fmt.Sprintf("nfs41: CREATE_SESSION granted %d slots above the offered %d; using %d",
			granted.Ca_maxrequests, requestedSlots, requestedSlots))
		grant = requestedSlots
	}
	count := effectiveSlots(s.want, grant, s.log)
	if count == 0 {
		s.abandonSession(ctx, ok.Csr_sessionid, "CREATE_SESSION granted zero fore-channel slots")
		return errors.New("nfs41: CREATE_SESSION granted zero fore-channel slots")
	}
	attrs.MaxRequests = uint32(count)

	s.stateMu.Lock()
	s.id = ok.Csr_sessionid
	s.slots = newSlotTable(count)
	s.attrs = attrs
	s.destroyed = false
	s.stateMu.Unlock()
	return nil
}

// abandonSession tears down a session this client has just been given and has
// decided it cannot use. Without it every local rejection above leaks a session
// on the server until its lease expires, while the client reports only an error.
//
// Best effort by design: the caller is already returning a failure, and the only
// thing an error here changes is how long the leak lasts. It runs while the
// caller still holds createGate, which keeps "one CREATE_SESSION in flight per
// clientid" true across the teardown as well.
func (s *Session) abandonSession(ctx context.Context, id [16]byte, reason string) {
	s.log(fmt.Sprintf("nfs41: destroying the session just created: %s", reason))

	op := xdr.Nfs_argop4{Argop: xdr.OP_DESTROY_SESSION}
	op.Opdestroysession().Dsa_sessionid = id
	status, _, err := callCompound(ctx, s.c, "destroy-session", []xdr.Nfs_argop4{op})
	switch {
	case err != nil:
		s.log(fmt.Sprintf("nfs41: DESTROY_SESSION for the abandoned session: %v", err))
	case status != NFS4_OK && status != NFS4ERR_BADSESSION:
		s.log(fmt.Sprintf("nfs41: DESTROY_SESSION for the abandoned session: status %d", status))
	}
}

// sendReclaimCompleteOnce declares that this clientid has no state to reclaim,
// exactly once for the whole registration. A failure is logged but does not
// invalidate the new session: this is an optimization that avoids grace-period
// ambiguity, not a correctness gate.
//
// The gate is released before Session.Do is called, so nothing holds it across
// the round trip except this one attempt, and a concurrent NewSession that
// cannot afford to wait for it gets its context error instead.
func (s *Session) sendReclaimCompleteOnce(ctx context.Context) {
	first, err := s.reg.beginReclaimComplete(ctx)
	if err != nil {
		s.log(fmt.Sprintf("nfs41: RECLAIM_COMPLETE not sent: %v", err))
		return
	}
	if !first {
		return
	}
	defer s.reg.endReclaimComplete()

	op := xdr.Nfs_argop4{Argop: xdr.OP_RECLAIM_COMPLETE}
	op.Opreclaimcomplete().Rca_one_fs = false
	status, _, err := s.Do(ctx, []xdr.Nfs_argop4{op})
	if err != nil {
		s.log(fmt.Sprintf("nfs41: RECLAIM_COMPLETE failed: %v", err))
		return
	}
	if status != NFS4_OK {
		s.log(fmt.Sprintf("nfs41: RECLAIM_COMPLETE status %d", status))
	}
}

func (s *Session) clearStateLocked() {
	s.destroyed = true
	s.id = [16]byte{}
	s.slots = nil
	s.attrs = ChannelAttrs{}
}

// Do runs one session-bound COMPOUND. SEQUENCE is always its first operation and
// always sets cachethis=false through OpSequence. The returned results include
// that leading SEQUENCE result followed by the caller's operation results.
func (s *Session) Do(ctx context.Context, ops []xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4, error) {
	if ctx == nil {
		return 0, nil, errors.New("nfs41: nil context")
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	for i, op := range ops {
		if op.Argop == xdr.OP_SEQUENCE {
			return 0, nil, fmt.Errorf("nfs41: operation %d is SEQUENCE; Session.Do supplies SEQUENCE as operation 0", i)
		}
	}

	// Lifecycle changes wait for every in-flight call to finish before replacing
	// or destroying the session and its slot table.
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	status, reply, err := s.do(ctx, ops, false)
	return status, reply.gen, err
}

// DoFast is Do, decoded by the hand-written decoder in fastdecode.go instead of
// the generated one. It exists because that decoder is 30x faster on a READDIR
// reply and allocates 19x less; see fastdecode.go for the measurement and why the
// generated decoder could not simply be improved.
//
// It shares every line of slot acquisition, SEQUENCE validation and slot
// release with Do. That sharing is the point: a second copy of the slot
// bookkeeping is how a fast path acquires a correctness bug the slow path does
// not have.
//
// The returned slices ALIAS the reply buffer, which is what makes the decoder
// cheap. Anything retained past this call must be cloned.
//
// A caller must handle both return shapes. When the fast decoder meets an
// operation or attribute it was not taught it declines, and this returns
// generated results instead -- so callers get `fast` or `gen`, never neither, and
// must not assume which.
func (s *Session) DoFast(ctx context.Context, ops []xdr.Nfs_argop4) (uint32, []fastResult, []xdr.Nfs_resop4, error) {
	if ctx == nil {
		return 0, nil, nil, errors.New("nfs41: nil context")
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, nil, err
	}
	for i, op := range ops {
		if op.Argop == xdr.OP_SEQUENCE {
			return 0, nil, nil, fmt.Errorf("nfs41: operation %d is SEQUENCE; Session.DoFast supplies SEQUENCE as operation 0", i)
		}
	}

	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	status, reply, err := s.do(ctx, ops, true)
	return status, reply.fast, reply.gen, err
}

// fastDecodeEnabled is the kill switch for the hand-written decoder. It is a
// variable rather than a constant so a test can force the fallback and prove the
// generated path still serves every caller -- a fallback nothing exercises is a
// fallback that has never been shown to work.
var fastDecodeEnabled = true

// decodedReply is one COMPOUND reply in whichever representation decoded it.
// Exactly one of fast and gen is non-nil. It exists so session.do can validate
// the SEQUENCE and manage the slot without caring which decoder ran.
type decodedReply struct {
	fast []fastResult
	gen  []xdr.Nfs_resop4
}

func (d decodedReply) count() int {
	if d.fast != nil {
		return len(d.fast)
	}
	return len(d.gen)
}

// firstIsSequence reports whether the reply begins with a SEQUENCE result, which
// RFC 8881 requires of every session COMPOUND.
func (d decodedReply) firstIsSequence() bool {
	if d.count() == 0 {
		return false
	}
	if d.fast != nil {
		return d.fast[0].Op == uint32(xdr.OP_SEQUENCE)
	}
	return d.gen[0].Resop == xdr.OP_SEQUENCE
}

// sequence returns the leading SEQUENCE result's status and the three identifiers
// the slot check needs.
func (d decodedReply) sequence() (status uint32, sessionID [16]byte, slotID, seqID uint32) {
	if d.fast != nil {
		r := d.fast[0]
		return r.Status, r.SessionID, r.SlotID, r.SequenceID
	}
	res := d.gen[0].Opsequence()
	status = uint32(res.Sr_status)
	if status != NFS4_OK {
		return status, sessionID, 0, 0
	}
	ok := res.Sr_resok4()
	return status, ok.Sr_sessionid, uint32(ok.Sr_slotid), uint32(ok.Sr_sequenceid)
}

// decodeSessionReply decodes with the fast decoder when the caller asked for it
// and the decoder accepts the reply, and with the generated decoder otherwise.
//
// A decline is not an error and must not be reported as one: the generated
// decoder is the reference implementation and handles every reply this client can
// receive, so declining costs speed and nothing else.
func decodeSessionReply(reply []byte, wantFast bool) (uint32, decodedReply, error) {
	if wantFast && fastDecodeEnabled {
		status, results, ok, err := decodeCompoundFast(reply)
		if err == nil && ok {
			return status, decodedReply{fast: results}, nil
		}
		// Fall through on both a decline and an error. An error here means the
		// reply is malformed, and the generated decoder produces the better
		// diagnosis for the caller to report.
	}
	status, results, err := ParseCompound(reply)
	if err != nil {
		return 0, decodedReply{}, err
	}
	return status, decodedReply{gen: results}, nil
}

// do assumes the caller either holds lifecycle for reading or has not published
// the Session yet.
func (s *Session) do(ctx context.Context, ops []xdr.Nfs_argop4, wantFast bool) (uint32, decodedReply, error) {
	s.stateMu.RLock()
	id := s.id
	table := s.slots
	attrs := s.attrs
	destroyed := s.destroyed
	s.stateMu.RUnlock()
	if destroyed || table == nil {
		return 0, decodedReply{}, errors.New("nfs41: session is not active")
	}
	// One operation is reserved for the mandatory leading SEQUENCE.
	if uint64(len(ops))+1 > uint64(attrs.MaxOperations) {
		return 0, decodedReply{}, fmt.Errorf("nfs41: session COMPOUND has %d operations; negotiated maximum is %d", len(ops)+1, attrs.MaxOperations)
	}

	sl, err := table.acquire(ctx)
	if err != nil {
		return 0, decodedReply{}, err
	}

	highest := table.size() - 1
	compoundOps := make([]xdr.Nfs_argop4, 1, len(ops)+1)
	compoundOps[0] = OpSequence(id, sl.seqID, sl.id, uint32(highest))
	compoundOps = append(compoundOps, ops...)
	request, err := BuildCompound("session", compoundOps)
	if err != nil {
		table.reclaim(sl)
		return 0, decodedReply{}, fmt.Errorf("nfs41: build session COMPOUND: %w", err)
	}
	// ca_maxrequestsize includes RPC headers. Reserve the maximum AUTH_SYS
	// overhead rpc.go permits, so every request admitted here fits regardless of
	// the credential length selected by the caller.
	callSize := uint64(len(request)) + uint64(maxRPCCallOverhead)
	if callSize > uint64(attrs.MaxRequestSize) {
		table.reclaim(sl)
		return 0, decodedReply{}, fmt.Errorf("nfs41: session COMPOUND call may be %d bytes; negotiated request maximum is %d", callSize, attrs.MaxRequestSize)
	}

	reply, err := s.c.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
	if err != nil {
		// ErrGarbageArgs joins ErrNotSent here because the two share the property
		// this branch actually turns on: the server did not execute SEQUENCE, so
		// the sequence ID this slot reserved was never consumed. GARBAGE_ARGS is
		// decided while decoding RPC arguments, before any NFS operation runs.
		//
		// The asymmetry is what makes reclaiming the safe choice even if that
		// reasoning were wrong. Reclaiming an already-consumed sequence ID
		// reissues it; sa_cachethis is always false, so the server holds no cached
		// reply to object with, and the reissue is answered normally or with
		// NFS4ERR_RETRY_UNCACHED_REP, which classify() already retries under a
		// bounded budget. Releasing an unconsumed one yields
		// NFS4ERR_SEQ_MISORDERED, which classify() maps to a session rebuild --
		// and rebuilding trips the one-session-per-client-ID limit recorded in
		// RFC-Deviations.md section 1. A bounded retry against a rebuild storm is
		// not a close call.
		if errors.Is(err, ErrNotSent) || errors.Is(err, ErrGarbageArgs) {
			table.reclaim(sl)
		} else {
			table.release(sl)
		}
		return 0, decodedReply{}, fmt.Errorf("nfs41: session COMPOUND: %w", err)
	}

	status, decoded, err := decodeSessionReply(reply, wantFast)
	if err != nil {
		// The record reached the server; even an undecodable reply cannot undo
		// the SEQUENCE operation it may have processed.
		table.release(sl)
		return 0, decodedReply{}, fmt.Errorf("nfs41: parse session COMPOUND: %w", err)
	}

	if !decoded.firstIsSequence() {
		table.release(sl)
		return 0, decodedReply{}, errors.New("nfs41: session COMPOUND reply does not begin with SEQUENCE")
	}
	if decoded.count() > len(ops)+1 {
		table.release(sl)
		return 0, decodedReply{}, fmt.Errorf("nfs41: session COMPOUND returned %d results for %d operations", decoded.count(), len(ops)+1)
	}
	seqStatus, replySessionID, replySlotID, replySeqID := decoded.sequence()
	if seqStatus != NFS4_OK {
		// RFC 8881 section 2.203.0.113.2: an error from SEQUENCE does not
		// consume the slot's sequence ID, so the reservation is handed back.
		//
		// Exactly one status is excluded from that rule, and Task 10's retry loop
		// must not re-derive this: NFS4ERR_SEQ_FALSE_RETRY means the server holds
		// a cached reply for this seqid and the request does not match it, and it
		// requires the client to ADVANCE the seqid rather than reissue it.
		// Reclaiming there would reissue the same value forever and livelock the
		// retry. It is unreachable from this client: a slot is owned exclusively
		// between acquire and release, so no two different COMPOUNDs ever carry
		// one seqid, and sa_cachethis is always false, so the server has no
		// cached reply to compare a retry against. If either of those ever
		// changes, this branch has to grow a case before the retry loop does.
		table.reclaim(sl)
		return status, decoded, nil
	}
	if status == NFS4_OK && decoded.count() != len(ops)+1 {
		table.release(sl)
		return 0, decodedReply{}, fmt.Errorf("nfs41: successful session COMPOUND returned %d results for %d operations", decoded.count(), len(ops)+1)
	}
	if replySessionID != id || replySlotID != sl.id || replySeqID != sl.seqID {
		table.release(sl)
		return 0, decodedReply{}, errors.New("nfs41: SEQUENCE reply does not match request")
	}
	// sr_target_highest_slotid is deliberately not acted on, and the growTo call
	// that used to be here was provably dead code rather than a live feature.
	// create sizes the table at the full grant and caps it at the same
	// attrs.MaxRequests that would bound the growth, so every target the server
	// can legally send names a slot the table already has: the guard in growTo
	// was unconditionally true. Removing it makes the dead branch visible instead
	// of implying the client negotiates upward at runtime.
	//
	// slotTable.growTo stays. It encodes the invariant a seeded-below-the-grant
	// startup would need — growth is one-way, and a lower target never shrinks a
	// table with slots in flight — and rewiring it is a one-line change if the
	// startup slot count ever stops being the whole grant. Shrinking on a lower
	// target is not implemented and must not be: it would strand in-flight slots.
	table.release(sl)
	return status, decoded, nil
}

// Rebuild destroys this connection's session best-effort and creates a new one
// on the same live Conn with the same registration. Dialing and EXCHANGE_ID are
// owned by the connection pool, not by Session.
func (s *Session) Rebuild(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nfs41: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.c == nil {
		return fmt.Errorf("nfs41: rebuild session: %w", ErrConnClosed)
	}
	if err := s.c.connectionError(); err != nil {
		return fmt.Errorf("nfs41: rebuild session: %w", err)
	}

	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if err := s.c.connectionError(); err != nil {
		return fmt.Errorf("nfs41: rebuild session: %w", err)
	}
	// DESTROY_SESSION is best effort: BADSESSION is already the desired state,
	// and another server status must not prevent trying the replacement. A
	// transport failure is different because create cannot work on the same dead
	// Conn and the pool needs the ErrConnClosed signal to redial.
	if err := s.destroy(ctx); err != nil {
		if connErr := s.c.connectionError(); connErr != nil {
			return fmt.Errorf("nfs41: rebuild session: %w", connErr)
		}
		s.stateMu.Lock()
		s.clearStateLocked()
		s.stateMu.Unlock()
	}
	if err := s.create(ctx); err != nil {
		return fmt.Errorf("nfs41: rebuild session: %w", err)
	}
	return nil
}

// Destroy tears down the session. It is safe to call more than once.
func (s *Session) Destroy(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nfs41: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	return s.destroy(ctx)
}

func (s *Session) destroy(ctx context.Context) error {
	s.stateMu.RLock()
	id := s.id
	alreadyDestroyed := s.destroyed
	s.stateMu.RUnlock()
	if alreadyDestroyed {
		return nil
	}

	op := xdr.Nfs_argop4{Argop: xdr.OP_DESTROY_SESSION}
	op.Opdestroysession().Dsa_sessionid = id
	status, results, err := callCompound(ctx, s.c, "destroy-session", []xdr.Nfs_argop4{op})
	if err != nil {
		return fmt.Errorf("nfs41: DESTROY_SESSION: %w", err)
	}
	if status == NFS4ERR_BADSESSION {
		// A prior DESTROY_SESSION may have succeeded and lost its reply, or the
		// server may have discarded the session independently. Either way the
		// requested postcondition already holds.
		s.stateMu.Lock()
		s.clearStateLocked()
		s.stateMu.Unlock()
		return nil
	}
	if status != NFS4_OK {
		return fmt.Errorf("nfs41: DESTROY_SESSION status %d", status)
	}
	if len(results) != 1 || results[0].Resop != xdr.OP_DESTROY_SESSION {
		return fmt.Errorf("nfs41: DESTROY_SESSION returned %d unexpected results", len(results))
	}
	if uint32(results[0].Opdestroysession().Dsr_status) != NFS4_OK {
		return fmt.Errorf("nfs41: DESTROY_SESSION result status %d", results[0].Opdestroysession().Dsr_status)
	}

	s.stateMu.Lock()
	s.clearStateLocked()
	s.stateMu.Unlock()
	return nil
}

// Slots returns the current usable fore-channel slot count.
func (s *Session) Slots() int {
	if s == nil {
		return 0
	}
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	s.stateMu.RLock()
	table := s.slots
	s.stateMu.RUnlock()
	if table == nil {
		return 0
	}
	return table.size()
}

// ChannelAttrs returns the granted fore-channel attributes after local clamps.
func (s *Session) ChannelAttrs() ChannelAttrs {
	if s == nil {
		return ChannelAttrs{}
	}
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.attrs
}

func callCompound(ctx context.Context, c *Conn, tag string, ops []xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4, error) {
	request, err := BuildCompound(tag, ops)
	if err != nil {
		return 0, nil, err
	}
	reply, err := c.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
	if err != nil {
		return 0, nil, err
	}
	return ParseCompound(reply)
}
