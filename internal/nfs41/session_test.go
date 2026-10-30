package nfs41

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// TestSlotAcquireIsExclusive is the load-bearing invariant. Per-slot sequence
// ordering (RFC 5661 section 2.10.6) falls out of exclusive ownership; if two
// goroutines can hold one slot, the sequence discipline is gone and there is no
// second mechanism protecting it.
func TestSlotAcquireIsExclusive(t *testing.T) {
	st := newSlotTable(4)
	var mu sync.Mutex
	held := map[uint32]bool{}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := st.acquire(context.Background())
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			mu.Lock()
			if held[s.id] {
				mu.Unlock()
				t.Errorf("slot %d handed out twice concurrently", s.id)
				st.release(s)
				return
			}
			held[s.id] = true
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			delete(held, s.id)
			mu.Unlock()
			st.release(s)
		}()
	}
	wg.Wait()
}

func TestSlotSeqIDAdvancesPerSlot(t *testing.T) {
	// Size 1, not 2. With two slots the reuse is not guaranteed, so the original
	// `if b.id == a.id && ...` guard made the assertion conditional on a
	// scheduling detail -- it passes vacuously whenever the table hands back the
	// other slot, which is most of the time. One slot forces the reuse.
	st := newSlotTable(1)
	a, err := st.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := a.seqID
	st.release(a)
	b, err := st.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b.id != a.id {
		t.Fatalf("a one-slot table handed out slot %d then %d", a.id, b.id)
	}
	if b.seqID != first+1 {
		t.Fatalf("slot %d reused with seqid %d, want %d", b.id, b.seqID, first+1)
	}
}

// TestSlotReclaimUndoesTheSeqIDAdvance covers the reclaim path, which had no
// test at all despite being the reason reclaim exists.
//
// The distinction is the whole correctness argument for the slot table:
// exclusive ownership guarantees ORDERING, not DELIVERY. release() means "the
// server saw this seqid, move on"; reclaim() means "it provably never left the
// client, so put the seqid back". Getting reclaim wrong in the safe-looking
// direction -- treating a not-sent request as sent -- leaves a permanent gap in
// that slot's sequence, and every subsequent request on it earns
// NFS4ERR_SEQ_MISORDERED. That is rpc.ErrNotSent's only consumer.
func TestSlotReclaimUndoesTheSeqIDAdvance(t *testing.T) {
	st := newSlotTable(1)
	a, err := st.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := a.seqID
	st.reclaim(a)

	b, err := st.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b.seqID != first {
		t.Fatalf("after reclaim the next acquire got seqid %d, want %d reissued; "+
			"a skipped seqid earns NFS4ERR_SEQ_MISORDERED on every later request for this slot",
			b.seqID, first)
	}
	st.release(b)

	// And release still advances, so reclaim did not disable the counter.
	c, err := st.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.seqID != first+1 {
		t.Fatalf("after release the next acquire got seqid %d, want %d", c.seqID, first+1)
	}
}

// TestSlotAcquireHonoursContextCancellation is why acquire takes a context at
// all: with every slot in flight it must block, and a caller that gives up has
// to be able to.
func TestSlotAcquireHonoursContextCancellation(t *testing.T) {
	st := newSlotTable(1)
	held, err := st.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer st.release(held)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := st.acquire(ctx); err == nil {
		t.Fatal("acquire returned a second slot from a one-slot table with one in flight")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("acquire error = %v, want it to wrap context.DeadlineExceeded", err)
	}
}

func TestSlotTableNeverExceedsTheServerGrant(t *testing.T) {
	// The flag asks for more than the server offered. The grant wins, and the
	// clamp is logged rather than fatal: an S500R1 grants 128 and the simulator
	// grants 6, and both must work with the same default flag value.
	var logged string
	got := effectiveSlots(1000, 6, func(s string) { logged = s })
	if got != 6 {
		t.Fatalf("effectiveSlots = %d, want 6", got)
	}
	if logged == "" {
		t.Fatal("clamping to the server grant must be logged")
	}
}

func TestSlotTableGrowsToTheServerTarget(t *testing.T) {
	// RFC 5661 lets a server raise the usable slot count after the fact via
	// sr_target_highest_slotid. A client that ignores it simply runs slower than
	// it could, so handle it even though it has not yet been observed.
	st := newSlotTable(4)
	st.growTo(8, 16) // target 8, bounded by a cap of 16
	if st.size() != 8 {
		t.Fatalf("size = %d after growTo(8), want 8", st.size())
	}
	st.growTo(64, 16)
	if st.size() != 16 {
		t.Fatalf("size = %d, want the cap of 16", st.size())
	}
	// Growth is one-way: a lower target must not shrink a table with slots in flight.
	st.growTo(2, 16)
	if st.size() != 16 {
		t.Fatalf("size = %d after a lower target, want 16 — shrinking would strand in-flight slots", st.size())
	}
}

func TestCreateSessionAgainstTheFakeServer(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()

	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-test"))
	if err != nil {
		t.Fatal(err)
	}
	if reg.ID() == 0 {
		t.Fatal("clientid = 0")
	}
	if reg.Identity().Owner == "" {
		t.Error("server owner was not recorded")
	}

	s, err := NewSession(context.Background(), c, reg, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Slots() != srv.GrantedSlots() {
		t.Fatalf("Slots() = %d, want the server's grant of %d", s.Slots(), srv.GrantedSlots())
	}
	// The negotiated attributes must reach a caller: Task 12 sizes READDIR from
	// ca_maxresponsesize and phase 4 batches from ca_maxoperations, and neither
	// can read them off the Session if they were dropped at negotiation.
	attrs := s.ChannelAttrs()
	if attrs.MaxResponseSize == 0 || attrs.MaxOperations == 0 {
		t.Errorf("ChannelAttrs() = %+v; the granted fore-channel attributes were not retained", attrs)
	}
	if attrs.MaxResponseSize > maxRecordSize || attrs.MaxRequestSize > maxRecordSize {
		t.Errorf("ChannelAttrs() = %+v, above the RPC layer's %d-byte record cap", attrs, maxRecordSize)
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestCreateSessionSequencesPerClientID is the test the frozen interface could
// not express, and the reason it changed. RFC 8881 section 18.36.3: csa_sequence
// starts at the eir_sequenceid EXCHANGE_ID returned and increments per clientid.
// A client that sends 1 twice works against the fake and is refused by a real
// server on its second session — exactly what Task 14 does on its second
// connection.
func TestCreateSessionSequencesPerClientID(t *testing.T) {
	// The subject IS multiple sessions on one clientid, which only an
	// RFC-conformant server permits.
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

	reg, err := ExchangeID(context.Background(), c1, []byte("permissionreset-seq"))
	if err != nil {
		t.Fatal(err)
	}

	// One EXCHANGE_ID, two sessions, one clientid — the Task 14 shape.
	s1, err := NewSession(context.Background(), c1, reg, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Destroy(context.Background())
	s2, err := NewSession(context.Background(), c2, reg, 0, nil)
	if err != nil {
		t.Fatalf("second session on the same clientid: %v", err)
	}
	defer s2.Destroy(context.Background())

	if got := srv.ClientIDCount(); got != 1 {
		t.Errorf("ClientIDCount() = %d, want 1: both sessions share one clientid", got)
	}
	// The fake records every csa_sequence it saw and refuses a repeat, so this
	// assertion fails outright rather than reporting a mismatch, if the client
	// resends. Keep the explicit check anyway: it names what broke.
	if got := srv.CreateSessionSequences(); len(got) != 2 || got[0] == got[1] {
		t.Errorf("csa_sequence values = %v, want two distinct increasing values", got)
	}
}

// TestNewSessionLogsAClampedGrant covers the log sink. The requirement to report
// a grant below what was asked for predates the sink existing, so it was
// unimplementable rather than merely unimplemented.
func TestNewSessionLogsAClampedGrant(t *testing.T) {
	srv := startFakeServer(t, withSlots(2))
	defer srv.Close()
	c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	reg, err := ExchangeID(context.Background(), c, []byte("permissionreset-clamp"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	s, err := NewSession(context.Background(), c, reg, 64, func(msg string) {
		lines = append(lines, msg)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy(context.Background())

	if s.Slots() != 2 {
		t.Fatalf("Slots() = %d, want the grant of 2 rather than the requested 64", s.Slots())
	}
	if len(lines) == 0 {
		t.Fatal("asking for 64 slots and being granted 2 was not logged")
	}
}

// TestReclaimCompleteIsSentOncePerClientID pins the per-clientid scope. Sessions
// share a clientid, RECLAIM_COMPLETE with rca_one_fs false is a per-clientid
// operation, and a strict server answers NFS4ERR_COMPLETE_ALREADY to the second.
func TestReclaimCompleteIsSentOncePerClientID(t *testing.T) {
	// Counts RECLAIM_COMPLETE across several sessions sharing a clientid, which
	// requires a server that grants them.
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

	reg, err := ExchangeID(context.Background(), c1, []byte("permissionreset-reclaim"))
	if err != nil {
		t.Fatal(err)
	}
	s1, err := NewSession(context.Background(), c1, reg, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Destroy(context.Background())
	s2, err := NewSession(context.Background(), c2, reg, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Destroy(context.Background())

	if got := srv.CallCount(uint32(xdr.OP_RECLAIM_COMPLETE)); got != 1 {
		t.Errorf("RECLAIM_COMPLETE sent %d times for one clientid, want 1", got)
	}
}

func TestSequenceSetsCachethisFalse(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	c, _ := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	defer c.Close()
	reg, _ := ExchangeID(context.Background(), c, []byte("t"))
	s, _ := NewSession(context.Background(), c, reg, 0, nil)
	defer s.Destroy(context.Background())

	if _, _, err := s.Do(context.Background(), []xdr.Nfs_argop4{OpPutRootFH(), OpGetFH()}); err != nil {
		t.Fatal(err)
	}
	if srv.SawCachethis() {
		t.Fatal("SEQUENCE requested reply caching; every op here is idempotent and the cache must stay off")
	}
}

func TestFakeServerInjectsAnErrorExactlyOnce(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	srv.InjectOnce(opSETATTR, NFS4ERR_DELAY)

	c, _ := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
	defer c.Close()
	reg, _ := ExchangeID(context.Background(), c, []byte("t"))
	s, _ := NewSession(context.Background(), c, reg, 0, nil)
	defer s.Destroy(context.Background())

	st, _, err := s.Do(context.Background(), []xdr.Nfs_argop4{OpPutRootFH(), OpSetACL([]byte{0, 0, 0, 0})})
	if err != nil {
		t.Fatal(err)
	}
	if st != NFS4ERR_DELAY {
		t.Fatalf("first call status = %d, want NFS4ERR_DELAY", st)
	}
	st, _, err = s.Do(context.Background(), []xdr.Nfs_argop4{OpPutRootFH(), OpSetACL([]byte{0, 0, 0, 0})})
	if err != nil {
		t.Fatal(err)
	}
	if st != NFS4_OK {
		t.Fatalf("second call status = %d, want NFS4_OK — the injection must fire once", st)
	}
}

// TestCreateSessionPopulatesTheBackChannel covers the one server behaviour that
// stopped this client from opening a session on a FlashArray.
//
// The client declines callbacks, and used to say so by sending
// csa_back_chan_attrs entirely zeroed. A FlashBlade accepts that; a Purity//FA
// answers NFS4ERR_TOOSMALL, and since CREATE_SESSION is the first thing a session
// does, the whole transport was unusable there. A zeroed structure is, read
// literally, a set of values that are all too small.
//
// The attributes are populated unconditionally rather than as a retry, so this
// asserts the shape on an ordinary server too: declining the back channel is
// expressed by omitting the FLAG, not by zeroing the attributes.
func TestCreateSessionPopulatesTheBackChannel(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []fakeOpt
	}{
		{"server that requires them (FlashArray)", []fakeOpt{withRequiredBackChannelAttrs()}},
		{"server that does not care (FlashBlade)", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeServer(t, tc.opts...)
			defer srv.Close()

			c, err := NewConn(context.Background(), srv.Dialer(), AuthSys{Machine: "test"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			reg, err := ExchangeID(context.Background(), c, []byte("back-channel"))
			if err != nil {
				t.Fatalf("EXCHANGE_ID: %v", err)
			}
			sess, err := NewSession(context.Background(), c, reg, 0, nil)
			if err != nil {
				t.Fatalf("CREATE_SESSION: %v", err)
			}
			defer sess.Destroy(context.Background())

			args := srv.CreateSessionArgs()
			// One attempt, not two: the attributes are populated up front, so there
			// is nothing to retry. A regression that went back to retrying would
			// still open a session and would only show up here.
			if len(args) != 1 {
				t.Fatalf("got %d CREATE_SESSION attempts, want 1", len(args))
			}
			back := args[0].Csa_back_chan_attrs
			if back.Ca_maxrequests == 0 || back.Ca_maxrequestsize == 0 ||
				back.Ca_maxresponsesize == 0 || back.Ca_maxoperations == 0 {
				t.Errorf("back channel attrs are not populated: %+v", back)
			}
			// The fore channel still asks for no reply cache. FA accepts that once
			// the back channel is populated, which is what retired the earlier
			// theory that FA required a non-zero cached size.
			if got := args[0].Csa_fore_chan_attrs.Ca_maxresponsesize_cached; got != 0 {
				t.Errorf("offered ca_maxresponsesize_cached %d, want 0", got)
			}
		})
	}
}
