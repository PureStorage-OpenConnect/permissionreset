package nfs41

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

func TestPoolOpensOneSessionPerConnection(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(8))
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 4, Export: "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if srv.ConnectionCount() != 4 {
		t.Fatalf("%d connections, want 4", srv.ConnectionCount())
	}
	if srv.SessionCount() != 4 {
		t.Fatalf("%d sessions, want 4 — one per connection is the entire point", srv.SessionCount())
	}
	// One clientid PER CONNECTION, not one for the pool. This assertion was
	// inverted until 2026-08-21: it required exactly 1, because the pool was
	// designed to share a registration. Hardware refuses that outright — a
	// FlashBlade permits one session per clientid and answers the second
	// CREATE_SESSION with NFS4ERR_INVAL — so N independent clients is the only
	// shape that works. See trunkprobe_live_test.go.
	if srv.ClientIDCount() != 4 {
		t.Fatalf("%d clientids, want 4 — each connection must run its own EXCHANGE_ID, "+
			"because one clientid carries only one session", srv.ClientIDCount())
	}
	if srv.BindConnToSessionCount() != 0 {
		t.Fatal("BIND_CONN_TO_SESSION was sent; this client shares no session state and must never trunk")
	}
}

type blockingWriteConn struct {
	net.Conn
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *blockingWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Write(p)
}

func TestRebuildBlocksOnlyTheAffectedConnection(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(2))
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "f0", FH: "h0"}, {Name: "f1", FH: "h1"}},
	})
	defer srv.Close()

	baseDialer := srv.Dialer()
	var blockNext atomic.Bool
	entered := make(chan struct{})
	release := make(chan struct{})
	releaseWrites := sync.OnceFunc(func() { close(release) })
	defer releaseWrites()
	dialer := func(ctx context.Context) (net.Conn, error) {
		conn, err := baseDialer(ctx)
		if err != nil || !blockNext.CompareAndSwap(true, false) {
			return conn, err
		}
		return &blockingWriteConn{Conn: conn, entered: entered, release: release}, nil
	}

	cl, err := newClientWithDialer(context.Background(), Config{
		Connections: 2, Export: "/", RPCTimeout: 2 * time.Second,
		RetryBudget: 5, RetryBaseDelay: time.Millisecond,
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	blockNext.Store(true)
	if err := cl.pool[0].conn.Close(); err != nil {
		t.Fatal(err)
	}
	cl.nextEntry.Store(0)
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- cl.SetACL(transport.Ref{Path: "/f0", FH: []byte("h0")}, []byte{0, 0, 0, 0})
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("affected entry did not reach its blocked replacement connection")
	}

	// Entry zero is now holding its exclusive rebuild lock across CREATE_SESSION.
	// A client-wide lifecycle lock would strand this operation behind it; the
	// per-entry lock lets entry one continue immediately.
	cl.nextEntry.Store(1)
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- cl.SetACL(transport.Ref{Path: "/f1", FH: []byte("h1")}, []byte{0, 0, 0, 0})
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("operation on unaffected connection: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("operation on unaffected connection waited for another entry's rebuild")
	}

	releaseWrites()
	if err := <-firstDone; err != nil {
		t.Fatalf("operation on rebuilt connection: %v", err)
	}
}

func TestInFlightCapacityIsConnectionsTimesSlots(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(8))
	entries := make([]fakeEntry, 64)
	for i := range entries {
		entries[i] = fakeEntry{Name: fmt.Sprintf("f%d", i), FH: fmt.Sprintf("h%d", i)}
	}
	srv.AddTree(map[string][]fakeEntry{"/": entries})
	defer srv.Close()

	// Build the client BEFORE holding replies. Session setup is itself a pair of
	// COMPOUNDs, so holding first strands EXCHANGE_ID and CREATE_SESSION, New
	// times out, and a discarded error hands back a nil *Client whose first
	// SetACL segfaults rather than reporting anything useful.
	cl, err := newTestClientErr(t, srv, Config{Connections: 4, Export: "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	srv.HoldRepliesUntilSignalled()
	// Release on every exit path. Without this a failed WaitForInFlight leaves 32
	// goroutines parked on held replies until their RPC deadlines expire, which
	// turned a one-line failure into a 90-second one.
	defer srv.ReleaseReplies()

	// 32 concurrent SETATTRs should all reach the server before any reply is sent.
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cl.SetACL(transport.Ref{Path: fmt.Sprintf("/f%d", i), FH: []byte(fmt.Sprintf("h%d", i))}, []byte{0, 0, 0, 0})
		}(i)
	}
	if !srv.WaitForInFlight(32, 5*time.Second) {
		t.Fatalf("only %d calls reached the server; 4 connections x 8 slots must give 32 in flight", srv.InFlight())
	}
	srv.ReleaseReplies()
	wg.Wait()
}

// TestCloseWaitsForAnEntryRebuild pins that Close cannot return while a pool
// entry is mid-rebuild, so a replacement connection can never outlive the
// client that owns it.
//
// The rebuild is driven through the DEAD-CONNECTION path rather than a stale
// clientid, because that is the only path that dials. A stale clientid used to
// dial too — it replaced the whole pool under a fresh registration — but per-entry
// registration means Rebuild on a live connection now succeeds and returns
// without ever reaching the dialer.
func TestCloseWaitsForAnEntryRebuild(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(2))
	defer srv.Close()

	baseDialer := srv.Dialer()
	var dials atomic.Int32
	replacementDialed := make(chan struct{})
	releaseDial := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseDial) })
	defer release()
	dialer := func(ctx context.Context) (net.Conn, error) {
		if dials.Add(1) == 3 {
			close(replacementDialed)
			select {
			case <-releaseDial:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return baseDialer(ctx)
	}

	cl, err := newClientWithDialer(context.Background(), Config{
		Connections: 2, Export: "/", RPCTimeout: 2 * time.Second,
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}

	entry := cl.pool[0]
	entry.lifecycle.Lock()
	failedGeneration, failedRegistration := entry.generation, entry.session.reg
	// Kill this entry's connection so Rebuild fails with ErrConnClosed and
	// rebuildEntry has to redial, which is what the blocked dialer intercepts.
	entry.conn.Close()
	entry.lifecycle.Unlock()

	rebuildDone := make(chan error, 1)
	go func() {
		rebuildDone <- cl.rebuildEntry(context.Background(), entry, failedGeneration, failedRegistration)
	}()
	select {
	case <-replacementDialed:
	case <-time.After(time.Second):
		release()
		cl.Close()
		t.Fatal("the entry rebuild did not reach the blocked dial")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- cl.Close() }()
	select {
	case err := <-closeDone:
		release()
		<-rebuildDone
		t.Fatalf("Close returned while an entry rebuild was still dialing: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	release()
	if err := <-rebuildDone; err != nil {
		t.Fatalf("rebuild entry: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestStaleClientIDReplacesOnlyItsOwnEntry pins the consequence of giving each
// connection its own clientid: a clientid the server has forgotten invalidates
// exactly one pool entry.
//
// Under the previous shared-registration design this test's ancestor asserted
// the opposite — that one stale clientid rebuilt the WHOLE pool under a single
// fresh EXCHANGE_ID — because every session depended on the one registration.
// That coordination is now unnecessary, and its absence is the thing worth
// asserting: the other entries must keep serving on their original clientids.
func TestStaleClientIDReplacesOnlyItsOwnEntry(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(4), withForgetClientIDAfter(4))
	entries := []fakeEntry{{Name: "f", FH: "h"}}
	srv.AddTree(map[string][]fakeEntry{"/": entries})
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{
		Connections: 4, Export: "/", RetryBudget: 5, RetryBaseDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	// Record every entry's registration before the fault so the survivors can be
	// checked for having been left alone, not merely for still working.
	before := make([]*ClientRegistration, len(cl.pool))
	for i, e := range cl.pool {
		e.lifecycle.RLock()
		before[i] = e.session.reg
		e.lifecycle.RUnlock()
	}

	// withForgetClientIDAfter(4) forgets the clientid of the 4th successful
	// CREATE_SESSION, and each connection now registers its own, so the forgotten
	// clientid belongs to the LAST entry. Under the shared-registration design any
	// entry would have done, because there was only one clientid to forget.
	victim := len(cl.pool) - 1
	entry := cl.pool[victim]
	entry.lifecycle.Lock()
	oldGeneration := entry.generation
	err = entry.session.Rebuild(context.Background())
	entry.lifecycle.Unlock()
	if !isStaleClientID(err) {
		t.Fatalf("Rebuild() error = %v, want NFS4ERR_STALE_CLIENTID", err)
	}
	srv.mu.Lock()
	srv.forgetClientIDAfter = 0
	srv.mu.Unlock()

	if err := cl.rebuildEntry(context.Background(), entry, oldGeneration, before[victim]); err != nil {
		t.Fatalf("rebuild the entry whose clientid went stale: %v", err)
	}

	entry.lifecycle.RLock()
	newGeneration, newReg := entry.generation, entry.session.reg
	entry.lifecycle.RUnlock()
	if newGeneration <= oldGeneration {
		t.Errorf("entry %d generation = %d, want greater than %d", victim, newGeneration, oldGeneration)
	}
	if newReg == before[victim] {
		t.Errorf("entry %d kept the stale registration; recovery must run a fresh EXCHANGE_ID", victim)
	}

	for i := range cl.pool {
		if i == victim {
			continue
		}
		cl.pool[i].lifecycle.RLock()
		reg := cl.pool[i].session.reg
		cl.pool[i].lifecycle.RUnlock()
		if reg != before[i] {
			t.Errorf("pool entry %d was re-registered; one stale clientid must not disturb "+
				"the other entries, whose clientids are still valid", i)
		}
	}

	if err := cl.SetACL(transport.Ref{Path: "/f", FH: []byte("h")}, []byte{0, 0, 0, 0}); err != nil {
		t.Fatalf("operation after recovery: %v", err)
	}
}

// TestSecondSessionOnOneClientIDIsRefused is the regression guard for Defect 3.
// It asserts the FAKE's behaviour, not the client's, because the fake being more
// permissive than the array is precisely what let the shared-registration pool
// pass the whole suite and then fail at startup on hardware.
func TestSecondSessionOnOneClientIDIsRefused(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(4))
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	entry := cl.pool[0]
	entry.lifecycle.RLock()
	reg := entry.session.reg
	entry.lifecycle.RUnlock()

	conn, err := NewConn(context.Background(), srv.Dialer(), CurrentAuthSys())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Same registration, second session. Hardware answers NFS4ERR_INVAL.
	_, err = NewSession(context.Background(), conn, reg, 0, nil)
	if err == nil {
		t.Fatal("the fake granted a second session on one clientid; it must model the " +
			"FlashBlade restriction or the connection pool's shape is untestable")
	}
	var createErr *SessionCreateError
	if !errors.As(err, &createErr) || createErr.Status != NFS4ERR_INVAL {
		t.Fatalf("error = %v, want a SessionCreateError carrying NFS4ERR_INVAL", err)
	}
}

// TestManySessionsPerClientIDCanBeModelled proves withManySessionsPerClientID
// actually flips the behaviour, so the default is a deliberate choice rather
// than the only thing the fake can express. Without this, a bug that made the
// refusal unconditional would be invisible.
func TestManySessionsPerClientIDCanBeModelled(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(4), withManySessionsPerClientID())
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	entry := cl.pool[0]
	entry.lifecycle.RLock()
	reg := entry.session.reg
	entry.lifecycle.RUnlock()

	conn, err := NewConn(context.Background(), srv.Dialer(), CurrentAuthSys())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	session, err := NewSession(context.Background(), conn, reg, 0, nil)
	if err != nil {
		t.Fatalf("with the opt-out set, a second session on one clientid must succeed: %v", err)
	}
	defer func() { _ = session.Destroy(context.Background()) }()
}

func TestSlotsFlagIsClampedToTheGrant(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(6))
	defer srv.Close()
	var logged []string
	cl, err := newTestClientErr(t, srv, Config{
		Connections: 1, Export: "/", Slots: 128,
		Log: func(s string) { logged = append(logged, s) },
	})
	if err != nil {
		t.Fatalf("asking for more slots than the grant must clamp, not fail: %v", err)
	}
	defer cl.Close()
	// Match the clamp line specifically, not a bare "6". The gate logs the
	// observed FATTR4_MAXFILESIZE (70368744177664) through this same sink, and
	// that string contains a "6" -- so a substring test for "6" alone passes with
	// the clamp log deleted outright, which is how this assertion was vacuous as
	// first written.
	const want = "requested 128 session slots; server granted 6; using 6"
	if joined := strings.Join(logged, "\n"); !strings.Contains(joined, want) {
		t.Errorf("the clamp must be logged with the value actually used; want a line containing %q, got:\n%s", want, joined)
	}
}

func TestWorkIsSpreadAcrossConnections(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(2))
	entries := make([]fakeEntry, 64)
	for i := range entries {
		entries[i] = fakeEntry{Name: fmt.Sprintf("f%d", i), FH: fmt.Sprintf("h%d", i)}
	}
	srv.AddTree(map[string][]fakeEntry{"/": entries})
	defer srv.Close()
	cl, err := newTestClientErr(t, srv, Config{Connections: 4, Export: "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := cl.SetACL(transport.Ref{Path: fmt.Sprintf("/f%d", i), FH: []byte(fmt.Sprintf("h%d", i))}, []byte{0, 0, 0, 0}); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("%d of 64 operations failed, first: %v", len(errs), errs[0])
	}

	// Assert the pool's WIDTH before asserting the spread. Iterating
	// CallsPerConnection alone is vacuous: a single-connection client yields a
	// one-entry map whose only entry is non-zero, so the loop below passes with
	// the pool absent entirely. That is exactly how this test passed before the
	// pool existed.
	per := srv.CallsPerConnection()
	if len(per) != 4 {
		t.Fatalf("work reached %d connections, want 4; --connections is being ignored", len(per))
	}
	for conn, n := range per {
		if n == 0 {
			t.Errorf("connection %d received no work; the pool is not distributing", conn)
		}
	}
}

func TestOneDeadConnectionDoesNotKillTheRun(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withSlots(4))
	entries := make([]fakeEntry, 64)
	for i := range entries {
		entries[i] = fakeEntry{Name: fmt.Sprintf("f%d", i), FH: fmt.Sprintf("h%d", i)}
	}
	srv.AddTree(map[string][]fakeEntry{"/": entries})
	defer srv.Close()
	cl, err := newTestClientErr(t, srv, Config{
		Connections: 4, Export: "/", RetryBudget: 5, RetryBaseDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	srv.DropConnection() // kill one mid-run

	var failures int
	for i := 0; i < 40; i++ {
		if err := cl.SetACL(transport.Ref{Path: fmt.Sprintf("/f%d", i), FH: []byte(fmt.Sprintf("h%d", i))}, []byte{0, 0, 0, 0}); err != nil {
			failures++
		}
	}
	if failures != 0 {
		t.Fatalf("%d operations failed; a dropped connection must rebuild its session and replay", failures)
	}
}
