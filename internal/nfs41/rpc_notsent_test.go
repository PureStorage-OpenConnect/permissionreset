package nfs41

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// The sent/not-sent distinction exists so a caller holding sequence state can
// tell whether the server consumed a slot's seqid. Getting it wrong in either
// direction is expensive: treating "sent" as "not sent" replays a request that
// already executed, and treating "not sent" as "sent" leaves a gap in the slot's
// sequence and the next request earns NFS4ERR_SEQ_MISORDERED.
//
// These live in their own file because rpc_test.go is the task's frozen
// specification. They are additions, not edits to it.

// TestCancelBeforeWriteAdmissionReportsNotSent covers the case the plan and an
// earlier revision of Call's own doc comment both got wrong. Nothing drains
// c.writes, so the call blocks in the admission select and the record provably
// never reaches the wire.
func TestCancelBeforeWriteAdmissionReportsNotSent(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()

	c := newConnOnWire(cli, AuthSys{Machine: "test"})
	defer c.Close()

	// net.Pipe is unbuffered and no one reads srv, so the writer goroutine wedges
	// on its first write and admission for this call never happens.
	ctx0, cancel0 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel0()
	go c.Call(ctx0, 100003, 4, 1, []byte("wedge-the-writer"))
	time.Sleep(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Call(ctx, 100003, 4, 1, []byte("never-admitted"))

	if err == nil {
		t.Fatal("want an error, got nil")
	}
	if !errors.Is(err, ErrNotSent) {
		t.Errorf("err = %v, want it to satisfy errors.Is(err, ErrNotSent); a caller "+
			"would quarantine a slot it did not need to, or fail to quarantine one it did", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the underlying cause preserved", err)
	}
}

// TestCancelAfterWriteAdmissionDoesNotReportNotSent is the other half. The
// server reads the record and then says nothing, so the call is cancelled while
// awaiting a reply — the request is on the wire and may have executed.
func TestCancelAfterWriteAdmissionDoesNotReportNotSent(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()

	read := make(chan struct{})
	go func() {
		if _, err := readRecord(srv); err == nil {
			close(read)
		}
	}()

	c := newConnOnWire(cli, AuthSys{Machine: "test"})
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := c.Call(ctx, 100003, 4, 1, []byte("sent-then-silent"))

	select {
	case <-read:
	default:
		t.Fatal("the server never read the record; this test did not exercise the post-admission path")
	}
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	if errors.Is(err, ErrNotSent) {
		t.Errorf("err = %v, must NOT satisfy ErrNotSent: the record reached the wire, "+
			"so the seqid was legitimately consumed and replaying it is unsafe", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
}

// TestOversizeCallReportsNotSent pins the third not-sent path: buildCall
// rejecting a request larger than the record cap, before any I/O.
func TestOversizeCallReportsNotSent(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	go func() {
		for {
			if _, err := readRecord(srv); err != nil {
				return
			}
		}
	}()

	c := newConnOnWire(cli, AuthSys{Machine: "test"})
	defer c.Close()

	_, err := c.Call(context.Background(), 100003, 4, 1, make([]byte, maxRecordSize+1))
	if err == nil {
		t.Fatal("want an error for an oversize call, got nil")
	}
	if !errors.Is(err, ErrNotSent) {
		t.Errorf("err = %v, want ErrNotSent: nothing was written", err)
	}
}

// TestNotSentLeavesNoPendingWaiter guards the leak that would otherwise hide
// behind the new error wrapping.
func TestNotSentLeavesNoPendingWaiter(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()

	c := newConnOnWire(cli, AuthSys{Machine: "test"})
	defer c.Close()

	ctx0, cancel0 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel0()
	go c.Call(ctx0, 100003, 4, 1, []byte("wedge"))
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < 25; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		c.Call(ctx, 100003, 4, 1, []byte("x"))
		cancel()
	}

	c.mu.Lock()
	n := len(c.pending)
	c.mu.Unlock()
	// The one wedged call may still be registered; the 25 cancelled ones must not.
	if n > 1 {
		t.Errorf("pending holds %d waiters after 25 not-sent cancellations, want at most 1", n)
	}
}

// TestRecordMarkerIsNotSentOnAnAdmissionCancel is a byte-level check that
// "not sent" means it: the server must see nothing at all.
func TestRecordMarkerIsNotSentOnAnAdmissionCancel(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()

	c := newConnOnWire(cli, AuthSys{Machine: "test"})
	defer c.Close()

	ctx0, cancel0 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel0()
	go c.Call(ctx0, 100003, 4, 1, []byte("first-wedges-the-writer"))
	time.Sleep(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Call(ctx, 100003, 4, 1, []byte("SECOND")); !errors.Is(err, ErrNotSent) {
		t.Fatalf("setup: want ErrNotSent, got %v", err)
	}

	// Drain whatever did reach the wire. Only the first call's record may appear.
	srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	rec, err := readRecord(srv)
	if err != nil {
		return // nothing arrived at all, which also satisfies the claim
	}
	if len(rec) >= 4 {
		// The second call would have had the next xid. Its absence is the point.
		if xid := binary.BigEndian.Uint32(rec[:4]); xid != 1 {
			t.Errorf("first record on the wire has xid %d, want 1; a not-sent call reached the server", xid)
		}
	}
	srv.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if extra, err := readRecord(srv); err == nil {
		t.Errorf("a second record reached the server (%d bytes); the cancelled call was not-sent", len(extra))
	}
}
