package nfs41

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// acceptedReply builds the RFC 5531 section 9 reply a server sends for a call it
// accepted and executed successfully:
//
//	xid          uint32
//	mtype        uint32 = REPLY (1)
//	reply_stat   uint32 = MSG_ACCEPTED (0)
//	verf.flavor  uint32 = AUTH_NONE (0)
//	verf.length  uint32 = 0
//	accept_stat  uint32 = SUCCESS (0)
//	body         opaque, already-encoded results
//
// Six words of header, then the body verbatim. No record marker — the caller
// wraps it in recordMark, so a test can frame it wrongly on purpose.
func acceptedReply(xid uint32, body []byte) []byte {
	out := make([]byte, 0, 24+len(body))
	for _, w := range []uint32{xid, 1, 0, 0, 0, 0} {
		out = binary.BigEndian.AppendUint32(out, w)
	}
	return append(out, body...)
}

func TestRecordMarkFramesOneFragment(t *testing.T) {
	got := recordMark(make([]byte, 100))
	want := uint32(0x80000000 | 100)
	if binary.BigEndian.Uint32(got[:4]) != want {
		t.Fatalf("marker = %#08x, want %#08x", binary.BigEndian.Uint32(got[:4]), want)
	}
	if len(got) != 104 {
		t.Fatalf("len = %d, want 104", len(got))
	}
}

func TestReadRecordReassemblesFragments(t *testing.T) {
	var buf bytes.Buffer
	// Two fragments: 4 bytes, then a final 3 bytes.
	binary.Write(&buf, binary.BigEndian, uint32(4))
	buf.Write([]byte{1, 2, 3, 4})
	binary.Write(&buf, binary.BigEndian, uint32(0x80000000|3))
	buf.Write([]byte{5, 6, 7})

	got, err := readRecord(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3, 4, 5, 6, 7}) {
		t.Fatalf("got %v, want [1 2 3 4 5 6 7]", got)
	}
}

func TestReadRecordRejectsAnAbsurdFragment(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(0x80000000|(maxRecordSize+1)))
	if _, err := readRecord(&buf); err == nil {
		t.Fatal("want an error for a fragment larger than maxRecordSize, got nil")
	}
}

// TestCallDemuxesOutOfOrderReplies is the reason the reader is a separate
// goroutine: with many slots in flight, replies do not arrive in call order.
func TestCallDemuxesOutOfOrderReplies(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()

	// Server: read two calls, reply to the second one first.
	var xids []uint32
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			rec, err := readRecord(srv)
			if err != nil {
				return
			}
			mu.Lock()
			xids = append(xids, binary.BigEndian.Uint32(rec[:4]))
			mu.Unlock()
		}
		mu.Lock()
		second, first := xids[1], xids[0]
		mu.Unlock()
		srv.Write(recordMark(acceptedReply(second, []byte("B"))))
		time.Sleep(10 * time.Millisecond)
		srv.Write(recordMark(acceptedReply(first, []byte("A"))))
	}()

	c := newConnOnWire(cli, AuthSys{Machine: "test"})
	defer c.Close()

	type res struct {
		body []byte
		err  error
	}
	r1 := make(chan res, 1)
	r2 := make(chan res, 1)
	ctx := context.Background()
	go func() { b, e := c.Call(ctx, 100003, 4, 1, []byte("one")); r1 <- res{b, e} }()
	time.Sleep(5 * time.Millisecond)
	go func() { b, e := c.Call(ctx, 100003, 4, 1, []byte("two")); r2 <- res{b, e} }()

	a := <-r1
	b := <-r2
	if a.err != nil || b.err != nil {
		t.Fatalf("errors: %v %v", a.err, b.err)
	}
	if !bytes.Equal(a.body, []byte("A")) {
		t.Errorf("first call got %q, want A — replies were demuxed by arrival order, not by xid", a.body)
	}
	if !bytes.Equal(b.body, []byte("B")) {
		t.Errorf("second call got %q, want B", b.body)
	}
	<-done
}

func TestCallHonoursContextDeadline(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	go io.Copy(io.Discard, srv) // accept the call, never reply

	c := newConnOnWire(cli, AuthSys{Machine: "test"})
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Call(ctx, 100003, 4, 1, nil); err == nil {
		t.Fatal("want a deadline error, got nil")
	}
}

func TestPendingCallsAreReleasedOnConnectionLoss(t *testing.T) {
	srv, cli := net.Pipe()
	go io.Copy(io.Discard, srv)

	c := newConnOnWire(cli, AuthSys{Machine: "test"})
	errc := make(chan error, 1)
	go func() { _, err := c.Call(context.Background(), 100003, 4, 1, nil); errc <- err }()
	time.Sleep(20 * time.Millisecond)
	srv.Close()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("want an error after the peer closed, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Call hung after the connection dropped; the reader must fail every pending call")
	}
}

// countingConn counts Write calls so a test can tell one write(2) per record
// from one per batch. It also records the bytes, because the interesting failure
// of a gathered write is not a lost record but a mangled boundary between two.
type countingConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
	body   []byte

	// hold, when non-nil, blocks the first Write until it is closed. That is what
	// makes gathering deterministic rather than a race: writeLoop is parked inside
	// its first write while the remaining senders queue behind it, so its next
	// pass has something to gather.
	hold     chan struct{}
	holdOnce sync.Once
}

func (c *countingConn) Write(b []byte) (int, error) {
	if c.hold != nil {
		c.holdOnce.Do(func() { <-c.hold })
	}
	c.mu.Lock()
	c.writes++
	c.body = append(c.body, b...)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *countingConn) counts() (int, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, bytes.Clone(c.body)
}

// TestConcurrentCallsShareOneWrite pins the gathering in writeLoop.
//
// Both halves matter. Without the count, a writeLoop that quietly stopped
// gathering would pass every other test in this file -- the records still go out
// and the replies still demux, just one syscall at a time, which is precisely
// the cost this change exists to remove. Without the byte comparison, a batch
// that dropped or truncated a record on the way into net.Buffers would look like
// a successful optimisation until a server rejected the garbage.
//
// net.Pipe cannot do writev, so net.Buffers falls back to sequential writes
// through countingConn.Write -- which is why the assertion counts batches at the
// point the batching decision is made, not Write calls on the connection. The
// connection is still wrapped, for the bytes it captures.
//
// GATHERING HAS TO BE FORCED, NOT HOPED FOR. writeLoop gathers whatever is parked
// on an unbuffered channel at the instant it looks, so releasing N callers
// together and asserting a gather occurred is a bet on the scheduler: on a
// lightly loaded multi-core machine each sender hands off its record before the
// next arrives, every record goes out alone, and "writeLoop is not gathering"
// fires against a writeLoop that is working correctly. This test failed five runs
// in six that way, which made it worse than no test -- it trained the reader to
// re-run until green.
//
// So the first Write is held. writeLoop takes one record, blocks inside the
// write, and the other callers pile onto the channel behind it; releasing the
// hold lets its next pass gather them. The assertion is then a property of
// writeLoop rather than of the scheduler.
func TestConcurrentCallsShareOneWrite(t *testing.T) {
	const calls = 8

	srv, cli := net.Pipe()
	defer srv.Close()

	// The server reads every call, then replies to all of them. Replying only
	// after all 8 have arrived is what guarantees the senders pile up on the
	// unbuffered channel, which is the condition writeLoop gathers under.
	var mu sync.Mutex
	var xids []uint32
	read := make(chan struct{})
	go func() {
		for i := 0; i < calls; i++ {
			rec, err := readRecord(srv)
			if err != nil {
				return
			}
			mu.Lock()
			xids = append(xids, binary.BigEndian.Uint32(rec[:4]))
			mu.Unlock()
		}
		close(read)
		mu.Lock()
		defer mu.Unlock()
		for _, xid := range xids {
			srv.Write(recordMark(acceptedReply(xid, []byte("ok"))))
		}
	}()

	counting := &countingConn{Conn: cli, hold: make(chan struct{})}
	c := newConnOnWire(counting, AuthSys{Machine: "test"})
	defer c.Close()

	errs := make(chan error, calls)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < calls; i++ {
		go func() {
			start.Wait()
			_, err := c.Call(context.Background(), 100003, 4, 1, []byte("body"))
			errs <- err
		}()
	}
	// Releasing the callers together is what puts several of them on the channel
	// at once; staggered sends would each be written alone and prove nothing.
	start.Done()

	// Wait for every caller to reach the hand-off, then let the held first write
	// proceed. queuedForWrite counts arrivals at the select, so at this point one
	// record is with writeLoop and the rest are parked behind it -- exactly the
	// condition writeLoop gathers under. A sender counted but not yet parked is
	// harmless: it is simply not in the batch, and the assertion needs some
	// gathering, not maximal gathering.
	deadline := time.Now().Add(10 * time.Second)
	for c.queuedForWrite.Load() < calls {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d callers reached the write hand-off",
				c.queuedForWrite.Load(), calls)
		}
		runtime.Gosched()
	}
	close(counting.hold)

	for i := 0; i < calls; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	<-read

	_, body := counting.counts()
	batches, records := c.batches.Load(), c.recordsWritten.Load()
	if records != calls {
		t.Fatalf("writeLoop handled %d records, want %d", records, calls)
	}
	if batches >= records {
		t.Errorf("%d records went out in %d batches: writeLoop is not gathering",
			records, batches)
	}

	// Every record must still be present and intact. Walking the written bytes
	// as records proves the boundaries survived: a truncated or doubled record
	// makes the walk land off the end.
	found := 0
	for off := 0; off < len(body); found++ {
		if len(body)-off < 4 {
			t.Fatalf("record %d: %d trailing bytes, not a record marker", found, len(body)-off)
		}
		mark := binary.BigEndian.Uint32(body[off : off+4])
		length := int(mark & 0x7fffffff)
		if mark&0x80000000 == 0 {
			t.Fatalf("record %d is not marked last; the writer must not fragment", found)
		}
		off += 4 + length
		if off > len(body) {
			t.Fatalf("record %d claims %d bytes but only %d remain", found, length, len(body)-off+length)
		}
	}
	if found != calls {
		t.Errorf("wrote %d records, want %d", found, calls)
	}
}
