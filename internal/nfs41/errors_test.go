package nfs41

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// TestClassificationTable is the whole point of having a table: the disposition
// for a status is a lookup a reader can check against the RFC, not a conclusion
// reassembled from conditionals spread through the call paths.
//
// The `why` column is load-bearing documentation. When one of these fires in a
// customer run, the question is always "should this have been retried", and the
// answer needs to be readable here.
func TestClassificationTable(t *testing.T) {
	cases := []struct {
		status uint32
		want   disposition
		why    string
	}{
		{NFS4ERR_DELAY, dispRetry, "server is busy; back off and try the same call"},
		{NFS4ERR_GRACE, dispRetry, "server is in its grace period"},
		{NFS4ERR_RESOURCE, dispRetry, "transient server resource shortage"},
		{NFS4ERR_RETRY_UNCACHED_REP, dispRetry, "a replay the server declined to answer from cache because we set cachethis false; resending is correct and cheap, every op here is idempotent"},
		{NFS4ERR_REP_TOO_BIG, dispRetry, "the reply exceeded ca_maxresponsesize; ReadDir shrinks rd_maxcount itself, and this arm keeps every other call site from failing an object permanently on the first occurrence"},

		{NFS4ERR_BADSESSION, dispRebuild, "our session is gone"},
		{NFS4ERR_DEADSESSION, dispRebuild, "our session is dead"},
		{NFS4ERR_BADSLOT, dispRebuild, "our slot state disagrees with the server's"},
		{NFS4ERR_SEQ_MISORDERED, dispRebuild, "reachable via the not-sent window; slotTable.reclaim closes it, this is the backstop"},

		{NFS4ERR_ACCESS, dispFail, "a real permission answer; fail the object, keep the run alive"},
		{NFS4ERR_PERM, dispFail, "a real permission answer"},
		{NFS4ERR_NOENT, dispFail, "the object is gone"},
		{NFS4ERR_INVAL, dispFail, "we sent something the server rejected; retrying sends it again"},
	}
	for _, c := range cases {
		if got := classify(c.status, nil); got != c.want {
			t.Errorf("classify(%d) = %v, want %v (%s)", c.status, got, c.want, c.why)
		}
	}
}

// TestStatusesHandledAtTheCallSiteFallThroughToFail pins the deliberate
// omissions. NFS4ERR_STALE and NFS4ERR_BADHANDLE recover by re-resolving
// Ref.Path with a LOOKUP from root, and NFS4ERR_TOOSMALL and NFS4ERR_NOT_SAME
// are handled inside ReadDir, so none of them belongs in the switch.
//
// dispFail is the correct fallback rather than an oversight: if a call site ever
// forgets to handle one, the object fails and the run continues, which is the
// same outcome as any other real answer about that object. Asserting it here
// stops someone "fixing" the omission by adding them to the retry arm, where a
// dead filehandle would be retried forever.
func TestStatusesHandledAtTheCallSiteFallThroughToFail(t *testing.T) {
	for _, tc := range []struct {
		status uint32
		name   string
		who    string
	}{
		{NFS4ERR_STALE, "NFS4ERR_STALE", "the call site, by LOOKUP from root"},
		{NFS4ERR_BADHANDLE, "NFS4ERR_BADHANDLE", "the call site, by LOOKUP from root"},
		{NFS4ERR_TOOSMALL, "NFS4ERR_TOOSMALL", "ReadDir, by growing the byte budget"},
		{NFS4ERR_NOT_SAME, "NFS4ERR_NOT_SAME", "ReadDir, by restarting the cookie chain"},
	} {
		if got := classify(tc.status, nil); got != dispFail {
			t.Errorf("classify(%s) = %v, want dispFail; recovery belongs to %s, and the fallback must not retry",
				tc.name, got, tc.who)
		}
	}
}

// TestUnrecognisedStatusFailsClosed covers the default arm's real purpose. An
// unknown status retried forever would stall a 1.1M-object run on one object;
// failing it costs one entry in the error count.
func TestUnrecognisedStatusFailsClosed(t *testing.T) {
	// Not assigned by RFC 5662, whose highest value is 10087.
	if got := classify(60000, nil); got != dispFail {
		t.Errorf("classify(60000) = %v, want dispFail for an unrecognised status", got)
	}
	// NFS4_OK should never reach classify, but if it does, treating it as
	// retryable would loop on a call that already succeeded.
	if got := classify(NFS4_OK, nil); got != dispFail {
		t.Errorf("classify(NFS4_OK) = %v, want dispFail", got)
	}
}

// TestConnectionLossRebuildsTheSession — note dispRebuild is the classification,
// not the whole recovery. Per Task 8's amendment, Session.Rebuild only re-runs
// CREATE_SESSION on a live Conn; when the Conn itself is gone the pool in Task 14
// dials a replacement and builds a fresh Session on the same ClientRegistration.
// classify does not need to distinguish the two, because the caller that acts on
// dispRebuild does: Session.Rebuild returns an error wrapping ErrConnClosed when
// the connection is the problem.
func TestConnectionLossRebuildsTheSession(t *testing.T) {
	if got := classify(0, ErrConnClosed); got != dispRebuild {
		t.Fatalf("classify(ErrConnClosed) = %v, want dispRebuild", got)
	}
}

// TestGarbageArgsFailsRatherThanRebuilding is the one error that must NOT reach
// the blanket dispRebuild above it.
//
// GARBAGE_ARGS arrives as a well-formed RPC reply on a live connection, so the
// premise the blanket rule rests on — the transport failed, there is no
// meaningful status — is false for it. Neither of its two meanings is repaired by
// a new session: either this client encoded something the server cannot decode,
// or the COMPOUND's shape is refused on this platform, which
// RFC-Deviations.md section 4 records FlashBlade doing instead of answering
// NFS4ERR_TOO_MANY_OPS. A rebuilt session would be handed the identical bytes and
// answer identically.
//
// What makes this worth a test rather than a comment is the cost of the wrong
// answer. Rebuilding runs DESTROY_SESSION + CREATE_SESSION against the
// one-session-per-client-ID limit in section 1, so a single refused shape becomes
// a session-rebuild storm — which is what abandoned two hardware runs of the
// parked batching spike, partway through, with objects already modified.
func TestGarbageArgsFailsRatherThanRebuilding(t *testing.T) {
	if got := classify(0, ErrGarbageArgs); got != dispFail {
		t.Fatalf("classify(ErrGarbageArgs) = %v, want dispFail", got)
	}
	// Wrapped exactly as rpc.go returns it, since that is the only form the
	// classifier ever sees.
	wrapped := fmt.Errorf("rpc: xid %d: %w", 42, ErrGarbageArgs)
	if got := classify(0, wrapped); got != dispFail {
		t.Fatalf("classify(wrapped ErrGarbageArgs) = %v, want dispFail", got)
	}
}

// TestATransportErrorOutranksTheStatus pins the ordering inside classify. A
// COMPOUND that failed at the transport layer has no meaningful status — the
// status argument is whatever zero value or partial read the caller had — so the
// error must win. Checking the status first would classify a dead connection as
// a retry and spin on a socket every call already fails on.
// The statuses here are deliberately ones that have their OWN arm in the switch.
// Pairing a transport error with a status that already falls through to dispFail
// proves nothing: the answer is dispRebuild either way, so the test passes even
// if the error check is moved below the switch. NFS4ERR_DELAY and
// NFS4ERR_BADSESSION are the discriminating cases — a status-first classify
// returns dispRetry for the first one, which would spin on a dead socket.
func TestATransportErrorOutranksTheStatus(t *testing.T) {
	if got := classify(NFS4ERR_DELAY, ErrConnClosed); got != dispRebuild {
		t.Errorf("classify(NFS4ERR_DELAY, ErrConnClosed) = %v, want dispRebuild; a transport error must outrank a retryable status, or the client spins on a socket every call already fails on", got)
	}
	if got := classify(NFS4ERR_GRACE, ErrNotSent); got != dispRebuild {
		t.Errorf("classify(NFS4ERR_GRACE, ErrNotSent) = %v, want dispRebuild", got)
	}
	// And a status that would already rebuild still reports rebuild, so the
	// ordering is not accidentally inverted into "error means retry".
	if got := classify(NFS4ERR_BADSESSION, ErrConnClosed); got != dispRebuild {
		t.Errorf("classify(NFS4ERR_BADSESSION, ErrConnClosed) = %v, want dispRebuild", got)
	}
	// A real answer about the object plus a dead connection is still the dead
	// connection: the status was never actually received.
	if got := classify(NFS4ERR_ACCESS, ErrConnClosed); got != dispRebuild {
		t.Errorf("classify(NFS4ERR_ACCESS, ErrConnClosed) = %v, want dispRebuild", got)
	}
}

func TestBackoffIsExponentialAndBounded(t *testing.T) {
	p := RetryPolicy{Budget: 5, BaseDelay: 100 * time.Millisecond}
	prev := time.Duration(0)
	for i := 0; i < p.Budget; i++ {
		d := p.backoff(i)
		if d <= prev {
			t.Fatalf("backoff(%d) = %v, not greater than backoff(%d) = %v", i, d, i-1, prev)
		}
		prev = d
	}
	if p.backoff(0) != 100*time.Millisecond {
		t.Fatalf("backoff(0) = %v, want the base delay", p.backoff(0))
	}
}

// TestBackoffCannotOverflowTheDuration covers the shift cap. Without it a large
// attempt number shifts a positive base delay into a negative duration, and a
// negative sleep returns immediately — turning the backoff into a hot spin at
// exactly the moment the server is asking for relief.
func TestBackoffCannotOverflowTheDuration(t *testing.T) {
	p := RetryPolicy{Budget: 100, BaseDelay: time.Millisecond}
	for _, attempt := range []int{-1, 0, 20, 21, 64, 1000} {
		if d := p.backoff(attempt); d <= 0 {
			t.Errorf("backoff(%d) = %v, want a positive delay; a non-positive sleep makes the retry a hot spin", attempt, d)
		}
	}
	// A negative attempt is clamped to attempt 0 rather than shifting right.
	if got, want := p.backoff(-1), p.backoff(0); got != want {
		t.Errorf("backoff(-1) = %v, want it clamped to backoff(0) = %v", got, want)
	}
	// The cap is a plateau, not a wrap: past it every attempt returns the same
	// bounded delay.
	if got, want := p.backoff(1000), p.backoff(20); got != want {
		t.Errorf("backoff(1000) = %v, want the capped backoff(20) = %v", got, want)
	}
}

// TestGarbageArgsReplyCarriesTheSentinel closes the loop the classifier depends
// on. TestGarbageArgsFailsRatherThanRebuilding asserts what classify does with
// ErrGarbageArgs; this asserts that a real GARBAGE_ARGS reply is what produces
// it, so the two cannot drift apart into a sentinel nothing ever returns.
//
// The reply is hand-built rather than taken from the fake server on purpose: the
// fake answers an undecodable call by dropping the connection, which its own
// comment calls "the same thing a real server's GARBAGE_ARGS-then-hangup looks
// like". It is not the same thing. FlashBlade answers with a well-formed RPC
// reply carrying GARBAGE_ARGS and keeps the connection, and that reply — not a
// hangup — is what the sequence accounting and the classifier both turn on.
func TestGarbageArgsReplyCarriesTheSentinel(t *testing.T) {
	var reply []byte
	for _, word := range []uint32{
		7,                        // xid
		uint32(xdr.REPLY),        //
		uint32(xdr.MSG_ACCEPTED), //
		uint32(xdr.AUTH_NONE),    // verifier flavour
		0,                        // verifier length
		uint32(xdr.GARBAGE_ARGS), // accept status
	} {
		reply = binary.BigEndian.AppendUint32(reply, word)
	}

	_, err := parseAcceptedReply(reply)
	if err == nil {
		t.Fatal("parseAcceptedReply accepted a GARBAGE_ARGS reply")
	}
	if !errors.Is(err, ErrGarbageArgs) {
		t.Fatalf("GARBAGE_ARGS reply produced %v, which does not match ErrGarbageArgs; "+
			"the classifier and the slot accounting both branch on errors.Is and would "+
			"fall through to a session rebuild", err)
	}
	// The xid must survive into the message: a shape refusal has to be
	// attributable to a call, and there is nothing else in the reply to name it.
	if !strings.Contains(err.Error(), "xid 7") {
		t.Errorf("error %q does not name the xid", err.Error())
	}
}
