package nfs41

import (
	"errors"
	"fmt"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// StatusError wraps an NFS4 status code so callers can check specific errors
// with errors.As.
type StatusError struct {
	Op     string
	Path   string
	Status uint32
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("nfs41: %s %s: %s (%d)", e.Op, e.Path, xdr.Nfsstat4(e.Status), e.Status)
}

// IsExist reports whether the error is NFS4ERR_EXIST.
func IsExist(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status == NFS4ERR_EXIST
	}
	return false
}

// IsAccess reports whether the error is NFS4ERR_ACCESS.
func IsAccess(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status == NFS4ERR_ACCESS
	}
	return false
}

// NFSStatus returns the raw NFS4 status code. It exists so a caller that
// cannot import this package can still recognize a specific status via a
// local, unexported interface and errors.As -- internal/apply's audit-ACE
// preflight is the reason: nfs41's own test files (apply_walk_test.go,
// differential_test.go) import internal/apply, so internal/apply importing
// this package back would be a cycle.
func (e *StatusError) NFSStatus() uint32 { return e.Status }

// disposition is what to do about a failed operation. Three buckets, chosen so
// that the decision is a table lookup rather than a chain of conditionals
// scattered through the call paths.
type disposition int

const (
	// dispRetry: transient, the same call will likely succeed shortly.
	dispRetry disposition = iota
	// dispRebuild: our session state disagrees with the server's. Tear the
	// session down, CREATE_SESSION again on the same clientid, and replay.
	dispRebuild
	// dispFail: a real answer about this object. Record it and keep the run
	// alive, exactly as an errno failure is handled on the kernel path.
	dispFail
)

// String makes the disposition readable in test failures and logs. Without it
// every "want dispRebuild, got 0" message reports an integer and the reader has
// to count the iota.
func (d disposition) String() string {
	switch d {
	case dispRetry:
		return "dispRetry"
	case dispRebuild:
		return "dispRebuild"
	case dispFail:
		return "dispFail"
	default:
		return "disposition(?)"
	}
}

// classify maps a status or a transport error to a disposition.
//
// Retry is tractable here only because every operation this client issues is
// idempotent: SETATTR of a fixed ACL, READDIR at a given cookie, GETATTR,
// LOOKUP. There is no operation whose double execution corrupts anything, which
// is also why SEQUENCE sets cachethis = false and the reply cache is unused.
//
// NFS4ERR_SEQ_MISORDERED gets the same sledgehammer as a dead session rather
// than clever slot resynchronization.
//
// CORRECTED. Earlier drafts of this plan called it "unreachable given exclusive
// slot ownership". It is reachable, and the window is precise: a Call cancelled
// before write admission has already consumed the slot's seqid without the server
// ever seeing it, so the next request on that slot skips a number. Exclusive
// ownership guarantees ordering, not delivery.
//
// Task 8's slotTable.reclaim exists to close that window at the source, which is
// the right fix. Rebuilding here is the backstop for whatever it misses — if this
// fires, our sequence state is already wrong and rebuilding is the only honest
// response.
func classify(status uint32, err error) disposition {
	// A transport-level failure means the connection is gone. Rebuild rather
	// than retrying on a socket the reader has already failed every call on.
	//
	// This check is first on purpose: when the transport failed there is no
	// meaningful status to consult, so examining one would classify a dead
	// connection by whatever zero value the caller happened to pass.
	if err != nil {
		// GARBAGE_ARGS is the exception, and it has to be tested before the
		// blanket rebuild. It is a well-formed reply from a live connection, so
		// the premise above -- transport failed, no meaningful status -- does not
		// hold. Rebuilding cannot help either of its two meanings: the server
		// could not decode what this client encoded, or the COMPOUND's shape is
		// refused on this platform (RFC-Deviations.md section 4). A new session
		// would receive the identical bytes and answer identically, so a rebuild
		// buys nothing and spends the one-session-per-client-ID limit from
		// section 1 to buy it. Fail the object and let the run continue.
		if errors.Is(err, ErrGarbageArgs) {
			return dispFail
		}
		return dispRebuild
	}

	switch status {
	case NFS4ERR_DELAY, NFS4ERR_GRACE, NFS4ERR_RESOURCE, NFS4ERR_RETRY_UNCACHED_REP, NFS4ERR_REP_TOO_BIG:
		// RETRY_UNCACHED_REP is what a server sends when it declines to answer a
		// replay from its reply cache — which is every request this client makes,
		// since SEQUENCE sets cachethis = false. Resending is both correct and
		// cheap here precisely because the operations are idempotent.
		//
		// REP_TOO_BIG is here as a backstop, not as its real recovery. ReadDir is
		// the only call site that can produce a reply large enough to earn it, and
		// it handles the status itself by shrinking rd_maxcount, which is the only
		// response that actually converges. This arm covers the call sites that
		// cannot shrink anything: without it the default arm returns dispFail and
		// the object fails permanently on the first occurrence, whereas retrying
		// costs a bounded budget and is safe because every operation is idempotent.
		return dispRetry

	case NFS4ERR_BADSESSION, NFS4ERR_DEADSESSION, NFS4ERR_BADSLOT, NFS4ERR_SEQ_MISORDERED:
		return dispRebuild

	default:
		// Everything else is a real answer about this object, including the
		// four the tests name explicitly: ACCESS, PERM, NOENT, INVAL. Failing
		// closed here is deliberate. An unrecognized status retried forever
		// would stall a 1.1M-object run on one object, whereas failing it costs
		// one entry in the error count and the run continues.
		//
		// Four statuses reach this arm that are NOT meant to be handled here:
		// NFS4ERR_STALE and NFS4ERR_BADHANDLE recover by re-resolving Ref.Path
		// with a LOOKUP from root, and NFS4ERR_TOOSMALL and NFS4ERR_NOT_SAME are
		// handled inside ReadDir. Their recovery is specific enough that a shared
		// table would have to encode which call site is asking. dispFail is the
		// right fallback if a call site ever forgets one — the object fails and
		// the run continues — which is why they are deliberately absent from the
		// switch rather than mapped to dispRetry, where a dead filehandle would
		// be retried until the budget ran out.
		return dispFail
	}
}

// RetryPolicy bounds how hard a dispRetry is pursued. There is no unbounded
// loop anywhere in this client: on exhaustion the object fails and the error
// counter increments, exactly as an errno failure does on the kernel path.
type RetryPolicy struct {
	Budget    int
	BaseDelay time.Duration
}

// backoff returns the delay before the given zero-based attempt.
//
// Doubling per attempt, with the base delay as attempt 0. No jitter: the delays
// are already spread by the fact that thousands of operations are in flight and
// each hit its DELAY at a different moment, so added randomness would buy
// nothing here and would make the test above untestable.
func (p RetryPolicy) backoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	// Cap the shift so a large budget cannot overflow the duration. Overflow is
	// not merely inaccurate: shifting past the sign bit yields a negative
	// duration, and a non-positive sleep returns immediately, turning the
	// backoff into a hot spin at exactly the moment the server asked for relief.
	if attempt > 20 {
		attempt = 20
	}
	return p.BaseDelay << uint(attempt)
}
