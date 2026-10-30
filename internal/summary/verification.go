package summary

import (
	"encoding/json"
	"errors"
	"fmt"
)

// A write the server accepted, an NFS-visible ACL that equals the spec, a raw
// SMB descriptor that equals its source, and an audit event that reached a
// collector are four different claims. This file is the one place that names
// them, says what each proves and what it does not, and decides when a run may
// call itself verified. Every producer -- this CLI, the SMB companion, a later
// comparison tool, the GUI -- states its evidence in these terms rather than
// inventing its own.

// Dimension names one verification claim. The set is closed: Validate rejects
// a name it does not know, so a producer cannot coin a stronger-sounding claim.
type Dimension string

const (
	// DimWriteAccepted: the server returned success for the write. It says
	// nothing about what was stored.
	DimWriteAccepted Dimension = "write_accepted"
	// DimNFSSpecMatch: the ACL read back over NFS equals what the spec asks for.
	DimNFSSpecMatch Dimension = "nfs_spec_match"
	// DimSMBDescriptorFidelity: the raw SMB security descriptor equals the
	// expected one, read from SMB (PS-06).
	DimSMBDescriptorFidelity Dimension = "smb_descriptor_fidelity"
	// DimSACLRetention: audit ACEs present before the run are still present.
	DimSACLRetention Dimension = "sacl_retention"
	// DimEffectiveAccess: a principal's actual access, as the server evaluates it.
	DimEffectiveAccess Dimension = "effective_access"
	// DimAuditEventDelivery: an audited access produced an event at a collector.
	DimAuditEventDelivery Dimension = "audit_event_delivery"
)

// claim is what a dimension proves and, as importantly, the stronger claim it
// is routinely mistaken for.
type claim struct {
	proves, doesNotProve string
}

var claims = map[Dimension]claim{
	DimWriteAccepted:         {"the server accepted the write without error", "what the server stored; read-back is nfs_spec_match"},
	DimNFSSpecMatch:          {"the NFS-visible ACL equals the spec", "SMB descriptor fidelity or effective access"},
	DimSMBDescriptorFidelity: {"the raw SMB descriptor bytes equal the expected descriptor", "effective access; descriptor equality is not an access check"},
	DimSACLRetention:         {"audit ACEs present before the run are still present", "that audit events are generated or delivered"},
	DimEffectiveAccess:       {"the server grants the expected access to the tested principals", "access for principals that were not tested"},
	DimAuditEventDelivery:    {"audited access produced events at the collector", "events for objects or principals that were not exercised"},
}

// AllDimensions is every dimension, in the order a summary lists them.
var AllDimensions = []Dimension{
	DimWriteAccepted, DimNFSSpecMatch, DimSMBDescriptorFidelity,
	DimSACLRetention, DimEffectiveAccess, DimAuditEventDelivery,
}

// State is the outcome of one dimension.
type State string

const (
	StateMatched    State = "matched"     // every eligible object was checked and matched
	StateMismatched State = "mismatched"  // at least one checked object did not match
	StateUnreadable State = "unreadable"  // at least one eligible object could not be read
	StateNotChecked State = "not_checked" // the check did not run
	StateSampled    State = "sampled"     // a sample was checked and matched; the rest was not
	StateIncomplete State = "incomplete"  // the check ran but did not cover its scope
)

// Verdict is the run's overall verification outcome.
type Verdict string

const (
	// VerdictVerified: every required dimension matched with full coverage.
	VerdictVerified Verdict = "verified"
	// VerdictFailed: a required dimension found a mismatch.
	VerdictFailed Verdict = "failed"
	// VerdictUnverified: a required dimension is unreadable, incomplete,
	// sampled or not checked. Not a failure, and never a pass.
	VerdictUnverified Verdict = "unverified"
	// VerdictNotRequested: the run selected no verification. A repair run
	// lands here: a successful write is not verification.
	VerdictNotRequested Verdict = "not_requested"
)

// Coverage is a dimension's object accounting. Eligible is the objects in this
// dimension's scope that were enumerated; Matched + Mismatched + Unreadable +
// NotChecked equals it. When EnumerationComplete is false, Eligible counts only
// what was reached: nothing here estimates the size of a subtree that was never
// listed.
type Coverage struct {
	Eligible            int64  `json:"eligible"`
	Matched             int64  `json:"matched"`
	Mismatched          int64  `json:"mismatched"`
	Unreadable          int64  `json:"unreadable"`
	NotChecked          int64  `json:"not_checked"`
	EnumerationComplete bool   `json:"enumeration_complete"`
	Sampled             bool   `json:"sampled,omitempty"`
	SampleRule          string `json:"sample_rule,omitempty"`
}

// DimensionResult is one dimension's outcome. Proves and DoesNotProve are
// filled from the fixed claim table, never by the producer.
type DimensionResult struct {
	Name         Dimension `json:"name"`
	Required     bool      `json:"required"`
	State        State     `json:"state"`
	Proves       string    `json:"proves"`
	DoesNotProve string    `json:"does_not_prove"`
	Coverage     Coverage  `json:"coverage"`
	Note         string    `json:"note,omitempty"`
}

// Verification is the verdict and the per-dimension evidence behind it. Its
// size is fixed by the dimension list, not by the object count.
type Verification struct {
	Verdict    Verdict           `json:"verdict"`
	Dimensions []DimensionResult `json:"dimensions"`
}

// Accounting reconciles the run's objects. Included is what enumeration reached
// inside scope; Excluded is what an exclude pattern removed (a directory counts
// once, its subtree is never listed). Attempted = Succeeded + Failed are the
// writes sent; a dry run attempts nothing. Unverified is Included minus what a
// required dimension checked, so a repair run with no verification reports
// every object here.
type Accounting struct {
	Included            int64 `json:"included"`
	Excluded            int64 `json:"excluded"`
	Attempted           int64 `json:"attempted"`
	Succeeded           int64 `json:"succeeded"`
	Failed              int64 `json:"failed"`
	Unverified          int64 `json:"unverified"`
	EnumerationComplete bool  `json:"enumeration_complete"`
}

// ShardRef points at a file of per-object records. The manifest holds these
// references, never the records, so its size tracks shards and not objects.
type ShardRef struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Records int64  `json:"records"`
}

// DeriveState computes a dimension's state from its coverage. A mismatch
// outranks everything because it is a definite finding; after that, anything
// short of full, unsampled coverage keeps the dimension from matching.
func DeriveState(c Coverage) State {
	checked := c.Matched + c.Mismatched + c.Unreadable
	switch {
	case c.Mismatched > 0:
		return StateMismatched
	case c.Unreadable > 0:
		return StateUnreadable
	case checked == 0:
		return StateNotChecked
	case !c.EnumerationComplete || c.NotChecked > 0:
		if c.Sampled && c.EnumerationComplete {
			return StateSampled
		}
		return StateIncomplete
	case c.Sampled:
		return StateSampled
	default:
		return StateMatched
	}
}

// NewDimension builds a result with its state derived and its claim text
// taken from the table.
func NewDimension(d Dimension, required bool, c Coverage) DimensionResult {
	cl := claims[d]
	return DimensionResult{Name: d, Required: required, State: DeriveState(c), Proves: cl.proves, DoesNotProve: cl.doesNotProve, Coverage: c}
}

// NotChecked is a dimension the run did not exercise. Listing it, rather than
// leaving it out, is what stops a reader from assuming it passed.
func NotChecked(d Dimension) DimensionResult {
	return NewDimension(d, false, Coverage{})
}

// DeriveVerdict computes the overall verdict from the required dimensions.
func DeriveVerdict(dims []DimensionResult) Verdict {
	v := VerdictNotRequested
	for _, d := range dims {
		if !d.Required {
			continue
		}
		switch d.State {
		case StateMismatched:
			return VerdictFailed
		case StateMatched:
			if v == VerdictNotRequested {
				v = VerdictVerified
			}
		default:
			v = VerdictUnverified
		}
	}
	return v
}

// NewVerification lists every dimension -- the supplied results, and
// not_checked for the rest -- and derives the verdict.
func NewVerification(results ...DimensionResult) Verification {
	byName := make(map[Dimension]DimensionResult, len(results))
	for _, r := range results {
		byName[r.Name] = r
	}
	dims := make([]DimensionResult, 0, len(AllDimensions))
	for _, d := range AllDimensions {
		if r, ok := byName[d]; ok {
			dims = append(dims, r)
		} else {
			dims = append(dims, NotChecked(d))
		}
	}
	return Verification{Verdict: DeriveVerdict(dims), Dimensions: dims}
}

// Validate checks a verification record for internal consistency: known
// dimensions with their fixed claim text, coverage that adds up, states that
// follow from coverage, and a verdict that follows from the states. A record
// that calls itself verified while a required check is unreadable, incomplete
// or absent fails here.
func (v Verification) Validate() error {
	var errs []error
	seen := map[Dimension]bool{}
	for _, d := range v.Dimensions {
		cl, ok := claims[d.Name]
		if !ok {
			errs = append(errs, fmt.Errorf("unknown dimension %q", d.Name))
			continue
		}
		if seen[d.Name] {
			errs = append(errs, fmt.Errorf("dimension %q listed twice", d.Name))
		}
		seen[d.Name] = true
		if d.Proves != cl.proves || d.DoesNotProve != cl.doesNotProve {
			errs = append(errs, fmt.Errorf("dimension %q: claim text differs from the fixed claim", d.Name))
		}
		c := d.Coverage
		if c.Eligible < 0 || c.Matched < 0 || c.Mismatched < 0 || c.Unreadable < 0 || c.NotChecked < 0 {
			errs = append(errs, fmt.Errorf("dimension %q: negative count", d.Name))
		}
		if c.Matched+c.Mismatched+c.Unreadable+c.NotChecked != c.Eligible {
			errs = append(errs, fmt.Errorf("dimension %q: matched+mismatched+unreadable+not_checked = %d, eligible = %d",
				d.Name, c.Matched+c.Mismatched+c.Unreadable+c.NotChecked, c.Eligible))
		}
		if want := DeriveState(c); d.State != want {
			errs = append(errs, fmt.Errorf("dimension %q: state %q, coverage gives %q", d.Name, d.State, want))
		}
	}
	for _, d := range AllDimensions {
		if !seen[d] {
			errs = append(errs, fmt.Errorf("dimension %q missing; list it as not_checked", d))
		}
	}
	if want := DeriveVerdict(v.Dimensions); v.Verdict != want {
		errs = append(errs, fmt.Errorf("verdict %q, dimensions give %q", v.Verdict, want))
	}
	return errors.Join(errs...)
}

// Validate checks that the accounting reconciles.
func (a Accounting) Validate() error {
	var errs []error
	if a.Included < 0 || a.Excluded < 0 || a.Attempted < 0 || a.Succeeded < 0 || a.Failed < 0 || a.Unverified < 0 {
		errs = append(errs, errors.New("accounting: negative count"))
	}
	if a.Succeeded+a.Failed != a.Attempted {
		errs = append(errs, fmt.Errorf("accounting: succeeded+failed = %d, attempted = %d", a.Succeeded+a.Failed, a.Attempted))
	}
	if a.Attempted > a.Included {
		errs = append(errs, fmt.Errorf("accounting: attempted %d exceeds included %d", a.Attempted, a.Included))
	}
	if a.Unverified > a.Included {
		errs = append(errs, fmt.Errorf("accounting: unverified %d exceeds included %d", a.Unverified, a.Included))
	}
	return errors.Join(errs...)
}

// Decode reads a summary of any supported schema version and validates it.
// A version 1 summary predates the verification record and carries no
// unreadable count, so it migrates to unverified at best: a v1 validate run
// with mismatches is failed, anything else is unverified, never verified.
func Decode(b []byte) (*RunSummary, error) {
	var s RunSummary
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("decode summary: %w", err)
	}
	switch s.SchemaVersion {
	case 1:
		migrateV1(&s)
	case SchemaVersion:
	default:
		return nil, fmt.Errorf("summary schema_version %d is not supported (want 1 or %d)", s.SchemaVersion, SchemaVersion)
	}
	if err := s.Check(); err != nil {
		return nil, err
	}
	return &s, nil
}

func migrateV1(s *RunSummary) {
	complete := s.Errors.Walk == 0 && !s.Interrupted
	s.Accounting = Accounting{
		Included: s.Objects.Enumerated, Excluded: s.Objects.Excluded,
		Unverified: s.Objects.Enumerated, EnumerationComplete: complete,
	}
	if !s.Options.DryRun && !s.Validate {
		s.Accounting.Attempted = s.Objects.Applied + s.Objects.Failed
		s.Accounting.Succeeded = s.Objects.Applied
		s.Accounting.Failed = s.Objects.Failed
	}
	var results []DimensionResult
	if s.Validate {
		// v1 folded unreadable objects into errors.total with no split, so the
		// unchecked remainder cannot be attributed and stays not_checked.
		eligible := s.Objects.Enumerated - s.Objects.Symlinks
		c := Coverage{Eligible: eligible, Matched: s.Objects.Match, Mismatched: s.Objects.Mismatch, EnumerationComplete: false}
		c.NotChecked = max(0, eligible-c.Matched-c.Mismatched)
		c.Eligible = c.Matched + c.Mismatched + c.NotChecked
		d := NewDimension(DimNFSSpecMatch, true, c)
		d.Note = "migrated from schema 1: unreadable objects were not recorded separately"
		results = append(results, d)
		s.Accounting.Unverified = max(0, s.Objects.Enumerated-c.Matched-c.Mismatched)
	}
	s.Verification = NewVerification(results...)
	s.SchemaVersion = SchemaVersion
}

// Check checks the summary's verification and accounting records.
func (s *RunSummary) Check() error {
	return errors.Join(s.Verification.Validate(), s.Accounting.Validate())
}
