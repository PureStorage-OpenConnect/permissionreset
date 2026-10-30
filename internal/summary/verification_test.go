package summary

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata fixtures")

func TestDeriveStateCoversEveryState(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Coverage
		want State
	}{
		{"all matched", Coverage{Eligible: 5, Matched: 5, EnumerationComplete: true}, StateMatched},
		{"one mismatch", Coverage{Eligible: 5, Matched: 4, Mismatched: 1, EnumerationComplete: true}, StateMismatched},
		{"mismatch beats unreadable", Coverage{Eligible: 5, Matched: 3, Mismatched: 1, Unreadable: 1, EnumerationComplete: true}, StateMismatched},
		{"one unreadable", Coverage{Eligible: 5, Matched: 4, Unreadable: 1, EnumerationComplete: true}, StateUnreadable},
		{"never ran", Coverage{}, StateNotChecked},
		{"nothing checked", Coverage{Eligible: 5, NotChecked: 5, EnumerationComplete: true}, StateNotChecked},
		{"sample matched", Coverage{Eligible: 5, Matched: 2, NotChecked: 3, EnumerationComplete: true, Sampled: true, SampleRule: "every 2nd"}, StateSampled},
		{"partly checked", Coverage{Eligible: 5, Matched: 2, NotChecked: 3, EnumerationComplete: true}, StateIncomplete},
		{"walk failed", Coverage{Eligible: 5, Matched: 5}, StateIncomplete},
		{"sample over partial walk", Coverage{Eligible: 5, Matched: 2, NotChecked: 3, Sampled: true}, StateIncomplete},
	} {
		if got := DeriveState(tc.c); got != tc.want {
			t.Errorf("%s: DeriveState = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// fixtures is one summary per outcome. Each is written to testdata/valid and
// must decode to the verdict named here.
func fixtures() map[string]struct {
	s    *RunSummary
	want Verdict
} {
	base := func(acc Accounting, v Verification) *RunSummary {
		s := sample()
		s.SchemaVersion = SchemaVersion
		s.Accounting, s.Verification = acc, v
		return s
	}
	full := Coverage{Eligible: 10, Matched: 10, EnumerationComplete: true}
	req := func(c Coverage) Verification {
		return NewVerification(NewDimension(DimNFSSpecMatch, true, c))
	}
	acc := func(unverified int64, complete bool) Accounting {
		return Accounting{Included: 10, Unverified: unverified, EnumerationComplete: complete}
	}
	return map[string]struct {
		s    *RunSummary
		want Verdict
	}{
		"matched":     {base(acc(0, true), req(full)), VerdictVerified},
		"mismatched":  {base(acc(0, true), req(Coverage{Eligible: 10, Matched: 9, Mismatched: 1, EnumerationComplete: true})), VerdictFailed},
		"unreadable":  {base(acc(1, true), req(Coverage{Eligible: 10, Matched: 9, Unreadable: 1, EnumerationComplete: true})), VerdictUnverified},
		"not_checked": {base(acc(10, true), req(Coverage{Eligible: 10, NotChecked: 10, EnumerationComplete: true})), VerdictUnverified},
		"sampled":     {base(acc(7, true), req(Coverage{Eligible: 10, Matched: 3, NotChecked: 7, EnumerationComplete: true, Sampled: true, SampleRule: "hash(path) mod 3 == 0"})), VerdictUnverified},
		"incomplete":  {base(acc(0, false), req(Coverage{Eligible: 10, Matched: 10})), VerdictUnverified},
		"repair_only": {base(Accounting{Included: 10, Attempted: 10, Succeeded: 9, Failed: 1, Unverified: 10, EnumerationComplete: true},
			NewVerification(NewDimension(DimWriteAccepted, false, Coverage{Eligible: 10, Matched: 9, Mismatched: 1, EnumerationComplete: true}))), VerdictNotRequested},
		// A required dimension that matched does not cover one that did not run.
		"required_omitted": {base(acc(0, true), NewVerification(
			NewDimension(DimNFSSpecMatch, true, full),
			NewDimension(DimSMBDescriptorFidelity, true, Coverage{}))), VerdictUnverified},
	}
}

func TestFixturesDecodeToTheirVerdict(t *testing.T) {
	dir := filepath.Join("testdata", "valid")
	for name, f := range fixtures() {
		path := filepath.Join(dir, name+".json")
		if *update {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := f.s.WriteFile(path); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test -update to regenerate)", name, err)
		}
		got, err := Decode(b)
		if err != nil {
			t.Errorf("%s: Decode: %v", name, err)
			continue
		}
		if got.Verification.Verdict != f.want {
			t.Errorf("%s: verdict %q, want %q", name, got.Verification.Verdict, f.want)
		}
	}
}

// invalid is a forged or inconsistent summary per rule Validate enforces,
// each derived from the clean "matched" fixture.
func invalid() map[string]struct {
	mutate func(m map[string]any)
	errSub string
} {
	dim := func(m map[string]any, i int) map[string]any {
		return m["verification"].(map[string]any)["dimensions"].([]any)[i].(map[string]any)
	}
	cov := func(m map[string]any, i int) map[string]any { return dim(m, i)["coverage"].(map[string]any) }
	const spec = 1 // nfs_spec_match's index in AllDimensions
	return map[string]struct {
		mutate func(m map[string]any)
		errSub string
	}{
		"verified_with_unreadable": {func(m map[string]any) {
			c := cov(m, spec)
			c["matched"], c["unreadable"] = 9.0, 1.0
		}, "state \"matched\", coverage gives \"unreadable\""},
		"verified_while_incomplete": {func(m map[string]any) {
			cov(m, spec)["enumeration_complete"] = false
		}, "coverage gives \"incomplete\""},
		"verified_with_required_not_run": {func(m map[string]any) {
			dim(m, 2)["required"] = true
		}, "verdict \"verified\", dimensions give \"unverified\""},
		"dimension_omitted": {func(m map[string]any) {
			v := m["verification"].(map[string]any)
			v["dimensions"] = v["dimensions"].([]any)[:5]
		}, "\"audit_event_delivery\" missing"},
		"descriptor_claims_effective_access": {func(m map[string]any) {
			dim(m, 2)["proves"] = "effective access"
		}, "claim text differs"},
		"retention_claims_delivery": {func(m map[string]any) {
			dim(m, 3)["does_not_prove"] = ""
		}, "claim text differs"},
		"unknown_dimension": {func(m map[string]any) {
			dim(m, 0)["name"] = "fully_verified"
		}, "unknown dimension"},
		"coverage_does_not_add_up": {func(m map[string]any) {
			cov(m, spec)["eligible"] = 11.0
		}, "eligible = 11"},
		"accounting_does_not_reconcile": {func(m map[string]any) {
			m["accounting"].(map[string]any)["attempted"] = 3.0
		}, "succeeded+failed = 0, attempted = 3"},
		"unknown_schema_version": {func(m map[string]any) {
			m["schema_version"] = 99.0
		}, "not supported"},
	}
}

func TestInvalidFixturesAreRejected(t *testing.T) {
	dir := filepath.Join("testdata", "invalid")
	for name, f := range invalid() {
		path := filepath.Join(dir, name+".json")
		if *update {
			b, err := json.Marshal(fixtures()["matched"].s)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			f.mutate(m)
			out, _ := json.MarshalIndent(m, "", "  ")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test -update to regenerate)", name, err)
		}
		_, err = Decode(b)
		if err == nil {
			t.Errorf("%s: Decode accepted it", name)
			continue
		}
		if !strings.Contains(err.Error(), f.errSub) {
			t.Errorf("%s: error %q does not mention %q", name, err, f.errSub)
		}
	}
}

// WriteFile must refuse what Decode would reject, so a producer bug cannot
// publish a clean verdict.
func TestWriteFileRefusesForgedVerdict(t *testing.T) {
	s := fixtures()["unreadable"].s
	s.Verification.Verdict = VerdictVerified
	if err := s.WriteFile(filepath.Join(t.TempDir(), "s.json")); err == nil {
		t.Fatal("WriteFile wrote a verified verdict over an unreadable required check")
	}
}

// A successful write is not verification, and the claim table says so for
// each of the claims most often overread.
func TestClaimsDisclaimTheStrongerClaim(t *testing.T) {
	for d, want := range map[Dimension]string{
		DimWriteAccepted:         "what the server stored",
		DimSMBDescriptorFidelity: "effective access",
		DimSACLRetention:         "delivered",
	} {
		if got := NewDimension(d, false, Coverage{}).DoesNotProve; !strings.Contains(got, want) {
			t.Errorf("%s does_not_prove = %q, want it to mention %q", d, got, want)
		}
	}
	for _, d := range AllDimensions {
		if claims[d].proves == "" || claims[d].doesNotProve == "" {
			t.Errorf("%s has no claim text", d)
		}
	}
}

// The manifest's size depends on configuration, not on how many objects ran.
func TestManifestSizeIndependentOfObjectCount(t *testing.T) {
	size := func(n int64) int {
		s := sample()
		s.Accounting = Accounting{Included: n, Unverified: 0, EnumerationComplete: true}
		s.Verification = NewVerification(NewDimension(DimNFSSpecMatch, true, Coverage{Eligible: n, Matched: n, EnumerationComplete: true}))
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	small, huge := size(10), size(1<<62)
	if huge-small > 64 {
		t.Errorf("manifest grew %d bytes from 10 to 2^62 objects", huge-small)
	}
}

// A v1 summary has no unreadable count, so migrating it can find a failure
// but never a pass.
func TestDecodeMigratesV1Conservatively(t *testing.T) {
	v1 := func(validate bool, match, mismatch int64) []byte {
		m := map[string]any{
			"schema_version": 1, "validate": validate, "target": "/t",
			"objects": map[string]any{"enumerated": match + mismatch, "match": match, "mismatch": mismatch},
			"options": map[string]any{"dry_run": false},
		}
		b, _ := json.Marshal(m)
		return b
	}
	for _, tc := range []struct {
		name string
		b    []byte
		want Verdict
	}{
		{"clean validate", v1(true, 10, 0), VerdictUnverified},
		{"mismatch validate", v1(true, 9, 1), VerdictFailed},
		{"repair", v1(false, 0, 0), VerdictNotRequested},
	} {
		s, err := Decode(tc.b)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if s.SchemaVersion != SchemaVersion || s.Verification.Verdict != tc.want {
			t.Errorf("%s: version %d verdict %q, want %d %q", tc.name, s.SchemaVersion, s.Verification.Verdict, SchemaVersion, tc.want)
		}
	}

	// A real v1 summary from the lab decodes.
	b, err := os.ReadFile(filepath.Join("..", "..", "benchmarks", "sacl-fa-20261015", "out-sacl-f07-r20261015-144602", "compare.json"))
	if err != nil {
		t.Skip(err)
	}
	if s, err := Decode(b); err != nil {
		t.Errorf("lab v1 summary: %v", err)
	} else if s.Verification.Verdict == VerdictVerified {
		t.Error("lab v1 summary migrated to verified")
	}
}
