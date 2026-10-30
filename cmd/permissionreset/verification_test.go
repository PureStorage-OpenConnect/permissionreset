package main

import (
	"testing"

	runpkg "github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/stats"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/summary"
)

func TestVerificationFor(t *testing.T) {
	for _, tc := range []struct {
		name       string
		res        runpkg.Result
		verdict    summary.Verdict
		state      summary.State // of the dimension the run exercised
		dim        summary.Dimension
		unverified int64
	}{
		{"clean validate",
			runpkg.Result{IsValidate: true, Stats: stats.Snapshot{Enumerated: 10, Symlinks: 1}, MatchCount: 9},
			summary.VerdictVerified, summary.StateMatched, summary.DimNFSSpecMatch, 1},
		{"validate with a mismatch",
			runpkg.Result{IsValidate: true, Stats: stats.Snapshot{Enumerated: 10}, MatchCount: 9, MismatchCount: 1},
			summary.VerdictFailed, summary.StateMismatched, summary.DimNFSSpecMatch, 0},
		{"validate with an unreadable ACL",
			runpkg.Result{IsValidate: true, Stats: stats.Snapshot{Enumerated: 10}, MatchCount: 9, UnreadableCount: 1},
			summary.VerdictUnverified, summary.StateUnreadable, summary.DimNFSSpecMatch, 1},
		{"validate with a walk error",
			runpkg.Result{IsValidate: true, Stats: stats.Snapshot{Enumerated: 10}, MatchCount: 10, WalkErrors: 1},
			summary.VerdictUnverified, summary.StateIncomplete, summary.DimNFSSpecMatch, 0},
		{"interrupted validate",
			runpkg.Result{IsValidate: true, Stats: stats.Snapshot{Enumerated: 10}, MatchCount: 4, Interrupted: true},
			summary.VerdictUnverified, summary.StateIncomplete, summary.DimNFSSpecMatch, 6},
		{"clean apply",
			runpkg.Result{Stats: stats.Snapshot{Enumerated: 10, Applied: 10}},
			summary.VerdictNotRequested, summary.StateMatched, summary.DimWriteAccepted, 10},
		{"dry run",
			runpkg.Result{DryRun: true, Stats: stats.Snapshot{Enumerated: 10, Applied: 10}},
			summary.VerdictNotRequested, summary.StateNotChecked, summary.DimWriteAccepted, 10},
	} {
		acc, v := verificationFor(tc.res)
		s := summary.RunSummary{Accounting: acc, Verification: v}
		if err := s.Check(); err != nil {
			t.Errorf("%s: inconsistent: %v", tc.name, err)
		}
		if v.Verdict != tc.verdict {
			t.Errorf("%s: verdict %q, want %q", tc.name, v.Verdict, tc.verdict)
		}
		for _, d := range v.Dimensions {
			if d.Name == tc.dim && d.State != tc.state {
				t.Errorf("%s: %s state %q, want %q", tc.name, d.Name, d.State, tc.state)
			}
		}
		if acc.Unverified != tc.unverified {
			t.Errorf("%s: unverified %d, want %d", tc.name, acc.Unverified, tc.unverified)
		}
	}
}
