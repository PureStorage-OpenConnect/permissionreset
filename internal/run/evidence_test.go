package run

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
)

// evFile adapts a writer into an evidence shard file.
type evFile struct {
	io.Writer
}

func (evFile) Sync() error  { return nil }
func (evFile) Close() error { return nil }

// newEvidence opens an uncompressed, unrotated sink in a temp dir unless o
// says otherwise.
func newEvidence(t *testing.T, o evidence.Options) *evidence.Sink {
	t.Helper()
	if o.Dir == "" {
		o.Dir = filepath.Join(t.TempDir(), "evidence")
	}
	if o.ShardBytes == 0 {
		o.ShardBytes = -1
	}
	s, err := evidence.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// evidenceText is every record the run's closed sink kept, in order.
func evidenceText(t *testing.T, s *evidence.Sink, res Result) string {
	t.Helper()
	if res.Evidence == nil {
		t.Fatal("Run did not close the evidence sink (Result.Evidence is nil)")
	}
	var b strings.Builder
	for _, sh := range res.Evidence.Shards {
		data, err := os.ReadFile(filepath.Join(s.Dir(), sh.Path))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

// fullDisk accepts the first `room` bytes and then fails every write with
// ENOSPC, like a filesystem filling up mid-run.
type fullDisk struct {
	room int64
	n    atomic.Int64
}

func (d *fullDisk) Write(p []byte) (int, error) {
	if d.n.Add(int64(len(p))) > d.room {
		return 0, syscall.ENOSPC
	}
	return len(p), nil
}

// TestEvidenceFailureStopsMutation is the PS-09 safety property: once the
// evidence cannot be written, the run makes no further change. Every file left
// unchanged must be accounted for, the manifest must say incomplete, and the
// run must fail with ErrEvidenceIncomplete-or-worse, never succeed.
func TestEvidenceFailureStopsMutation(t *testing.T) {
	root := t.TempDir()
	const n = 400
	for i := range n {
		dir := filepath.Join(root, "d"+string(rune('a'+i%20)))
		os.MkdirAll(dir, 0o755)
		if err := os.WriteFile(filepath.Join(dir, "f"+strings.Repeat("x", i%7)+string(rune('A'+i/20))), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	specPath, loadedSpec := writeSpec(t, posixSpec)
	disk := &fullDisk{room: 200}
	ev := newEvidence(t, evidence.Options{
		QueueRecords: 1,
		Create:       func(string) (evidence.File, error) { return evFile{disk}, nil },
	})
	var out, errOut strings.Builder
	res, err := Run(context.Background(), Config{
		Root: root, SpecPath: specPath, Spec: loadedSpec, Transport: "kernel",
		Workers: 1, BatchSize: 1, Apply: true, Quiet: true,
		Evidence: ev, ErrOut: &errOut,
	}, &out)
	if err == nil {
		t.Fatal("Run succeeded although its evidence could not be written")
	}
	if !res.EvidenceStopped {
		t.Fatalf("EvidenceStopped = false; stderr=%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "making no further changes") {
		t.Errorf("stderr does not say the run stopped: %s", errOut.String())
	}
	m := res.Evidence
	if m == nil || m.Status != evidence.StatusIncomplete || m.Error == "" {
		t.Fatalf("manifest = %+v, want incomplete with the error", m)
	}
	if m.RecordsWritten+m.RecordsDropped != m.RecordsSubmitted {
		t.Fatalf("records do not reconcile: %+v", m)
	}

	// Count what the run actually changed. posixSpec sets files to 0644; the
	// files were created 0600, so every 0644 file is a change the run made.
	changed := 0
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, _ := d.Info(); fi.Mode().Perm() == 0o644 {
				changed++
			}
		}
		return nil
	})
	if changed >= n {
		t.Fatalf("all %d files were changed; the run kept writing after the evidence failed", n)
	}
	if int64(changed) > res.Stats.Applied {
		t.Fatalf("%d files changed but only %d applies counted", changed, res.Stats.Applied)
	}
	// One worker and a queue of one: at most the queued record, one blocked
	// in Write, and one more change before its record is refused.
	if m.RecordsInFlight < 1 || m.RecordsInFlight > int64(m.QueueRecords)+2 {
		t.Fatalf("records_in_flight = %d, want 1..%d", m.RecordsInFlight, m.QueueRecords+2)
	}
	if res.NotAttempted == 0 {
		t.Fatal("not_attempted = 0; the run should have left reached objects unwritten")
	}
}

// A clean run's evidence is complete, reconciles, and carries one record per
// object; the summary-facing Result carries the manifest.
func TestEvidenceCompleteOnCleanRun(t *testing.T) {
	root := logSplitTree(t)
	specPath, loadedSpec := writeSpec(t, posixSpec)
	ev := newEvidence(t, evidence.Options{})
	var out strings.Builder
	res, err := Run(context.Background(), Config{
		Root: root, SpecPath: specPath, Spec: loadedSpec, Transport: "kernel",
		Workers: 2, BatchSize: 1, Apply: true, Quiet: true, Evidence: ev,
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Evidence.Status != evidence.StatusComplete || res.Evidence.RecordsDropped != 0 {
		t.Fatalf("manifest = %+v", res.Evidence)
	}
	text := evidenceText(t, ev, res)
	if !strings.Contains(text, "SKIP: symlink") || !strings.Contains(text, "file.txt") {
		t.Fatalf("evidence = %q", text)
	}
	if !strings.Contains(out.String(), "Evidence:") {
		t.Errorf("stdout does not name the evidence: %s", out.String())
	}
}

// A run that returns before it walks anything says so in its manifest instead
// of calling an empty set of records complete.
func TestEvidenceIncompleteWhenRunEndsEarly(t *testing.T) {
	specPath, loadedSpec := writeSpec(t, posixSpec)
	ev := newEvidence(t, evidence.Options{})
	res, err := Run(context.Background(), Config{
		Root: t.TempDir(), SpecPath: specPath, Spec: loadedSpec, Transport: "kernel",
		Workers: 1, BatchSize: 1, Resume: true, Quiet: true, Evidence: ev,
	}, io.Discard)
	if err == nil {
		t.Fatal("--resume without --checkpoint should have been refused")
	}
	if res.Evidence == nil || res.Evidence.Status != evidence.StatusIncomplete {
		t.Fatalf("manifest = %+v, want incomplete", res.Evidence)
	}
}

// The detailed profile's before-state is the NFSv4 ACL; a posix run's apply
// line already carries the old mode, so detailed adds nothing there.
func TestDetailedEvidenceAddsNothingForPosix(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	specPath, loadedSpec := writeSpec(t, posixSpec)
	ev := newEvidence(t, evidence.Options{Profile: evidence.ProfileDetailed})
	res, err := Run(context.Background(), Config{
		Root: root, SpecPath: specPath, Spec: loadedSpec, Transport: "kernel",
		Workers: 1, BatchSize: 1, Apply: true, Quiet: true, Evidence: ev,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	text := evidenceText(t, ev, res)
	if strings.Contains(text, "before=") || !strings.Contains(text, "(was 0600)") {
		t.Fatalf("evidence:\n%s", text)
	}
}

func TestBeforeState(t *testing.T) {
	if got := beforeState(nil, false); got != "before=unread" {
		t.Errorf("unread = %q", got)
	}
	if got := beforeState([]byte{1, 2, 3}, true); got != "before=unparseable" {
		t.Errorf("garbage = %q", got)
	}
	acl, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwatTnNcCy", "A:g:GROUP@:rtncy"})
	if err != nil {
		t.Fatal(err)
	}
	if got := beforeState(acl, true); !strings.HasPrefix(got, "before=A::OWNER@:") || !strings.Contains(got, ",A:g:GROUP@:") {
		t.Errorf("acl = %q", got)
	}
}
