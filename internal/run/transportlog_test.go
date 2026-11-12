package run

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestUserspaceTransportMessagesGoToStderrOnly pins #47: what the userspace
// transport logs about itself (the server gate, the slot grant, the unsafe
// override) is shown on stderr, and never lands in --log, which holds only
// failures, or in the evidence, which holds only per-object records. The
// construction seam stands in for nfs41.New, sends the messages a real gate
// sends through the Config.Log it was given, and hands back a kernel transport
// over a temp tree so the run itself is clean.
func TestUserspaceTransportMessagesGoToStderrOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	msgs := []string{
		"nfs41: server fake identified itself as \"fake\"",
		"nfs41: requested 128 session slots; server granted 6; using 6",
		"WARNING: server fake is not a recognized FlashBlade (1); continuing under the unsafe server override",
	}
	prev := newUserspaceTransport
	newUserspaceTransport = func(_ context.Context, c nfs41.Config) (transport.Transport, error) {
		if c.Log == nil {
			t.Fatal("Run handed the userspace transport no Log sink")
		}
		for _, m := range msgs {
			c.Log(m)
		}
		return transport.NewKernel(root)
	}
	t.Cleanup(func() { newUserspaceTransport = prev })

	specPath, loadedSpec := writeSpec(t, posixSpec)
	ev := newEvidence(t, evidence.Options{})
	var out, errOut, logOut bytes.Buffer
	res, err := Run(context.Background(), Config{
		Root: root, SpecPath: specPath, Spec: loadedSpec, Transport: "userspace",
		Workers: 1, BatchSize: 1, Apply: true, Quiet: true,
		Log: &logOut, Evidence: ev, ErrOut: &errOut,
	}, &out)
	if err != nil {
		t.Fatalf("Run: %v; stderr=%s", err, errOut.String())
	}
	if res.Evidence.Status != evidence.StatusComplete {
		t.Fatalf("manifest = %+v", res.Evidence)
	}

	for _, m := range msgs {
		if !strings.Contains(errOut.String(), m) {
			t.Errorf("stderr is missing the transport message %q; stderr=%s", m, errOut.String())
		}
	}
	if logOut.Len() != 0 {
		t.Errorf("--log of a clean run is not empty: %q", logOut.String())
	}
	text := evidenceText(t, ev, res)
	if !strings.Contains(text, "file.txt") {
		t.Fatalf("evidence has no record for the file, so the check below proves nothing: %q", text)
	}
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if !hasRecordPrefix(line) {
			t.Errorf("evidence line is not a documented record kind: %q", line)
		}
	}
}

// hasRecordPrefix reports whether line starts with one of the record kinds
// docs/evidence.md documents, or HANDOFF: from a partitioned run.
func hasRecordPrefix(line string) bool {
	for _, p := range []string{"OK:", "WOULD:", "FALLBACK:", "SKIP:", "EXCLUDE:", "ERR:", "HANDOFF:"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}
