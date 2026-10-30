package summary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sample() *RunSummary {
	s := &RunSummary{
		Tool:      Tool{Name: "permissionreset", Version: "1.2.3", Commit: "abc123", Date: "2026-08-23"},
		Target:    "/mnt/fb-perms/tree",
		Transport: Trans{Name: "userspace", Server: "192.0.2.50:2049", Export: "/fb-perms", Platform: "flashblade", FilesystemID: 42, FilesystemIDSource: "fsid"},
		Spec:      Spec{Path: "/etc/spec.yaml", SHA256: strings.Repeat("a", 64), Protocol: "nfsv4"},
		Options:   Opts{Workers: 1024, BatchSize: 50, Connections: 16, DryRun: false, Compare: true, SetOwner: true, CheckpointPath: "/var/ck", Resume: true},
		Objects:   Counts{Enumerated: 10, Applied: 7, Skipped: 2, Symlinks: 1, Failed: 0},
		Errors:    Errs{Walk: 1, Apply: 2, DirFix: 3, Total: 6},
		Prepass:   Pre{DirsFixed: 4, Errors: 3, FixSeconds: 1.5, ReaddirSeconds: 2.5},
		Phases:    Phase{PrepassSeconds: 0, ApplySeconds: 9, TotalSeconds: 10, Fused: true},
		ExitCode:  1,
		RunID:     strings.Repeat("0", 32),
		Accounting: Accounting{
			Included: 10, Attempted: 7, Succeeded: 7, Unverified: 10,
		},
		Verification: NewVerification(NewDimension(DimWriteAccepted, false, Coverage{Eligible: 7, Matched: 7})),
	}
	s.Stamp(time.Unix(0, 0), time.Unix(60, 0))
	return s
}

// The JSON is a contract with automation, so the shape is asserted key by key.
// A rename is a schema change and must break this test.
func TestJSONShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")
	if err := sample().WriteFile(path); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("summary is not valid JSON: %v", err)
	}
	for _, k := range []string{
		"schema_version", "tool", "target", "transport", "spec", "options",
		"objects", "errors", "prepass", "phases", "interrupted", "exit_code",
		"started_at", "finished_at", "run_id", "accounting", "verification",
	} {
		if _, ok := m[k]; !ok {
			t.Errorf("top-level key %q missing", k)
		}
	}
	if got := m["schema_version"]; got != float64(SchemaVersion) {
		t.Errorf("schema_version = %v, want %d", got, SchemaVersion)
	}
	if got := m["exit_code"]; got != float64(1) {
		t.Errorf("exit_code = %v, want 1", got)
	}

	nested := map[string][]string{
		"tool":         {"name", "version", "commit", "date"},
		"transport":    {"name", "server", "export", "platform", "filesystem_id", "filesystem_id_source"},
		"spec":         {"path", "sha256", "protocol"},
		"options":      {"workers", "batch_size", "connections", "workers_defaulted", "dry_run", "compare", "set_owner", "pfind", "one_filesystem", "checkpoint_path", "resume"},
		"objects":      {"enumerated", "applied", "skipped", "symlinks", "failed"},
		"errors":       {"walk", "apply", "dir_fix", "duplicate_completions", "total"},
		"prepass":      {"dirs_fixed", "errors", "fix_seconds_summed", "readdir_seconds_summed"},
		"phases":       {"prepass_seconds", "apply_seconds", "total_seconds", "fused"},
		"accounting":   {"included", "excluded", "attempted", "succeeded", "failed", "unverified", "enumeration_complete"},
		"verification": {"verdict", "dimensions"},
	}
	for parent, keys := range nested {
		sub, ok := m[parent].(map[string]any)
		if !ok {
			t.Errorf("%q is not an object", parent)
			continue
		}
		for _, k := range keys {
			if _, ok := sub[k]; !ok {
				t.Errorf("%s.%s missing", parent, k)
			}
		}
	}

	// A round trip must preserve every value, which is the property a consumer
	// actually depends on.
	var back RunSummary
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	want := sample()
	want.SchemaVersion = SchemaVersion
	if !reflect.DeepEqual(back, *want) {
		t.Errorf("round trip lost data:\n got %+v\nwant %+v", back, *want)
	}
}

// Timestamps are RFC 3339 in UTC. A local-time stamp in a bundle collected
// across sites is not comparable, so the Z is part of the contract.
func TestStampIsUTCRFC3339(t *testing.T) {
	s := &RunSummary{}
	s.Stamp(time.Date(2026, 8, 23, 12, 0, 0, 0, time.FixedZone("PDT", -7*3600)), time.Date(2026, 8, 23, 13, 0, 0, 0, time.UTC))
	if s.StartedAt != "2026-08-23T19:00:00Z" {
		t.Errorf("StartedAt = %q", s.StartedAt)
	}
	if s.FinishedAt != "2026-08-23T13:00:00Z" {
		t.Errorf("FinishedAt = %q", s.FinishedAt)
	}
}

// Omitted-when-empty fields must actually be absent: a kernel-transport run
// claiming "server": "" would read as a userspace run with a blank server.
func TestEmptyOptionalFieldsAreOmitted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	s := &RunSummary{Transport: Trans{Name: "kernel", FilesystemIDSource: "st_dev"}, Verification: NewVerification()}
	if err := s.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, absent := range []string{`"server"`, `"export"`, `"connections"`, `"checkpoint_path"`, `"log_path"`} {
		if strings.Contains(string(b), absent) {
			t.Errorf("expected %s to be omitted, got:\n%s", absent, b)
		}
	}
}

func TestFileDigestMatchesSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yaml")
	content := []byte("protocol: nfsv4\nrules: []\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	got, err := FileDigest(path)
	if err != nil {
		t.Fatalf("FileDigest: %v", err)
	}
	if got != want {
		t.Errorf("digest = %q, want %q", got, want)
	}
	if len(got) != 64 || strings.ToLower(got) != got {
		t.Errorf("digest is not 64 lowercase hex chars: %q", got)
	}
}

func TestFileDigestChangesWithContent(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	da, err := FileDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := FileDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da == db {
		t.Error("different contents produced the same digest")
	}
}

func TestFileDigestMissingFile(t *testing.T) {
	if _, err := FileDigest(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

// Atomic write: the destination is either absent or complete, never partial,
// and no temp file is left behind.
func TestWriteFileIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")
	if err := sample().WriteFile(path); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "summary.json" {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory should hold only the summary, got %v", names)
	}
}

func TestWriteFileOverwritesInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(path, []byte("stale garbage that is much longer than the new content"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := sample()
	s.ExitCode = 0
	if err := s.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "stale") {
		t.Errorf("stale content survived the overwrite:\n%s", b)
	}
	var back RunSummary
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("overwritten file is not valid JSON: %v", err)
	}
	if back.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", back.ExitCode)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("temp file left behind: %d entries", len(ents))
	}
}

// A failing write must not leave a temp file for a collector to pick up.
func TestWriteFileLeavesNoTempOnFailure(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "asdir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Renaming a file over a non-empty directory fails.
	if err := os.WriteFile(filepath.Join(sub, "child"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sample().WriteFile(sub); err == nil {
		t.Fatal("expected WriteFile to fail when the destination is a non-empty directory")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Errorf("temp file left behind after failure: %d entries in %s", len(ents), dir)
	}
}

func TestWriteFileEndsWithNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := sample().WriteFile(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Error("summary should end with a newline")
	}
}
