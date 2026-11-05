package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
	binDir    string // removed by TestMain; os.MkdirTemp has no t.Cleanup across tests
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func generateTreeBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			buildErr = err
			return
		}
		dir, err := os.MkdirTemp("", "generate-tree-bin")
		if err != nil {
			buildErr = err
			return
		}
		binDir = dir
		out := filepath.Join(dir, "generate-tree")
		cmd := exec.Command(goTool, "build", "-o", out, ".")
		if b, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build: %v: %s", err, b)
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatalf("building generate-tree: %v", buildErr)
	}
	return binPath
}

const binaryTimeout = 30 * time.Second

type cmdResult struct {
	code   int
	stdout string
	stderr string
}

func runBinary(t *testing.T, args ...string) cmdResult {
	t.Helper()
	bin := generateTreeBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), binaryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("generate-tree did not exit within %s with args %q", binaryTimeout, args)
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running generate-tree: %v", err)
	}
	return cmdResult{code: code, stdout: out.String(), stderr: errb.String()}
}

func TestVersionFlag(t *testing.T) {
	var out, errOut strings.Builder
	if code := run([]string{"--version"}, &out, &errOut); code != 0 {
		t.Fatalf("--version exit %d; stderr: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "generate-tree "+version+" (") {
		t.Errorf("--version printed %q", out.String())
	}
}

func TestHelpFlag(t *testing.T) {
	r := runBinary(t, "-help")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0", r.code)
	}
	if !strings.Contains(r.stderr, "Usage") {
		t.Fatalf("stderr = %q, want Usage message", r.stderr)
	}
}

func TestNoTargetExitsNonzero(t *testing.T) {
	r := runBinary(t, "-principals", "/dev/null")
	if r.code == 0 {
		t.Fatal("exit code = 0, want nonzero when no target argument given")
	}
	if !strings.Contains(r.stderr, "Usage") {
		t.Fatalf("stderr = %q, want Usage message", r.stderr)
	}
}

func TestMissingPrincipalsExitsNonzero(t *testing.T) {
	target := t.TempDir()
	r := runBinary(t, target)
	if r.code == 0 {
		t.Fatal("exit code = 0, want nonzero when --principals omitted")
	}
	if !strings.Contains(r.stderr, "--principals is required") {
		t.Fatalf("stderr = %q, want principals-required message", r.stderr)
	}
}

func TestInvalidScaleExitsNonzero(t *testing.T) {
	target := t.TempDir()
	principals := minimalPrincipals(t)
	r := runBinary(t, "-scale", "bogus", "-principals", principals, target)
	if r.code == 0 {
		t.Fatal("exit code = 0, want nonzero for invalid scale")
	}
	if !strings.Contains(r.stderr, "unknown scale") {
		t.Fatalf("stderr = %q, want unknown-scale message", r.stderr)
	}
}

func TestDryRunCreatesNoFiles(t *testing.T) {
	target := t.TempDir()
	principals := minimalPrincipals(t)

	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	before := len(entries)

	r := runBinary(t, "-dry-run", "-principals", principals, "-scale", "small", target)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", r.code, r.stderr)
	}

	entries, err = os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != before {
		t.Fatalf("dry-run created %d entries in target, want %d", len(entries), before)
	}
}

func TestBadPrincipalsFileExitsNonzero(t *testing.T) {
	target := t.TempDir()
	r := runBinary(t, "-principals", "/no/such/file.json", target)
	if r.code == 0 {
		t.Fatal("exit code = 0, want nonzero for missing principals file")
	}
	if !strings.Contains(r.stderr, "reading principals") {
		t.Fatalf("stderr = %q, want reading-principals error", r.stderr)
	}
}

func TestMalformedPrincipalsExitsNonzero(t *testing.T) {
	target := t.TempDir()
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`not json`), 0600); err != nil {
		t.Fatal(err)
	}
	r := runBinary(t, "-principals", bad, target)
	if r.code == 0 {
		t.Fatal("exit code = 0, want nonzero for malformed principals JSON")
	}
	if !strings.Contains(r.stderr, "parsing principals") {
		t.Fatalf("stderr = %q, want parsing-principals error", r.stderr)
	}
}

func TestEmptyRosterExitsNonzero(t *testing.T) {
	target := t.TempDir()
	empty := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(empty, []byte(`{"domain":"","roles":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	r := runBinary(t, "-principals", empty, target)
	if r.code == 0 {
		t.Fatal("exit code = 0, want nonzero for empty roster")
	}
	if !strings.Contains(r.stderr, "must have") {
		t.Fatalf("stderr = %q, want must-have error", r.stderr)
	}
}

// minimalPrincipals writes a valid but minimal roster that satisfies the CLI
// validation. The principals themselves don't need to resolve — dry-run and
// scale-validation tests never reach setxattr.
func minimalPrincipals(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "principals.json")
	data := `{
		"domain": "test.local",
		"roles": {
			"admin_user": "admin@test.local",
			"admin_group": "admins@test.local",
			"readonly_user": "reader@test.local",
			"readonly_group": "readers@test.local",
			"ops_user": "ops@test.local",
			"ops_group": "opsgrp@test.local",
			"hr_user": "hr@test.local",
			"hr_group": "hrgrp@test.local",
			"legal_user": "legal@test.local",
			"legal_group": "legalgrp@test.local",
			"marketing_user": "mkt@test.local",
			"marketing_group": "mktgrp@test.local"
		}
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
