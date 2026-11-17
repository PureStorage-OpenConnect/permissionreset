package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/restore"
)

func captureRestoreConfig(t *testing.T) *restore.Config {
	t.Helper()
	old := restoreCommand
	captured := new(restore.Config)
	restoreCommand = func(_ context.Context, cfg restore.Config, _, _ io.Writer) (restore.Result, error) {
		*captured = cfg
		return restore.Result{Mode: cfg.Mode.String(), Reference: cfg.Reference, Target: cfg.Target}, nil
	}
	t.Cleanup(func() { restoreCommand = old })
	return captured
}

func restoreRoots(t *testing.T) (ref, target string) {
	t.Helper()
	base := t.TempDir()
	ref, target = filepath.Join(base, "snap"), filepath.Join(base, "live")
	for _, d := range []string{ref, target} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return ref, target
}

func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runWithFlagSet(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRestoreFlagSelectsModeAndRoots(t *testing.T) {
	cfg := captureRestoreConfig(t)
	ref, target := restoreRoots(t)
	for _, tc := range []struct {
		args []string
		want restore.Mode
	}{
		{nil, restore.DryRun},
		{[]string{"--apply"}, restore.Apply},
		{[]string{"--apply", "--dry-run"}, restore.DryRun},
		{[]string{"--validate"}, restore.Validate},
		{[]string{"--validate", "--apply"}, restore.Validate},
	} {
		args := append([]string{"--restore-from", ref}, tc.args...)
		args = append(args, "--allow-writable-reference", target)
		if code, _, errOut := runArgs(t, args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", tc.args, code, errOut)
		}
		if cfg.Mode != tc.want {
			t.Errorf("%v: mode %s, want %s", tc.args, cfg.Mode, tc.want)
		}
		if cfg.Reference != ref || cfg.Target != target {
			t.Errorf("roots = %s -> %s", cfg.Reference, cfg.Target)
		}
		if !cfg.ReferenceWritable {
			t.Error("a tmpdir reference is writable")
		}
	}
}

func TestRestoreRefusesConflictingFlags(t *testing.T) {
	captureRestoreConfig(t)
	ref, target := restoreRoots(t)
	specPath := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(specPath, []byte("protocol: nfsv4\n"), 0o644)
	for _, extra := range [][]string{
		{"--spec", specPath},
		{"--sacl"},
		{"--compare"},
		{"--set-owner"},
		{"--pfind"},
		{"--transport", "userspace"},
		{"--partitions", "m.yaml"},
		{"--checkpoint", "c.ckpt"}, // without --apply
		{"--resume"},
	} {
		args := append([]string{"--restore-from", ref}, extra...)
		args = append(args, target)
		code, _, errOut := runArgs(t, args...)
		if code == 0 {
			t.Errorf("%v accepted", extra)
		}
		if !strings.Contains(errOut, "ERROR") && !strings.Contains(errOut, "error") {
			t.Errorf("%v: no error text: %q", extra, errOut)
		}
	}
}

func TestRestoreRefusesOverlappingRoots(t *testing.T) {
	captureRestoreConfig(t)
	ref, target := restoreRoots(t)
	inner := filepath.Join(target, "sub")
	os.Mkdir(inner, 0o755)
	for _, pair := range [][2]string{{target, target}, {inner, target}, {target, inner}} {
		code, _, errOut := runArgs(t, "--restore-from", pair[0], pair[1])
		if code == 0 {
			t.Errorf("%s -> %s accepted", pair[0], pair[1])
		}
		if !strings.Contains(errOut, "same directory") && !strings.Contains(errOut, "inside") {
			t.Errorf("%s -> %s: %q", pair[0], pair[1], errOut)
		}
	}
	// A sibling whose name shares a prefix is not inside.
	if err := checkRootsDisjoint(ref, ref+"2"); err != nil {
		t.Errorf("prefix sibling refused: %v", err)
	}
}

func TestRestoreOptionsNeedRestoreFrom(t *testing.T) {
	_, target := restoreRoots(t)
	for _, flag := range []string{"--allow-writable-reference", "--allow-audit-removal"} {
		code, _, errOut := runArgs(t, "--spec", "x.yaml", flag, target)
		if code == 0 || !strings.Contains(errOut, "requires --restore-from") {
			t.Errorf("%s: exit %d %q", flag, code, errOut)
		}
	}
}

func TestRestoreWritesJSONSummary(t *testing.T) {
	captureRestoreConfig(t)
	ref, target := restoreRoots(t)
	js := filepath.Join(t.TempDir(), "sum.json")
	if code, _, errOut := runArgs(t, "--restore-from", ref, "--json-summary", js, target); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	data, err := os.ReadFile(js)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["mode"] != "dry-run" || got["reference"] != ref || got["target"] != target {
		t.Errorf("summary = %s", data)
	}
}
