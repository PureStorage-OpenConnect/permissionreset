package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readBundle unpacks a written bundle into member name -> contents.
func readBundle(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gz.Close()
	out := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = string(data)
	}
	return out
}

const testSpec = `protocol: nfsv4
default:
  owner: alice
  group: legal-team
  acl:
    - "A::OWNER@:rwaDdxtTnNcCoy"
    - "A:g:GROUP@:rwadxtTnNcy"
    - "A::bob@corp.example:rwadxtTnNcCoy"   # the reviewer
    - "A:g:analysts@corp.example:rxtncy"
rules:
  - match:
      type: directory
      pattern: "*.case"
    mode: "0750"
    acl:
      - "A:fd:bob@corp.example:rwaDdxtTnNcCoy"
smb:
  server: fb-lab-01
  credentials: /etc/samba/secret.conf
`

// writeCheckpoint fabricates a checkpoint file: a 48-byte header with the real
// magic and version, then n 16-byte records.
func writeCheckpoint(t *testing.T, path string, n int) {
	t.Helper()
	buf := make([]byte, 48+16*n)
	copy(buf[0:4], "CKPT")
	binary.LittleEndian.PutUint16(buf[4:6], 1)
	for i := 0; i < 32; i++ {
		buf[8+i] = byte(i)
	}
	for i := range buf[48:] {
		buf[48+i] = 0xFA
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}
}

func mounts(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "mounts")
	body := "" +
		"/dev/sda1 / ext4 rw,relatime 0 0\n" +
		"192.0.2.50:/fb-perms /mnt/fb-perms nfs4 rw,vers=4.1,nconnect=16 0 0\n" +
		"tmpfs /run tmpfs rw 0 0\n" +
		"192.0.2.9:/legacy /mnt/legacy nfs rw,vers=3 0 0\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write mounts: %v", err)
	}
	return p
}

func TestSupportBundleAllInputs(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(specPath, []byte(testSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	sumPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(sumPath, []byte(`{"schema_version":1,"target":"/mnt/x"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "run.log")
	if err := os.WriteFile(logPath, []byte("ERROR /mnt/x/a: permission denied\nERROR /mnt/x/b: stale handle\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ckptPath := filepath.Join(dir, "run.ckpt")
	writeCheckpoint(t, ckptPath, 7)

	out := filepath.Join(dir, "bundle.tar.gz")
	in := bundleInputs{
		SpecPath:       specPath,
		SummaryPath:    sumPath,
		CheckpointPath: ckptPath,
		LogPath:        logPath,
		Version:        "1.2.3",
		Commit:         "abc1234",
		Date:           "2026-08-23",
		procMounts:     mounts(t, dir),
		procVersion:    "",
	}
	if err := writeSupportBundle(in, out); err != nil {
		t.Fatalf("writeSupportBundle: %v", err)
	}

	got := readBundle(t, out)
	for _, want := range []string{
		"bundle/README.txt", "bundle/REDACTIONS.txt", "bundle/version.txt",
		"bundle/system.txt", "bundle/spec.yaml", "bundle/summary.json",
		"bundle/checkpoint-meta.txt", "bundle/errors.log",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("bundle is missing %s (have %v)", want, keys(got))
		}
	}

	if !strings.Contains(got["bundle/version.txt"], "permissionreset 1.2.3") ||
		!strings.Contains(got["bundle/version.txt"], "abc1234") {
		t.Errorf("version.txt does not identify the build: %q", got["bundle/version.txt"])
	}
	if !strings.Contains(got["bundle/system.txt"], "go version") ||
		!strings.Contains(got["bundle/system.txt"], "GOOS/GOARCH") {
		t.Errorf("system.txt missing runtime facts: %q", got["bundle/system.txt"])
	}
	// Mount table: nfs and nfs4 lines only.
	sys := got["bundle/system.txt"]
	if !strings.Contains(sys, "/mnt/fb-perms") || !strings.Contains(sys, "/mnt/legacy") {
		t.Errorf("nfs mounts not carried: %q", sys)
	}
	if strings.Contains(sys, "ext4") || strings.Contains(sys, "tmpfs") {
		t.Errorf("non-nfs mount lines leaked into system.txt: %q", sys)
	}
	if got["bundle/summary.json"] != `{"schema_version":1,"target":"/mnt/x"}`+"\n" {
		t.Errorf("summary.json was not copied verbatim: %q", got["bundle/summary.json"])
	}
	if !strings.Contains(got["bundle/errors.log"], "stale handle") {
		t.Errorf("errors.log missing content: %q", got["bundle/errors.log"])
	}
	if strings.Contains(got["bundle/errors.log"], "truncated") {
		t.Errorf("short log should not be marked truncated: %q", got["bundle/errors.log"])
	}
	meta := got["bundle/checkpoint-meta.txt"]
	if !strings.Contains(meta, `magic:         "CKPT"`) {
		t.Errorf("checkpoint magic missing: %q", meta)
	}
	if !strings.Contains(meta, "completed_dirs: 7") {
		t.Errorf("checkpoint record count wrong: %q", meta)
	}
	// The body must never be carried: the fabricated records contain byte 250,
	// which appears nowhere in a header dump.
	if strings.Contains(meta, "\xfa") {
		t.Errorf("checkpoint body bytes leaked into metadata")
	}
	if !strings.Contains(got["bundle/README.txt"], "PATHS ARE PRESENT") {
		t.Errorf("README does not warn that paths are present: %q", got["bundle/README.txt"])
	}
}

func TestSupportBundleRedactsSpec(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(specPath, []byte(testSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "b.tar.gz")
	if err := writeSupportBundle(bundleInputs{SpecPath: specPath, procMounts: mounts(t, dir)}, out); err != nil {
		t.Fatal(err)
	}
	spec := readBundle(t, out)["bundle/spec.yaml"]

	for _, secret := range []string{"alice", "legal-team", "bob@corp.example", "analysts@corp.example", "/etc/samba/secret.conf"} {
		if strings.Contains(spec, secret) {
			t.Errorf("redacted spec still contains %q:\n%s", secret, spec)
		}
	}
	// Structure survives: well-known principals, flags, permission letters,
	// modes, patterns and comments are all still there.
	for _, keep := range []string{"A::OWNER@:rwaDdxtTnNcCoy", "A:g:GROUP@:rwadxtTnNcy",
		`mode: "0750"`, `pattern: "*.case"`, "# the reviewer", "protocol: nfsv4", "server: fb-lab-01"} {
		if !strings.Contains(spec, keep) {
			t.Errorf("redaction destroyed %q:\n%s", keep, spec)
		}
	}
	if !strings.Contains(spec, "credentials: <redacted>") {
		t.Errorf("credential key not dropped:\n%s", spec)
	}
	// bob appears in two rules and must carry one stable placeholder in both.
	// With salted hashing we can't predict the exact token, but we can find it
	// by looking for user- prefixed placeholders that appear exactly twice.
	bobCount := 0
	for _, line := range strings.Split(spec, "\n") {
		if strings.Contains(line, "bob") {
			t.Errorf("bob's name leaked through redaction:\n%s", spec)
		}
	}
	// Find the placeholder used for bob's ACE (the one after A:: that isn't OWNER@)
	var bobPlaceholder string
	for _, line := range strings.Split(spec, "\n") {
		if strings.Contains(line, "# the reviewer") {
			// This line had bob's ACE
			if idx := strings.Index(line, "user-"); idx >= 0 {
				end := idx + 17 // "user-" + 12 hex
				if end <= len(line) {
					bobPlaceholder = line[idx:end]
				}
			}
		}
	}
	if bobPlaceholder == "" {
		t.Errorf("could not find bob's placeholder in spec:\n%s", spec)
	} else {
		bobCount = strings.Count(spec, bobPlaceholder)
		if bobCount != 2 {
			t.Errorf("expected stable placeholder %s twice, got %d:\n%s", bobPlaceholder, bobCount, spec)
		}
	}

	red := readBundle(t, out)["bundle/REDACTIONS.txt"]
	for _, want := range []string{"principal names", "owner/group", "credential-looking keys", "salted SHA-256"} {
		if !strings.Contains(red, want) {
			t.Errorf("REDACTIONS.txt does not explain %q:\n%s", want, red)
		}
	}
}

func TestSupportBundleNoRedact(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(specPath, []byte(testSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "b.tar.gz")
	in := bundleInputs{SpecPath: specPath, NoRedact: true, procMounts: mounts(t, dir)}
	if err := writeSupportBundle(in, out); err != nil {
		t.Fatal(err)
	}
	got := readBundle(t, out)
	if !strings.Contains(got["bundle/spec.yaml"], "bob@corp.example") {
		t.Errorf("--no-redact should carry the spec verbatim:\n%s", got["bundle/spec.yaml"])
	}
	if !strings.Contains(got["bundle/spec.yaml"], "credentials: /etc/samba/secret.conf") {
		t.Error("--no-redact should not drop credential keys from the spec text")
	}
	if !strings.Contains(got["bundle/REDACTIONS.txt"], "nothing was redacted") {
		t.Errorf("REDACTIONS.txt should say redaction was off:\n%s", got["bundle/REDACTIONS.txt"])
	}
	if !strings.Contains(got["bundle/README.txt"], "--no-redact") {
		t.Errorf("README should record that redaction was off:\n%s", got["bundle/README.txt"])
	}
}

func TestSupportBundleMissingInputs(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "b.tar.gz")
	in := bundleInputs{
		Version:        "dev",
		CheckpointPath: filepath.Join(dir, "does-not-exist.ckpt"),
		procMounts:     filepath.Join(dir, "no-mounts"),
	}
	if err := writeSupportBundle(in, out); err != nil {
		t.Fatalf("a bundle with no inputs must still be written: %v", err)
	}
	got := readBundle(t, out)
	for _, absent := range []string{"bundle/spec.yaml", "bundle/summary.json", "bundle/errors.log", "bundle/checkpoint-meta.txt"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s should not exist when its input is missing", absent)
		}
	}
	readme := got["bundle/README.txt"]
	if !strings.Contains(readme, "Not included") {
		t.Fatalf("README has no skip section:\n%s", readme)
	}
	for _, note := range []string{"no --spec given", "no --json-summary given", "no --log given", "unreadable"} {
		if !strings.Contains(readme, note) {
			t.Errorf("README does not note %q:\n%s", note, readme)
		}
	}
	if !strings.Contains(got["bundle/system.txt"], "mount table unavailable") {
		t.Errorf("an unreadable mount table should say so:\n%s", got["bundle/system.txt"])
	}
	// version.txt and system.txt are unconditional.
	if _, ok := got["bundle/version.txt"]; !ok {
		t.Error("version.txt must always be present")
	}
}

func TestSupportBundleRefusesCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".fb-credentials", "prod-credentials.yaml", "my.password.txt", "id_rsa"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("api_token=SUPERSECRETVALUE\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "b.tar.gz")
		in := bundleInputs{SpecPath: p, SummaryPath: p, LogPath: p, procMounts: mounts(t, dir)}
		if err := writeSupportBundle(in, out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for member, body := range readBundle(t, out) {
			if strings.Contains(body, "SUPERSECRETVALUE") {
				t.Errorf("%s: contents of %s leaked into %s", name, name, member)
			}
		}
		got := readBundle(t, out)
		for _, absent := range []string{"bundle/spec.yaml", "bundle/summary.json", "bundle/errors.log"} {
			if _, ok := got[absent]; ok {
				t.Errorf("%s: %s was collected from a credential file", name, absent)
			}
		}
		if !strings.Contains(got["bundle/README.txt"], "looks like a credential file") {
			t.Errorf("%s: refusal not recorded in README:\n%s", name, got["bundle/README.txt"])
		}
	}
}

func TestSupportBundleTailsBigLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "big.log")
	var b strings.Builder
	const total = 4321
	for i := 1; i <= total; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "b.tar.gz")
	if err := writeSupportBundle(bundleInputs{LogPath: logPath, procMounts: mounts(t, dir)}, out); err != nil {
		t.Fatal(err)
	}
	got := readBundle(t, out)
	log := got["bundle/errors.log"]
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	// One marker line plus the tail.
	if len(lines) != bundleTailLines+1 {
		t.Fatalf("expected %d lines (marker + tail), got %d", bundleTailLines+1, len(lines))
	}
	if !strings.Contains(lines[0], "last 1000 of 4321 lines") {
		t.Errorf("marker line wrong: %q", lines[0])
	}
	if lines[1] != fmt.Sprintf("line %d", total-bundleTailLines+1) {
		t.Errorf("tail starts at the wrong line: %q", lines[1])
	}
	if lines[len(lines)-1] != fmt.Sprintf("line %d", total) {
		t.Errorf("tail does not end at the last line: %q", lines[len(lines)-1])
	}
	if !strings.Contains(got["bundle/README.txt"], "last 1000 lines") {
		t.Errorf("README does not mention truncation:\n%s", got["bundle/README.txt"])
	}
}

func TestTailFileShorterThanLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "l")
	// No trailing newline on the last line: it must still be carried.
	if err := os.WriteFile(p, []byte("a\nb\nc"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, truncated, err := tailFile(p, 10)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("a 3-line file is not truncated at a limit of 10")
	}
	if string(data) != "a\nb\nc" {
		t.Errorf("got %q", string(data))
	}
}

func TestRedactACENonACELinesUntouched(t *testing.T) {
	for _, v := range []string{"0750", "*.case", "directory", "A::OWNER@", "a:b:c:d:e"} {
		if _, _, ok := redactACE(v); ok {
			t.Errorf("%q should not be treated as an ACE", v)
		}
	}
	got, name, ok := redactACE("A:fdg:team@x:rxtncy")
	if !ok {
		t.Fatal("a 4-field ACE should be recognised")
	}
	if name != "team@x" {
		t.Errorf("principal misparsed: %q", name)
	}
	if got != "A:fdg:"+redactToken("team@x")+":rxtncy" {
		t.Errorf("ACE rewritten wrong: %q", got)
	}
}

func TestSupportBundleRedactsErrorLog(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(specPath, []byte(testSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "run.log")
	logContent := "MISMATCH: /mnt/x/a want acl A::bob@corp.example:rwaDdxtTnNcCoy have A::OWNER@:rwaDdxtTnNcCoy\n" +
		"MISMATCH: /mnt/x/b want acl A:g:analysts@corp.example:rxtncy have A:g:GROUP@:rxtncy\n" +
		"ERROR /mnt/x/c: permission denied\n"
	if err := os.WriteFile(logPath, []byte(logContent), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "b.tar.gz")
	if err := writeSupportBundle(bundleInputs{SpecPath: specPath, LogPath: logPath, procMounts: mounts(t, dir)}, out); err != nil {
		t.Fatal(err)
	}
	got := readBundle(t, out)
	log := got["bundle/errors.log"]
	for _, secret := range []string{"bob@corp.example", "analysts@corp.example"} {
		if strings.Contains(log, secret) {
			t.Errorf("error log still contains principal %q:\n%s", secret, log)
		}
	}
	// Well-known principals survive
	if !strings.Contains(log, "OWNER@") || !strings.Contains(log, "GROUP@") {
		t.Errorf("well-known principals should not be redacted:\n%s", log)
	}
	// Paths survive
	if !strings.Contains(log, "/mnt/x/a") || !strings.Contains(log, "/mnt/x/b") {
		t.Errorf("paths should be preserved:\n%s", log)
	}
	// ACE structure survives
	if !strings.Contains(log, "rwaDdxtTnNcCoy") || !strings.Contains(log, "rxtncy") {
		t.Errorf("ACE permissions should be preserved:\n%s", log)
	}
	// Non-ACE lines unchanged
	if !strings.Contains(log, "ERROR /mnt/x/c: permission denied") {
		t.Errorf("non-ACE lines should pass through:\n%s", log)
	}
}

func TestSupportBundleNoRedactKeepsLogVerbatim(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "run.log")
	logContent := "MISMATCH: /mnt/x/a want acl A::bob@corp.example:rwaDdxtTnNcCoy\n"
	if err := os.WriteFile(logPath, []byte(logContent), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "b.tar.gz")
	if err := writeSupportBundle(bundleInputs{LogPath: logPath, NoRedact: true, procMounts: mounts(t, dir)}, out); err != nil {
		t.Fatal(err)
	}
	got := readBundle(t, out)
	if !strings.Contains(got["bundle/errors.log"], "bob@corp.example") {
		t.Errorf("--no-redact should keep log verbatim:\n%s", got["bundle/errors.log"])
	}
}

func TestCredentialName(t *testing.T) {
	yes := []string{".fb-credentials", "/etc/x/CREDENTIALS", "a-password-b", "svc.secret", ".netrc", "id_rsa", "key.pem"}
	no := []string{"spec.yaml", "summary.json", "run.log", "run.ckpt", "/mnt/x/keys.txt"}
	for _, p := range yes {
		if !credentialName(p) {
			t.Errorf("%q should be refused", p)
		}
	}
	for _, p := range no {
		if credentialName(p) {
			t.Errorf("%q should be allowed", p)
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
