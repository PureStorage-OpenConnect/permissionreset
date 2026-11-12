package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

// ---- helpers ---------------------------------------------------------------

// fakeReader is a speccapture.Reader backed by maps, for use in tests that
// need a working Capture without any mount or network.
type fakeReader struct {
	attrs  map[string]transport.Attr
	rawACL map[string][]byte
}

func (f *fakeReader) Stat(r transport.Ref) (transport.Attr, error) {
	a, ok := f.attrs[r.Path]
	if !ok {
		// Wraps fs.ErrNotExist, as the kernel transport's lstat ENOENT does.
		return transport.Attr{}, fmt.Errorf("fakeReader: no attr for %q: %w", r.Path, fs.ErrNotExist)
	}
	return a, nil
}

// ProbeTarget and SetACL make fakeReader an auditproof.Prober: the probe is
// one more map entry, and SetACL keeps what it is given, audit ACEs included.
func (f *fakeReader) ProbeTarget(dir transport.Ref) (transport.Ref, bool, func() error, error) {
	probe := dir.Path + "/.probe"
	f.rawACL[probe] = nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData}})
	return transport.Ref{Path: probe}, false, func() error { delete(f.rawACL, probe); return nil }, nil
}

func (f *fakeReader) SetACL(r transport.Ref, acl []byte) error {
	f.rawACL[r.Path] = acl
	return nil
}

func (f *fakeReader) GetACL(r transport.Ref) ([]byte, error) {
	b, ok := f.rawACL[r.Path]
	if !ok {
		return nil, fmt.Errorf("fakeReader: no ACL for %q", r.Path)
	}
	return b, nil
}

// mustEncodeACL parses ACE strings into the binary NFSv4 ACL format.
func mustEncodeACL(t *testing.T, aces []string) []byte {
	t.Helper()
	raw, err := nfs4acl.ParseACLSpec(aces)
	if err != nil {
		t.Fatalf("ParseACLSpec(%v): %v", aces, err)
	}
	return raw
}

// workingFakeReader returns a fakeReader that Capture will accept for the
// given dir and file paths. scratchDirs are further directories that exist,
// for --probe-dir and --verify-write; any other path does not.
func workingFakeReader(dirPath, filePath string, t *testing.T, scratchDirs ...string) *fakeReader {
	t.Helper()
	dirACL := mustEncodeACL(t, []string{"A:fd:OWNER@:rwaDxtTcCoy", "A:fdg:GROUP@:rxtncy"})
	fileACL := mustEncodeACL(t, []string{"A::OWNER@:rwaTcCoy", "A:g:GROUP@:rncy"})
	r := &fakeReader{
		attrs: map[string]transport.Attr{
			dirPath:  {IsDir: true, Kind: transport.KindDirectory},
			filePath: {IsDir: false, Kind: transport.KindRegular},
		},
		rawACL: map[string][]byte{
			dirPath:  dirACL,
			filePath: fileACL,
		},
	}
	for _, d := range scratchDirs {
		r.attrs[d] = transport.Attr{IsDir: true, Kind: transport.KindDirectory}
	}
	return r
}

// mountTableFor returns a minimal /proc/mounts entry for the given mount point
// with NFSv4.1 options, formatted as the kernel writes it.
func mountTableFor(server, export, mountPoint string) string {
	return fmt.Sprintf("%s:%s %s nfs4 rw,relatime,vers=4.1,rsize=1048576 0 0\n",
		server, export, mountPoint)
}

// fakeDepsWithKernel returns a deps that satisfies runKernel for tests: it
// injects a working fake reader and a mount table that maps both dir and file
// to the same NFSv4.1 mount.
func fakeDepsWithKernel(dirPath, filePath, mountPoint string, t *testing.T, scratchDirs ...string) deps {
	t.Helper()
	reader := workingFakeReader(dirPath, filePath, t, scratchDirs...)
	mt := mountTableFor("192.0.2.1", "/export", mountPoint)
	return deps{
		newKernel: func(_ string) (speccapture.Reader, error) { return reader, nil },
		openMounts: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(mt)), nil
		},
		resolveMount: func(target string, _ io.Reader) (tuning.Mount, error) {
			return tuning.Mount{
				MountPoint: mountPoint,
				FSType:     "nfs4",
				Server:     "192.0.2.1",
				Export:     "/export",
			}, nil
		},
	}
}

// ---- flag / startup tests --------------------------------------------------

func TestRunVersionFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--version"}, &out, &errBuf, productionDeps())
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(errBuf.String(), "build-spec") {
		t.Errorf("stderr %q does not contain 'build-spec'", errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty for --version, got %q", out.String())
	}
}

func TestRunMissingOutput(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"/some/dir", "/some/file"}, &out, &errBuf, productionDeps())
	if code == 0 {
		t.Fatal("expected non-zero exit for missing --output")
	}
	if !strings.Contains(errBuf.String(), "--output") {
		t.Errorf("stderr %q should mention --output", errBuf.String())
	}
	if out.Len() > 0 {
		t.Errorf("stdout should be empty on error, got %q", out.String())
	}
}

func TestRunMissingPositionals(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--output", "-"}, &out, &errBuf, productionDeps())
	if code == 0 {
		t.Fatal("expected non-zero exit for missing positionals")
	}
	if !strings.Contains(errBuf.String(), "DIRECTORY FILE") {
		t.Errorf("stderr %q should mention positionals", errBuf.String())
	}
}

func TestRunOnlyOnePositional(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--output", "-", "/some/dir"}, &out, &errBuf, productionDeps())
	if code == 0 {
		t.Fatal("expected non-zero exit for single positional")
	}
}

func TestRunHelpExitsZero(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--help"}, &out, &errBuf, productionDeps())
	if code != 0 {
		t.Fatalf("--help exit code = %d, want 0", code)
	}
}

// ---- output file tests -----------------------------------------------------

func TestRunExistingOutputRefused(t *testing.T) {
	// Create a pre-existing output file.
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "spec.yaml")
	if err := os.WriteFile(outPath, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Override caps to Linux so --transport=kernel is permitted.
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	mountPoint := filepath.Join(tmp, "mnt")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	dirPath := filepath.Join(mountPoint, "dir")
	filePath := filepath.Join(mountPoint, "file.txt")

	d := fakeDepsWithKernel(dirPath, filePath, mountPoint, t)

	var out, errBuf bytes.Buffer
	code := run([]string{"--transport", "kernel", "--accept-unproven-read", "--output", outPath, dirPath, filePath},
		&out, &errBuf, d)

	if code == 0 {
		t.Fatal("expected non-zero exit for existing output file")
	}
	if !strings.Contains(errBuf.String(), "already exists") {
		t.Errorf("stderr %q should mention 'already exists'", errBuf.String())
	}
	if out.Len() > 0 {
		t.Errorf("stdout should be empty on error, got %q", out.String())
	}
}

func TestRunStdoutClean(t *testing.T) {
	// With --output -, stdout receives only YAML; stderr receives status/identity.
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	tmp := t.TempDir()
	mountPoint := filepath.Join(tmp, "mnt")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	dirPath := filepath.Join(mountPoint, "dir")
	filePath := filepath.Join(mountPoint, "file.txt")

	d := fakeDepsWithKernel(dirPath, filePath, mountPoint, t)

	var out, errBuf bytes.Buffer
	code := run([]string{"--transport", "kernel", "--accept-unproven-read", "--output", "-", dirPath, filePath},
		&out, &errBuf, d)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, errBuf.String())
	}

	yaml := out.String()
	if !strings.Contains(yaml, "protocol: nfsv4") {
		t.Errorf("stdout YAML missing 'protocol: nfsv4'; got:\n%s", yaml)
	}
	// stdout must not contain identity/status prose that belongs on stderr.
	if strings.Contains(yaml, "ACL identity") {
		t.Errorf("stdout contains status text that should go to stderr:\n%s", yaml)
	}
	// stderr must contain the identity report, not the YAML.
	if !strings.Contains(errBuf.String(), "ACL identity") {
		t.Errorf("stderr %q should contain identity report", errBuf.String())
	}
	if strings.Contains(errBuf.String(), "protocol: nfsv4") {
		t.Errorf("stderr should not contain YAML content")
	}
}

// ---- kernel same-mount / version rejection --------------------------------

func TestRunKernelDifferentMountPoints(t *testing.T) {
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	tmp := t.TempDir()

	// resolveMount returns different mount points for dir vs file.
	call := 0
	d := deps{
		newKernel: func(_ string) (speccapture.Reader, error) {
			return nil, fmt.Errorf("should not reach newKernel")
		},
		openMounts: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(
				"192.0.2.1:/exp1 /mnt/a nfs4 rw,vers=4.1 0 0\n" +
					"192.0.2.1:/exp2 /mnt/b nfs4 rw,vers=4.1 0 0\n",
			)), nil
		},
		resolveMount: func(target string, _ io.Reader) (tuning.Mount, error) {
			call++
			if call == 1 {
				return tuning.Mount{MountPoint: "/mnt/a", FSType: "nfs4", Server: "192.0.2.1", Export: "/exp1"}, nil
			}
			return tuning.Mount{MountPoint: "/mnt/b", FSType: "nfs4", Server: "192.0.2.1", Export: "/exp2"}, nil
		},
	}

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "kernel", "--output", filepath.Join(tmp, "spec.yaml"),
		"/mnt/a/dir", "/mnt/b/file.txt",
	}, &out, &errBuf, d)

	if code == 0 {
		t.Fatal("expected non-zero exit for different mount points")
	}
	if !strings.Contains(errBuf.String(), "same NFS mount") {
		t.Errorf("stderr %q should mention 'same NFS mount'", errBuf.String())
	}
}

func TestRunKernelNotNFS41(t *testing.T) {
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	tmp := t.TempDir()
	// Mount table has vers=4.0, not 4.1.
	d := deps{
		newKernel: func(_ string) (speccapture.Reader, error) {
			return nil, fmt.Errorf("should not reach newKernel")
		},
		openMounts: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(
				"192.0.2.1:/export /mnt/share nfs4 rw,vers=4.0 0 0\n",
			)), nil
		},
		resolveMount: func(_ string, _ io.Reader) (tuning.Mount, error) {
			return tuning.Mount{MountPoint: "/mnt/share", FSType: "nfs4"}, nil
		},
	}

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "kernel", "--output", filepath.Join(tmp, "spec.yaml"),
		"/mnt/share/dir", "/mnt/share/file.txt",
	}, &out, &errBuf, d)

	if code == 0 {
		t.Fatal("expected non-zero exit for non-4.1 mount")
	}
	if !strings.Contains(errBuf.String(), "NFSv4.1") {
		t.Errorf("stderr %q should mention NFSv4.1", errBuf.String())
	}
}

// ---- userspace path validation ---------------------------------------------

func TestValidateUserspaceArgs(t *testing.T) {
	cases := []struct {
		name    string
		dir     string
		file    string
		server  string
		export  string
		wantErr string
	}{
		{
			name: "missing server",
			dir:  "/export/dir", file: "/export/file.txt",
			server: "", export: "/export",
			wantErr: "--server is required",
		},
		{
			name: "missing export",
			dir:  "/export/dir", file: "/export/file.txt",
			server: "192.0.2.1", export: "",
			wantErr: "--export is required",
		},
		{
			name: "dir outside export",
			dir:  "/other/dir", file: "/export/file.txt",
			server: "192.0.2.1", export: "/export",
			wantErr: "not inside export",
		},
		{
			name: "file outside export",
			dir:  "/export/dir", file: "/other/file.txt",
			server: "192.0.2.1", export: "/export",
			wantErr: "not inside export",
		},
		{
			name: "dir is export root",
			dir:  "/export", file: "/export/file.txt",
			server: "192.0.2.1", export: "/export",
			wantErr: "is the export root",
		},
		{
			name: "dir dotdot escape",
			dir:  "/export/subdir/../../../etc", file: "/export/file.txt",
			server: "192.0.2.1", export: "/export",
			wantErr: "not inside export",
		},
		{
			name: "backslash hint",
			dir:  `\export\dir`, file: "/export/file.txt",
			server: "192.0.2.1", export: "/export",
			wantErr: "backslashes",
		},
		{
			name: "not absolute",
			dir:  "relative/dir", file: "/export/file.txt",
			server: "192.0.2.1", export: "/export",
			wantErr: "absolute",
		},
		{
			name: "valid paths",
			dir:  "/export/subdir", file: "/export/file.txt",
			server: "192.0.2.1", export: "/export",
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUserspaceArgs(tc.dir, tc.file, tc.server, tc.export)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateBackslashHintShowsForwardSlash(t *testing.T) {
	err := validateUserspaceArgs(`\export\dir`, "/export/file.txt", "192.0.2.1", "/export")
	if err == nil {
		t.Fatal("expected error")
	}
	// The hint must show the forward-slash form.
	if !strings.Contains(err.Error(), "/export/dir") {
		t.Errorf("error %q should show forward-slash hint /export/dir", err.Error())
	}
}

// fakeVerifier is a speccapture.ReplayVerifier that records SetACL calls and
// echoes them back on GetACL, producing a stable fixed-point. Set failErr to
// simulate a server rejection.
type fakeVerifier struct {
	acls    map[string][]byte
	failErr error
}

func (f *fakeVerifier) CreateProbeDirectory(parent transport.Ref, name string) (transport.Ref, error) {
	if f.failErr != nil {
		return transport.Ref{}, f.failErr
	}
	return transport.Ref{Path: parent.Path + "/" + name}, nil
}

func (f *fakeVerifier) CreateProbeFile(parent transport.Ref, name string) (transport.Ref, error) {
	if f.failErr != nil {
		return transport.Ref{}, f.failErr
	}
	return transport.Ref{Path: parent.Path + "/" + name}, nil
}

func (f *fakeVerifier) SetACL(ref transport.Ref, acl []byte) error {
	if f.failErr != nil {
		return f.failErr
	}
	if f.acls == nil {
		f.acls = make(map[string][]byte)
	}
	f.acls[ref.Path] = append([]byte(nil), acl...)
	return nil
}

func (f *fakeVerifier) GetACL(ref transport.Ref) ([]byte, error) {
	if f.failErr != nil {
		return nil, f.failErr
	}
	acl, ok := f.acls[ref.Path]
	if !ok {
		return nil, fmt.Errorf("fakeVerifier: no ACL for %q", ref.Path)
	}
	return acl, nil
}

func (f *fakeVerifier) Remove(parent transport.Ref, name string) error {
	if f.failErr != nil {
		return f.failErr
	}
	return nil
}

// fakeDepsWithUserspace returns a deps that satisfies runUserspace for tests:
// it injects a fakeReader and a fakeVerifier without any network connection.
func fakeDepsWithUserspace(dirPath, filePath string, v speccapture.ReplayVerifier, t *testing.T, scratchDirs ...string) deps {
	t.Helper()
	reader := workingFakeReader(dirPath, filePath, t, scratchDirs...)
	return deps{
		newKernel: func(_ string) (speccapture.Reader, error) {
			return nil, fmt.Errorf("not expected in userspace test")
		},
		openMounts: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("")), nil
		},
		resolveMount: func(_ string, _ io.Reader) (tuning.Mount, error) {
			return tuning.Mount{}, fmt.Errorf("not expected in userspace test")
		},
		newUserspace: func(_ context.Context, _ nfs41.Config) (speccapture.Reader, speccapture.ReplayVerifier, func() error, error) {
			return reader, v, func() error { return nil }, nil
		},
	}
}

// ---- output-to-file tests --------------------------------------------------

func TestRunOutputFile(t *testing.T) {
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "spec.yaml")
	mountPoint := filepath.Join(tmp, "mnt")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	dirPath := filepath.Join(mountPoint, "dir")
	filePath := filepath.Join(mountPoint, "file.txt")

	d := fakeDepsWithKernel(dirPath, filePath, mountPoint, t)

	var out, errBuf bytes.Buffer
	code := run([]string{"--transport", "kernel", "--accept-unproven-read", "--output", outPath, dirPath, filePath},
		&out, &errBuf, d)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, errBuf.String())
	}
	// stdout must be empty when writing to a file.
	if out.Len() > 0 {
		t.Errorf("stdout should be empty for file output, got %q", out.String())
	}
	// Output file must contain valid YAML.
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(content), "protocol: nfsv4") {
		t.Errorf("output file missing 'protocol: nfsv4': %s", content)
	}
	// stderr must report the absolute path.
	if !strings.Contains(errBuf.String(), "wrote") {
		t.Errorf("stderr %q should contain 'wrote'", errBuf.String())
	}
}

// ---- userspace capture path ------------------------------------------------

func TestRunUserspaceCapture(t *testing.T) {
	// Verify the full userspace path: fake connection, capture, stdout YAML,
	// identity report on stderr.
	const (
		dirPath  = "/export/subdir"
		filePath = "/export/file.txt"
		server   = "192.0.2.1"
		export   = "/export"
	)
	d := fakeDepsWithUserspace(dirPath, filePath, nil, t)

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "userspace",
		"--server", server,
		"--export", export,
		"--auth-uid", "10010", "--auth-gid", "10000",
		"--accept-unproven-read",
		"--output", "-",
		dirPath, filePath,
	}, &out, &errBuf, d)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, errBuf.String())
	}
	yaml := out.String()
	if !strings.Contains(yaml, "protocol: nfsv4") {
		t.Errorf("stdout YAML missing 'protocol: nfsv4'; got:\n%s", yaml)
	}
	// Status and identity must go to stderr, not stdout.
	if strings.Contains(yaml, "ACL identity") {
		t.Errorf("stdout contains status text that belongs on stderr:\n%s", yaml)
	}
	if !strings.Contains(errBuf.String(), "ACL identity") {
		t.Errorf("stderr %q should contain identity report", errBuf.String())
	}
}

// ---- --verify-write kernel path --------------------------------------------

func TestRunVerifyWriteKernelDifferentMount(t *testing.T) {
	// Scratch on a different mount point must be rejected before Verify is called.
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	tmp := t.TempDir()
	mountPoint := filepath.Join(tmp, "mnt")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	dirPath := filepath.Join(mountPoint, "dir")
	filePath := filepath.Join(mountPoint, "file.txt")
	scratchPath := filepath.Join(tmp, "other")

	reader := workingFakeReader(dirPath, filePath, t)
	mt := mountTableFor("192.0.2.1", "/export", mountPoint)
	call := 0
	d := deps{
		newKernel: func(_ string) (speccapture.Reader, error) { return reader, nil },
		openMounts: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(mt)), nil
		},
		resolveMount: func(target string, _ io.Reader) (tuning.Mount, error) {
			call++
			if call <= 2 {
				// dir and file exemplars are on mountPoint
				return tuning.Mount{MountPoint: mountPoint, FSType: "nfs4", Server: "192.0.2.1", Export: "/export"}, nil
			}
			// scratch is on a different mount
			return tuning.Mount{MountPoint: filepath.Join(tmp, "other_mnt"), FSType: "nfs4", Server: "192.0.2.1", Export: "/export2"}, nil
		},
	}

	outPath := filepath.Join(tmp, "spec.yaml")
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "kernel",
		"--output", outPath,
		"--verify-write", scratchPath,
		dirPath, filePath,
	}, &out, &errBuf, d)

	if code == 0 {
		t.Fatal("expected non-zero exit for scratch on different mount")
	}
	if !strings.Contains(errBuf.String(), "same NFS mount") {
		t.Errorf("stderr %q should mention 'same NFS mount'", errBuf.String())
	}
	// No output file must be created.
	if _, err := os.Stat(outPath); err == nil {
		t.Error("output file must not be created when verify-write fails")
	}
}

func TestRunVerifyWriteKernelEqualsExemplar(t *testing.T) {
	// scratch == dirExemplar is caught by speccapture.Verify.
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	tmp := t.TempDir()
	mountPoint := filepath.Join(tmp, "mnt")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	dirPath := filepath.Join(mountPoint, "dir")
	filePath := filepath.Join(mountPoint, "file.txt")

	d := fakeDepsWithKernel(dirPath, filePath, mountPoint, t)
	outPath := filepath.Join(tmp, "spec.yaml")

	var out, errBuf bytes.Buffer
	// scratch == dirPath: Verify must return an error.
	code := run([]string{
		"--transport", "kernel",
		"--output", outPath,
		"--verify-write", dirPath,
		dirPath, filePath,
	}, &out, &errBuf, d)

	if code == 0 {
		t.Fatal("expected non-zero exit when scratch equals directory exemplar")
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Error("output file must not be created when verify-write fails")
	}
}

// ---- --verify-write userspace path -----------------------------------------

func TestRunVerifyWriteUserspaceOutsideExport(t *testing.T) {
	// Scratch outside the export is rejected by validateServerPath before Verify.
	const (
		dirPath  = "/export/subdir"
		filePath = "/export/file.txt"
		server   = "192.0.2.1"
		export   = "/export"
	)
	d := fakeDepsWithUserspace(dirPath, filePath, &fakeVerifier{}, t)

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "spec.yaml")
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "userspace",
		"--server", server, "--export", export,
		"--auth-uid", "10010", "--auth-gid", "10000",
		"--output", outPath,
		"--verify-write", "/other/scratch",
		dirPath, filePath,
	}, &out, &errBuf, d)

	if code == 0 {
		t.Fatal("expected non-zero exit for scratch outside export")
	}
	if !strings.Contains(errBuf.String(), "not inside export") {
		t.Errorf("stderr %q should mention 'not inside export'", errBuf.String())
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Error("output file must not be created when verify-write fails")
	}
}

func TestRunVerifyWriteUserspaceEqualsExemplar(t *testing.T) {
	// scratch == dirArg: speccapture.Verify returns an error.
	const (
		dirPath  = "/export/subdir"
		filePath = "/export/file.txt"
		server   = "192.0.2.1"
		export   = "/export"
	)
	d := fakeDepsWithUserspace(dirPath, filePath, &fakeVerifier{}, t)

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "spec.yaml")
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "userspace",
		"--server", server, "--export", export,
		"--auth-uid", "10010", "--auth-gid", "10000",
		"--output", outPath,
		"--verify-write", dirPath,
		dirPath, filePath,
	}, &out, &errBuf, d)

	if code == 0 {
		t.Fatal("expected non-zero exit when scratch equals directory exemplar")
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Error("output file must not be created when verify-write fails")
	}
}

func TestRunVerifyWriteUserspaceFailureNoOutput(t *testing.T) {
	// Verifier returns an error: no output file must be created.
	const (
		dirPath  = "/export/subdir"
		filePath = "/export/file.txt"
		server   = "192.0.2.1"
		export   = "/export"
		scratch  = "/export/scratch"
	)
	v := &fakeVerifier{failErr: fmt.Errorf("server rejected ACL: NFS4ERR_PERM")}
	d := fakeDepsWithUserspace(dirPath, filePath, v, t, scratch)

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "spec.yaml")
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "userspace",
		"--server", server, "--export", export,
		"--auth-uid", "10010", "--auth-gid", "10000",
		"--output", outPath,
		"--verify-write", scratch,
		dirPath, filePath,
	}, &out, &errBuf, d)

	if code == 0 {
		t.Fatal("expected non-zero exit when verifier fails")
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Error("output file must not be created when verify-write fails")
	}
	if !strings.Contains(errBuf.String(), "verify-write") {
		t.Errorf("stderr %q should mention verify-write failure", errBuf.String())
	}
}

func TestRunVerifyWriteUserspaceSuccess(t *testing.T) {
	// Happy path: verify succeeds, output file written with valid YAML.
	const (
		dirPath  = "/export/subdir"
		filePath = "/export/file.txt"
		server   = "192.0.2.1"
		export   = "/export"
		scratch  = "/export/scratch"
	)
	d := fakeDepsWithUserspace(dirPath, filePath, &fakeVerifier{}, t, scratch)

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "verified-spec.yaml")
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "userspace",
		"--server", server, "--export", export,
		"--auth-uid", "10010", "--auth-gid", "10000",
		"--output", outPath,
		"--verify-write", scratch,
		dirPath, filePath,
	}, &out, &errBuf, d)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, errBuf.String())
	}
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(content), "protocol: nfsv4") {
		t.Errorf("output YAML missing 'protocol: nfsv4': %s", content)
	}
	// stdout must be empty for file output.
	if out.Len() > 0 {
		t.Errorf("stdout should be empty for file output, got %q", out.String())
	}
}

// ---- audit ACEs: DACL-keeping default and --with-dacl ----------------------

func TestRunAuditCaptureDefaultAndWithDACL(t *testing.T) {
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	tmp := t.TempDir()
	mountPoint := filepath.Join(tmp, "mnt")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	dirPath := filepath.Join(mountPoint, "dir")
	filePath := filepath.Join(mountPoint, "file.txt")

	for _, withDACL := range []bool{false, true} {
		d := fakeDepsWithKernel(dirPath, filePath, mountPoint, t)
		reader := workingFakeReader(dirPath, filePath, t)
		reader.rawACL[dirPath] = mustEncodeACL(t, []string{"A:fd:OWNER@:rwaDxtTcCoy", "U:fdSF:EVERYONE@:rwadxTNcCoy"})
		d.newKernel = func(_ string) (speccapture.Reader, error) { return reader, nil }

		args := []string{"--transport", "kernel", "--accept-unproven-read", "--output", "-"}
		if withDACL {
			args = append(args, "--with-dacl")
		}
		var out, errBuf bytes.Buffer
		if code := run(append(args, dirPath, filePath), &out, &errBuf, d); code != 0 {
			t.Fatalf("withDACL=%v: exit %d; stderr: %s", withDACL, code, errBuf.String())
		}
		yaml := out.String()
		if !strings.Contains(yaml, "sacl:") {
			t.Errorf("withDACL=%v: YAML has no sacl:\n%s", withDACL, yaml)
		}
		if strings.Contains(yaml, "    acl:") != withDACL {
			t.Errorf("withDACL=%v: acl: presence wrong:\n%s", withDACL, yaml)
		}
		if !strings.Contains(errBuf.String(), "NOTE: ") || !strings.Contains(errBuf.String(), "audit bypass") {
			t.Errorf("withDACL=%v: stderr lacks the bypass NOTE: %s", withDACL, errBuf.String())
		}
	}
}

func TestRunHelpListsWithDACL(t *testing.T) {
	var out, errBuf bytes.Buffer
	run([]string{"--help"}, &out, &errBuf, deps{})
	if !strings.Contains(errBuf.String(), "-with-dacl") {
		t.Errorf("help does not list --with-dacl:\n%s", errBuf.String())
	}
}

// ---- --sacl-plan -----------------------------------------------------------

// updateGolden rewrites testdata/saclplan.golden.json instead of comparing:
// go test ./cmd/build_spec/ -run SaclPlanGolden -args -update
var updateGolden = flag.Bool("update", false, "rewrite golden files")

func TestRunSaclPlanGolden(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--sacl-plan", "testdata/saclplan.yaml"}, &out, &errBuf, deps{}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errBuf.String())
	}
	golden := filepath.Join("testdata", "saclplan.golden.json")
	if *updateGolden {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	// Tolerate a CRLF checkout of the golden file.
	if got, w := out.String(), strings.ReplaceAll(string(want), "\r\n", "\n"); got != w {
		t.Errorf("plan differs from %s:\n--- got\n%s\n--- want\n%s", golden, got, w)
	}
}

func TestRunSaclPlanErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.yaml", "protocol: nfsv4\ndefault:\n  sacl: []\n")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing spec", []string{"--sacl-plan", filepath.Join(dir, "nope.yaml")}, "read spec"},
		{"invalid spec", []string{"--sacl-plan", write("bad.yaml", "protocol: nfsv4\ndefault:\n  sacl: [\"A::OWNER@:r\"]\n")}, "only U (audit)"},
		{"unknown key", []string{"--sacl-plan", write("typo.yaml", "protocol: nfsv4\ndefault:\n  sacl_mode: []\n")}, "sacl_mode"},
		{"posix spec", []string{"--sacl-plan", write("posix.yaml", "protocol: posix\ndefault:\n  mode: \"0755\"\n")}, "needs protocol nfsv4"},
		{"empty value", []string{"--sacl-plan="}, "needs the path"},
		{"with --output", []string{"--sacl-plan", good, "--output", "-"}, "cannot be combined with --output"},
		{"with --verify-write", []string{"--verify-write", "/x", "--sacl-plan", good}, "--verify-write"},
		{"with --with-dacl", []string{"--sacl-plan", good, "--with-dacl"}, "--with-dacl"},
		{"with positionals", []string{"--sacl-plan", good, "/d", "/f"}, "no positional arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := run(tt.args, &out, &errBuf, deps{})
			if code == 0 {
				t.Fatalf("exit 0, want non-zero; stdout:\n%s", out.String())
			}
			if out.Len() != 0 {
				t.Errorf("stdout must stay empty on error, got %q", out.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("stderr %q does not mention %q", errBuf.String(), tt.want)
			}
		})
	}
}

func TestRunHelpListsSaclPlan(t *testing.T) {
	var out, errBuf bytes.Buffer
	run([]string{"--help"}, &out, &errBuf, deps{})
	if !strings.Contains(errBuf.String(), "-sacl-plan") {
		t.Errorf("help does not list --sacl-plan:\n%s", errBuf.String())
	}
}

// ---- read-safety guard (PS-02) ----------------------------------------------

// kernelGuardRun runs a kernel capture with extra flags against a fake mount
// and returns the exit code, stdout and stderr.
func kernelGuardRun(t *testing.T, mountFor func(target, mountPoint string) string, extra ...string) (int, string, string) {
	t.Helper()
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	mountPoint := filepath.Join(t.TempDir(), "mnt")
	dirPath := filepath.Join(mountPoint, "dir")
	filePath := filepath.Join(mountPoint, "file.txt")
	d := fakeDepsWithKernel(dirPath, filePath, mountPoint, t, "/mnt/scratch")
	if mountFor != nil {
		d.resolveMount = func(target string, _ io.Reader) (tuning.Mount, error) {
			return tuning.Mount{MountPoint: mountFor(target, mountPoint), FSType: "nfs4", Server: "192.0.2.1", Export: "/export"}, nil
		}
	}
	args := append([]string{"--transport", "kernel", "--output", "-"}, extra...)
	var out, errBuf bytes.Buffer
	code := run(append(args, dirPath, filePath), &out, &errBuf, d)
	return code, out.String(), errBuf.String()
}

func TestRunRefusesAnUnprovenReadByDefault(t *testing.T) {
	code, out, stderr := kernelGuardRun(t, nil)
	if code == 0 {
		t.Fatal("exit 0, want a refusal")
	}
	if out != "" {
		t.Errorf("stdout = %q, want no YAML", out)
	}
	for _, want := range []string{"--probe-dir", "--accept-unproven-read", "Nothing was read"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

func TestRunProbeDirProvesBeforeCapture(t *testing.T) {
	code, out, stderr := kernelGuardRun(t, nil, "--probe-dir", "/mnt/scratch")
	if code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(out, "protocol: nfsv4") {
		t.Errorf("stdout missing YAML:\n%s", out)
	}
	if strings.Contains(stderr, "no audit-bypass proof") {
		t.Errorf("proven capture printed the unproven-read note:\n%s", stderr)
	}
	// #31: the passed proof is reported, naming the probe, ahead of every other
	// NOTE (those are printed after the capture has read the exemplars).
	const passed = "NOTE: audit-bypass proof passed: the array kept an audit ACE written to disposable probe file /mnt/scratch/.probe"
	if !strings.Contains(stderr, passed) {
		t.Fatalf("stderr missing the proof line %q:\n%s", passed, stderr)
	}
	if i := strings.Index(stderr, "NOTE: "); i != strings.Index(stderr, passed) {
		t.Errorf("another NOTE precedes the proof line:\n%s", stderr)
	}
}

func TestRunAcceptUnprovenReadPrintsTheNote(t *testing.T) {
	code, _, stderr := kernelGuardRun(t, nil, "--accept-unproven-read")
	if code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "NOTE: the exemplar ACLs were read with no audit-bypass proof") {
		t.Errorf("stderr missing the unproven-read NOTE:\n%s", stderr)
	}
	if strings.Contains(stderr, "proof passed") {
		t.Errorf("an unproven read reported a passed proof:\n%s", stderr)
	}
}

func TestRunProbeDirMustBeOnTheExemplarMount(t *testing.T) {
	code, _, stderr := kernelGuardRun(t, func(target, mountPoint string) string {
		if strings.Contains(target, "elsewhere") {
			return "/other"
		}
		return mountPoint
	}, "--probe-dir", "/elsewhere/scratch")
	if code == 0 || !strings.Contains(stderr, "same NFS mount") {
		t.Fatalf("exit %d, want a same-mount refusal; stderr: %s", code, stderr)
	}
}

// ---- probe and scratch directories must already exist ----------------------

// TestRunMissingProbeDirIsRefusedNotCreated: a --probe-dir that does not exist
// stops the run before the proof or any exemplar read, says build-spec does not
// create it, and writes no spec.
func TestRunMissingProbeDirIsRefusedNotCreated(t *testing.T) {
	code, out, stderr := kernelGuardRun(t, nil, "--probe-dir", "/mnt/scrach")
	if code == 0 {
		t.Fatal("exit 0, want a refusal")
	}
	if out != "" {
		t.Errorf("stdout = %q, want no YAML", out)
	}
	for _, want := range []string{
		`probe directory "/mnt/scrach" does not exist`,
		"build-spec does not create it",
		"Nothing was read",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "proof passed") {
		t.Errorf("the proof ran against a missing directory:\n%s", stderr)
	}
}

// TestRunProbeDirThatIsAFileIsRefused: --probe-dir naming a regular file (here
// the file exemplar) is refused with the not-a-directory hint.
func TestRunProbeDirThatIsAFileIsRefused(t *testing.T) {
	old := caps
	caps = platform.Linux()
	defer func() { caps = old }()

	mountPoint := filepath.Join(t.TempDir(), "mnt")
	dirPath := filepath.Join(mountPoint, "dir")
	filePath := filepath.Join(mountPoint, "file.txt")
	d := fakeDepsWithKernel(dirPath, filePath, mountPoint, t)
	var out, errBuf bytes.Buffer
	code := run([]string{"--transport", "kernel", "--output", "-", "--probe-dir", filePath, dirPath, filePath}, &out, &errBuf, d)
	if code == 0 {
		t.Fatal("exit 0, want a refusal")
	}
	for _, want := range []string{"is not a directory", "not a file or a symlink", "Nothing was read"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, errBuf.String())
		}
	}
}

// TestRunMissingVerifyWriteScratchFailsBeforeCapture: a --verify-write scratch
// that does not exist, given alongside a separate --probe-dir that does, is
// refused before the capture runs -- the proof never starts.
func TestRunMissingVerifyWriteScratchFailsBeforeCapture(t *testing.T) {
	code, out, stderr := kernelGuardRun(t, nil, "--probe-dir", "/mnt/scratch", "--verify-write", "/mnt/verify")
	if code == 0 {
		t.Fatal("exit 0, want a refusal")
	}
	if out != "" {
		t.Errorf("stdout = %q, want no YAML", out)
	}
	if want := `--verify-write scratch "/mnt/verify" does not exist`; !strings.Contains(stderr, want) {
		t.Errorf("stderr missing %q:\n%s", want, stderr)
	}
	if strings.Contains(stderr, "proof passed") {
		t.Errorf("the capture ran before the scratch was checked:\n%s", stderr)
	}
}

// TestRunMissingVerifyWriteAsProbeDir: with no --probe-dir, the probe defaults
// to the --verify-write scratch, and a missing one is refused as the probe
// directory.
func TestRunMissingVerifyWriteAsProbeDir(t *testing.T) {
	code, _, stderr := kernelGuardRun(t, nil, "--verify-write", "/mnt/verify")
	if code == 0 {
		t.Fatal("exit 0, want a refusal")
	}
	if want := `probe directory "/mnt/verify" does not exist`; !strings.Contains(stderr, want) {
		t.Errorf("stderr missing %q:\n%s", want, stderr)
	}
}

// TestRunUserspaceMissingProbeDir: the userspace path refuses a missing probe
// directory the same way, before any capture.
func TestRunUserspaceMissingProbeDir(t *testing.T) {
	const (
		dirPath  = "/export/subdir"
		filePath = "/export/file.txt"
	)
	d := fakeDepsWithUserspace(dirPath, filePath, &fakeVerifier{}, t)
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "userspace",
		"--server", "192.0.2.1", "--export", "/export",
		"--auth-uid", "10010", "--auth-gid", "10000",
		"--output", "-",
		"--probe-dir", "/export/missing",
		dirPath, filePath,
	}, &out, &errBuf, d)
	if code == 0 {
		t.Fatal("exit 0, want a refusal")
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want no YAML", out.String())
	}
	for _, want := range []string{`probe directory "/export/missing" does not exist`, "Nothing was read"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, errBuf.String())
		}
	}
}

// TestRunUserspaceMissingVerifyWriteScratch: a separate --verify-write scratch
// that does not exist is refused before the capture on the userspace path too.
func TestRunUserspaceMissingVerifyWriteScratch(t *testing.T) {
	const (
		dirPath  = "/export/subdir"
		filePath = "/export/file.txt"
	)
	d := fakeDepsWithUserspace(dirPath, filePath, &fakeVerifier{}, t, "/export/scratch")
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--transport", "userspace",
		"--server", "192.0.2.1", "--export", "/export",
		"--auth-uid", "10010", "--auth-gid", "10000",
		"--output", "-",
		"--probe-dir", "/export/scratch",
		"--verify-write", "/export/verify",
		dirPath, filePath,
	}, &out, &errBuf, d)
	if code == 0 {
		t.Fatal("exit 0, want a refusal")
	}
	if want := `--verify-write scratch "/export/verify" does not exist`; !strings.Contains(errBuf.String(), want) {
		t.Errorf("stderr missing %q:\n%s", want, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "proof passed") {
		t.Errorf("the capture ran before the scratch was checked:\n%s", errBuf.String())
	}
}
