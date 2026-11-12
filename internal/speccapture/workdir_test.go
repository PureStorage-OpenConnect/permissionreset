package speccapture_test

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// noentErr is an NFS4ERR_NOENT status, as the userspace client returns it.
type noentErr struct{}

func (*noentErr) Error() string     { return "NFS4ERR_NOENT" }
func (*noentErr) NFSStatus() uint32 { return 2 }

// TestCaptureRefusesAMissingProbeDir: a probe directory that does not exist is
// refused before the probe is created and before either exemplar is read, and
// the capture does not create it. Both transports' not-found errors count.
func TestCaptureRefusesAMissingProbeDir(t *testing.T) {
	for name, statErr := range map[string]error{
		"kernel ENOENT":           fmt.Errorf("lstat /vol/missing: %w", syscall.ENOENT),
		"userspace NFS4ERR_NOENT": fmt.Errorf("nfs41: stat /vol/missing: %w", &noentErr{}),
	} {
		t.Run(name, func(t *testing.T) {
			p, dir, file := newProber(t)
			p.statErr = map[string]error{"/vol/missing": statErr}
			_, err := speccapture.CaptureWithOptions(p, dir, file, speccapture.Options{ProbeDir: "/vol/missing"})
			if !errors.Is(err, speccapture.ErrDirMissing) {
				t.Fatalf("err = %v, want ErrDirMissing", err)
			}
			if want := `probe directory "/vol/missing" does not exist`; !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, want it to contain %q", err, want)
			}
			if len(p.calls) != 0 {
				t.Errorf("calls = %v, want none: no probe, no exemplar read", p.calls)
			}
		})
	}
}

// TestCaptureRefusesAProbeDirThatIsNotADirectory: a file or a symlink at the
// probe path is refused before the probe is created. A symlink is not
// followed, since it could point off the mount the caller checked.
func TestCaptureRefusesAProbeDirThatIsNotADirectory(t *testing.T) {
	for name, attr := range map[string]transport.Attr{
		"regular file":       {Kind: transport.KindRegular},
		"symlink to a dir":   {Kind: transport.KindSymlink, IsSymlink: true},
		"symlink, dir flags": {Kind: transport.KindSymlink, IsSymlink: true, IsDir: true},
	} {
		t.Run(name, func(t *testing.T) {
			p, dir, file := newProber(t)
			p.attrs["/vol/notdir"] = attr
			_, err := speccapture.CaptureWithOptions(p, dir, file, speccapture.Options{ProbeDir: "/vol/notdir"})
			if !errors.Is(err, speccapture.ErrNotDir) {
				t.Fatalf("err = %v, want ErrNotDir", err)
			}
			if len(p.calls) != 0 {
				t.Errorf("calls = %v, want none", p.calls)
			}
		})
	}
}

// TestCaptureProbeDirStatFailureIsNotMissing: a stat failure other than not
// found (here, access denied) stops the capture but is not reported as a
// missing directory, so the operator is not told to mkdir something that exists.
func TestCaptureProbeDirStatFailureIsNotMissing(t *testing.T) {
	p, dir, file := newProber(t)
	p.statErr = map[string]error{"/vol/scratch": fmt.Errorf("lstat /vol/scratch: %w", syscall.EACCES)}
	_, err := speccapture.CaptureWithOptions(p, dir, file, speccapture.Options{ProbeDir: "/vol/scratch"})
	if err == nil {
		t.Fatal("err = nil, want a refusal")
	}
	if errors.Is(err, speccapture.ErrDirMissing) || errors.Is(err, speccapture.ErrNotDir) {
		t.Errorf("err = %v, want neither ErrDirMissing nor ErrNotDir", err)
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Errorf("err = %v, want the stat error wrapped", err)
	}
	if len(p.calls) != 0 {
		t.Errorf("calls = %v, want none", p.calls)
	}
}

func TestCheckWorkDirAcceptsADirectory(t *testing.T) {
	p, _, _ := newProber(t)
	if err := speccapture.CheckWorkDir(p, "/vol/scratch", "probe directory"); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}
