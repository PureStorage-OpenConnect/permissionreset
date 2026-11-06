package run

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/apply"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// aclOnlyTransport answers GetACL with a fixed ACL and records SetACL. Every
// other method panics through the nil embedded interface except ProbeTarget,
// which is implemented so apply.ProveAuditBypass's disposable-probe privilege
// proof (PS-02, run first by runPreflight) can complete -- the point of these
// tests is that nothing is written to the real root, not that the disposable
// probe is never touched. probeACL starts as a copy of acl (so it has
// something to keep) and echoes SetACL so the retention check passes;
// rootWrites, not writes, is what these tests assert is zero.
type aclOnlyTransport struct {
	transport.Transport
	acl        []byte
	probeACL   []byte
	writes     int
	rootWrites int
}

func (a *aclOnlyTransport) ProbeTarget(transport.Ref) (transport.Ref, bool, func() error, error) {
	if a.probeACL == nil {
		a.probeACL = append([]byte(nil), a.acl...)
	}
	return transport.Ref{Path: "/probe-target"}, true, func() error { return nil }, nil
}

func (a *aclOnlyTransport) GetACL(ref transport.Ref) ([]byte, error) {
	if ref.Path == "/probe-target" {
		return a.probeACL, nil
	}
	return a.acl, nil
}

func (a *aclOnlyTransport) SetACL(ref transport.Ref, acl []byte) error {
	a.writes++
	if ref.Path == "/probe-target" {
		a.probeACL = acl
		return nil
	}
	a.rootWrites++
	return nil
}

// TestPreflightRefusesUnmappedRootForKeepDACL is the run-level guard: a
// DACL-keeping spec over a root whose DACL shows the nobody sentinel is
// refused before the probe, with the operator hint, and nothing is written.
func TestPreflightRefusesUnmappedRootForKeepDACL(t *testing.T) {
	_, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")
	tr := &aclOnlyTransport{acl: nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "1402", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Who: "65534", Mask: nfs4acl.MaskReadData},
	})}

	var errOut strings.Builder
	err := runPreflight(tr, Config{Root: "/tree", Spec: s}, &errOut)
	if !errors.Is(err, errRunFailed) || !errors.Is(err, apply.ErrUnmappedPrincipal) {
		t.Fatalf("runPreflight error = %v, want errRunFailed wrapping ErrUnmappedPrincipal", err)
	}
	if tr.rootWrites != 0 {
		t.Fatalf("SetACL to the live root called %d times, want 0", tr.rootWrites)
	}
	for _, want := range []string{"65534", "uidNumber/gidNumber", "SMB side"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, errOut.String())
		}
	}
}

// TestRunKeepDACLApplyNeedsFlatteningAck: an --sacl apply with a DACL-keeping
// rule is refused before the transport is touched unless the operator passes
// --accept-dacl-flattening; dry run and --validate are not refused by it.
func TestRunKeepDACLApplyNeedsFlatteningAck(t *testing.T) {
	keep := "protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n"
	run := func(cfg Config) (string, error) {
		root := t.TempDir()
		specPath, s := writeSpec(t, keep)
		var out, errOut strings.Builder
		cfg.Sacl, cfg.Root, cfg.SpecPath, cfg.Spec = true, root, specPath, s
		cfg.Transport, cfg.Workers, cfg.BatchSize, cfg.Quiet, cfg.ErrOut = "kernel", 1, 1, true, &errOut
		_, err := Run(context.Background(), cfg, &out)
		return errOut.String(), err
	}

	stderr, err := run(Config{Apply: true})
	if !errors.Is(err, ErrDACLFlattening) {
		t.Fatalf("apply without ack: error = %v, want ErrDACLFlattening", err)
	}
	for _, want := range []string{"--accept-dacl-flattening", "SMB side", "Effective access is kept"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}

	for name, cfg := range map[string]Config{
		"apply with ack": {Apply: true, AcceptDACLFlattening: true},
		"dry run":        {DryRun: true},
		"validate":       {Validate: true},
	} {
		if _, err := run(cfg); errors.Is(err, ErrDACLFlattening) {
			t.Errorf("%s: refused with ErrDACLFlattening, want it to get past the ack check", name)
		}
	}
}

// TestRunSpecDACLApplyNeedsNoFlatteningAck: an acl:+sacl: rule writes the
// spec's own DACL, so nothing is flattened and no ack is asked for.
func TestRunSpecDACLApplyNeedsNoFlatteningAck(t *testing.T) {
	root := t.TempDir()
	specPath, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")
	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{Sacl: true, Apply: true, Root: root, SpecPath: specPath, Spec: s,
		Transport: "kernel", Workers: 1, BatchSize: 1, Quiet: true, ErrOut: &errOut}, &out)
	if errors.Is(err, ErrDACLFlattening) {
		t.Fatalf("acl:+sacl: apply refused with ErrDACLFlattening")
	}
}

// TestPreflightKeepsAuditedRootForDACLReset is PS-04: without --sacl, an acl:
// rule with no sacl: key keeps each object's audit ACEs, so an audited root is
// no longer a reason to refuse -- and the preflight never writes the live root.
func TestPreflightKeepsAuditedRootForDACLReset(t *testing.T) {
	_, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n")
	tr := &aclOnlyTransport{acl: nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagSuccessAccess, Who: "EVERYONE@", Mask: nfs4acl.MaskReadData},
	})}
	var errOut strings.Builder
	if err := runPreflight(tr, Config{Root: "/tree", Spec: s}, &errOut); err != nil {
		t.Fatalf("runPreflight error = %v, want nil\n%s", err, errOut.String())
	}
	if tr.rootWrites != 0 {
		t.Fatalf("SetACL to the live root called %d times, want 0", tr.rootWrites)
	}
}

// TestPreflightDACLResetFailsClosedWithoutBypass: a DACL reset that keeps
// auditing reads every object, so a failed audit-bypass proof stops the run
// before any live object is touched.
func TestPreflightDACLResetFailsClosedWithoutBypass(t *testing.T) {
	_, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n")
	tr := &orderingTransport{probeErr: errors.New("probe create denied")}
	var errOut strings.Builder
	if err := runPreflight(tr, Config{Root: "/tree", Spec: s}, &errOut); err == nil {
		t.Fatal("runPreflight() error = nil, want a refusal")
	}
	for _, c := range tr.calls {
		if strings.HasSuffix(c, ":/tree") {
			t.Fatalf("live root was touched (%q) despite a failed bypass proof; call trace=%v", c, tr.calls)
		}
	}
}

// TestPreflightRefusesSyntheticRangeRootForKeepDACL is #52 at the root.
func TestPreflightRefusesSyntheticRangeRootForKeepDACL(t *testing.T) {
	_, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")
	tr := &aclOnlyTransport{acl: nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "1402", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Who: "2000000003", Mask: nfs4acl.MaskReadData},
	})}
	var errOut strings.Builder
	err := runPreflight(tr, Config{Root: "/tree", Spec: s, Sacl: true}, &errOut)
	if !errors.Is(err, apply.ErrSyntheticRangePrincipal) || tr.rootWrites != 0 {
		t.Fatalf("error = %v, root writes = %d; want ErrSyntheticRangePrincipal and no write to the live root", err, tr.rootWrites)
	}
}

// orderingTransport records the sequence of ProbeTarget/GetACL/SetACL calls,
// tagged by the ref path, so a test can assert *when* the live root was
// touched relative to the disposable probe -- not just whether it was.
type orderingTransport struct {
	transport.Transport
	calls    []string
	probeACL []byte
	rootACL  []byte
	probeErr error
}

func (o *orderingTransport) ProbeTarget(transport.Ref) (transport.Ref, bool, func() error, error) {
	o.calls = append(o.calls, "ProbeTarget")
	if o.probeErr != nil {
		return transport.Ref{}, false, nil, o.probeErr
	}
	return transport.Ref{Path: "/probe-target"}, true, func() error {
		o.calls = append(o.calls, "cleanup:/probe-target")
		return nil
	}, nil
}

func (o *orderingTransport) GetACL(ref transport.Ref) ([]byte, error) {
	o.calls = append(o.calls, "GetACL:"+ref.Path)
	if ref.Path == "/probe-target" {
		return o.probeACL, nil
	}
	return o.rootACL, nil
}

func (o *orderingTransport) SetACL(ref transport.Ref, acl []byte) error {
	o.calls = append(o.calls, "SetACL:"+ref.Path)
	if ref.Path == "/probe-target" {
		o.probeACL = acl
	}
	return nil
}

// TestPreflightProvesAuditBypassBeforeAnyLiveRootRead is the PS-02 (#71)
// regression: on an array where an unprivileged read empties inherited
// auditing, CheckKeepDACLTarget's own live GetACL(root) is
// itself destructive. runPreflight must prove the audit bypass on a
// disposable probe target first and never touch the live root (GetACL or
// SetACL) until that proof has succeeded.
func TestPreflightProvesAuditBypassBeforeAnyLiveRootRead(t *testing.T) {
	_, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")
	tr := &orderingTransport{
		probeACL: nfs4acl.Encode([]nfs4acl.ACE{
			{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
		}),
		rootACL: nfs4acl.Encode([]nfs4acl.ACE{
			{Type: nfs4acl.TypeAllow, Who: "1402", Mask: nfs4acl.MaskReadData},
		}),
	}
	var errOut strings.Builder
	if err := runPreflight(tr, Config{Root: "/tree", Spec: s}, &errOut); err != nil {
		t.Fatalf("runPreflight() error = %v, want nil; call trace=%v, stderr=%q", err, tr.calls, errOut.String())
	}

	probeIdx, firstRootTouch := -1, -1
	for i, c := range tr.calls {
		if c == "ProbeTarget" && probeIdx == -1 {
			probeIdx = i
		}
		if strings.HasSuffix(c, ":/tree") && firstRootTouch == -1 {
			firstRootTouch = i
		}
	}
	if probeIdx == -1 {
		t.Fatalf("ProbeTarget was never called; call trace=%v", tr.calls)
	}
	if firstRootTouch == -1 {
		t.Fatalf("the live root (/tree) was never read or written at all; call trace=%v", tr.calls)
	}
	if firstRootTouch < probeIdx {
		t.Fatalf("the live root was touched (call %d) before ProbeTarget ran (call %d); call trace=%v",
			firstRootTouch, probeIdx, tr.calls)
	}
}

// TestPreflightRefusesWithoutTouchingLiveRootWhenBypassProofFails pins the
// fail-closed half of PS-02: when the disposable-probe privilege proof
// itself fails, runPreflight must refuse before ever reading or writing the
// live root -- not fall through to CheckKeepDACLTarget and
// read root anyway.
func TestPreflightRefusesWithoutTouchingLiveRootWhenBypassProofFails(t *testing.T) {
	_, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")
	tr := &orderingTransport{probeErr: errors.New("probe create denied")}
	var errOut strings.Builder
	err := runPreflight(tr, Config{Root: "/tree", Spec: s}, &errOut)
	if err == nil {
		t.Fatal("runPreflight() error = nil, want a refusal")
	}
	for _, c := range tr.calls {
		if strings.HasSuffix(c, ":/tree") {
			t.Fatalf("live root was touched (%q) despite a failed bypass proof; call trace=%v", c, tr.calls)
		}
	}
}

// TestRunHighIDApplyNeedsAllowHighIDs: an apply whose spec names an id at or
// above 1e9 is refused before the transport is touched (#50: FB stored every
// such ACE as a different SID, exit 0). Dry run, --validate and
// --allow-high-ids get past the check with a WARNING instead.
func TestRunHighIDApplyNeedsAllowHighIDs(t *testing.T) {
	high := "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::1402:rwaDxtTnNcCoy\"\n    - \"A::2000000003:rxtncy\"\n"
	run := func(cfg Config) (string, error) {
		root := t.TempDir()
		specPath, s := writeSpec(t, high)
		var out, errOut strings.Builder
		cfg.Root, cfg.SpecPath, cfg.Spec = root, specPath, s
		cfg.Transport, cfg.Workers, cfg.BatchSize, cfg.Quiet, cfg.ErrOut = "kernel", 1, 1, true, &errOut
		_, err := Run(context.Background(), cfg, &out)
		return errOut.String(), err
	}

	stderr, err := run(Config{Apply: true})
	if !errors.Is(err, ErrHighIDPrincipal) {
		t.Fatalf("apply without --allow-high-ids: error = %v, want ErrHighIDPrincipal", err)
	}
	for _, want := range []string{"ERROR:", "default: 2000000003", "--allow-high-ids", "Nothing was written"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}

	for name, cfg := range map[string]Config{
		"apply with --allow-high-ids": {Apply: true, AllowHighIDs: true},
		"dry run":                     {DryRun: true},
		"validate":                    {Validate: true},
	} {
		stderr, err := run(cfg)
		if errors.Is(err, ErrHighIDPrincipal) {
			t.Errorf("%s: refused with ErrHighIDPrincipal, want only a WARNING", name)
		}
		want := "WARNING: the spec names principals with ids at or above 1000000000"
		if cfg.AllowHighIDs {
			// The operator has said the target is not a FlashBlade, so only a
			// one-line NOTE is printed, not the FlashBlade warning.
			want = "NOTE: --allow-high-ids: 1 spec principal(s)"
			if strings.Contains(stderr, "WARNING:") {
				t.Errorf("%s: stderr still carries the FlashBlade WARNING:\n%s", name, stderr)
			}
		}
		if !strings.Contains(stderr, want) {
			t.Errorf("%s: stderr missing %q:\n%s", name, want, stderr)
		}
	}
}

// TestRunHighIDNamedPrincipal: a name that resolves to a high id is refused
// the same way, and the error shows the id it resolved to.
func TestRunHighIDNamedPrincipal(t *testing.T) {
	old := highIDLookup
	defer func() { highIDLookup = old }()
	highIDLookup = func(who string, isGroup bool) (string, bool) {
		if who == "sacl-map-grp@example.net" && isGroup {
			return "1880600173", true
		}
		return "", false
	}

	root := t.TempDir()
	specPath, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::1402:rwaDxtTnNcCoy\"\n    - \"A:g:sacl-map-grp@example.net:rxtncy\"\n")
	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{Apply: true, Root: root, SpecPath: specPath, Spec: s,
		Transport: "kernel", Workers: 1, BatchSize: 1, Quiet: true, ErrOut: &errOut}, &out)
	if !errors.Is(err, ErrHighIDPrincipal) {
		t.Fatalf("error = %v, want ErrHighIDPrincipal", err)
	}
	if !strings.Contains(errOut.String(), "sacl-map-grp@example.net=1880600173") {
		t.Errorf("stderr does not name the resolved id:\n%s", errOut.String())
	}
}

// TestNeedsAuditBypassProof pins which nfsv4 runs read existing objects' ACLs
// and so must prove the audit bypass first: --validate always reads, and
// --compare reads before a blind acl:+sacl: write it may skip.
func TestNeedsAuditBypassProof(t *testing.T) {
	_, dacl := writeSpec(t, "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n")
	_, both := writeSpec(t, saclSpecDACL)
	_, posix := writeSpec(t, posixSpec)
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"DACL reset apply", Config{Spec: dacl}, true},
		{"DACL reset validate", Config{Spec: dacl, Validate: true}, true},
		{"acl+sacl apply", Config{Spec: both, Sacl: true}, false},
		{"acl+sacl compare", Config{Spec: both, Sacl: true, Compare: true}, true},
		{"acl+sacl validate", Config{Spec: both, Sacl: true, Validate: true}, true},
		{"posix validate", Config{Spec: posix, Validate: true}, false},
		{"posix compare", Config{Spec: posix, Compare: true}, false},
	}
	for _, c := range cases {
		if got := needsAuditBypassProof(c.cfg); got != c.want {
			t.Errorf("%s: needsAuditBypassProof = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestPreflightCompareFailsClosedWithoutBypass: --compare reads every object
// before an acl:+sacl: write, so a failed proof stops the run before the live
// root is touched.
func TestPreflightCompareFailsClosedWithoutBypass(t *testing.T) {
	_, s := writeSpec(t, saclSpecDACL)
	tr := &orderingTransport{probeErr: errors.New("probe create denied")}
	var errOut strings.Builder
	if err := runPreflight(tr, Config{Root: "/tree", Spec: s, Sacl: true, Compare: true}, &errOut); err == nil {
		t.Fatal("runPreflight() error = nil, want a refusal")
	}
	for _, c := range tr.calls {
		if strings.HasSuffix(c, ":/tree") {
			t.Fatalf("live root was touched (%q) despite a failed bypass proof; call trace=%v", c, tr.calls)
		}
	}
}

// TestProveAuditBypassAloneLeavesTheRootUntouched: the --validate proof for a
// spec with no sacl: key touches only the disposable probe.
func TestProveAuditBypassAloneLeavesTheRootUntouched(t *testing.T) {
	_, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n")
	tr := &orderingTransport{probeErr: errors.New("probe create denied")}
	var errOut strings.Builder
	if err := proveAuditBypass(tr, Config{Root: "/tree", Spec: s, Validate: true}, &errOut); err == nil {
		t.Fatal("proveAuditBypass() error = nil, want a refusal")
	}
	for _, c := range tr.calls {
		if strings.HasSuffix(c, ":/tree") {
			t.Fatalf("live root was touched (%q); call trace=%v", c, tr.calls)
		}
	}
	if !strings.Contains(errOut.String(), "ERROR:") {
		t.Errorf("stderr = %q, want the failure rendered", errOut.String())
	}
}

// TestDryRunCompareNotesNoEffect: an nfsv4 dry run reads no ACL, so --compare
// cannot skip matching objects; the run says so instead of implying a diff.
func TestDryRunCompareNotesNoEffect(t *testing.T) {
	root := t.TempDir()
	specPath, s := writeSpec(t, "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n")
	var out, errOut strings.Builder
	_, _ = Run(context.Background(), Config{DryRun: true, Compare: true, Root: root, SpecPath: specPath, Spec: s,
		Transport: "kernel", Workers: 1, BatchSize: 1, Quiet: true, ErrOut: &errOut}, &out)
	if !strings.Contains(errOut.String(), "NOTE: --compare has no effect on an nfsv4 dry run") {
		t.Fatalf("stderr missing the dry-run --compare NOTE:\n%s", errOut.String())
	}
}
