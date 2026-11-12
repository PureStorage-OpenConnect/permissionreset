// Package speccapture reads NFSv4 ACLs from two exemplar objects (a directory
// and a regular file) and produces a validated permissionreset spec YAML.
//
// The package owns no CLI flags and no filesystem or network construction.
// Callers supply a Reader; the package supplies the logic.
package speccapture

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/auditproof"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// Reader is the narrow interface Capture uses to observe the two exemplar
// objects. Implementations may be the kernel or userspace transport; tests use
// a fake. ACLs are read individually -- no batch -- for precise error attribution.
type Reader interface {
	Stat(transport.Ref) (transport.Attr, error)
	GetACL(transport.Ref) ([]byte, error)
}

// Principal kinds, as IdentityReport and Principal.Kind name them.
const (
	KindSpecial      = "special"       // OWNER@, GROUP@, EVERYONE@
	KindNamed        = "named"         // contains '@' but not one of the three special forms
	KindNumericUser  = "numeric user"  // all decimal digits, no g flag
	KindNumericGroup = "numeric group" // all decimal digits, g flag set
)

// KindCounts counts distinct principals by kind.
type KindCounts struct {
	Special      int
	Named        int
	NumericUser  int
	NumericGroup int
}

// Principal is one distinct principal across both exemplars, with where it
// appears. A numeric user and a numeric group with the same id are two
// principals: the g flag, not the spelling, tells them apart.
type Principal struct {
	Who      string // as the server returned it: numeric ids are not resolved
	Group    bool   // the ACE carries the g flag
	Kind     string // one of the Kind constants
	DirDACL  bool   // in an allow or deny ACE on the directory exemplar
	FileDACL bool   // in an allow or deny ACE on the file exemplar
	DirSACL  bool   // in an audit ACE on the directory exemplar
	FileSACL bool   // in an audit ACE on the file exemplar
}

// Where lists the ACLs the principal appears in, e.g. "directory DACL, file SACL".
func (p Principal) Where() string {
	var w []string
	for _, e := range []struct {
		in   bool
		name string
	}{{p.DirDACL, "directory DACL"}, {p.FileDACL, "file DACL"}, {p.DirSACL, "directory SACL"}, {p.FileSACL, "file SACL"}} {
		if e.in {
			w = append(w, e.name)
		}
	}
	return strings.Join(w, ", ")
}

// IdentityReport counts the distinct principals in both exemplar ACLs, once
// each however many ACEs name them. The DACL (allow and deny ACEs) and the
// SACL (audit ACEs) are counted separately; alarm ACEs are left out, as the
// spec leaves them out.
type IdentityReport struct {
	Special      int // distinct DACL principals of each kind
	Named        int
	NumericUser  int
	NumericGroup int
	SACL         KindCounts  // distinct audit-ACE principals of each kind
	Principals   []Principal // every distinct principal, in the order first seen
	Verified     bool        // false from Capture; set to true by a verifier
}

// String renders the report for human consumption (stderr). The last line
// always reports verification status.
func (r IdentityReport) String() string {
	var b strings.Builder
	b.WriteString("ACL identity summary (distinct principals in both exemplars; numeric ids are as the server returned them):\n")
	fmt.Fprintf(&b, "  DACL: special %d, named %d, numeric user %d, numeric group %d\n",
		r.Special, r.Named, r.NumericUser, r.NumericGroup)
	fmt.Fprintf(&b, "  SACL: special %d, named %d, numeric user %d, numeric group %d\n",
		r.SACL.Special, r.SACL.Named, r.SACL.NumericUser, r.SACL.NumericGroup)
	width := 0
	for _, p := range r.Principals {
		if n := len(p.label()); n > width {
			width = n
		}
	}
	for _, p := range r.Principals {
		fmt.Fprintf(&b, "    %-*s  %-13s  %s\n", width, p.label(), p.Kind, p.Where())
	}
	if r.Verified {
		b.WriteString("write verification: passed\n")
	} else {
		b.WriteString("write verification: not performed\n")
	}
	return b.String()
}

// Options selects what a capture with audit ACEs emits and how the capture
// makes reading the exemplars safe. WithDACL has no effect when neither
// exemplar carries an audit (U) ACE: that spec is the DACL spec it has always
// been.
type Options struct {
	// WithDACL also writes each exemplar's DACL as acl:. By default a capture
	// that finds audit ACEs emits DACL-keeping rules (sacl: and no acl:), which
	// leave every object's own DACL in place and replace only its SACL.
	WithDACL bool

	// ProbeDir is a directory where the capture may create and remove a
	// disposable probe to prove the audit bypass before it reads either
	// exemplar's ACL (PS-02). The Reader must also be an auditproof.Prober.
	ProbeDir string

	// OnProof, when set, is called once the audit-bypass proof under ProbeDir
	// passes and before either exemplar's ACL is read, so a caller can report
	// the proof in order with the reads (#31).
	OnProof func(auditproof.Proof)

	// AcceptUnprovenRead reads the exemplars with no proof. On an array where
	// an unprivileged read empties inherited auditing, that read can change
	// the exemplars. Ignored when ProbeDir is set.
	AcceptUnprovenRead bool
}

// ErrUnprovenRead reports a capture asked to read exemplar ACLs with neither
// a probe directory nor an explicit acceptance of the unproven read.
var ErrUnprovenRead = errors.New("reading the exemplar ACLs needs a proven audit bypass first: " +
	"give a probe directory where a disposable object can be created and removed, " +
	"or explicitly accept an unproven read")

// ErrDirMissing reports a probe or scratch directory that does not exist.
// The capture never creates one: a directory it made would be a write left
// behind in the export, and a mistyped path would put it in live data.
var ErrDirMissing = errors.New("does not exist")

// ErrNotDir reports a probe or scratch path that names something other than a
// directory. A symlink counts: following it could move the probe off the mount
// the caller checked.
var ErrNotDir = errors.New("is not a directory")

// CheckWorkDir confirms that path names an existing directory, not a symlink,
// before anything is created under it. label names the path in the error
// ("probe directory", "--verify-write scratch"). It reads only path's
// attributes, never an ACL. A missing path wraps ErrDirMissing, a
// non-directory wraps ErrNotDir, and any other stat failure is returned
// wrapped as is.
func CheckWorkDir(r Reader, path, label string) error {
	a, err := r.Stat(transport.Ref{Path: path})
	if err != nil {
		if isNotExist(err) {
			return fmt.Errorf("%s %q %w", label, path, ErrDirMissing)
		}
		return fmt.Errorf("%s %q: %w", label, path, err)
	}
	if a.IsSymlink {
		return fmt.Errorf("%s %q %w (it is a symlink, which is never followed)", label, path, ErrNotDir)
	}
	if !a.IsDir {
		return fmt.Errorf("%s %q %w", label, path, ErrNotDir)
	}
	return nil
}

// nfsStatuser is implemented by the userspace client's status errors.
type nfsStatuser interface{ NFSStatus() uint32 }

// isNotExist recognizes a missing path from either transport: ENOENT from the
// kernel's lstat, or NFS4ERR_NOENT from the userspace client.
func isNotExist(err error) bool {
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	var se nfsStatuser
	return errors.As(err, &se) && se.NFSStatus() == uint32(xdr.NFS4ERR_NOENT)
}

// proveReadSafe runs before any exemplar ACL is read. It proves the audit
// bypass under opts.ProbeDir, or returns ErrUnprovenRead unless the operator
// accepted the risk, in which case it returns the note to show.
func proveReadSafe(r Reader, opts Options) (note string, err error) {
	if opts.ProbeDir != "" {
		p, ok := r.(auditproof.Prober)
		if !ok {
			return "", fmt.Errorf("probe directory %q: this transport cannot create a disposable probe", opts.ProbeDir)
		}
		if err := CheckWorkDir(r, opts.ProbeDir, "probe directory"); err != nil {
			return "", err
		}
		proof, err := auditproof.Prove(p, transport.Ref{Path: opts.ProbeDir})
		if err != nil {
			return "", fmt.Errorf("probe directory %q: %w", opts.ProbeDir, err)
		}
		if opts.OnProof != nil {
			opts.OnProof(proof)
		}
		return "", nil
	}
	if opts.AcceptUnprovenRead {
		return "the exemplar ACLs were read with no audit-bypass proof; on an array where an " +
			"unprivileged read empties inherited auditing, check the exemplars' audit ACEs from SMB", nil
	}
	return "", ErrUnprovenRead
}

// Result holds the output of a successful Capture call.
type Result struct {
	DirACEs   []string       // formatted DACL (A/D) ACE strings for the directory exemplar
	FileACEs  []string       // formatted DACL (A/D) ACE strings for the file exemplar
	DirSACL   []string       // formatted audit (U) ACE strings for the directory exemplar
	FileSACL  []string       // formatted audit (U) ACE strings for the file exemplar
	KeepsDACL bool           // the YAML has DACL-keeping rules (sacl: without acl:)
	Notes     []string       // operator notes for stderr, one line each, without a NOTE: prefix
	YAML      []byte         // validated spec YAML, ready to write to a file
	Identity  IdentityReport // principal-kind tallies; Verified is always false here
	opts      Options
	proofNote string // the unproven-read note, kept for Verify
}

// HasSACL reports whether either exemplar carried an audit ACE.
func (r *Result) HasSACL() bool { return len(r.DirSACL) > 0 || len(r.FileSACL) > 0 }

// Capture reads ACLs from dir and file, formats them as ACE strings, and
// returns a Result whose YAML has been validated through spec.Parse.
//
// Preconditions checked before any ACL read:
//   - dir must be a directory (IsDir true, IsSymlink false)
//   - file must be a regular non-symlink (IsDir false, IsSymlink false)
//   - reversed order, two directories, two files, symlinks, and stat errors
//     each produce a distinct error.
//
// ACLs are read individually; any FormatACL error names the exemplar and ACE
// index so the operator knows which object has the unsupported mask bit.
func Capture(r Reader, dir, file transport.Ref) (*Result, error) {
	return CaptureWithOptions(r, dir, file, Options{})
}

// CaptureWithOptions is Capture with the audit-ACE output choice made explicit.
func CaptureWithOptions(r Reader, dir, file transport.Ref, opts Options) (*Result, error) {
	// Stat both exemplars before touching any ACL.
	dirAttr, err := r.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat directory exemplar %q: %w", dir.Path, err)
	}
	fileAttr, err := r.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("stat file exemplar %q: %w", file.Path, err)
	}

	if dirAttr.Kind != transport.KindDirectory {
		if fileAttr.Kind == transport.KindDirectory {
			return nil, fmt.Errorf(
				"arguments are reversed: %q is a directory and %q is not; expected (directory, file)",
				file.Path, dir.Path)
		}
		if dirAttr.Kind == transport.KindSymlink {
			return nil, fmt.Errorf("directory exemplar %q is a symlink; provide a real directory", dir.Path)
		}
		return nil, fmt.Errorf("directory exemplar %q is not a directory", dir.Path)
	}
	if fileAttr.Kind == transport.KindDirectory {
		return nil, fmt.Errorf(
			"file exemplar %q is a directory; both arguments are directories -- expected (directory, file)",
			file.Path)
	}
	if fileAttr.Kind == transport.KindSymlink {
		return nil, fmt.Errorf("file exemplar %q is a symlink; provide a regular file", file.Path)
	}
	if fileAttr.Kind != transport.KindRegular {
		return nil, fmt.Errorf("file exemplar %q is not a regular file", file.Path)
	}

	// Prove the read is safe before either ACL is read (PS-02): the warning
	// about unprivileged reads further down comes too late to protect them.
	proofNote, err := proveReadSafe(r, opts)
	if err != nil {
		return nil, err
	}

	// Read ACLs individually for precise error attribution.
	dirRaw, err := r.GetACL(dir)
	if err != nil {
		return nil, fmt.Errorf("get ACL for directory %q: %w", dir.Path, err)
	}
	fileRaw, err := r.GetACL(file)
	if err != nil {
		return nil, fmt.Errorf("get ACL for file %q: %w", file.Path, err)
	}

	// Format ACEs. FormatACL rejects unsupported mask bits and names the ACE index.
	dirACEs, err := nfs4acl.FormatACL(dirRaw)
	if err != nil {
		return nil, fmt.Errorf("directory ACL %q: %w", dir.Path, err)
	}
	fileACEs, err := nfs4acl.FormatACL(fileRaw)
	if err != nil {
		return nil, fmt.Errorf("file ACL %q: %w", file.Path, err)
	}

	idReport := buildIdentityReport(dirRaw, fileRaw)

	res, err := assemble(dirRaw, dirACEs, fileRaw, fileACEs, opts)
	if err != nil {
		return nil, err
	}
	res.Identity = idReport
	res.addProofNote(proofNote)
	return res, nil
}

// addProofNote records the unproven-read note first among the notes, where
// Verify can carry it into the result it rebuilds.
func (r *Result) addProofNote(note string) {
	if note == "" {
		return
	}
	r.proofNote = note
	r.Notes = append([]string{note}, r.Notes...)
}

// assemble splits each exemplar's formatted ACEs into DACL and SACL by type,
// drops alarm (L) ACEs, builds the YAML and validates it through spec.Parse --
// the same validation permissionreset uses at startup. Capture and Verify both end
// here, so a verified spec has the same shape as an unverified one.
func assemble(dirRaw []byte, dirACEs []string, fileRaw []byte, fileACEs []string, opts Options) (*Result, error) {
	res := &Result{opts: opts}
	var alarms int
	var err error
	if res.DirACEs, res.DirSACL, alarms, err = splitByType(dirRaw, dirACEs); err != nil {
		return nil, fmt.Errorf("directory ACL: %w", err)
	}
	fa := 0
	if res.FileACEs, res.FileSACL, fa, err = splitByType(fileRaw, fileACEs); err != nil {
		return nil, fmt.Errorf("file ACL: %w", err)
	}
	alarms += fa

	res.KeepsDACL = res.HasSACL() && !opts.WithDACL
	res.YAML = buildYAML(res)
	if _, err := spec.Parse(res.YAML, "<generated>"); err != nil {
		return nil, fmt.Errorf("internal: generated YAML failed spec validation: %w", err)
	}

	if alarms > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"dropped %d alarm (L) ACE(s): permissionreset cannot write them, and FlashArray does not act on them", alarms))
	}
	switch {
	case res.KeepsDACL:
		res.Notes = append(res.Notes,
			fmt.Sprintf("captured %d audit (U) ACE(s); the spec keeps each object's own DACL and replaces only its SACL "+
				"(to set the DACL as well, capture with --with-dacl, or turn on \"Also write the DACL\" in the desktop app)", len(res.DirSACL)+len(res.FileSACL)),
			"apply it with permissionreset --sacl, as an identity with the array's audit bypass: root over AUTH_SYS with root squash off, "+
				"or an AD identity the array grants it; Domain Admins membership is not enough")
	case res.HasSACL():
		res.Notes = append(res.Notes,
			fmt.Sprintf("captured %d audit (U) ACE(s) as sacl: alongside the DACL (--with-dacl); "+
				"applying this spec replaces every object's DACL", len(res.DirSACL)+len(res.FileSACL)),
			"apply it with permissionreset --sacl, as an identity with the array's audit bypass: root over AUTH_SYS with root squash off, "+
				"or an AD identity the array grants it; Domain Admins membership is not enough")
	}
	if res.HasSACL() {
		for _, e := range []struct {
			kind string
			sacl []string
		}{{"directory", res.DirSACL}, {"file", res.FileSACL}} {
			if len(e.sacl) == 0 {
				res.Notes = append(res.Notes, fmt.Sprintf(
					"the %s exemplar has no audit (U) ACEs, so the %s rule is sacl: [] -- applying it removes "+
						"the audit ACEs from every %s it matches; edit that rule if this is not intended", e.kind, e.kind, e.kind))
			}
		}
	} else {
		res.Notes = append(res.Notes,
			"no audit (U) ACEs were read; on FlashArray an identity without the audit bypass sees none even "+
				"when they exist, and on Purity//FA before 6.12.1 that read also empties an inheriting SACL on the "+
				"exemplar -- capture FlashArray exemplars with the bypass")
		if opts.WithDACL {
			res.Notes = append(res.Notes, "--with-dacl has no effect: there are no audit ACEs, so the spec sets the DACL as always")
		}
	}
	return res, nil
}

// splitByType pairs each formatted ACE with its decoded type. FormatACL emits
// one line per decoded ACE in order, so index i in lines is ACE i in raw.
func splitByType(raw []byte, lines []string) (dacl, sacl []string, alarms int, err error) {
	aces, err := nfs4acl.DecodeACL(raw)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(aces) != len(lines) {
		return nil, nil, 0, fmt.Errorf("internal: %d decoded ACEs but %d formatted lines", len(aces), len(lines))
	}
	for i, ace := range aces {
		switch ace.Type {
		case nfs4acl.TypeAudit:
			sacl = append(sacl, lines[i])
		case nfs4acl.TypeAlarm:
			alarms++
		default:
			dacl = append(dacl, lines[i])
		}
	}
	return dacl, sacl, alarms, nil
}

// buildYAML constructs the spec YAML from formatted ACE slices.
//
// Format contract: two-space indent, double-quoted ACE strings, LF newlines on
// all platforms, exactly one trailing newline, deterministic field order.
// A Linux and Windows capture of the same two server ACLs must produce
// byte-identical output.
//
// With no audit ACEs the output is exactly the DACL spec build-spec has always
// written, with no sacl: key, so it runs without --sacl; under --sacl the SACL
// guard refuses it before it replaces a FlashArray SACL. With audit ACEs
// every rule gets sacl: -- sacl: [] for an exemplar that had none, which is
// what that exemplar says -- and acl: only under --with-dacl.
func buildYAML(r *Result) []byte {
	var b strings.Builder
	// Comment block: note provenance and the file-rule coverage.
	b.WriteString("# build-spec capture -- generated by permissionreset build-spec\n")
	b.WriteString("# type: file also matches FIFO, socket, and device nodes; exclude by name\n")
	b.WriteString("# if the file exemplar's ACL is not appropriate for them.\n")
	if r.KeepsDACL {
		b.WriteString("# Rules with sacl: and no acl: keep each object's own DACL and replace only\n")
		b.WriteString("# its audit (U) ACEs. Apply with the array's audit bypass.\n")
	}
	b.WriteString("protocol: nfsv4\n")
	b.WriteString("default: {}\n")
	b.WriteString("rules:\n")
	writeRule(&b, "directory", r.DirACEs, r.DirSACL, r.HasSACL(), r.KeepsDACL)
	writeRule(&b, "file", r.FileACEs, r.FileSACL, r.HasSACL(), r.KeepsDACL)
	return []byte(b.String())
}

func writeRule(b *strings.Builder, kind string, dacl, sacl []string, withSACL, keepsDACL bool) {
	b.WriteString("  - match:\n")
	fmt.Fprintf(b, "      type: %s\n", kind)
	if !keepsDACL {
		b.WriteString("    acl:\n")
		for _, ace := range dacl {
			fmt.Fprintf(b, "      - %q\n", ace)
		}
	}
	if !withSACL {
		return
	}
	if len(sacl) == 0 {
		b.WriteString("    sacl: []\n")
		return
	}
	b.WriteString("    sacl:\n")
	for _, ace := range sacl {
		fmt.Fprintf(b, "      - %q\n", ace)
	}
}

// specialWho is the set of NFSv4 special principal spellings.
var specialWho = map[string]bool{
	"OWNER@":    true,
	"GROUP@":    true,
	"EVERYONE@": true,
}

// isAllDigits reports whether s is a non-empty string of ASCII decimal digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// label is the principal as the summary prints it: a group's numeric id or
// name gets a "g:" prefix, as in the spec's ACE strings.
func (p Principal) label() string {
	if p.Group && p.Kind != KindSpecial {
		return "g:" + p.Who
	}
	return p.Who
}

// principalKind classifies who. The g flag (nfs4acl.FlagGroup), not the who
// spelling, distinguishes numeric group from numeric user. No local identity
// resolution is performed. A who of no known form returns "".
func principalKind(who string, isGroup bool) string {
	switch {
	case specialWho[who]:
		return KindSpecial
	case strings.Contains(who, "@"):
		return KindNamed
	case isAllDigits(who) && !isGroup:
		return KindNumericUser
	case isAllDigits(who) && isGroup:
		return KindNumericGroup
	}
	return ""
}

func (k *KindCounts) add(kind string) {
	switch kind {
	case KindSpecial:
		k.Special++
	case KindNamed:
		k.Named++
	case KindNumericUser:
		k.NumericUser++
	case KindNumericGroup:
		k.NumericGroup++
	}
}

// buildIdentityReport decodes the directory and file exemplars' raw ACLs and
// counts their distinct principals, DACL and SACL apart.
func buildIdentityReport(dirRaw, fileRaw []byte) IdentityReport {
	var rep IdentityReport
	index := map[string]int{} // principal key -> index in rep.Principals
	for i, raw := range [][]byte{dirRaw, fileRaw} {
		aces, err := nfs4acl.DecodeACL(raw)
		if err != nil {
			continue
		}
		for _, ace := range aces {
			if ace.Type == nfs4acl.TypeAlarm {
				continue
			}
			isGroup := ace.Flags&nfs4acl.FlagGroup != 0
			kind := principalKind(ace.Who, isGroup)
			if kind == "" {
				continue
			}
			// The specials are distinct by name alone; GROUP@ may or may not carry g.
			key := ace.Who
			if kind != KindSpecial && isGroup {
				key = "g:" + key
			}
			n, ok := index[key]
			if !ok {
				n = len(rep.Principals)
				index[key] = n
				rep.Principals = append(rep.Principals, Principal{Who: ace.Who, Group: isGroup && kind != KindSpecial, Kind: kind})
			}
			p := &rep.Principals[n]
			audit := ace.Type == nfs4acl.TypeAudit
			switch {
			case i == 0 && !audit:
				p.DirDACL = true
			case i == 1 && !audit:
				p.FileDACL = true
			case i == 0:
				p.DirSACL = true
			default:
				p.FileSACL = true
			}
		}
	}
	var dacl KindCounts
	for _, p := range rep.Principals {
		if p.DirDACL || p.FileDACL {
			dacl.add(p.Kind)
		}
		if p.DirSACL || p.FileSACL {
			rep.SACL.add(p.Kind)
		}
	}
	rep.Special, rep.Named, rep.NumericUser, rep.NumericGroup = dacl.Special, dacl.Named, dacl.NumericUser, dacl.NumericGroup
	return rep
}
