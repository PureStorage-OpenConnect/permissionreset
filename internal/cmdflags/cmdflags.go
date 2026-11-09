// Package cmdflags holds the command-line plumbing all three binaries share:
// the platform gate that hides and refuses what a build cannot do, and the
// AUTH_SYS credential flags.
//
// It exists as a package rather than as a copy per command because what is
// being shared is an operator-visible CONTRACT -- which flags refuse, and with
// what words -- not a utility. Two copies of a contract have two owners, no
// shared test, and drift that no failing test reports.
package cmdflags

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
)

// Capability is one thing a build can or cannot do, carrying enough identity to
// explain itself.
//
// Name is what is missing, phrased as a capability rather than as an operating
// system. Needs is what would restore it, or the alternative that works here.
// A gate parameterised on a bare bool can say neither, which is why the
// previous revision's message was hardcoded to "requires Linux" -- a sentence
// that is wrong the first time a capability is false on a Linux build.
type Capability struct {
	Supported bool
	Name      string // "the NFSv4 ACL extended attribute system.nfs4_acl"
	Needs     string // "use --transport=userspace, which speaks NFSv4.1 directly"
}

func KernelTransport(c platform.Capabilities) Capability {
	return Capability{
		Supported: c.KernelTransport,
		Name:      "the NFSv4 ACL extended attribute system.nfs4_acl, a Linux NFS client feature",
		Needs:     "use --transport=userspace, which speaks NFSv4.1 to the array directly and needs no mount",
	}
}

func Pfind(c platform.Capabilities) Capability {
	return Capability{
		Supported: c.Pfind,
		Name:      "RapidFile pfind enumerating a mounted export",
		Needs:     "drop the flag; the built-in parallel walk is the default and needs nothing installed",
	}
}

// Gate registers flags that only function on some builds.
//
// It registers the flag EVERYWHERE and refuses an explicit use, rather than
// declining to register it. Omitting the flag makes the flag package answer
// "flag provided but not defined: -pfind" and exit 2, which reads like a typo
// rather than a platform limit and misleads anyone porting a working Linux
// command line. Registering everywhere also means the flag surface cannot
// silently diverge between platforms.
//
// Hiding uses the idiom already in each command: the custom fs.Usage skips any
// flag whose usage string is empty, which is how -cpuprofile, -memprofile and
// -rpc-stats stay out of --help while remaining functional.
type Gate struct {
	OS   string // caps.OS, not runtime.GOOS: tests pretend to be another platform
	Arch string // runtime.GOARCH

	gated  []gatedFlag  // refused whenever typed
	values []gatedValue // refused only for one value
}

type gatedFlag struct {
	name string
	cap  Capability
}

type gatedValue struct {
	name  string
	value string
	cap   Capability
}

// Bool registers a boolean flag that no value of works without c.
func (g *Gate) Bool(fs *flag.FlagSet, c Capability, name string, def bool, usage string) *bool {
	if !c.Supported {
		usage = ""
		g.gated = append(g.gated, gatedFlag{name: name, cap: c})
	}
	return fs.Bool(name, def, usage)
}

// String registers a string flag that no value of works without c. For a flag
// where only SOME values need c -- --transport is the example, since userspace
// is exactly what works where kernel does not -- register it with fs.String and
// call Value instead.
func (g *Gate) String(fs *flag.FlagSet, c Capability, name, def, usage string) *string {
	if !c.Supported {
		usage = ""
		g.gated = append(g.gated, gatedFlag{name: name, cap: c})
	}
	return fs.String(name, def, usage)
}

// Value records that one value of an otherwise-supported flag needs c. The flag
// keeps its usage string and stays in --help, because the operator has a real
// choice to make and the help text is where they make it.
//
// This is the difference between telling a Mac operator "--transport requires
// Linux" -- for a flag whose working value they may well have typed -- and
// telling them which value is unavailable and why.
func (g *Gate) Value(name, value string, c Capability) {
	if !c.Supported {
		g.values = append(g.values, gatedValue{name: name, value: value, cap: c})
	}
}

// Reject reports EVERY refusal this command line earns and returns true if
// there was at least one.
//
// explicit comes from tuning.Explicit(fs), which lists TYPED flags rather than
// flags holding a non-zero value, so a gated flag sitting at its default is
// silent. values maps flag name to its parsed value, for the value gates; it is
// consulted whether or not the flag was typed, because an unsupported DEFAULT is
// just as broken as an unsupported argument.
func (g *Gate) Reject(explicit map[string]bool, values map[string]string, errOut io.Writer) bool {
	var msgs []string
	for _, gf := range g.gated {
		if explicit[gf.name] {
			msgs = append(msgs, fmt.Sprintf(
				"error: --%s is unavailable on this build (%s/%s): it needs %s\n  %s",
				gf.name, g.OS, g.Arch, gf.cap.Name, gf.cap.Needs))
		}
	}
	for _, gv := range g.values {
		if values[gv.name] == gv.value {
			msgs = append(msgs, fmt.Sprintf(
				"error: --%s=%s is unavailable on this build (%s/%s): it needs %s\n  %s",
				gv.name, gv.value, g.OS, g.Arch, gv.cap.Name, gv.cap.Needs))
		}
	}
	if len(msgs) == 0 {
		return false
	}
	sort.Strings(msgs) // stable output regardless of registration order
	for _, m := range msgs {
		fmt.Fprintln(errOut, m)
	}
	return true
}

// GatedNames returns the names this gate refuses outright, for the
// completeness test each command carries. Value gates are not included: their
// flag is supported and visible.
func (g *Gate) GatedNames() []string {
	out := make([]string, 0, len(g.gated))
	for _, gf := range g.gated {
		out = append(out, gf.name)
	}
	sort.Strings(out)
	return out
}

// localUIDCeiling is the uid below which an id looks like a local account
// rather than a directory one. 1000 is the conventional first non-system uid on
// Linux; macOS starts local accounts at 501, which is comfortably under it.
const localUIDCeiling = 1000

// CurrentAuthSys is the process credential, injectable so a test can decide
// what "the running user" is. Without the seam the default-path warning below
// cannot be tested, and an untestable warning is how the previous revision came
// to assert that the default path is silent.
var CurrentAuthSys = nfs41.CurrentAuthSys

// ProcessCredentialNotes is injectable for the same reason CurrentAuthSys is:
// what this process's group list happens to be is not something a test can
// arrange, and a note nothing can exercise is a note nothing keeps true.
var ProcessCredentialNotes = nfs41.ProcessCredentialNotes

// credentialFromProcess mirrors platform.CredentialFromProcess as a var so
// tests running on Linux/Darwin can exercise the Windows code path that refuses
// userspace startup without explicit --auth-uid and --auth-gid. Production
// code reads the constant (via this var's initialiser), so there is no runtime
// overhead and no divergence.
var credentialFromProcess = platform.CredentialFromProcess

// AuthFlags is the four-flag AUTH_SYS surface, shared by every command that can
// speak the userspace transport.
type AuthFlags struct {
	UID      *int
	GID      *int
	GIDs     *string
	Hostname *string
}

// RegisterAuth registers the four flags. qualify wraps each usage string, so a
// command with two transports can append "(--transport=userspace only)" and a
// command with one can leave it off; pass an identity function if there is
// nothing to say.
//
// These flags are NOT gated. They work on Linux too -- they are how you run as
// a different identity without sudo -u.
func RegisterAuth(fs *flag.FlagSet, qualify func(string) string) *AuthFlags {
	return &AuthFlags{
		UID:      fs.Int("auth-uid", 0, qualify("AUTH_SYS uid (default: the running user)")),
		GID:      fs.Int("auth-gid", 0, qualify("AUTH_SYS gid (default: the running user)")),
		GIDs:     fs.String("auth-gids", "", qualify("AUTH_SYS auxiliary gids, comma-separated (default: the running user's groups)")),
		Hostname: fs.String("auth-hostname", "", qualify("AUTH_SYS machine name (default: os.Hostname)")),
	}
}

// Resolve builds the AUTH_SYS credential the userspace transport will present,
// and the warnings worth printing about it.
//
// It returns nil when the operator named none of the four flags, which tells
// nfs41 to build the credential from the process exactly as it always has. Any
// explicit flag produces a whole credential: the fields not named are filled
// from the process, so --auth-uid alone does not silently blank the gid and the
// auxiliary group list.
//
// The warnings inspect the EFFECTIVE uid, typed or not. The default,
// process-derived credential is the case they exist for -- a Mac's local uid is
// typically 501 and means nothing to the array -- and a warning that only fires
// when the operator typed a number is a warning for the case where they had
// already thought about it.
//
// They fire only on the userspace transport, because AUTH_SYS is what that
// transport puts on the wire; a kernel-transport run authenticates through the
// mount and never sends this credential. They never block: a lab export may
// well accept a low uid, and refusing would make --auth-uid mandatory for a
// working configuration.
func (a *AuthFlags) Resolve(explicit map[string]bool, transport string) (*nfs41.AuthSys, []string, error) {
	// On platforms where os.Getuid/os.Getgid return -1 (Windows), casting to
	// uint32 gives 4294967295 — not a valid AUTH_SYS identity. Refuse before
	// reading any process state so the garbage value never reaches the wire.
	if !credentialFromProcess && transport == "userspace" &&
		(!explicit["auth-uid"] || !explicit["auth-gid"]) {
		return nil, nil, fmt.Errorf(
			"--auth-uid and --auth-gid are required on this platform: " +
				"the process uid/gid are not available (os.Getuid and os.Getgid return -1). " +
				"Provide both flags to identify yourself to the array")
	}

	var auth nfs41.AuthSys
	if credentialFromProcess {
		auth = CurrentAuthSys()
	} else {
		// No usable process credential; seed the machine name from os.Hostname
		// so the field is meaningful even when uid/gid come entirely from flags.
		host, err := os.Hostname()
		if err != nil {
			host = "localhost"
		}
		auth.Machine = host
	}

	typed := explicit["auth-uid"] || explicit["auth-gid"] ||
		explicit["auth-gids"] || explicit["auth-hostname"]

	if explicit["auth-uid"] {
		if *a.UID < 0 {
			return nil, nil, fmt.Errorf("--auth-uid must not be negative: %d", *a.UID)
		}
		auth.UID = uint32(*a.UID)
	}
	if explicit["auth-gid"] {
		if *a.GID < 0 {
			return nil, nil, fmt.Errorf("--auth-gid must not be negative: %d", *a.GID)
		}
		auth.GID = uint32(*a.GID)
	}
	if explicit["auth-gids"] {
		parsed, err := ParseGIDList(*a.GIDs)
		if err != nil {
			return nil, nil, err
		}
		auth.AuxGIDs = parsed
	}
	if explicit["auth-hostname"] {
		if *a.Hostname == "" {
			return nil, nil, fmt.Errorf("--auth-hostname must not be empty")
		}
		auth.Machine = *a.Hostname
	}

	warnings := credentialWarnings(auth, transport)

	// Only when the operator did not name the list: --auth-gids replaces the
	// process groups outright, so what the process happened to carry is no
	// longer a fact about the credential going on the wire. An over-long
	// explicit list is refused at encode, not truncated.
	if transport == "userspace" && !explicit["auth-gids"] {
		warnings = append(warnings, ProcessCredentialNotes()...)
	}

	if !typed {
		// Nil, not &auth: "nothing was typed" must keep meaning "let nfs41 build
		// it", so this task changes no behaviour for a run that names no flag.
		return nil, warnings, nil
	}
	return &auth, warnings, nil
}

// credentialWarnings inspects the credential that will actually go on the wire.
func credentialWarnings(auth nfs41.AuthSys, transport string) []string {
	if transport != "userspace" {
		return nil
	}
	switch {
	case auth.UID == 0:
		// Deliberately silent. Root squash is real and common, but so is a
		// Linux operator running the userspace transport under sudo against an
		// export that does not squash -- a supported configuration that worked
		// for months without comment. Warning on every uid-0 run makes the one
		// warning channel the credential path has cry wolf on the case the
		// operator already understands. The fact is not lost: it is reported by
		// run.rootSquashHint as an explanation attached to a failure that
		// actually happened, which is where it tells the operator something.
		return nil
	case auth.UID < localUIDCeiling:
		return []string{
			fmt.Sprintf("WARNING: the AUTH_SYS uid is %d, which looks like a local account rather "+
				"than a directory one; the array resolves ids from its own directory and a local "+
				"uid usually means nothing to it. Give --auth-uid/--auth-gid to say who you are.",
				auth.UID),
		}
	}
	return nil
}

// RegisterSacl registers --sacl, SACL mode for a FlashArray run. Without it a
// spec that names sacl: is refused and acl: specs run as they always have.
// With it, internal/run also refuses an NFSv4 rule that sets acl: with no
// sacl: key (Spec.MissingSACL), because on FlashArray writing that DACL
// deletes the object's existing audit ACEs, and runs the audit-bypass
// preflight.
//
// Not gated through Gate: every build that can write an NFSv4 ACL can write
// audit ACEs, so there is no platform this flag is unavailable on.
func RegisterSacl(fs *flag.FlagSet) *bool {
	return fs.Bool("sacl", false,
		"SACL mode: allow sacl: (audit ACEs) in the spec, and refuse any acl: rule without a sacl: key, since on FlashArray and FlashBlade that write deletes the object's existing audit ACEs")
}

// RegisterAcceptDACLFlattening registers --accept-dacl-flattening. internal/run
// refuses to apply a DACL-keeping (sacl:-only) rule without it: FlashArray's NFS
// view carries no inherited marker, so writing the DACL back stores every
// inherited ACE as explicit and marks the DACL protected (D:P). Effective access is
// kept, but Windows inheritance is not (RISKS.md #11).
func RegisterAcceptDACLFlattening(fs *flag.FlagSet) *bool {
	return fs.Bool("accept-dacl-flattening", false,
		"with --sacl, allow a sacl:-only (DACL-keeping) apply although FlashArray stores every inherited ACE it writes back as explicit and marks the DACL protected (D:P); effective access is kept, Windows inheritance is not. For SMB-written data, add the SACL over SMB instead")
}

// RegisterAllowAuditedDACLReset registers --allow-audited-dacl-reset. Without
// it a DACL reset refuses each object that already carries audit ACEs
// (apply.ErrAuditedObject): FlashArray marks the SACL and DACL protected on
// any NFS ACL write (S:AI -> S:P, D:AI -> D:P), so the audit entries survive
// but their Windows inheritance does not. The kernel transport cannot tell
// FlashArray from FlashBlade, so the refusal applies on both.
func RegisterAllowAuditedDACLReset(fs *flag.FlagSet) *bool {
	return fs.Bool("allow-audited-dacl-reset", false,
		"without --sacl, let a DACL reset write objects that carry audit ACEs. The audit entries are kept, but FlashArray marks the SACL and DACL protected (S:AI -> S:P, D:AI -> D:P), so their Windows inheritance is lost. For SMB-written data, reset those objects over SMB instead")
}

// RegisterAllowHighIDs registers --allow-high-ids. internal/run refuses to apply
// a spec that names an id at or above 1000000000 without it: FlashBlade decodes
// every such id as 1000000000+RID on an NFS write, so the ACE lands on a
// different SID (RISKS.md #12). FlashArray is not affected, and the kernel
// transport cannot tell the two apart, so the operator says which it is.
func RegisterAllowHighIDs(fs *flag.FlagSet) *bool {
	return fs.Bool("allow-high-ids", false,
		"allow an apply whose spec names ids at or above 1000000000. FlashBlade stores such ids as a different SID (1000000000 + RID); pass it only for FlashArray, or for FlashBlade ids that are already the array's own 1000000000 + RID form")
}

// ParseGIDList turns "10020,10021" into []uint32. An empty string is an empty
// list, which is a legitimate thing to send: it says the identity belongs to no
// auxiliary groups, which is different from saying nothing about them.
func ParseGIDList(s string) ([]uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []uint32{}, nil
	}
	parts := strings.Split(s, ",")
	out := make([]uint32, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("--auth-gids: %q is not a number", p)
		}
		if n < 0 {
			return nil, fmt.Errorf("--auth-gids: %d must not be negative", n)
		}
		out = append(out, uint32(n))
	}
	return out, nil
}
