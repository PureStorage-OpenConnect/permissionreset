package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"gopkg.in/yaml.v3"
)

type Spec struct {
	Protocol string    `yaml:"protocol"`
	Default  RulePerms `yaml:"default"`
	Rules    []Rule    `yaml:"rules"`
	SMB      SMBConfig `yaml:"smb"`

	// Exclude lists glob patterns naming objects the run must not touch. See
	// NewExcluder for the matching rules; the CLI's --exclude flag adds to this
	// list rather than replacing it.
	Exclude []string `yaml:"exclude"`
}

type Rule struct {
	Match     RuleMatch `yaml:"match"`
	RulePerms `yaml:",inline"`
}

type RuleMatch struct {
	Type    string `yaml:"type"`
	Pattern string `yaml:"pattern"`
}

type RulePerms struct {
	Mode  string   `yaml:"mode"`
	ACL   []string `yaml:"acl"`
	DACL  []string `yaml:"dacl"`
	Owner string   `yaml:"owner"`
	Group string   `yaml:"group"`

	// Sacl is the audit ACEs ("U" lines) to write alongside acl:, as a separate
	// list rather than mixed into acl: because they go on the wire last and are
	// validated differently (every line must be type U carrying S, F, or both).
	//
	// It is *[]string, not []string, because the SACL guard (MissingSACL) needs
	// to tell "no sacl: key at all" from "sacl: []" -- an explicit, deliberate
	// empty audit ACL. A plain []string cannot: both decode to a nil/empty
	// slice. A custom UnmarshalYAML was the other option the plan considered,
	// but RulePerms is embedded with `yaml:",inline"` in Rule, and yaml.v3
	// flattens an inlined struct's fields into the parent by reflection rather
	// than calling the inlined type's UnmarshalYAML -- so a custom unmarshaler
	// here would fire for `default:` (a plain nested field) but silently not
	// fire for `rules: [...]` entries (inline). The pointer works identically
	// in both shapes and needs no custom decoder, so KnownFields(true) keeps
	// rejecting unknown keys (e.g. a typo'd sacl_mode:) exactly as it does today.
	Sacl *[]string `yaml:"sacl"`

	// encodedACL is ACL++SACL in wire form, encoded once when the spec is
	// validated.
	//
	// It exists because the apply path used to re-parse and re-encode these
	// strings for every object: a 1.1M-object run spent 280 MB splitting the same
	// handful of ACE lines over and over. The spec is immutable after Load, so
	// the answer is the same every time.
	//
	// Unexported and untagged so YAML neither reads nor writes it -- a spec file
	// cannot supply pre-encoded bytes, and the only way to populate it is to go
	// through the parser that validates them.
	encodedACL []byte

	// saclACEs is Sacl parsed into ACE structs, populated by validatePerms. It
	// exists so encodedACL can be built as Encode(aclACEs ++ saclACEs) without
	// re-parsing the SACL lines, and so a future caller (the privilege preflight)
	// can ask what audit ACEs a rule carries without re-parsing Sacl itself.
	saclACEs []nfs4acl.ACE
}

// KeepDACL reports whether this is a DACL-keeping rule: sacl: is given and
// acl: is not. Such a rule replaces only the object's audit ACEs and leaves the
// DACL the object already has (plan v3), so it has no EncodedACL of its own.
func (p *RulePerms) KeepDACL() bool {
	return p.Sacl != nil && len(p.ACL) == 0
}

// PreserveSACL reports whether this rule replaces the DACL and keeps the
// object's existing audit ACEs: acl: is given and no sacl: key is (PS-04).
// Saying nothing about auditing preserves it; sacl: entries replace it, and
// sacl: [] clears it. Under --sacl such a rule is refused at load instead
// (MissingSACL), so this only governs a run without --sacl.
func (p *RulePerms) PreserveSACL() bool {
	return len(p.ACL) > 0 && p.Sacl == nil
}

// SaclSet reports whether this rule's spec text named a sacl: key at all,
// `sacl: []` included. It is the distinction MissingSACL and the guard act on:
// a nil Sacl means the operator said nothing about auditing, while a non-nil,
// empty Sacl means they said "no audit ACEs, on purpose."
func (p *RulePerms) SaclSet() bool {
	return p.Sacl != nil
}

// SaclACEs returns this rule's audit ACEs, parsed. It exists so a caller
// outside this package -- the privilege preflight -- can ask what audit ACEs a
// rule carries without re-parsing Sacl itself.
//
// Like EncodedACL, it falls back to an on-demand parse when saclACEs was never
// populated: a Spec built by Load always has it precomputed by validatePerms,
// but a struct literal (tests, and nothing stops future code from doing the
// same) has not been through validate(). Returning nil there would be the
// dangerous answer for a caller probing write privilege -- it would read as
// "no audit ACEs configured" for a rule that plainly configures some.
func (p *RulePerms) SaclACEs() []nfs4acl.ACE {
	if p.saclACEs != nil {
		return p.saclACEs
	}
	if p.Sacl == nil {
		return nil
	}
	aces, err := parseACELines(*p.Sacl)
	if err != nil {
		return nil
	}
	return aces
}

// EncodedACL returns the wire-form ACL for these permissions, or nil when none
// is configured. The bytes are shared, not copied: callers must treat them as
// read-only, which every caller does -- they go straight to SetACL or to a
// structural comparison.
//
// A Spec built by Load always has this precomputed. A Spec assembled as a struct
// literal -- which tests do, and which nothing stops future code from doing --
// has not been through validate(), so this encodes on demand instead of
// returning nil. Returning nil would be the dangerous answer: the apply path
// would read it as "no ACL configured" for a rule that plainly configures one,
// and skip objects it was asked to fix.
//
// The fallback is deliberately uncached. Caching it would need a lock or a
// sync.Once here, and this is read concurrently by every apply worker; paying
// for that on every Load-built spec to speed up a path only tests take is the
// wrong trade. The encode is idempotent and the inputs are immutable, so the
// fallback is safe to run concurrently.
func (p *RulePerms) EncodedACL() []byte {
	if p.encodedACL != nil {
		return p.encodedACL
	}
	// No acl: means no fixed bytes: a DACL-keeping rule is built per object
	// from that object's DACL, never from this.
	if len(p.ACL) == 0 {
		return nil
	}
	aclACEs, err := parseACELines(p.ACL)
	if err != nil {
		return nil
	}
	var saclACEs []nfs4acl.ACE
	if p.Sacl != nil {
		saclACEs, err = parseACELines(*p.Sacl)
		if err != nil {
			return nil
		}
	}
	return nfs4acl.Encode(append(aclACEs, saclACEs...))
}

// parseACELines parses a YAML-style ACE list (blank lines and #-comments
// tolerated, same as validatePerms and countACEs) into ACE structs, in order.
func parseACELines(lines []string) ([]nfs4acl.ACE, error) {
	var aces []nfs4acl.ACE
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' {
			continue
		}
		ace, err := nfs4acl.ParseACELine(line)
		if err != nil {
			return nil, err
		}
		aces = append(aces, ace)
	}
	return aces, nil
}

type SMBConfig struct {
	Server      string `yaml:"server"`
	Share       string `yaml:"share"`
	Credentials string `yaml:"credentials"`
}

// Parse parses and validates a spec from in-memory YAML bytes.
// source is used in error messages (e.g. a file path or "<generated>").
// It shares all validation with Load.
func Parse(data []byte, source string) (*Spec, error) {
	var s Spec
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse spec %s: %w", source, err)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("spec %s: %w", source, err)
	}
	return &s, nil
}

func Load(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	return Parse(data, path)
}

var validProtocols = map[string]bool{"posix": true, "nfsv4": true, "smb": true}

func (s *Spec) validate() error {
	if s.Protocol == "" {
		return fmt.Errorf("missing required key 'protocol'")
	}
	if !validProtocols[s.Protocol] {
		return fmt.Errorf("unknown protocol %q (valid: posix, nfsv4, smb)", s.Protocol)
	}

	if err := s.validatePerms("default", &s.Default); err != nil {
		return err
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		label := fmt.Sprintf("rule[%d]", i)
		if r.Match.Type != "" && r.Match.Type != "file" && r.Match.Type != "directory" {
			return fmt.Errorf("%s: unknown match type %q (valid: file, directory)", label, r.Match.Type)
		}
		if r.Match.Pattern != "" {
			if _, err := filepath.Match(r.Match.Pattern, "test"); err != nil {
				return fmt.Errorf("%s: invalid glob pattern %q: %w", label, r.Match.Pattern, err)
			}
		}
		if err := s.validatePerms(label, &r.RulePerms); err != nil {
			return err
		}
	}

	for i, p := range s.Exclude {
		if err := ValidateExcludePattern(p); err != nil {
			return fmt.Errorf("exclude[%d]: %w", i, err)
		}
	}

	if s.Protocol == "smb" {
		return fmt.Errorf("protocol %q is not yet supported; use posix or nfsv4", s.Protocol)
	}

	// Reject specs with no effective operation.
	if !s.hasEffectiveOp() {
		return fmt.Errorf("spec has no effective operation: default and all rules are empty")
	}

	return nil
}

func (s *Spec) hasEffectiveOp() bool {
	if s.Default.Mode != "" || len(s.Default.ACL) > 0 || len(s.Default.DACL) > 0 ||
		s.Default.Owner != "" || s.Default.Group != "" || s.Default.Sacl != nil {
		return true
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		if r.Mode != "" || len(r.ACL) > 0 || len(r.DACL) > 0 ||
			r.Owner != "" || r.Group != "" || r.Sacl != nil {
			return true
		}
	}
	return false
}

func (s *Spec) validatePerms(label string, p *RulePerms) error {
	if p.Owner != "" || p.Group != "" {
		fmt.Fprintf(os.Stderr, "NOTE: %s sets owner/group — use --set-owner to apply (requires root or CAP_CHOWN)\n", label)
	}

	switch s.Protocol {
	case "posix":
		if len(p.ACL) > 0 || len(p.DACL) > 0 {
			return fmt.Errorf("%s: acl/dacl fields are not valid for protocol posix", label)
		}
		if p.Sacl != nil {
			return fmt.Errorf("%s: sacl field is not valid for protocol posix -- posix mode bits have no audit ACEs", label)
		}
		if p.Mode != "" {
			m, err := strconv.ParseUint(p.Mode, 8, 32)
			if err != nil {
				return fmt.Errorf("%s: invalid mode %q: must be octal (e.g. \"0755\")", label, p.Mode)
			}
			if m > 07777 {
				return fmt.Errorf("%s: mode %q exceeds 07777", label, p.Mode)
			}
		}
	case "nfsv4":
		if p.Mode != "" {
			return fmt.Errorf("%s: mode field is not valid for protocol nfsv4", label)
		}
		var aclACEs []nfs4acl.ACE
		for j, line := range p.ACL {
			if strings.TrimSpace(line) == "" || line[0] == '#' {
				continue
			}
			ace, err := nfs4acl.ParseACELine(line)
			if err != nil {
				return fmt.Errorf("%s: acl[%d]: %w", label, j, err)
			}
			switch ace.Type {
			case nfs4acl.TypeAudit:
				return fmt.Errorf("%s: acl[%d]: U (audit) ACEs belong in sacl:, not acl: -- move this line to the sacl list", label, j)
			case nfs4acl.TypeAlarm:
				return fmt.Errorf("%s: acl[%d]: L (alarm) ACEs belong in sacl:, not acl: -- move this line to the sacl list", label, j)
			}
			aclACEs = append(aclACEs, ace)
		}

		var saclACEs []nfs4acl.ACE
		if p.Sacl != nil {
			for j, line := range *p.Sacl {
				if strings.TrimSpace(line) == "" || line[0] == '#' {
					continue
				}
				ace, err := nfs4acl.ParseACELine(line)
				if err != nil {
					return fmt.Errorf("%s: sacl[%d]: %w", label, j, err)
				}
				if ace.Type != nfs4acl.TypeAudit {
					return fmt.Errorf("%s: sacl[%d]: only U (audit) ACEs are valid in a sacl list", label, j)
				}
				if ace.Flags&(nfs4acl.FlagSuccessAccess|nfs4acl.FlagFailedAccess) == 0 {
					return fmt.Errorf("%s: sacl[%d]: a U ACE must carry S, F, or both", label, j)
				}
				saclACEs = append(saclACEs, ace)
			}
		}
		p.saclACEs = saclACEs

		// Encode once, here, where a failure is still a spec error reported
		// before traversal rather than a per-object error 400,000 objects in.
		// The loops above have already established every line parses, so this
		// cannot fail for a reason the caller has not already been told about --
		// but it is checked rather than ignored, because "cannot fail" and "is
		// not checked" is how the two drift apart.
		//
		// The SACL goes last because FA stores it last: the positional ACLEqual
		// comparison --compare and --validate use holds only if this spec's
		// wire order matches what the array hands back.
		//
		// A DACL-keeping rule (sacl: with no acl:) gets no encodedACL: its wire
		// form depends on each object's own DACL, so there is no one set of bytes
		// to cache, and a SACL-only ACL written blind would remove all access.
		if len(aclACEs) > 0 {
			p.encodedACL = nfs4acl.Encode(append(aclACEs, saclACEs...))
		}
	}

	return nil
}

// MissingSACL returns the label of every nfsv4 rule -- "default" or
// "rule[N]", matching the labels validate's own errors use -- that sets acl:
// but names no sacl: key at all. It is empty for a posix spec, since the guard
// only concerns the NFSv4 write that replaces DACL and SACL together.
//
// This is the SACL guard's data: on FlashArray, writing a DACL with no SACL
// deletes whatever audit ACEs the object already carries. internal/run refuses
// a spec with a non-empty MissingSACL() when the operator passes --sacl,
// and a rule that already has sacl: (even sacl: []) is not reported here --
// that is the operator saying what they want, empty or not.
func (s *Spec) MissingSACL() []string {
	if s.Protocol != "nfsv4" {
		return nil
	}
	var out []string
	check := func(label string, p *RulePerms) {
		if len(p.ACL) > 0 && p.Sacl == nil {
			out = append(out, label)
		}
	}
	check("default", &s.Default)
	for i := range s.Rules {
		check(fmt.Sprintf("rule[%d]", i), &s.Rules[i].RulePerms)
	}
	return out
}

// SyntheticRangePrincipals returns "label: who" for every acl: and sacl:
// entry of an nfsv4 rule whose principal is an id at or above
// nfs4acl.SyntheticIDFloor. FlashBlade decodes such ids as 1000000000+RID on
// write (#52, #50), so internal/run refuses an apply that names one.
//
// A numeric who is checked as written. A name@domain who is checked only when
// lookup is non-nil and resolves it, and is reported as "label: who=id". A
// special (OWNER@, EVERYONE@) is never checked.
func (s *Spec) SyntheticRangePrincipals(lookup func(who string, isGroup bool) (string, bool)) []string {
	if s.Protocol != "nfsv4" {
		return nil
	}
	var out []string
	checkLine := func(label, line string) {
		a, err := nfs4acl.ParseACELine(line)
		if err != nil {
			return
		}
		switch {
		case nfs4acl.IsSyntheticRangeWho(a.Who):
			out = append(out, label+": "+a.Who)
		case lookup != nil && strings.Contains(a.Who, "@") && !strings.HasSuffix(a.Who, "@"):
			if id, ok := lookup(a.Who, a.Flags&nfs4acl.FlagGroup != 0); ok && nfs4acl.IsSyntheticRangeWho(id) {
				out = append(out, label+": "+a.Who+"="+id)
			}
		}
	}
	check := func(label string, p *RulePerms) {
		for _, line := range p.ACL {
			checkLine(label, line)
		}
		if p.Sacl != nil {
			for _, line := range *p.Sacl {
				checkLine(label, line)
			}
		}
	}
	check("default", &s.Default)
	for i := range s.Rules {
		check(fmt.Sprintf("rule[%d]", i), &s.Rules[i].RulePerms)
	}
	return out
}

// NamedPrincipals returns one ACE per distinct (who, group flag) named by any
// acl: or sacl: entry of an nfsv4 spec, in first-seen order. Only Who and
// FlagGroup are meaningful in the result. Specials (OWNER@, EVERYONE@) are
// left out, and so is any who that is already nobody (nfs4acl.IsUnmappedWho):
// the probe built from this list asks which principals the array renders as
// nobody, and those were written that way on purpose.
func (s *Spec) NamedPrincipals() []nfs4acl.ACE {
	if s.Protocol != "nfsv4" {
		return nil
	}
	var out []nfs4acl.ACE
	seen := map[nfs4acl.ACE]bool{}
	addLine := func(line string) {
		a, err := nfs4acl.ParseACELine(line)
		if err != nil || strings.HasSuffix(a.Who, "@") || nfs4acl.IsUnmappedWho(a.Who) {
			return
		}
		p := nfs4acl.ACE{Flags: a.Flags & nfs4acl.FlagGroup, Who: a.Who}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add := func(p *RulePerms) {
		for _, line := range p.ACL {
			addLine(line)
		}
		if p.Sacl != nil {
			for _, line := range *p.Sacl {
				addLine(line)
			}
		}
	}
	add(&s.Default)
	for i := range s.Rules {
		add(&s.Rules[i].RulePerms)
	}
	return out
}

// UsesSacl reports whether any nfsv4 rule (default included) carries at least
// one audit ACE, whether alongside acl: (spec-DACL) or on its own
// (DACL-keeping). internal/run consults this to decide whether a run needs
// the privilege preflight to prove the audit-ACE write actually sticks, and
// whether to print the audit-policy NOTE -- both unconditional whenever sacl:
// is in play, so this is the one place that answers "is it".
func (s *Spec) UsesSacl() bool {
	if s.Protocol != "nfsv4" {
		return false
	}
	if len(s.Default.SaclACEs()) > 0 {
		return true
	}
	for i := range s.Rules {
		if len(s.Rules[i].SaclACEs()) > 0 {
			return true
		}
	}
	return false
}

// SaclRules returns the label of every nfsv4 rule that names a sacl: key at
// all, sacl: [] included, using the same labels as MissingSACL. internal/run
// refuses a spec with a non-empty SaclRules() unless the operator passes
// --sacl: writing audit ACEs needs the audit bypass on FlashArray and FlashBlade, so
// it is opt-in rather than something a spec turns on by itself.
func (s *Spec) SaclRules() []string {
	if s.Protocol != "nfsv4" {
		return nil
	}
	var out []string
	if s.Default.Sacl != nil {
		out = append(out, "default")
	}
	for i := range s.Rules {
		if s.Rules[i].Sacl != nil {
			out = append(out, fmt.Sprintf("rule[%d]", i))
		}
	}
	return out
}

// KeepDACLRules returns the label of every nfsv4 rule that is DACL-keeping
// (KeepDACL), using the same labels as MissingSACL.
func (s *Spec) KeepDACLRules() []string {
	if s.Protocol != "nfsv4" {
		return nil
	}
	var out []string
	if s.Default.KeepDACL() {
		out = append(out, "default")
	}
	for i := range s.Rules {
		if s.Rules[i].KeepDACL() {
			out = append(out, fmt.Sprintf("rule[%d]", i))
		}
	}
	return out
}

func (s *Spec) MatchRule(path string, isDir bool) *Rule {
	base := filepath.Base(path)
	for i := range s.Rules {
		r := &s.Rules[i]
		if r.Match.Type == "directory" && !isDir {
			continue
		}
		if r.Match.Type == "file" && isDir {
			continue
		}
		if r.Match.Pattern != "" {
			matched, _ := filepath.Match(r.Match.Pattern, base)
			if !matched {
				continue
			}
		}
		return r
	}
	return nil
}

// EffectivePerms returns the first matching rule, or the default if none match.
// A matching rule REPLACES the default entirely — fields the rule omits are
// zero-valued, not inherited from the default.
func (s *Spec) EffectivePerms(path string, isDir bool) *RulePerms {
	if r := s.MatchRule(path, isDir); r != nil {
		return &r.RulePerms
	}
	return &s.Default
}
