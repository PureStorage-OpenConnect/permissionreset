// Package saclplan turns a loaded permissionreset spec into the JSON plan that
// tools/set-saclonly/Set-SaclOnly.ps1 reads to write SACLs over SMB.
//
// The plan exists so that the spec has one parser. Set-SaclOnly selects
// objects with the same rules and excludes permissionreset would, and writes the
// audit ACEs those rules name; everything that decides what a spec means --
// validation, rule labels, the exclude split, the NFSv4-to-Windows ACE
// translation -- happens here, and PowerShell only matches and writes.
package saclplan

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
)

// Schema is the plan format version. Bump it on any change a consumer would
// have to know about.
const Schema = 1

// SchemaSMB is the version of the plan BuildSMB makes for permissionreset-smb:
// schema 1 plus each rule's DACL (Rule.Dacl), and stricter principals. Schema 1
// stays what --sacl-plan writes, because Set-SaclOnly reads only schema 1.
const SchemaSMB = 2

// Windows ACE types for the DACL (MS-DTYP 2.4.4.1).
const (
	WindowsAllowType = 0
	WindowsDenyType  = 1
)

// WindowsAuditType is SYSTEM_AUDIT_ACE_TYPE.
const WindowsAuditType = 2

// Windows ACE header flags. The bit values differ from NFSv4's, which is why
// TranslateFlags maps them one by one rather than copying the word.
const (
	WinObjectInherit    = 0x01 // OI
	WinContainerInherit = 0x02 // CI
	WinNoPropagate      = 0x04 // NP
	WinInheritOnly      = 0x08 // IO
	WinInherited        = 0x10 // ID
	WinSuccessfulAccess = 0x40 // SA
	WinFailedAccess     = 0x80 // FA
)

// flagMap is NFSv4 flag -> Windows flag and SDDL token, in the order Windows
// itself writes the tokens. FlagGroup is absent: it has no Windows bit and is
// reported as ACE.Group instead.
var flagMap = []struct {
	nfs4 uint32
	win  uint8
	sddl string
}{
	{nfs4acl.FlagFileInherit, WinObjectInherit, "OI"},
	{nfs4acl.FlagDirInherit, WinContainerInherit, "CI"},
	{nfs4acl.FlagNoPropInherit, WinNoPropagate, "NP"},
	{nfs4acl.FlagInheritOnly, WinInheritOnly, "IO"},
	{nfs4acl.FlagInherited, WinInherited, "ID"},
	{nfs4acl.FlagSuccessAccess, WinSuccessfulAccess, "SA"},
	{nfs4acl.FlagFailedAccess, WinFailedAccess, "FA"},
}

// windowsMaskBits is every NFSv4 mask bit that has the same value and meaning
// as a Windows FILE_* or standard right.
const windowsMaskBits = nfs4acl.MaskReadData | nfs4acl.MaskWriteData | nfs4acl.MaskAppendData |
	nfs4acl.MaskReadNamedAttrs | nfs4acl.MaskWriteNamedAttrs | nfs4acl.MaskExecute |
	nfs4acl.MaskDeleteChild | nfs4acl.MaskReadAttributes | nfs4acl.MaskWriteAttributes |
	nfs4acl.MaskDelete | nfs4acl.MaskReadACL | nfs4acl.MaskWriteACL |
	nfs4acl.MaskWriteOwner | nfs4acl.MaskSynchronize

// wellKnown maps the NFSv4 special principals to their SID and SDDL alias.
// The match is exact: RFC 7530 specials are upper case, and a lower-case
// "everyone@" is left for PowerShell to fail to resolve rather than guessed at.
var wellKnown = map[string]struct{ sid, alias string }{
	"EVERYONE@": {"S-1-1-0", "WD"},
	"OWNER@":    {"S-1-3-0", "CO"},
	"GROUP@":    {"S-1-3-1", "CG"},
}

type Plan struct {
	Schema   int     `json:"schema"`
	Source   string  `json:"source"`
	Protocol string  `json:"protocol"`
	Exclude  Exclude `json:"exclude"`
	Default  Rule    `json:"default"`
	Rules    []Rule  `json:"rules"`
}

// Exclude is the spec's exclude list, raw and split the way spec.NewExcluder
// splits it on Linux.
type Exclude struct {
	Patterns []string `json:"patterns"`
	Base     []string `json:"base"`
	Path     []string `json:"path"`
}

type Rule struct {
	Label    string `json:"label"`
	Match    Match  `json:"match"`
	SaclSet  bool   `json:"sacl_set"`
	KeepDACL bool   `json:"keep_dacl"`
	HasACL   bool   `json:"has_acl"`
	HasDACL  bool   `json:"has_dacl"`
	HasMode  bool   `json:"has_mode"`
	Owner    string `json:"owner"`
	Group    string `json:"group"`
	Sacl     []ACE  `json:"sacl"`
	// Dacl is the rule's acl: lines translated, set only by BuildSMB and only
	// when the rule has acl:. Absent means the rule says nothing about the DACL.
	Dacl []ACE `json:"dacl,omitempty"`
}

type Match struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

type ACE struct {
	Line         string `json:"line"`
	NFS4Flags    uint32 `json:"nfs4_flags"`
	NFS4Mask     uint32 `json:"nfs4_mask"`
	WindowsType  int    `json:"windows_type"`
	WindowsFlags uint8  `json:"windows_flags"`
	WindowsMask  uint32 `json:"windows_mask"`
	Principal    string `json:"principal"`
	Group        bool   `json:"group"`
	SID          string `json:"sid"`
	SDDL         string `json:"sddl"`
}

// Build makes the plan for a spec that spec.Load has already validated. source
// is the spec path as the operator gave it. Only nfsv4 specs have a plan.
//
// Rules that are not sacl:-only are reported, not refused: Set-SaclOnly
// decides what it will do with them.
func Build(s *spec.Spec, source string) (*Plan, error) {
	if s.Protocol != "nfsv4" {
		return nil, fmt.Errorf("spec %s: protocol is %q; a SACL plan needs protocol nfsv4", source, s.Protocol)
	}
	patterns := append([]string{}, s.Exclude...)
	// spec.Load checks for an absolute pattern with filepath.IsAbs, which on
	// Windows lets "/abs/x" through. permissionreset runs on Linux and would refuse
	// it, so the plan refuses it too rather than handing PowerShell a pattern
	// permissionreset never accepts.
	for i, pat := range patterns {
		if path.IsAbs(pat) {
			return nil, fmt.Errorf("spec %s: exclude[%d]: absolute exclude pattern %q can never match (paths are matched relative to the target root)", source, i, pat)
		}
	}
	base, rel := spec.SplitExcludes(patterns)
	p := &Plan{
		Schema:   Schema,
		Source:   source,
		Protocol: s.Protocol,
		Exclude:  Exclude{Patterns: patterns, Base: base, Path: rel},
		Rules:    []Rule{},
	}
	var err error
	if p.Default, err = buildRule("default", spec.RuleMatch{}, &s.Default); err != nil {
		return nil, err
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		pr, err := buildRule(fmt.Sprintf("rule[%d]", i), r.Match, &r.RulePerms)
		if err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, pr)
	}
	return p, nil
}

// BuildSMB makes the schema 2 plan that permissionreset-smb reads. On top of
// Build it translates every rule's acl: lines to Rule.Dacl, and refuses what
// the SMB write path cannot write faithfully (smb/DESIGN-write-path.md, 2.3):
//   - an I (inherited) flag in any ACE: inheritance is computed, and a written
//     ID ACE that does not match the parent is a frozen copy;
//   - OWNER@ or GROUP@ in acl:: on Windows they become CREATOR OWNER/GROUP,
//     which do not mean the object's owner or group;
//   - a numeric principal or owner/group: an SMB ACE needs a SID;
//   - dacl: (a field no SMB rule defines).
func BuildSMB(s *spec.Spec, source string) (*Plan, error) {
	p, err := Build(s, source)
	if err != nil {
		return nil, err
	}
	p.Schema = SchemaSMB
	if err := smbRule(&p.Default, &s.Default); err != nil {
		return nil, err
	}
	for i := range s.Rules {
		if err := smbRule(&p.Rules[i], &s.Rules[i].RulePerms); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func smbRule(r *Rule, rp *spec.RulePerms) error {
	if len(rp.DACL) > 0 {
		return fmt.Errorf("%s: dacl: is not supported in an SMB plan; use acl: instead", r.Label)
	}
	for _, f := range []struct{ name, v string }{{"owner", rp.Owner}, {"group", rp.Group}} {
		if isNumeric(f.v) {
			return fmt.Errorf("%s: %s %q is a numeric id; an SMB plan needs a name that resolves to a SID", r.Label, f.name, f.v)
		}
	}
	for j, a := range r.Sacl {
		if err := smbPrincipalOK(a, false); err != nil {
			return fmt.Errorf("%s: sacl[%d]: %w", r.Label, j, err)
		}
	}
	if !r.HasACL {
		return nil
	}
	r.Dacl = []ACE{}
	for j, line := range rp.ACL {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' {
			continue
		}
		a, err := nfs4acl.ParseACELine(t)
		if err != nil {
			return fmt.Errorf("%s: acl[%d]: %w", r.Label, j, err)
		}
		ace, err := TranslateDACE(a)
		if err != nil {
			return fmt.Errorf("%s: acl[%d]: %w", r.Label, j, err)
		}
		if err := smbPrincipalOK(ace, true); err != nil {
			return fmt.Errorf("%s: acl[%d]: %w", r.Label, j, err)
		}
		ace.Line = t
		r.Dacl = append(r.Dacl, ace)
	}
	return nil
}

func smbPrincipalOK(a ACE, dacl bool) error {
	if a.NFS4Flags&nfs4acl.FlagInherited != 0 {
		return fmt.Errorf("%q: the I (inherited) flag is not allowed in an SMB plan; permissionreset-smb computes inheritance from the parent", a.Line)
	}
	if dacl && (a.Principal == "OWNER@" || a.Principal == "GROUP@") {
		return fmt.Errorf("%q: %s in a DACL is not supported over SMB: Windows has no principal for the object's own owner or group", a.Line, a.Principal)
	}
	if isNumeric(a.Principal) {
		return fmt.Errorf("%q: numeric principal %s has no SID; name the account instead", a.Line, a.Principal)
	}
	return nil
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// TranslateDACE converts one NFSv4 allow or deny ACE to its Windows form, as
// TranslateACE does for audit ACEs. Line is left for the caller to fill.
func TranslateDACE(a nfs4acl.ACE) (ACE, error) {
	var typ int
	var sddlType string
	switch a.Type {
	case nfs4acl.TypeAllow:
		typ, sddlType = WindowsAllowType, "A"
	case nfs4acl.TypeDeny:
		typ, sddlType = WindowsDenyType, "D"
	default:
		return ACE{}, fmt.Errorf("ACE type %d is not A or D; only allow and deny ACEs translate to a DACL", a.Type)
	}
	return translate(a, typ, sddlType)
}

// Marshal renders the plan as indented JSON with a trailing newline.
func (p *Plan) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func buildRule(label string, m spec.RuleMatch, rp *spec.RulePerms) (Rule, error) {
	r := Rule{
		Label:    label,
		Match:    Match{Type: m.Type, Pattern: m.Pattern},
		SaclSet:  rp.SaclSet(),
		KeepDACL: rp.KeepDACL(),
		HasACL:   len(rp.ACL) > 0,
		HasDACL:  len(rp.DACL) > 0,
		HasMode:  rp.Mode != "",
		Owner:    rp.Owner,
		Group:    rp.Group,
		Sacl:     []ACE{},
	}
	if rp.Sacl == nil {
		return r, nil
	}
	for j, line := range *rp.Sacl {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' {
			continue
		}
		a, err := nfs4acl.ParseACELine(t)
		if err != nil {
			return Rule{}, fmt.Errorf("%s: sacl[%d]: %w", label, j, err)
		}
		ace, err := TranslateACE(a)
		if err != nil {
			return Rule{}, fmt.Errorf("%s: sacl[%d]: %w", label, j, err)
		}
		ace.Line = t
		r.Sacl = append(r.Sacl, ace)
	}
	return r, nil
}

// TranslateACE converts one NFSv4 audit ACE to its Windows form. Line is left
// for the caller to fill.
func TranslateACE(a nfs4acl.ACE) (ACE, error) {
	if a.Type != nfs4acl.TypeAudit {
		return ACE{}, fmt.Errorf("ACE type %d is not U (audit); only audit ACEs translate to a SACL", a.Type)
	}
	return translate(a, WindowsAuditType, "AU")
}

func translate(a nfs4acl.ACE, typ int, sddlType string) (ACE, error) {
	flags, sddlFlags, err := TranslateFlags(a.Flags)
	if err != nil {
		return ACE{}, err
	}
	mask, err := TranslateMask(a.Mask)
	if err != nil {
		return ACE{}, err
	}
	out := ACE{
		NFS4Flags:    a.Flags,
		NFS4Mask:     a.Mask,
		WindowsType:  typ,
		WindowsFlags: flags,
		WindowsMask:  mask,
		Principal:    a.Who,
		Group:        a.Flags&nfs4acl.FlagGroup != 0,
	}
	if wk, ok := wellKnown[a.Who]; ok {
		out.SID = wk.sid
		out.SDDL = fmt.Sprintf("(%s;%s;0x%x;;;%s)", sddlType, sddlFlags, mask, wk.alias)
	}
	return out, nil
}

// TranslateFlags maps NFSv4 ACE flags to Windows ACE header flags and their
// SDDL tokens. The g flag is dropped; any bit nfs4acl does not define is an
// error.
func TranslateFlags(nfs4 uint32) (uint8, string, error) {
	var win uint8
	var sddl strings.Builder
	rest := nfs4 &^ nfs4acl.FlagGroup
	for _, f := range flagMap {
		if nfs4&f.nfs4 != 0 {
			win |= f.win
			sddl.WriteString(f.sddl)
			rest &^= f.nfs4
		}
	}
	if rest != 0 {
		return 0, "", fmt.Errorf("ACE flags 0x%x carry bits with no Windows equivalent (0x%x)", nfs4, rest)
	}
	return win, sddl.String(), nil
}

// TranslateMask returns the Windows access mask for an NFSv4 one. The bits
// share values, so the mask passes through; the retention bits, which mean
// nothing to Windows, and any undefined bit are refused.
func TranslateMask(nfs4 uint32) (uint32, error) {
	if ret := nfs4 & (nfs4acl.MaskWriteRetention | nfs4acl.MaskWriteRetHold); ret != 0 {
		return 0, fmt.Errorf("ACE mask 0x%x carries retention bits 0x%x, which have no Windows meaning", nfs4, ret)
	}
	if rest := nfs4 &^ windowsMaskBits; rest != 0 {
		return 0, fmt.Errorf("ACE mask 0x%x carries undefined bits 0x%x", nfs4, rest)
	}
	return nfs4, nil
}
