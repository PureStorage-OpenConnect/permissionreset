package saclplan

import (
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
)

func TestTranslateFlags(t *testing.T) {
	tests := []struct {
		name string
		nfs4 uint32
		win  uint8
		sddl string
	}{
		{"none", 0, 0, ""},
		{"f -> OI", nfs4acl.FlagFileInherit, 0x01, "OI"},
		{"d -> CI", nfs4acl.FlagDirInherit, 0x02, "CI"},
		{"n -> NP", nfs4acl.FlagNoPropInherit, 0x04, "NP"},
		{"i -> IO", nfs4acl.FlagInheritOnly, 0x08, "IO"},
		{"S -> SA", nfs4acl.FlagSuccessAccess, 0x40, "SA"},
		{"F -> FA", nfs4acl.FlagFailedAccess, 0x80, "FA"},
		{"I -> ID", nfs4acl.FlagInherited, 0x10, "ID"},
		{"g dropped", nfs4acl.FlagGroup, 0, ""},
		{"all", 0xff, 0xdf, "OICINPIOIDSAFA"},
		{"fdSFg", nfs4acl.FlagFileInherit | nfs4acl.FlagDirInherit | nfs4acl.FlagSuccessAccess |
			nfs4acl.FlagFailedAccess | nfs4acl.FlagGroup, 0xc3, "OICISAFA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			win, sddl, err := TranslateFlags(tt.nfs4)
			if err != nil {
				t.Fatalf("TranslateFlags(0x%x): %v", tt.nfs4, err)
			}
			if win != tt.win || sddl != tt.sddl {
				t.Errorf("TranslateFlags(0x%x) = 0x%x %q, want 0x%x %q", tt.nfs4, win, sddl, tt.win, tt.sddl)
			}
		})
	}
}

func TestTranslateFlagsRefusesUndefinedBit(t *testing.T) {
	if _, _, err := TranslateFlags(0x100); err == nil {
		t.Fatal("TranslateFlags(0x100) succeeded; want an error for an undefined bit")
	}
}

func TestTranslateMask(t *testing.T) {
	tests := []struct {
		name    string
		mask    uint32
		wantErr string
	}{
		{"all defined bits pass through", windowsMaskBits, ""},
		{"read data", nfs4acl.MaskReadData, ""},
		{"write retention", nfs4acl.MaskWriteRetention, "retention"},
		{"write ret hold", nfs4acl.MaskWriteRetHold | nfs4acl.MaskReadData, "retention"},
		{"undefined", 0x00200000, "undefined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TranslateMask(tt.mask)
			if tt.wantErr == "" {
				if err != nil || got != tt.mask {
					t.Fatalf("TranslateMask(0x%x) = 0x%x, %v; want 0x%x, nil", tt.mask, got, err, tt.mask)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("TranslateMask(0x%x) err = %v, want one mentioning %q", tt.mask, err, tt.wantErr)
			}
		})
	}
}

func TestTranslateACEPrincipals(t *testing.T) {
	tests := []struct {
		line, principal, sid, sddl string
		group                      bool
	}{
		{"U:fdSF:EVERYONE@:rwx", "EVERYONE@", "S-1-1-0", "(AU;OICISAFA;0x23;;;WD)", false},
		{"U:S:OWNER@:w", "OWNER@", "S-1-3-0", "(AU;SA;0x2;;;CO)", false},
		{"U:gF:GROUP@:d", "GROUP@", "S-1-3-1", "(AU;FA;0x10000;;;CG)", true},
		{"U:S:sacl-map2@example.net:r", "sacl-map2@example.net", "", "", false},
		{"U:gS:auditors:r", "auditors", "", "", true},
		{"U:S:1000003:r", "1000003", "", "", false},
		{"U:S:everyone@:r", "everyone@", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			a, err := nfs4acl.ParseACELine(tt.line)
			if err != nil {
				t.Fatal(err)
			}
			got, err := TranslateACE(a)
			if err != nil {
				t.Fatal(err)
			}
			if got.Principal != tt.principal || got.SID != tt.sid || got.SDDL != tt.sddl || got.Group != tt.group {
				t.Errorf("got principal=%q sid=%q sddl=%q group=%v, want %q %q %q %v",
					got.Principal, got.SID, got.SDDL, got.Group, tt.principal, tt.sid, tt.sddl, tt.group)
			}
			if got.WindowsType != WindowsAuditType || got.WindowsMask != a.Mask || got.NFS4Mask != a.Mask {
				t.Errorf("type/mask = %d 0x%x 0x%x, want 2 and 0x%x", got.WindowsType, got.WindowsMask, got.NFS4Mask, a.Mask)
			}
		})
	}
}

func TestTranslateACERefusesNonAudit(t *testing.T) {
	for _, line := range []string{"A::OWNER@:r", "D::OWNER@:r", "L:S:OWNER@:r"} {
		a, err := nfs4acl.ParseACELine(line)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := TranslateACE(a); err == nil {
			t.Errorf("TranslateACE(%s) succeeded; want a refusal", line)
		}
	}
}

func TestTranslateACERefusesRetention(t *testing.T) {
	// The line grammar has no letter for the retention bits, so build the ACE.
	a := nfs4acl.ACE{Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagSuccessAccess,
		Mask: nfs4acl.MaskReadData | nfs4acl.MaskWriteRetention, Who: "EVERYONE@"}
	if _, err := TranslateACE(a); err == nil {
		t.Fatal("TranslateACE accepted a mask with WriteRetention")
	}
}

func mustParse(t *testing.T, y string) *spec.Spec {
	t.Helper()
	s, err := spec.Parse([]byte(y), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuildRules(t *testing.T) {
	s := mustParse(t, `protocol: nfsv4
exclude: ["./logs/*.gz", ".snapshot", "a/../b/c"]
default:
  acl: ["A::OWNER@:rwx"]
rules:
  - match: {type: directory, pattern: "proj*"}
    sacl:
      - "U:fdS:EVERYONE@:rw"
      - "# comment"
      - "U:gF:auditors@example.net:d"
  - match: {type: file}
    sacl: []
  - match: {pattern: "*.log"}
    acl: ["A::OWNER@:rwx"]
    sacl: ["U:S:OWNER@:w"]
  - match: {type: file, pattern: "*.tmp"}
    acl: ["A::OWNER@:r"]
    dacl: ["A::OWNER@:r"]
`)
	p, err := Build(s, "some/spec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Schema != 1 || p.Source != "some/spec.yaml" || p.Protocol != "nfsv4" {
		t.Errorf("header = %d %q %q", p.Schema, p.Source, p.Protocol)
	}
	if got := strings.Join(p.Exclude.Base, ","); got != ".snapshot" {
		t.Errorf("exclude.base = %q", got)
	}
	if got := strings.Join(p.Exclude.Path, ","); got != "logs/*.gz,b/c" {
		t.Errorf("exclude.path = %q", got)
	}
	if got := strings.Join(p.Exclude.Patterns, ","); got != "./logs/*.gz,.snapshot,a/../b/c" {
		t.Errorf("exclude.patterns = %q", got)
	}

	d := p.Default
	if d.Label != "default" || d.Match != (Match{}) || d.SaclSet || d.KeepDACL || !d.HasACL || d.HasDACL || d.Sacl == nil || len(d.Sacl) != 0 {
		t.Errorf("default = %+v", d)
	}

	if len(p.Rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(p.Rules))
	}
	want := []struct {
		label, typ, pattern                string
		saclSet, keepDACL, hasACL, hasDACL bool
		nSacl                              int
	}{
		{"rule[0]", "directory", "proj*", true, true, false, false, 2},
		{"rule[1]", "file", "", true, true, false, false, 0},
		{"rule[2]", "", "*.log", true, false, true, false, 1},
		{"rule[3]", "file", "*.tmp", false, false, true, true, 0},
	}
	for i, w := range want {
		r := p.Rules[i]
		if r.Label != w.label || r.Match.Type != w.typ || r.Match.Pattern != w.pattern ||
			r.SaclSet != w.saclSet || r.KeepDACL != w.keepDACL || r.HasACL != w.hasACL || r.HasDACL != w.hasDACL ||
			r.Sacl == nil || len(r.Sacl) != w.nSacl {
			t.Errorf("rules[%d] = %+v, want %+v", i, r, w)
		}
	}
	if got := p.Rules[0].Sacl[0].Line; got != "U:fdS:EVERYONE@:rw" {
		t.Errorf("line = %q", got)
	}
	if got := p.Rules[0].Sacl[1]; got.Principal != "auditors@example.net" || !got.Group || got.SID != "" {
		t.Errorf("named group ACE = %+v", got)
	}
}

func TestBuildRefusesNonNFSv4(t *testing.T) {
	s := mustParse(t, "protocol: posix\ndefault:\n  mode: \"0755\"\n")
	if _, err := Build(s, "p.yaml"); err == nil || !strings.Contains(err.Error(), "nfsv4") {
		t.Fatalf("Build(posix) err = %v, want a protocol refusal", err)
	}
}

// spec.Load's filepath.IsAbs check passes "/abs/x" on Windows; the plan must
// refuse it as permissionreset on Linux does.
func TestBuildRefusesSlashAbsoluteExclude(t *testing.T) {
	s := &spec.Spec{Protocol: "nfsv4", Exclude: []string{"ok", "/abs/x"}}
	if _, err := Build(s, "p.yaml"); err == nil || !strings.Contains(err.Error(), "exclude[1]") {
		t.Fatalf("Build err = %v, want an exclude[1] refusal", err)
	}
}

func TestBuildSMB(t *testing.T) {
	s := mustParse(t, `protocol: nfsv4
default:
  acl: ["A:fd:EVERYONE@:rx", "D:fdg:blocked@example.net:w"]
  sacl: []
rules:
  - match: {type: directory, pattern: "audit*"}
    sacl: ["U:fdS:OWNER@:w"]
  - match: {type: file}
    acl: ["A::admins@example.net:rwx"]
`)
	p, err := BuildSMB(s, "s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Schema != SchemaSMB {
		t.Errorf("schema = %d, want %d", p.Schema, SchemaSMB)
	}
	d := p.Default.Dacl
	if len(d) != 2 {
		t.Fatalf("default dacl = %+v", d)
	}
	if d[0].WindowsType != WindowsAllowType || d[0].WindowsFlags != WinObjectInherit|WinContainerInherit ||
		d[0].SID != "S-1-1-0" || d[0].SDDL != "(A;OICI;0x21;;;WD)" || d[0].Line != "A:fd:EVERYONE@:rx" {
		t.Errorf("dacl[0] = %+v", d[0])
	}
	if d[1].WindowsType != WindowsDenyType || !d[1].Group || d[1].SID != "" || d[1].Principal != "blocked@example.net" {
		t.Errorf("dacl[1] = %+v", d[1])
	}
	// A sacl:-only rule has no Dacl; OWNER@ stays allowed in a SACL.
	if p.Rules[0].Dacl != nil || len(p.Rules[0].Sacl) != 1 {
		t.Errorf("rules[0] = %+v", p.Rules[0])
	}
	if len(p.Rules[1].Dacl) != 1 {
		t.Errorf("rules[1] dacl = %+v", p.Rules[1].Dacl)
	}
	// Build itself stays schema 1 and never sets Dacl.
	p1, err := Build(s, "s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p1.Schema != Schema || p1.Default.Dacl != nil {
		t.Errorf("Build changed: schema %d, dacl %+v", p1.Schema, p1.Default.Dacl)
	}
}

func TestBuildSMBRefuses(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"inherited flag in acl", "default:\n  acl: [\"A:I:admins@example.net:r\"]\n", "I (inherited)"},
		{"inherited flag in sacl", "default:\n  sacl: [\"U:IS:EVERYONE@:r\"]\n", "I (inherited)"},
		{"OWNER@ in acl", "default:\n  acl: [\"A::OWNER@:r\"]\n", "OWNER@ in a DACL"},
		{"GROUP@ in acl", "default:\n  acl: [\"A:g:GROUP@:r\"]\n", "GROUP@ in a DACL"},
		{"numeric in acl", "default:\n  acl: [\"A::1000:r\"]\n", "numeric principal"},
		{"numeric in sacl", "default:\n  sacl: [\"U:S:1000:r\"]\n", "numeric principal"},
		{"numeric owner", "default:\n  acl: [\"A::admins@example.net:r\"]\n  owner: \"1000\"\n", "numeric id"},
		{"dacl field", "default:\n  acl: [\"A::admins@example.net:r\"]\n  dacl: [\"A::admins@example.net:r\"]\n", "dacl: is not supported"},
		// Comment-only acl: has has_acl: true but nothing to translate; emitting it
		// would hand permissionreset-smb a plan Plan.cs refuses (has_acl with no
		// dacl). Refused at the boundary, naming the rule.
		{"comment-only acl in default", "default:\n  acl: [\"# rotated out\", \"   \" ]\n", "default: acl: holds no entries after comments"},
		{"comment-only acl in a rule", "default:\n  acl: [\"A::admins@example.net:r\"]\nrules:\n  - match: {type: directory}\n    acl: [\"# none left\"]\n", "rule[0]: acl: holds no entries after comments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustParse(t, "protocol: nfsv4\n"+tt.body)
			if _, err := BuildSMB(s, "s.yaml"); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestTranslateDACERefusesAudit(t *testing.T) {
	a, err := nfs4acl.ParseACELine("U:S:EVERYONE@:r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TranslateDACE(a); err == nil {
		t.Fatal("TranslateDACE accepted an audit ACE")
	}
}
