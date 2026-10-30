package spec

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
)

func writeSpec(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0664"
rules:
  - match:
      type: directory
    mode: "2775"
  - match:
      type: file
      pattern: "*.sh"
    mode: "0775"
`))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if s.Protocol != "posix" {
		t.Errorf("Protocol = %q, want posix", s.Protocol)
	}
	if len(s.Rules) != 2 {
		t.Errorf("len(Rules) = %d, want 2", len(s.Rules))
	}
}

func TestLoadNFSv4Valid(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
    - "A:g:GROUP@:rxtncy"
rules:
  - match:
      type: directory
    acl:
      - "A:fd:OWNER@:rwaDxtTcCoy"
`))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
}

func TestLoadMissingProtocol(t *testing.T) {
	_, err := Load(writeSpec(t, `default:
  mode: "0644"
`))
	if err == nil {
		t.Error("expected error for missing protocol")
	}
}

func TestLoadBadProtocol(t *testing.T) {
	_, err := Load(writeSpec(t, `protocol: ftp`))
	if err == nil {
		t.Error("expected error for unknown protocol")
	}
}

func TestLoadBadMode(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "999"
`))
	if err == nil {
		t.Error("expected error for non-octal mode")
	}
}

func TestLoadBadACE(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "X::OWNER@:r"
`))
	if err == nil {
		t.Error("expected error for bad ACE type")
	}
}

func TestLoadBadGlob(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
rules:
  - match:
      pattern: "[invalid"
    mode: "0644"
`))
	if err == nil {
		t.Error("expected error for bad glob pattern")
	}
}

func TestLoadBadMatchType(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
rules:
  - match:
      type: symlink
    mode: "0644"
`))
	if err == nil {
		t.Error("expected error for unknown match type")
	}
}

func TestLoadSMBRejected(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: smb
smb:
  server: myserver
  share: myshare
`))
	if err == nil {
		t.Error("expected error: smb protocol not yet supported")
	}
}

func TestLoadUnknownKey(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0644"
typo_key: something
`))
	if err == nil {
		t.Error("expected error for unknown top-level key")
	}
}

func TestLoadModeAbove07777(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "17777"
`))
	if err == nil {
		t.Error("expected error for mode above 07777")
	}
}

func TestLoadNoEffectiveOp(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
default: {}
`))
	if err == nil {
		t.Error("expected error for spec with no effective operation")
	}
}

func TestEffectivePerms(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0664"
rules:
  - match:
      type: directory
    mode: "2775"
  - match:
      type: file
      pattern: "*.sh"
    mode: "0775"
  - match:
      type: file
    mode: "0664"
`))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path  string
		isDir bool
		want  string
	}{
		{"/data/src", true, "2775"},
		{"/data/run.sh", false, "0775"},
		{"/data/readme.txt", false, "0664"},
		{"/data/script.py", false, "0664"},
	}
	for _, tt := range tests {
		p := s.EffectivePerms(tt.path, tt.isDir)
		if p.Mode != tt.want {
			t.Errorf("EffectivePerms(%q, isDir=%v).Mode = %q, want %q",
				tt.path, tt.isDir, p.Mode, tt.want)
		}
	}
}

func TestEffectivePermsDefault(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0644"
`))
	if err != nil {
		t.Fatal(err)
	}
	p := s.EffectivePerms("/any/path.txt", false)
	if p.Mode != "0644" {
		t.Errorf("Mode = %q, want 0644", p.Mode)
	}
}

func TestEffectivePermsFirstMatchWins(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0600"
rules:
  - match:
      type: file
      pattern: "*.sh"
    mode: "0755"
  - match:
      type: file
    mode: "0644"
`))
	if err != nil {
		t.Fatal(err)
	}
	p := s.EffectivePerms("/bin/deploy.sh", false)
	if p.Mode != "0755" {
		t.Errorf("deploy.sh should match *.sh rule, got %q", p.Mode)
	}
}

func TestEffectivePermsRuleReplacesDefault(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTnNcCoy"
  owner: "root"
  group: "wheel"
rules:
  - match:
      type: directory
    acl:
      - "A::OWNER@:rwaDxtTnNcCoy"
      - "A:g:GROUP@:rxtncy"
`))
	if err != nil {
		t.Fatal(err)
	}
	p := s.EffectivePerms("/data/subdir", true)
	if len(p.ACL) != 2 {
		t.Errorf("rule ACL should have 2 entries, got %d", len(p.ACL))
	}
	if p.Owner != "" {
		t.Errorf("rule omits owner, should be empty, got %q", p.Owner)
	}
	if p.Group != "" {
		t.Errorf("rule omits group, should be empty, got %q", p.Group)
	}
}

func TestLoadUnknownNestedKey(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0644"
rules:
  - match:
      type: file
      typo: oops
    mode: "0644"
`))
	if err == nil {
		t.Error("expected error for unknown key inside match block")
	}
}

func TestLoadUnknownRuleKey(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0644"
rules:
  - match:
      type: file
    mode: "0644"
    bogus: true
`))
	if err == nil {
		t.Error("expected error for unknown key inside rule")
	}
}

func TestLoadPosixRejectsACL(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0644"
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
`))
	if err == nil {
		t.Error("expected error for acl field in posix spec")
	}
}

func TestLoadNFSv4RejectsMode(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  mode: "0644"
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
`))
	if err == nil {
		t.Error("expected error for mode field in nfsv4 spec")
	}
}

func TestRuleReplacesDefault(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0644"
  owner: "root"
rules:
  - match:
      type: directory
    mode: "2775"
`))
	if err != nil {
		t.Fatal(err)
	}
	p := s.EffectivePerms("/data/src", true)
	if p.Mode != "2775" {
		t.Errorf("Mode = %q, want 2775", p.Mode)
	}
	if p.Owner != "" {
		t.Errorf("Owner = %q, want empty (rule replaces default entirely)", p.Owner)
	}
}

// TestLoadPrecomputesTheEncodedACL pins the optimisation itself. The apply path
// reads EncodedACL once per object; if Load ever stops populating it, every
// object silently falls back to encoding on demand and the 280 MB this removed
// comes straight back, with no test failing and no output changing.
func TestLoadPrecomputesTheEncodedACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(path, []byte(`protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
    - "D::EVERYONE@:wa"
rules:
  - match:
      type: directory
    acl:
      - "A:fd:OWNER@:rwaDxtTcCoy"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Default.encodedACL == nil {
		t.Error("default rule has no precomputed ACL; the apply path will re-encode per object")
	}
	if len(s.Rules) == 0 || s.Rules[0].encodedACL == nil {
		t.Error("matched rule has no precomputed ACL; the apply path will re-encode per object")
	}

	// The precomputed bytes and the on-demand fallback must agree, or a
	// Load-built spec and a literal-built one would apply different ACLs.
	fallback := (&RulePerms{ACL: s.Default.ACL}).EncodedACL()
	if !bytes.Equal(s.Default.EncodedACL(), fallback) {
		t.Errorf("precomputed ACL %x differs from the on-demand encode %x",
			s.Default.EncodedACL(), fallback)
	}
}

func TestShippedExampleSpecsLoad(t *testing.T) {
	examples, err := filepath.Glob("../../examples/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(examples) == 0 {
		t.Fatal("no example specs found under examples/")
	}
	for _, path := range examples {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			s, err := Load(path)
			if err != nil {
				t.Fatalf("Load(%s) = %v", name, err)
			}
			if s.Protocol == "" {
				t.Errorf("%s has no protocol", name)
			}
			if s.Default.Mode == "" && len(s.Default.ACL) == 0 && len(s.Rules) == 0 {
				t.Errorf("%s has no default and no rules", name)
			}
			for i, r := range s.Rules {
				if r.Match.Type == "" && r.Match.Pattern == "" {
					t.Errorf("%s rule[%d] has no match", name, i)
				}
			}
		})
	}
}

// TestEncodedACLFallsBackForLiteralSpecs covers the path a struct literal takes.
// Returning nil there would read to the apply path as "no ACL configured" and
// silently skip every object a rule was written to fix.
func TestEncodedACLFallsBackForLiteralSpecs(t *testing.T) {
	p := &RulePerms{ACL: []string{"A::OWNER@:rwaDxtTcCoy"}}
	if got := p.EncodedACL(); len(got) == 0 {
		t.Fatal("a spec built as a literal encoded to nothing; apply would skip the object")
	}
	if p := (&RulePerms{}); p.EncodedACL() != nil {
		t.Error("permissions with no ACL should encode to nil, not to an empty ACL")
	}
}

// ---------------------------------------------------------------------------
// sacl:

func TestLoadACLAndSaclEncodesAclThenSacl(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
  sacl:
    - "U:SF:EVERYONE@:rwaD"
`))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !s.Default.SaclSet() {
		t.Fatal("SaclSet() = false, want true: sacl: was given")
	}

	// EncodedACL() must be exactly Encode(aclACEs ++ saclACEs): the ACL entry
	// first, the SACL entry last, because FA stores it in that order and the
	// positional compare in --validate/--compare depends on it.
	aclOnly, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	full, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTcCoy", "U:SF:EVERYONE@:rwaD"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s.Default.EncodedACL(), aclOnly) {
		t.Fatal("EncodedACL() dropped the sacl: entry")
	}
	if !bytes.Equal(s.Default.EncodedACL(), full) {
		t.Errorf("EncodedACL() = %x, want acl++sacl = %x", s.Default.EncodedACL(), full)
	}
}

func TestLoadSaclRejectsNonUType(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
  sacl:
    - "D:SF:EVERYONE@:rwaD"
`))
	if err == nil {
		t.Error("expected error for a D line inside sacl:")
	}
}

func TestLoadSaclRequiresSuccessOrFailFlag(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
  sacl:
    - "U:g:EVERYONE@:rwaD"
`))
	if err == nil {
		t.Error("expected error for a U line in sacl: with neither S nor F")
	}
}

func TestLoadSaclRejectedUnderPosix(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0644"
  sacl: []
`))
	if err == nil {
		t.Error("expected error for sacl: under protocol posix")
	}
}

func TestLoadSaclWithoutACLKeepsDACL(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  sacl:
    - "U:SF:EVERYONE@:rwaD"
rules:
  - match: {type: file}
    sacl: []
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Default.KeepDACL() || !s.Rules[0].KeepDACL() {
		t.Error("KeepDACL() = false for a rule with sacl: and no acl:")
	}
	if b := s.Default.EncodedACL(); b != nil {
		t.Errorf("EncodedACL() = %d bytes for a DACL-keeping rule, want nil: a SACL-only write removes all access", len(b))
	}
	if got := s.KeepDACLRules(); len(got) != 2 {
		t.Errorf("KeepDACLRules() = %v, want default and rule[0]", got)
	}
	if got := s.MissingSACL(); len(got) != 0 {
		t.Errorf("MissingSACL() = %v, want empty", got)
	}
}

func TestLoadACLRejectsAuditType(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "U:SF:EVERYONE@:rwaD"
`))
	if err == nil {
		t.Error("expected error for a U (audit) line inside acl:")
	}
}

func TestLoadACLRejectsAlarmType(t *testing.T) {
	_, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "L:SF:EVERYONE@:rwaD"
`))
	if err == nil {
		t.Error("expected error for an L (alarm) line inside acl:")
	}
}

func TestSaclSetDistinguishesMissingFromEmpty(t *testing.T) {
	noKey, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
`))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if noKey.Default.SaclSet() {
		t.Error("SaclSet() = true for a spec with no sacl: key at all")
	}

	empty, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
  sacl: []
`))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !empty.Default.SaclSet() {
		t.Error("SaclSet() = false for sacl: [], want true: the key was given, just empty")
	}
	if n := len(*empty.Default.Sacl); n != 0 {
		t.Errorf("len(*Sacl) = %d, want 0 for sacl: []", n)
	}
}

func TestLoadUnknownSaclModeKeyRejected(t *testing.T) {
	// KnownFields(true) must keep rejecting a typo'd or dropped-in-v1 key
	// alongside sacl: -- sacl_mode: was a real field name considered and
	// dropped for v2 (see the plan), so a spec carrying it over is a mistake
	// worth catching at load time rather than one more ignored key.
	_, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
  sacl: []
  sacl_mode: merge
`))
	if err == nil {
		t.Error("expected error for unknown key sacl_mode:")
	}
}

// TestMissingSACLGuard exercises Spec.MissingSACL, the data behind the SACL
// guard in internal/run: an NFSv4 rule (default included) that sets acl: with
// no sacl: key at all is reported by name; a rule with sacl: -- even sacl: []
// -- is not, because that is the operator saying what they want.
func TestMissingSACLGuard(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
rules:
  - match:
      type: directory
    acl:
      - "A:fd:OWNER@:rwaDxtTcCoy"
    sacl: []
  - match:
      type: file
    acl:
      - "A::OWNER@:rwaDxtTcCoy"
`))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	got := s.MissingSACL()
	want := []string{"default", "rule[1]"}
	if len(got) != len(want) {
		t.Fatalf("MissingSACL() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("MissingSACL()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMissingSACLEmptyWhenAllRulesSetSacl(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
  sacl: []
`))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if got := s.MissingSACL(); len(got) != 0 {
		t.Errorf("MissingSACL() = %v, want empty: the only rule set sacl: []", got)
	}
}

func TestMissingSACLEmptyForPosix(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: posix
default:
  mode: "0644"
`))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if got := s.MissingSACL(); len(got) != 0 {
		t.Errorf("MissingSACL() = %v, want empty for posix: the guard only concerns NFSv4 writes", got)
	}
}

func TestSyntheticRangePrincipals(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::1402:rwaD"
    - "A::2000000003:rwaD"
rules:
  - match: { type: directory }
    acl:
      - "A:g:1000000544:rwaD"
      - "A::juser@example.net:rwaD"
`))
	if err != nil {
		t.Fatal(err)
	}
	got := s.SyntheticRangePrincipals(nil)
	if len(got) != 2 || got[0] != "default: 2000000003" || got[1] != "rule[0]: 1000000544" {
		t.Fatalf("SyntheticRangePrincipals = %v", got)
	}
}

// TestSyntheticRangePrincipalsNamedAndSacl: a name that resolves to a high id
// is reported with the id, a low one is not, the lookup is told whether the
// ACE is a group, and sacl: lines are checked like acl: lines.
func TestSyntheticRangePrincipalsNamedAndSacl(t *testing.T) {
	s, err := Load(writeSpec(t, `
protocol: nfsv4
default:
  acl:
    - "A::sacl-map1@example.net:rwaD"
    - "A:g:sacl-map-grp@example.net:rwaD"
    - "A::juser@example.net:rwaD"
    - "A::OWNER@:rwaD"
  sacl:
    - "U:SF:2000000003:rwaD"
`))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{
		"sacl-map1@example.net/user":     "2000000003",
		"sacl-map-grp@example.net/group": "1880600173",
		"juser@example.net/user":         "1445",
	}
	lookup := func(who string, isGroup bool) (string, bool) {
		kind := "/user"
		if isGroup {
			kind = "/group"
		}
		id, ok := ids[who+kind]
		return id, ok
	}
	got := s.SyntheticRangePrincipals(lookup)
	want := []string{"default: sacl-map1@example.net=2000000003", "default: sacl-map-grp@example.net=1880600173", "default: 2000000003"}
	if len(got) != len(want) {
		t.Fatalf("SyntheticRangePrincipals = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SyntheticRangePrincipals = %v, want %v", got, want)
		}
	}
}

func TestNamedPrincipals(t *testing.T) {
	sacl := []string{"U:SF:auditor@example.net:rw", "U:SF:EVERYONE@:rw"}
	s := &Spec{
		Protocol: "nfsv4",
		Default:  RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy", "A::1402:rxtncy", "A::65534:r"}},
		Rules: []Rule{{
			Match: RuleMatch{Type: "directory"},
			RulePerms: RulePerms{
				ACL: []string{
					"D:fdg:grp@example.net:dD",
					"A:fdg:grp@example.net:rwadxtTnNcy", // same principal: listed once
					"A::grp@example.net:r",              // same name as a user: a different principal
					"A::1402:rwadxtTnNcy",
				},
				Sacl: &sacl,
			},
		}},
	}
	got := s.NamedPrincipals()
	want := []nfs4acl.ACE{
		{Who: "1402"},
		{Flags: nfs4acl.FlagGroup, Who: "grp@example.net"},
		{Who: "grp@example.net"},
		{Who: "auditor@example.net"},
	}
	if len(got) != len(want) {
		t.Fatalf("NamedPrincipals = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if (&Spec{Protocol: "posix"}).NamedPrincipals() != nil {
		t.Error("a posix spec has no principals")
	}
}
