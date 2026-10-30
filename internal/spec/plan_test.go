package spec

import (
	"strings"
	"testing"
)

func planLines(t *testing.T, s *Spec, ctx PlanContext) []string {
	t.Helper()
	var b strings.Builder
	PrintPlan(&b, s, ctx)
	return strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
}

func TestPrintPlanShowsScopeRulesAndMode(t *testing.T) {
	s := &Spec{
		Protocol: "nfsv4",
		Default:  RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy", "# a comment", ""}},
		Rules: []Rule{
			{
				Match:     RuleMatch{Type: "directory"},
				RulePerms: RulePerms{ACL: []string{"A:fd:OWNER@:rwaDxtTnNcCy", "A:fdg:GROUP@:rxtncy"}, Owner: "0", Group: "0"},
			},
			{
				Match:     RuleMatch{Type: "file", Pattern: "*.pst"},
				RulePerms: RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy"}},
			},
		},
	}

	got := planLines(t, s, PlanContext{
		Target:        "/mnt/fb-perms/case42",
		Transport:     "kernel",
		OneFilesystem: true,
		Apply:         true,
		SetOwner:      true,
	})
	out := strings.Join(got, "\n")

	for _, want := range []string{
		"Protocol: nfsv4",
		"Target:   /mnt/fb-perms/case42",
		"transport=kernel, one-filesystem=on",
		"APPLY — real changes will be made",
		"[0] type=directory pattern=*",
		"acl=2 entries, owner=0, group=0",
		"[1] type=file pattern=*.pst",
		"default (no rule matched)",
		"will be applied (--set-owner)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan missing %q; got:\n%s", want, out)
		}
	}

	// Comments and blank lines in an acl list are not ACEs and must not be counted.
	if !strings.Contains(out, "acl=1 entries") {
		t.Errorf("default rule ACE count should exclude comments/blanks; got:\n%s", out)
	}

	// One line per rule keeps the block readable: "Plan:" plus 5 header lines
	// (protocol, target, scope, mode, exclude), the "Rules:" label, 2 rules, the
	// default, the identities header, 2 identities.
	if len(got) != 13 {
		t.Errorf("plan should be 13 lines, got %d:\n%s", len(got), out)
	}
}

func TestPrintPlanDryRunAndEmptyMatchers(t *testing.T) {
	s := &Spec{
		Protocol: "posix",
		Default:  RulePerms{Mode: "0644"},
		Rules:    []Rule{{RulePerms: RulePerms{Mode: "0755"}}},
	}
	out := strings.Join(planLines(t, s, PlanContext{Target: "/data", Transport: "userspace"}), "\n")

	for _, want := range []string{
		"DRY RUN — no changes will be made (pass --apply to apply)",
		"transport=userspace, one-filesystem=off",
		"[0] type=any pattern=*",
		"mode=0755",
		"mode=0644",
		"Identities: none set by this spec",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan missing %q; got:\n%s", want, out)
		}
	}
}

func TestPrintPlanFlagsUnresolvedIdentities(t *testing.T) {
	s := &Spec{
		Protocol: "posix",
		Default:  RulePerms{Mode: "0644", Owner: "no-such-user-permissionreset", Group: "no-such-group-permissionreset"},
	}
	out := strings.Join(planLines(t, s, PlanContext{Target: "/data", Transport: "kernel"}), "\n")

	if !strings.Contains(out, "owner no-such-user-permissionreset -> UNRESOLVED") {
		t.Errorf("unresolved owner not reported; got:\n%s", out)
	}
	if !strings.Contains(out, "group no-such-group-permissionreset -> UNRESOLVED") {
		t.Errorf("unresolved group not reported; got:\n%s", out)
	}
	if !strings.Contains(out, "not applied (--set-owner not set)") {
		t.Errorf("plan should say identities are inert without --set-owner; got:\n%s", out)
	}
}

func TestPrintPlanRuleThatSetsNothing(t *testing.T) {
	s := &Spec{Protocol: "posix", Default: RulePerms{Mode: "0644"}, Rules: []Rule{{Match: RuleMatch{Type: "file"}}}}
	out := strings.Join(planLines(t, s, PlanContext{Target: "/data", Transport: "kernel"}), "\n")
	if !strings.Contains(out, "(nothing)") {
		t.Errorf("an empty rule should read as setting nothing; got:\n%s", out)
	}
}

func TestPrintPlanShowsSaclEntryCount(t *testing.T) {
	empty := []string{}
	nonEmpty := []string{"U:SF:EVERYONE@:rwaD", "# comment"}
	s := &Spec{
		Protocol: "nfsv4",
		Default:  RulePerms{ACL: []string{"A::OWNER@:rwaDxtTcCoy"}, Sacl: &nonEmpty},
		Rules: []Rule{
			{Match: RuleMatch{Type: "directory"}, RulePerms: RulePerms{ACL: []string{"A:fd:OWNER@:rwaDxtTcCoy"}, Sacl: &empty}},
			{Match: RuleMatch{Type: "file"}, RulePerms: RulePerms{ACL: []string{"A::OWNER@:rwaDxtTcCoy"}}},
		},
	}
	out := strings.Join(planLines(t, s, PlanContext{Target: "/data", Transport: "kernel"}), "\n")

	if !strings.Contains(out, "sacl=1 entries") {
		t.Errorf("default should show sacl=1 entries (the comment line excluded); got:\n%s", out)
	}
	if !strings.Contains(out, "sacl=0 entries") {
		t.Errorf("the directory rule's sacl: [] should show sacl=0 entries, distinguishing it from no sacl: key; got:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "type=file pattern=*") && strings.Contains(line, "sacl=") {
			t.Errorf("the file rule has no sacl: key and must not show a sacl= entry; got:\n%s", out)
		}
	}
}
