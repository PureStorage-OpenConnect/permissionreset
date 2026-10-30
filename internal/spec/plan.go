package spec

import (
	"fmt"
	"io"
	"os/user"
	"sort"
	"strings"
)

// PlanContext carries the run-level facts that are not in the spec but that an
// operator needs in order to read the plan: where the run points, how it gets
// there, and whether it will actually write anything.
type PlanContext struct {
	Target        string // canonical target, post-canonicalization
	Transport     string // "kernel" or "userspace"
	OneFilesystem bool
	Apply         bool // true only when --apply was passed (real changes)
	SetOwner      bool // owner/group are applied only with --set-owner
	// Excludes is the effective pattern list, the spec's plus the command
	// line's. It belongs in the plan because it is the one part of the intent
	// that says what the run will NOT touch, and a wrong pattern is invisible in
	// the counts afterwards -- an excluded subtree looks like a small tree.
	Excludes []string
}

// PrintPlan writes an operator-visible summary of what the run intends to do,
// before any traversal happens. It is deliberately one line per rule: the point
// is that an operator can read the whole intent at a glance and abort, not that
// every field of the spec is reproduced.
//
// It touches the filesystem only through user/group lookup, and never fails: an
// identity that does not resolve is printed as unresolved rather than returning
// an error, because PreResolveIdentities is what decides whether that is fatal.
func PrintPlan(w io.Writer, s *Spec, ctx PlanContext) {
	mode := "DRY RUN — no changes will be made (pass --apply to apply)"
	if ctx.Apply {
		mode = "APPLY — real changes will be made"
	}

	fmt.Fprintln(w, "Plan:")
	fmt.Fprintf(w, "  Protocol: %s\n", s.Protocol)
	fmt.Fprintf(w, "  Target:   %s\n", ctx.Target)
	fmt.Fprintf(w, "  Scope:    transport=%s, one-filesystem=%s\n", ctx.Transport, onOff(ctx.OneFilesystem))
	fmt.Fprintf(w, "  Mode:     %s\n", mode)
	if len(ctx.Excludes) == 0 {
		fmt.Fprintln(w, "  Exclude:  none")
	} else {
		fmt.Fprintf(w, "  Exclude:  %s\n", strings.Join(ctx.Excludes, " "))
		fmt.Fprintln(w, "            (base-name glob unless it contains /, in which case it is")
		fmt.Fprintln(w, "             matched against the path relative to the target; matched")
		fmt.Fprintln(w, "             directories are pruned, subtree not enumerated)")
	}

	fmt.Fprintln(w, "  Rules (first match wins):")
	for i := range s.Rules {
		r := &s.Rules[i]
		fmt.Fprintf(w, "    [%d] %-28s -> %s\n", i, matchLabel(r.Match), setsLabel(&r.RulePerms))
	}
	fmt.Fprintf(w, "    %-32s -> %s\n", "default (no rule matched)", setsLabel(&s.Default))

	ids := s.planIdentities()
	if len(ids) == 0 {
		if s.Protocol == "posix" {
			fmt.Fprintln(w, "  Identities: none set by this spec")
		} else {
			fmt.Fprintln(w, "  Owner/group identities: none (ACL principals are set via acl: entries)")
		}
		return
	}
	note := "not applied (--set-owner not set)"
	if ctx.SetOwner {
		note = "will be applied (--set-owner)"
	}
	fmt.Fprintf(w, "  Identities (%s):\n", note)
	for _, id := range ids {
		fmt.Fprintf(w, "    %s\n", id)
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// matchLabel renders a rule's match criteria. An empty field means "any", which
// is worth printing explicitly: an omitted type is the difference between a rule
// that catches directories and one that catches everything.
func matchLabel(m RuleMatch) string {
	t := m.Type
	if t == "" {
		t = "any"
	}
	p := m.Pattern
	if p == "" {
		p = "*"
	}
	return fmt.Sprintf("type=%s pattern=%s", t, p)
}

// setsLabel renders what a rule sets. ACLs are summarized by entry count rather
// than listed: a rule line stays a line, and the spec file itself is the place
// to read individual ACEs.
func setsLabel(p *RulePerms) string {
	var parts []string
	if p.Mode != "" {
		parts = append(parts, "mode="+p.Mode)
	}
	if n := countACEs(p.ACL); n > 0 {
		parts = append(parts, fmt.Sprintf("acl=%d entries", n))
	}
	if n := countACEs(p.DACL); n > 0 {
		parts = append(parts, fmt.Sprintf("dacl=%d entries", n))
	}
	if p.KeepDACL() {
		parts = append(parts, "dacl=keep")
	}
	if p.Sacl != nil {
		parts = append(parts, fmt.Sprintf("sacl=%d entries", countACEs(*p.Sacl)))
	}
	if p.Owner != "" {
		parts = append(parts, "owner="+p.Owner)
	}
	if p.Group != "" {
		parts = append(parts, "group="+p.Group)
	}
	if len(parts) == 0 {
		return "(nothing)"
	}
	return strings.Join(parts, ", ")
}

// countACEs counts only lines that actually become ACEs: the loader tolerates
// blank lines and # comments in an acl list, and counting those would overstate
// what the rule sets.
func countACEs(lines []string) int {
	n := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == '#' {
			continue
		}
		n++
	}
	return n
}

// planIdentities lists the distinct owner/group principals the spec sets, each
// with its resolved id where one exists.
func (s *Spec) planIdentities() []string {
	seen := map[string]bool{}
	var out []string

	add := func(kind, name string) {
		if name == "" || seen[kind+":"+name] {
			return
		}
		seen[kind+":"+name] = true
		out = append(out, fmt.Sprintf("%s %s -> %s", kind, name, resolveIdentity(kind, name)))
	}

	collect := func(p *RulePerms) {
		add("owner", p.Owner)
		add("group", p.Group)
	}
	collect(&s.Default)
	for i := range s.Rules {
		collect(&s.Rules[i].RulePerms)
	}
	sort.Strings(out)
	return out
}

func resolveIdentity(kind, name string) string {
	if kind == "owner" {
		if u, err := user.Lookup(name); err == nil {
			return "uid " + u.Uid
		}
		if u, err := user.LookupId(name); err == nil {
			return "uid " + u.Uid
		}
		return "UNRESOLVED"
	}
	if g, err := user.LookupGroup(name); err == nil {
		return "gid " + g.Gid
	}
	if g, err := user.LookupGroupId(name); err == nil {
		return "gid " + g.Gid
	}
	return "UNRESOLVED"
}
