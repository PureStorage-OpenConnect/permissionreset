package spec

import (
	"reflect"
	"strings"
	"testing"
)

func TestLoadParsesExcludeList(t *testing.T) {
	p := writeSpec(t, "protocol: posix\ndefault:\n  mode: \"0755\"\nexclude:\n  - .snapshot\n  - \"*.tmp\"\n")
	s, err := Load(p)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{".snapshot", "*.tmp"}
	if !reflect.DeepEqual(s.Exclude, want) {
		t.Errorf("Exclude = %v, want %v", s.Exclude, want)
	}
}

// A pattern filepath.Match cannot compile must be refused at load, not silently
// matched against nothing for the length of a multi-hour traversal.
func TestLoadRejectsBadExcludePattern(t *testing.T) {
	p := writeSpec(t, "protocol: posix\ndefault:\n  mode: \"0755\"\nexclude:\n  - \"[\"\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("Load() error = nil, want a rejection of the malformed glob")
	}
	if !strings.Contains(err.Error(), "exclude[0]") {
		t.Errorf("Load() error = %v, want it to name the offending list entry", err)
	}
}

func TestLoadRejectsAbsoluteExcludePattern(t *testing.T) {
	p := writeSpec(t, "protocol: posix\ndefault:\n  mode: \"0755\"\nexclude:\n  - \"/mnt/data/.snapshot\"\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of absolute exclude pattern")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("Load() error = %v, want it to mention 'absolute'", err)
	}
}

func TestValidateExcludePatternRejectsDoublestar(t *testing.T) {
	if err := ValidateExcludePattern("**/.snapshot"); err == nil {
		t.Error("ValidateExcludePattern(**/.snapshot) = nil, want error for ** glob")
	}
	if err := ValidateExcludePattern("a/**/b"); err == nil {
		t.Error("ValidateExcludePattern(a/**/b) = nil, want error for ** glob")
	}
}

func TestValidateExcludePatternRejectsAbsolute(t *testing.T) {
	if err := ValidateExcludePattern("/etc/data"); err == nil {
		t.Error("ValidateExcludePattern(/etc/data) = nil, want error for absolute path")
	}
	if err := ValidateExcludePattern(".snapshot"); err != nil {
		t.Errorf("ValidateExcludePattern(.snapshot) = %v, want nil for relative pattern", err)
	}
}

func TestLoadRejectsEmptyExcludePattern(t *testing.T) {
	p := writeSpec(t, "protocol: posix\ndefault:\n  mode: \"0755\"\nexclude:\n  - \"\"\n")
	if _, err := Load(p); err == nil {
		t.Fatal("Load() error = nil, want an empty pattern to be refused")
	}
}

func TestMergeExcludesUnionsAndDedupes(t *testing.T) {
	got := MergeExcludes([]string{".snapshot", "*.tmp"}, []string{"*.tmp", "cache"})
	want := []string{".snapshot", "*.tmp", "cache"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeExcludes() = %v, want %v (spec order first, no duplicates)", got, want)
	}
	if got := MergeExcludes(nil, nil); got != nil {
		t.Errorf("MergeExcludes() = %v, want nil for no patterns", got)
	}
}

func TestExcluderMatchesBaseNameAnywhere(t *testing.T) {
	e, err := NewExcluder("/mnt/t", []string{".snapshot", "*.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/mnt/t/.snapshot", "/mnt/t/a/b/.snapshot", "/mnt/t/a/x.tmp"} {
		if !e.Match(p) {
			t.Errorf("Match(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/mnt/t/a", "/mnt/t/snapshot", "/mnt/t/a/x.tmpx"} {
		if e.Match(p) {
			t.Errorf("Match(%q) = true, want false", p)
		}
	}
}

// A pattern containing a slash is anchored at the target root, and
// filepath.Match wildcards never cross a separator, so it matches at one depth
// only. That limitation is the documented behavior, so it is tested.
func TestExcluderMatchesPathRelativeToRoot(t *testing.T) {
	e, err := NewExcluder("/mnt/t", []string{"logs/*.gz"})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Match("/mnt/t/logs/old.gz") {
		t.Error("Match(/mnt/t/logs/old.gz) = false, want true")
	}
	if e.Match("/mnt/t/a/logs/old.gz") {
		t.Error("a slash pattern must be anchored at the root, not matched at any depth")
	}
	if e.Match("/mnt/t/logs/deep/old.gz") {
		t.Error("filepath.Match wildcards must not cross a separator")
	}
	if e.Match("/elsewhere/logs/old.gz") {
		t.Error("a path outside the root must not match")
	}
}

// Excluding the target itself would turn the whole run into a no-op reported as
// success.
func TestExcluderNeverMatchesRoot(t *testing.T) {
	e, err := NewExcluder("/mnt/t/case42", []string{"case42"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Match("/mnt/t/case42") {
		t.Error("Match(root) = true, want false")
	}
	if !e.Match("/mnt/t/case42/a/case42") {
		t.Error("the pattern must still match the same name below the root")
	}
}

func TestExcluderMatchOrUnderCatchesDescendants(t *testing.T) {
	e, err := NewExcluder("/mnt/t", []string{".snapshot", "*.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/mnt/t/.snapshot",
		"/mnt/t/.snapshot/daily.1",
		"/mnt/t/.snapshot/daily.1/deep/file.txt",
		"/mnt/t/a/b/.snapshot/c/d",
		"/mnt/t/a/x.tmp",
	} {
		if !e.MatchOrUnder(p) {
			t.Errorf("MatchOrUnder(%q) = false, want true", p)
		}
	}
	for _, p := range []string{
		"/mnt/t/a",
		"/mnt/t/snapshot/file",
		"/mnt/t/a/x.tmpx",
	} {
		if e.MatchOrUnder(p) {
			t.Errorf("MatchOrUnder(%q) = true, want false", p)
		}
	}
}

func TestExcluderMatchOrUnderPathGlobAncestors(t *testing.T) {
	e, err := NewExcluder("/mnt/t", []string{"logs/*.gz"})
	if err != nil {
		t.Fatal(err)
	}
	if !e.MatchOrUnder("/mnt/t/logs/old.gz") {
		t.Error("MatchOrUnder should match the path itself")
	}
	if !e.MatchOrUnder("/mnt/t/logs/old.gz/child") {
		t.Error("MatchOrUnder must catch children of a path-glob match")
	}
	if e.MatchOrUnder("/mnt/t/a/logs/old.gz") {
		t.Error("slash pattern anchored at root, must not match deeper")
	}
}

func TestExcluderMatchOrUnderNilReceiver(t *testing.T) {
	var e *Excluder
	if e.MatchOrUnder("/mnt/t/anything") {
		t.Error("nil Excluder must match nothing")
	}
}

func TestNewExcluderCleansBeforeClassify(t *testing.T) {
	e, err := NewExcluder("/mnt/t", []string{"a/../b"})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Match("/mnt/t/b") {
		t.Error("cleaned pattern 'b' should match as base name")
	}
}

func TestNewExcluderNilForEmptyAndRejectsBadPattern(t *testing.T) {
	e, err := NewExcluder("/mnt/t", nil)
	if err != nil || e != nil {
		t.Fatalf("NewExcluder(nil) = %v, %v, want nil, nil", e, err)
	}
	if e.Match("/mnt/t/anything") {
		t.Error("a nil Excluder must match nothing")
	}
	if _, err := NewExcluder("/mnt/t", []string{"["}); err == nil {
		t.Error("NewExcluder() error = nil, want a rejection of the malformed glob")
	}
}

func TestPrintPlanShowsEffectiveExcludes(t *testing.T) {
	s := &Spec{Protocol: "posix", Default: RulePerms{Mode: "0755"}}
	var b strings.Builder
	PrintPlan(&b, s, PlanContext{Target: "/mnt/t", Transport: "kernel", Excludes: []string{".snapshot", "*.tmp"}})
	out := b.String()
	if !strings.Contains(out, "Exclude:  .snapshot *.tmp") {
		t.Errorf("plan should list the effective excludes; got:\n%s", out)
	}

	b.Reset()
	PrintPlan(&b, s, PlanContext{Target: "/mnt/t", Transport: "kernel"})
	if !strings.Contains(b.String(), "Exclude:  none") {
		t.Errorf("plan should say none when nothing is excluded; got:\n%s", b.String())
	}
}

func TestSplitExcludesCleansWithSlashSemantics(t *testing.T) {
	base, rel := SplitExcludes([]string{"./logs/*.gz", ".snapshot", "*.tmp", "a/../b/c", "logs/"})
	if got := strings.Join(base, ","); got != ".snapshot,*.tmp,logs" {
		t.Errorf("base = %q", got)
	}
	if got := strings.Join(rel, ","); got != "logs/*.gz,b/c" {
		t.Errorf("path = %q", got)
	}
	base, rel = SplitExcludes(nil)
	if base == nil || rel == nil {
		t.Errorf("SplitExcludes(nil) = %v, %v; want empty, non-nil slices", base, rel)
	}
}
