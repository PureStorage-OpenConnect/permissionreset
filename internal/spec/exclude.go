package spec

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// ValidateExcludePattern rejects a pattern filepath.Match cannot compile, and an
// empty one. Validation happens at spec load time and at flag parse time so a
// typo fails before a single directory is read, rather than silently matching
// nothing across a multi-hour traversal.
func ValidateExcludePattern(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("empty exclude pattern")
	}
	if filepath.IsAbs(p) {
		return fmt.Errorf("absolute exclude pattern %q can never match (paths are matched relative to the target root)", p)
	}
	if strings.Contains(p, "**") {
		return fmt.Errorf("exclude pattern %q contains **: Go's filepath.Match has no recursive glob; use a base-name pattern without slashes to match at any depth", p)
	}
	if _, err := filepath.Match(p, "probe"); err != nil {
		return fmt.Errorf("invalid glob pattern %q: %w", p, err)
	}
	return nil
}

// MergeExcludes unions the spec's exclude list with the command line's, in that
// order, dropping duplicates. The two compose rather than override: an operator
// adding --exclude for one run must not silently lose the patterns the spec
// author put there deliberately.
func MergeExcludes(fromSpec, fromFlags []string) []string {
	if len(fromSpec) == 0 && len(fromFlags) == 0 {
		// nil rather than an empty slice: a Result carrying [] instead of null
		// reads as "excludes were configured and matched nothing".
		return nil
	}
	seen := make(map[string]bool, len(fromSpec)+len(fromFlags))
	out := make([]string, 0, len(fromSpec)+len(fromFlags))
	for _, list := range [][]string{fromSpec, fromFlags} {
		for _, p := range list {
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// Excluder decides whether one path is out of scope for the run.
//
// MATCHING RULES, both filepath.Match syntax:
//
//   - A pattern with NO slash is matched against the path's BASE NAME, so
//     ".snapshot" excludes every .snapshot anywhere in the tree and "*.tmp"
//     excludes every temp file.
//   - A pattern WITH a slash is matched against the path relative to the target
//     root, e.g. "logs/*.gz". filepath.Match's wildcards never cross a
//     separator, so such a pattern is anchored at the root and matches a fixed
//     depth. There is no "**". A pattern with a slash that does not describe a
//     path under the root simply never matches.
//
// A matched DIRECTORY is pruned: it is not descended and nothing beneath it is
// enumerated, so one pattern removes a whole subtree at no traversal cost. The
// --pfind enumerator still walks the subtree (pfind is an external process that
// enumerates before we see its output), but the filter uses MatchOrUnder so
// children of an excluded directory are dropped from the stream.
type Excluder struct {
	root      string
	baseGlobs []string
	pathGlobs []string
}

// NewExcluder compiles a pattern list against a target root. It returns nil (and
// no error) for an empty list, and Excluder's methods tolerate a nil receiver,
// so callers do not need a "was anything excluded" branch.
func NewExcluder(root string, patterns []string) (*Excluder, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	for _, p := range patterns {
		if err := ValidateExcludePattern(p); err != nil {
			return nil, err
		}
	}
	e := &Excluder{root: filepath.Clean(root)}
	e.baseGlobs, e.pathGlobs = splitExcludes(patterns, filepath.Clean)
	return e, nil
}

// SplitExcludes sorts patterns into base-name and root-relative globs the way
// NewExcluder does, but cleans them with path.Clean, so the split is the one a
// Linux run makes whatever OS this runs on. build-spec --sacl-plan hands it to
// Set-SaclOnly.ps1, which must select exactly what permissionreset would.
// Both results are non-nil.
func SplitExcludes(patterns []string) (base, rel []string) {
	return splitExcludes(patterns, path.Clean)
}

// splitExcludes is the one split rule: a cleaned pattern containing "/" is
// matched against the root-relative path, any other against the base name.
func splitExcludes(patterns []string, clean func(string) string) (base, rel []string) {
	base, rel = []string{}, []string{}
	for _, p := range patterns {
		cleaned := clean(p)
		if strings.Contains(cleaned, "/") {
			rel = append(rel, cleaned)
			continue
		}
		base = append(base, cleaned)
	}
	return base, rel
}

// Match reports whether path is excluded. The root itself is never excluded: a
// pattern matching the target would turn the whole run into a no-op reported as
// success, which is worse than requiring the operator to fix the target.
func (e *Excluder) Match(path string) bool {
	if e == nil || path == "" {
		return false
	}
	clean := filepath.Clean(path)
	if clean == e.root {
		return false
	}
	base := filepath.Base(clean)
	for _, g := range e.baseGlobs {
		if ok, _ := filepath.Match(g, base); ok {
			return true
		}
	}
	if len(e.pathGlobs) == 0 {
		return false
	}
	rel, err := filepath.Rel(e.root, clean)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	for _, g := range e.pathGlobs {
		if ok, _ := filepath.Match(g, rel); ok {
			return true
		}
	}
	return false
}

// MatchOrUnder reports whether path itself or any ancestor between it and the
// root is excluded. The built-in walk prunes excluded directories before
// descent, so Match alone is sufficient. An external enumerator like pfind has
// already walked the subtree by the time its output arrives, so children of an
// excluded directory must be caught by testing ancestor components.
func (e *Excluder) MatchOrUnder(path string) bool {
	if e == nil || path == "" {
		return false
	}
	clean := filepath.Clean(path)
	for clean != e.root && clean != "/" && clean != "." {
		if e.Match(clean) {
			return true
		}
		clean = filepath.Dir(clean)
	}
	return false
}
