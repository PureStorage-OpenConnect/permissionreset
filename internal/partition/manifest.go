// Package partition splits one repair into stable, nonoverlapping subtree jobs
// (PS-12, #81), each with its own checkpoint and evidence, so a billion-object
// namespace restarts and is inspected one bounded piece at a time.
//
// A manifest names a root and a list of partitions, each a directory under the
// root. The partitions are disjoint by path: no partition may sit under
// another. Everything under the root that no partition claims -- the root
// itself, the ancestors of the partition roots and their other entries --
// belongs to one implicit partition, the residual, which walks the root and
// hands each partition root off instead of descending it. Every object reached
// by the walk is therefore owned by exactly one partition, and the residual's
// handoff count proves that every partition root was reached.
//
// Ownership at the boundary: a partition owns its root directory's own apply
// and everything beneath it; the residual owns the partition root's parent and
// never touches the partition root. The partitions run one at a time, residual
// first, so no two runs ever write the same directory, and the residual's fix
// of a non-traversable ancestor happens before any partition needs to cross it.
//
// Path disjointness is not inode disjointness. A hard link with names in two
// partitions is stamped by both, idempotently, exactly as two names in one run
// are (docs/NAMESPACE_SEMANTICS.md). A bind mount or a second mount of the same
// export can alias one directory under two names; on the kernel transport the
// manifest check refuses two partition roots with the same device and inode,
// but it cannot find an alias deeper than a partition root without walking.
package partition

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
)

// ResidualName is the implicit partition that owns everything no listed
// partition claims. Manifest names may not use it.
const ResidualName = "residual"

const manifestVersion = 1

// Manifest is the operator's file, as written.
type Manifest struct {
	Version int `yaml:"version"`
	// Root is the tree the partitions divide: a local path on the kernel
	// transport, a server-side path on the userspace transport.
	Root string `yaml:"root"`
	// Spec is the permission spec every partition applies. A relative path is
	// relative to the manifest file.
	Spec string `yaml:"spec"`
	// Exclude is unioned with the spec's exclude: list, as --exclude is. Slash
	// patterns are anchored at Root in every partition.
	Exclude []string `yaml:"exclude"`
	// StateDir holds the state file and every partition's checkpoint, evidence
	// and error log. Relative to the manifest file.
	StateDir string `yaml:"state_dir"`
	// Evidence turns on per-partition evidence directories. Default true:
	// evidence is what makes a partition's result checkable afterwards.
	Evidence   *bool       `yaml:"evidence"`
	Partitions []Partition `yaml:"partitions"`
}

// Partition is one listed subtree.
type Partition struct {
	Name string `yaml:"name"`
	// Path is relative to the manifest root.
	Path string `yaml:"path"`
}

// Job is one partition resolved against the manifest: what a single run is
// handed.
type Job struct {
	Name string
	// Root is the directory the run walks.
	Root string
	// Rel is Root relative to the manifest root; "." for the residual.
	Rel string
	// Handoff is the partition roots the residual prunes. Empty for a listed
	// partition.
	Handoff []string
}

// Plan is a loaded and validated manifest.
type Plan struct {
	Path     string
	Digest   string // SHA-256 of the manifest bytes
	Manifest Manifest
	// Root, SpecPath and StateDir are resolved: Root cleaned, the other two
	// made absolute against the manifest's directory.
	Root, SpecPath, StateDir string
	Spec                     *spec.Spec
	Excludes                 []string // effective: spec's, then the manifest's
	Evidence                 bool
	// Jobs is the residual first, then the listed partitions in manifest order.
	Jobs []Job
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Load reads, parses and validates a manifest. It reads nothing under Root:
// see CheckIdentity for the checks that need the tree.
func Load(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("partition manifest %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	p := &Plan{Path: path, Digest: hex.EncodeToString(sum[:]), Manifest: m}
	if err := p.resolve(); err != nil {
		return nil, fmt.Errorf("partition manifest %s: %w", path, err)
	}
	return p, nil
}

func (p *Plan) resolve() error {
	m := &p.Manifest
	if m.Version != manifestVersion {
		return fmt.Errorf("version: want %d, got %d", manifestVersion, m.Version)
	}
	if m.Root == "" || !filepath.IsAbs(m.Root) {
		return fmt.Errorf("root: must be an absolute path, got %q", m.Root)
	}
	p.Root = filepath.Clean(m.Root)
	if p.Root == "/" {
		return errors.New("root: may not be /")
	}
	if m.Spec == "" {
		return errors.New("spec: required")
	}
	if m.StateDir == "" {
		return errors.New("state_dir: required")
	}
	base := filepath.Dir(p.Path)
	abs := func(s string) (string, error) {
		if !filepath.IsAbs(s) {
			s = filepath.Join(base, s)
		}
		return filepath.Abs(s)
	}
	var err error
	if p.SpecPath, err = abs(m.Spec); err != nil {
		return err
	}
	if p.StateDir, err = abs(m.StateDir); err != nil {
		return err
	}
	p.Evidence = m.Evidence == nil || *m.Evidence

	if p.Spec, err = spec.Load(p.SpecPath); err != nil {
		return err
	}
	for i, x := range m.Exclude {
		if err := spec.ValidateExcludePattern(x); err != nil {
			return fmt.Errorf("exclude[%d]: %w", i, err)
		}
	}
	p.Excludes = spec.MergeExcludes(p.Spec.Exclude, m.Exclude)
	excluder, err := spec.NewExcluder(p.Root, p.Excludes)
	if err != nil {
		return err
	}

	if len(m.Partitions) == 0 {
		return errors.New("partitions: at least one is required")
	}
	names := map[string]int{}
	rels := make([]string, 0, len(m.Partitions))
	for i, part := range m.Partitions {
		label := fmt.Sprintf("partitions[%d]", i)
		if !nameRE.MatchString(part.Name) {
			return fmt.Errorf("%s.name: %q must be 1-64 characters of letters, digits, '.', '_' or '-', starting with a letter or digit", label, part.Name)
		}
		if strings.EqualFold(part.Name, ResidualName) {
			return fmt.Errorf("%s.name: %q is reserved for the implicit partition", label, part.Name)
		}
		if j, dup := names[strings.ToLower(part.Name)]; dup {
			return fmt.Errorf("%s.name: %q duplicates partitions[%d]", label, part.Name, j)
		}
		names[strings.ToLower(part.Name)] = i
		rel, err := cleanRel(part.Path)
		if err != nil {
			return fmt.Errorf("%s.path: %w", label, err)
		}
		// A partition the exclude list removes would be reached by nobody: the
		// residual prunes its ancestor (or it) as an exclusion before the
		// handoff, and the partition itself would repair what the operator
		// excluded.
		full := filepath.Join(p.Root, rel)
		if excluder.MatchOrUnder(full) {
			return fmt.Errorf("%s.path: %s is excluded (by the spec or manifest exclude list) or sits under an excluded directory", label, rel)
		}
		rels = append(rels, rel)
		p.Jobs = append(p.Jobs, Job{Name: part.Name, Root: full, Rel: rel})
	}
	if err := checkOverlap(rels, m.Partitions); err != nil {
		return err
	}

	residual := Job{Name: ResidualName, Root: p.Root, Rel: "."}
	for _, j := range p.Jobs {
		residual.Handoff = append(residual.Handoff, j.Root)
	}
	p.Jobs = append([]Job{residual}, p.Jobs...)
	return nil
}

// cleanRel accepts a relative, already-clean path with no glob metacharacters.
// Clean is required rather than applied: "a/../b" and "a/./b" are typos at
// best, and silently resolving them is how two partitions come to name one
// directory. Metacharacters are refused so a partition path can never be read
// as a pattern anywhere downstream.
func cleanRel(s string) (string, error) {
	switch {
	case s == "":
		return "", errors.New("required")
	case filepath.IsAbs(s):
		return "", fmt.Errorf("%q must be relative to root", s)
	case filepath.Clean(s) != s:
		return "", fmt.Errorf("%q is not clean (want %q)", s, filepath.Clean(s))
	case s == "." || s == ".." || strings.HasPrefix(s, "../"):
		return "", fmt.Errorf("%q must name a directory strictly under root", s)
	case strings.ContainsAny(s, `*?[]\`):
		return "", fmt.Errorf("%q contains a glob metacharacter", s)
	}
	return s, nil
}

// checkOverlap refuses duplicates and parent/child pairs. Sorted, a path's
// descendants follow it directly ("a" < "a/b" < "a0"), but "a-b" sorts between
// "a" and "a/b", so each path is compared with every later one until the
// prefix stops matching at all.
func checkOverlap(rels []string, parts []Partition) error {
	idx := make([]int, len(rels))
	for i := range idx {
		idx[i] = i
	}
	slices.SortFunc(idx, func(a, b int) int { return strings.Compare(rels[a], rels[b]) })
	for k, i := range idx {
		for _, j := range idx[k+1:] {
			if !strings.HasPrefix(rels[j], rels[i]) {
				break
			}
			switch {
			case rels[j] == rels[i]:
				return fmt.Errorf("partitions %q and %q both name %s", parts[i].Name, parts[j].Name, rels[i])
			case strings.HasPrefix(rels[j], rels[i]+"/"):
				return fmt.Errorf("partition %q (%s) is inside partition %q (%s); partitions may not nest",
					parts[j].Name, rels[j], parts[i].Name, rels[i])
			}
		}
	}
	return nil
}

// Job returns the named job, or nil.
func (p *Plan) Job(name string) *Job {
	for i := range p.Jobs {
		if p.Jobs[i].Name == name {
			return &p.Jobs[i]
		}
	}
	return nil
}
