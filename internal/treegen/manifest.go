package treegen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ManifestVersion is the schema version stamped into every manifest this
// package writes. Version 0 means a manifest written before the shape record
// existed; readers must treat a nil Shape as "shape unknown", never as
// "shape mismatched".
//
// It does not discriminate every key. Purely additive optional fields --
// manifest_path is the first -- are omitempty and safe in both directions, so
// they carry no version bump: an old reader ignores them and a new reader sees
// the zero value, which is the same answer it gets from an older manifest.
const ManifestVersion = 1

// ManifestName is the manifest's fixed basename inside a generated tree. It
// doubles as the marker that says "treegen created this root".
const ManifestName = "acl_manifest.json"

// ManifestShape records the generation parameters that produced a tree. It
// exists so a consumer can tell whether an existing tree is the tree it asked
// for without walking it, and so a probe run can be extrapolated to a full
// run: TotalPaths/Copies is the paths-per-copy figure used for sizing.
type ManifestShape struct {
	Copies          int   `json:"copies"`
	SeedFiles       int   `json:"seed_files"`
	MaxDepth        int   `json:"max_depth"`
	Seed            int64 `json:"seed"`
	FilesPerSubtree int   `json:"files_per_subtree"`
}

// SubtreeEntry records which directory scenario a directory received. One row
// per subtree, not per path — at 100M paths a per-path manifest would be tens
// of gigabytes.
//
// Used for both the "subtrees" and "departments" arrays: a department directory
// carries a scenario the same way a subtree root does, and giving them one type
// keeps the two arrays comparable rather than gratuitously distinct.
type SubtreeEntry struct {
	Path     string `json:"path"`
	Scenario string `json:"scenario"`
}

// FileOutlier records a file that received a file-specific scenario on top of
// its subtree's directory scenario.
type FileOutlier struct {
	Path     string `json:"path"`
	Scenario string `json:"scenario"`
}

// Manifest is the on-disk acl_manifest.json. It is the single definition of
// that schema; both generation paths write it through writeManifest.
type Manifest struct {
	Version         int               `json:"version"`
	GeneratedTarget string            `json:"generated_target"`
	Domain          string            `json:"domain"`
	Roles           map[string]string `json:"roles"`
	Shape           *ManifestShape    `json:"shape,omitempty"`

	// ManifestPath is where this file was written, recorded only when that is
	// not the default location beside the tree root. A mount-free run has no
	// local tree root, so its manifest lives somewhere the tree does not lead
	// to; without this a reader holding the manifest cannot tell whether it
	// belongs beside the tree or was placed deliberately.
	ManifestPath string `json:"manifest_path,omitempty"`

	TotalPaths   int64          `json:"total_paths"`
	Applied      int64          `json:"applied"`
	Failures     int64          `json:"failures"`
	Departments  []SubtreeEntry `json:"departments"`
	Subtrees     []SubtreeEntry `json:"subtrees"`
	FileOutliers []FileOutlier  `json:"file_outliers"`
}

// ManifestMeta carries the facts the stamping functions cannot derive from
// their own arguments: who the tree was stamped for, and what shape produced
// it.
//
// A non-nil Shape is honored as stated. A nil Shape means "I am not claiming a
// shape": a re-stamp then keeps whatever shape the tree's existing manifest
// records, because a re-stamp did not build the tree and its own Scale flags are
// not evidence about it.
type ManifestMeta struct {
	Roster Roster
	Shape  *ManifestShape

	// Path is where the manifest was written, when that is not the default
	// location beside the tree root. Empty means "beside the tree", which is
	// where every kernel-transport run puts it. A mount-free run has no tree
	// root on this host to put it beside, so the manifest it wrote is not
	// findable from the tree and recording the path is the only way a later
	// reader learns where it went.
	Path string
}

// ShapeFromConfig extracts the shape record a Config will produce.
func ShapeFromConfig(cfg Config) *ManifestShape {
	return &ManifestShape{
		Copies:          cfg.Scale.Copies,
		SeedFiles:       cfg.Scale.SeedFiles,
		MaxDepth:        cfg.Scale.MaxDepth,
		Seed:            cfg.Seed,
		FilesPerSubtree: cfg.FilesPerSubtree,
	}
}

// ReadManifest loads the manifest from a generated tree root. A missing file
// returns an error satisfying os.IsNotExist so callers can distinguish
// "no tree here" from "unreadable tree".
func ReadManifest(root string) (Manifest, error) {
	return readManifestAt(filepath.Join(root, ManifestName))
}

// readManifestAt reads a manifest from an exact path. --manifest can put one
// anywhere, so "beside the tree root" is only the default, not the rule, and a
// reader that assumes the default finds nothing.
func readManifestAt(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// writeManifest writes the manifest atomically and reports failures instead of
// discarding them — a silently missing manifest reads as "not a generated
// tree", which is the one conclusion that lets a caller delete the tree.
// recoverShape fills in a shape the caller did not state from the manifest
// already on disk at manifestPath.
//
// Re-stamping does not change the tree's shape, and this run's Scale flags need
// not be the ones that built it. A shape already on disk is therefore better
// evidence than anything this call infers -- but not better than a shape the
// caller states outright, which is honored as given.
//
// It reads manifestPath rather than the tree root because --manifest may have
// put the previous manifest elsewhere: looking beside the tree would find
// nothing, and the re-stamp would then write a manifest with no shape at all,
// silently destroying the only record sweep --reuse-scratch can verify.
func recoverShape(meta ManifestMeta, manifestPath string) ManifestMeta {
	if meta.Shape != nil {
		return meta
	}
	if prev, err := readManifestAt(manifestPath); err == nil && prev.Shape != nil {
		meta.Shape = prev.Shape
	}
	return meta
}

// writeManifestTo writes the manifest to an arbitrary local path, creating the
// parent directory if it is missing.
//
// Creating the directory belongs here rather than at the call site. It used to
// sit inline in RunContext, where its error gated the whole manifest block --
// so a MkdirAll failure skipped building AND writing the manifest without a
// word, while the run reported success. Every other failure on that path warns.
// See writeManifest above for why a silently missing manifest is the dangerous
// outcome rather than a cosmetic one.
func writeManifestTo(path string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create manifest directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".acl_manifest-*")
	if err != nil {
		return fmt.Errorf("create manifest temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Chmod(tmpName, 0644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// resolveManifestPath decides where acl_manifest.json goes.
//
// explicit is --manifest, and wins outright when set. localTarget is the tree
// root ON THIS HOST, or "" when there is none -- a mount-free run addresses the
// target on the server and has no local directory to put the manifest beside.
//
// The caller passes "" rather than a server-side path on purpose. This is the
// regression finding 12 names: joining a server-side path onto the local
// filesystem creates a stray directory tree named after the export, and a
// working directory that happens to hold a same-named directory would make it
// look deliberate. Deciding locality is the caller's job, because only the
// caller knows whether the mount table explained the target; this function is
// told the answer.
//
// The manifest cannot go over the wire. The client's op set has no OP_WRITE, so
// OPEN(CREATE) produces an empty file and there is no way to put bytes in it.
// Adding OP_WRITE is an explicit non-goal.
func resolveManifestPath(explicit, localTarget string) string {
	if explicit != "" {
		return explicit
	}
	if localTarget == "" {
		// No tree root on this host to sit beside, so the manifest lands in the
		// working directory. Record it absolute: a bare basename means nothing
		// to a reader who does not know which directory the run was started
		// from, and saying where it went is the only reason the path is
		// recorded at all.
		if abs, err := filepath.Abs(ManifestName); err == nil {
			return abs
		}
		return ManifestName
	}
	return filepath.Join(localTarget, ManifestName)
}

// recordedManifestPath is the value that goes in the manifest's own
// manifest_path field: the resolved path, or "" when that is the default
// location beside the tree and the tree already leads to it.
//
// It takes the resolved path rather than the raw --manifest value so that every
// call site records the same thing. They did not: the kernel sites recorded the
// flag as typed and the userspace site recorded the resolved path, which
// coincide only while the flag is set.
func recordedManifestPath(resolved, localTarget string) string {
	if localTarget != "" && resolved == filepath.Join(localTarget, ManifestName) {
		return ""
	}
	return resolved
}

// buildManifest assembles the manifest from a stamping run's results plus the
// metadata its caller holds.
func buildManifest(root string, meta ManifestMeta, totalPaths, applied, failures int64,
	departments, subtrees []SubtreeEntry, outliers []FileOutlier) Manifest {

	if departments == nil {
		departments = []SubtreeEntry{}
	}
	if subtrees == nil {
		subtrees = []SubtreeEntry{}
	}
	if outliers == nil {
		outliers = []FileOutlier{}
	}
	return Manifest{
		Version:         ManifestVersion,
		GeneratedTarget: root,
		Domain:          meta.Roster.Domain,
		Roles:           buildRoleMap(meta.Roster),
		Shape:           meta.Shape,
		ManifestPath:    meta.Path,
		TotalPaths:      totalPaths,
		Applied:         applied,
		Failures:        failures,
		Departments:     departments,
		Subtrees:        subtrees,
		FileOutliers:    outliers,
	}
}
