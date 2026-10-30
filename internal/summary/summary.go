// Package summary records what a permissionreset run did, in a form a machine can
// read.
//
// The stdout summary this mirrors is written for a person watching a terminal:
// it elides zero-valued lines, rounds seconds, and its wording has changed
// across releases. None of that is usable by an automation harness or by a
// support engineer reconstructing a run from a collected bundle, which is why
// this exists as a separate, versioned artifact rather than as a parse of the
// human output.
//
// Every field is filled by cmd/permissionreset; nothing in here touches the
// filesystem except FileDigest and WriteFile.
package summary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// SchemaVersion is bumped whenever a field changes meaning or disappears.
// Adding a field does not bump it: a consumer that ignores unknown keys keeps
// working, which is the whole point of writing JSON rather than a table.
//
// Version 2 adds run_id, accounting, verification and records. Every version 1
// field keeps its name and meaning; the bump is because verification.verdict,
// not objects.match/mismatch, is now the answer to "did this run verify", and
// a consumer must not mistake a v1 file for one that carries that answer.
// Decode migrates a v1 file explicitly.
const SchemaVersion = 2

// RunSummary is the complete machine-readable record of one run.
type RunSummary struct {
	SchemaVersion int    `json:"schema_version"`
	RunID         string `json:"run_id,omitempty"`
	Tool          Tool   `json:"tool"`
	Target        string `json:"target"`
	Transport     Trans  `json:"transport"`
	Spec          Spec   `json:"spec"`
	Options       Opts   `json:"options"`
	Objects       Counts `json:"objects"`
	Errors        Errs   `json:"errors"`
	Prepass       Pre    `json:"prepass"`
	Phases        Phase  `json:"phases"`
	Validate      bool   `json:"validate,omitempty"`
	Interrupted   bool   `json:"interrupted"`
	ExitCode      int    `json:"exit_code"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`

	Accounting   Accounting   `json:"accounting"`
	Verification Verification `json:"verification"`
	// Records references per-object evidence shards. Empty until a producer
	// writes them (PS-09); the manifest never inlines per-object data.
	Records []ShardRef `json:"records,omitempty"`
	// Evidence says whether Records is the whole record of the run. Nil when
	// the run wrote no evidence.
	Evidence *EvidenceStatus `json:"evidence,omitempty"`
}

// EvidenceStatus is the evidence manifest's verdict, carried into the summary
// so a reader of the summary alone knows whether to trust Records. The
// manifest in Dir is the full account.
type EvidenceStatus struct {
	Dir            string   `json:"dir"`
	Manifest       string   `json:"manifest"`
	Status         string   `json:"status"`
	Reasons        []string `json:"reasons,omitempty"`
	Profile        string   `json:"profile"`
	RecordsWritten int64    `json:"records_written"`
	RecordsDropped int64    `json:"records_dropped"`
	NotAttempted   int64    `json:"not_attempted"`
}

// Tool identifies the binary that produced the run, so a summary collected
// weeks later can be tied to a build.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Trans records how the filesystem was reached and which filesystem answered.
//
// FilesystemID is st_dev on the kernel transport and FATTR4_FSID in userspace;
// Source says which, because the two are not interchangeable when comparing
// two summaries. Both are zero when the identity could not be read, and
// Source is then "unknown" -- never silently 0/"st_dev".
type Trans struct {
	Name               string `json:"name"`
	Server             string `json:"server,omitempty"`
	Export             string `json:"export,omitempty"`
	Platform           string `json:"platform"`
	FilesystemID       uint64 `json:"filesystem_id"`
	FilesystemIDSource string `json:"filesystem_id_source"`
}

// Spec records which spec file was applied and its exact content, by digest.
// A path alone does not identify a spec: the file is routinely edited between
// runs, and "the spec at /etc/permissionreset/legal.yaml" names different rules on
// different days.
type Spec struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Protocol string `json:"protocol"`
}

// Opts is every effective option, after defaulting. These are the resolved
// values, not what was typed: --workers unset on a FlashBlade userspace run
// records 1024, because 1024 is what ran.
type Opts struct {
	Workers        int      `json:"workers"`
	BatchSize      int      `json:"batch_size"`
	Connections    int      `json:"connections,omitempty"`
	WorkersDefault bool     `json:"workers_defaulted"`
	DryRun         bool     `json:"dry_run"`
	Compare        bool     `json:"compare"`
	SetOwner       bool     `json:"set_owner"`
	Pfind          bool     `json:"pfind"`
	OneFilesystem  bool     `json:"one_filesystem"`
	Exclude        []string `json:"exclude,omitempty"`
	CheckpointPath string   `json:"checkpoint_path,omitempty"`
	Resume         bool     `json:"resume"`
	LogPath        string   `json:"log_path,omitempty"`
	AuditLogPath   string   `json:"audit_log_path,omitempty"`
	EvidenceDir    string   `json:"evidence_dir,omitempty"`
}

// Counts is the object accounting.
type Counts struct {
	Enumerated int64 `json:"enumerated"`
	Applied    int64 `json:"applied"`
	Skipped    int64 `json:"skipped"`
	Symlinks   int64 `json:"symlinks"`
	Excluded   int64 `json:"excluded"`
	Failed     int64 `json:"failed"`
	Match      int64 `json:"match,omitempty"`
	Mismatch   int64 `json:"mismatch,omitempty"`
	// AuditKept is objects whose existing audit ACEs a DACL reset wrote back
	// with the new DACL. It is what was sent, as the NFS view showed it: not a
	// read-back (sacl_retention) and not SMB descriptor state.
	AuditKept int64 `json:"audit_kept,omitempty"`
}

// Errs splits the error count by the phase that produced it. The stdout line
// collapses these into one number when it is zero, which is exactly the case
// where a harness still needs the breakdown to prove it was zero everywhere.
type Errs struct {
	Walk       int64 `json:"walk"`
	Apply      int64 `json:"apply"`
	DirFix     int64 `json:"dir_fix"`
	Duplicates int64 `json:"duplicate_completions"`
	Total      int64 `json:"total"`
}

// Pre is the pre-pass (directory fix) accounting. FixSeconds and
// ReaddirSeconds are summed across workers, not wall clock.
type Pre struct {
	DirsFixed      int     `json:"dirs_fixed"`
	Errors         int     `json:"errors"`
	FixSeconds     float64 `json:"fix_seconds_summed"`
	ReaddirSeconds float64 `json:"readdir_seconds_summed"`
}

// Phase is elapsed wall-clock time per phase. PrepassSeconds is zero on a
// fused run, where there is no separate pre-pass to time.
type Phase struct {
	PrepassSeconds float64 `json:"prepass_seconds"`
	ApplySeconds   float64 `json:"apply_seconds"`
	TotalSeconds   float64 `json:"total_seconds"`
	Fused          bool    `json:"fused"`
}

// FileDigest returns the lowercase hex SHA-256 of a file's contents. It streams
// rather than reading the whole file, because nothing here needs the bytes.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteFile writes the summary as indented JSON to path, atomically: a temp
// file in the same directory, fsynced, then renamed over the destination.
//
// Atomicity matters because the summary is written at the very end of a run
// that may have taken hours, and the thing reading it is usually a harness
// polling for the file to appear. A partial write would be read as a truncated
// run rather than as a write in progress.
//
// An inconsistent summary -- coverage that does not add up, or a verdict its
// dimensions do not support -- is refused rather than written.
func (s *RunSummary) WriteFile(path string) error {
	s.SchemaVersion = SchemaVersion
	if err := s.Check(); err != nil {
		return fmt.Errorf("refusing to write an inconsistent summary: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode summary: %w", err)
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".permissionreset-summary-*")
	if err != nil {
		return fmt.Errorf("create temp summary in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Any failure past this point leaves the temp file behind unless removed;
	// the rename is what makes the removal a no-op on success.
	defer os.Remove(tmpName)

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write summary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync summary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close summary: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename summary into place: %w", err)
	}
	return nil
}

// Stamp records the wall-clock bounds of the run in RFC 3339 with seconds.
func (s *RunSummary) Stamp(start, end time.Time) {
	s.StartedAt = start.UTC().Format(time.RFC3339)
	s.FinishedAt = end.UTC().Format(time.RFC3339)
}
