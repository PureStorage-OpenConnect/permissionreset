package partition

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// StateName is the state file inside the manifest's state_dir.
const StateName = "state.json"

const stateVersion = 1

// Partition status values.
const (
	StatusPending  = "pending"
	StatusRunning  = "running"
	StatusComplete = "complete"
	StatusFailed   = "failed"
)

// State is the durable record of a partitioned run: which partitions are done,
// and every attempt's result. It is rewritten whole (temp file, fsync,
// rename) after every status change, so a crash leaves either the old file or
// the new one.
type State struct {
	Version        int    `json:"state_version"`
	ManifestDigest string `json:"manifest_sha256"`
	// Mode is "apply" or "validate". A state belongs to one: a validate that
	// resumed an apply's state would report repairs as verified.
	Mode        string              `json:"mode"`
	ToolVersion string              `json:"tool_version"`
	Identities  map[string]Identity `json:"identities,omitempty"`
	Partitions  []PartState         `json:"partitions"`
}

// PartState is one partition's progress.
type PartState struct {
	Name     string    `json:"name"`
	Root     string    `json:"root"`
	Status   string    `json:"status"`
	Attempts []Attempt `json:"attempts,omitempty"`
}

// Attempt is one run of one partition.
type Attempt struct {
	N        int       `json:"n"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended,omitzero"`
	Resumed  bool      `json:"resumed"`
	ExitCode int       `json:"exit_code"`
	Error    string    `json:"error,omitempty"`
	// Reasons says why a finished attempt is not complete.
	Reasons             []string `json:"reasons,omitempty"`
	Counts              Counts   `json:"counts"`
	EnumerationComplete bool     `json:"enumeration_complete"`
	Interrupted         bool     `json:"interrupted,omitempty"`
	// Uncounted is set when the process died during the attempt: what it did
	// before dying is not in Counts.
	Uncounted bool `json:"uncounted,omitempty"`
	// HandedOff is the residual's pruned partition roots, this attempt.
	HandedOff      []string `json:"handed_off,omitempty"`
	Checkpoint     string   `json:"checkpoint,omitempty"`
	ErrorLog       string   `json:"error_log,omitempty"`
	EvidenceDir    string   `json:"evidence_dir,omitempty"`
	EvidenceStatus string   `json:"evidence_status,omitempty"`
	// EvidenceRecords is records written to the attempt's shards.
	EvidenceRecords int64 `json:"evidence_records,omitempty"`
}

// Counts is one attempt's object counts, the same fields the run summary
// reports, so an aggregate is a plain sum.
type Counts struct {
	Enumerated   int64 `json:"enumerated"`
	Applied      int64 `json:"applied"`
	Skipped      int64 `json:"skipped"`
	Symlinks     int64 `json:"symlinks"`
	Excluded     int64 `json:"excluded"`
	Failed       int64 `json:"failed"`
	Match        int64 `json:"match"`
	Mismatch     int64 `json:"mismatch"`
	Unreadable   int64 `json:"unreadable"`
	NotAttempted int64 `json:"not_attempted"`
	TotalErrors  int64 `json:"total_errors"`
}

func (c *Counts) add(o Counts) {
	c.Enumerated += o.Enumerated
	c.Applied += o.Applied
	c.Skipped += o.Skipped
	c.Symlinks += o.Symlinks
	c.Excluded += o.Excluded
	c.Failed += o.Failed
	c.Match += o.Match
	c.Mismatch += o.Mismatch
	c.Unreadable += o.Unreadable
	c.NotAttempted += o.NotAttempted
	c.TotalErrors += o.TotalErrors
}

// part returns name's state, or nil.
func (s *State) part(name string) *PartState {
	for i := range s.Partitions {
		if s.Partitions[i].Name == name {
			return &s.Partitions[i]
		}
	}
	return nil
}

func newState(p *Plan, mode, toolVersion string, ids map[string]Identity) *State {
	s := &State{
		Version: stateVersion, ManifestDigest: p.Digest, Mode: mode,
		ToolVersion: toolVersion, Identities: ids,
	}
	for _, j := range p.Jobs {
		s.Partitions = append(s.Partitions, PartState{Name: j.Name, Root: j.Root, Status: StatusPending})
	}
	return s
}

// loadState reads the state file, or returns nil when there is none.
func loadState(dir string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(dir, StateName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, StateName), err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("%s: unsupported state version %d", filepath.Join(dir, StateName), s.Version)
	}
	return &s, nil
}

// save writes the state atomically.
func (s *State) save(dir string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, StateName), append(data, '\n'))
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// lockDir takes an exclusive, non-blocking lock on dir/lock for the life of
// the process. Two drivers on one state directory would run the same partition
// at once, which is exactly the shared-boundary race serial execution rules
// out, so the second is refused rather than queued.
func lockDir(dir string) (release func(), err error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another partitioned run holds %s", filepath.Join(dir, "lock"))
		}
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
