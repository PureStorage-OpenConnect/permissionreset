package stats

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

type Stats struct {
	Applied    atomic.Int64
	Skipped    atomic.Int64
	Errors     atomic.Int64
	Enumerated atomic.Int64
	Symlinks   atomic.Int64
	// Excluded counts objects an exclude pattern took out of scope. An excluded
	// directory counts once, for itself: its subtree is never enumerated, so
	// there is nothing else to count.
	Excluded atomic.Int64
}

type Snapshot struct {
	Applied    int64
	Skipped    int64
	Errors     int64
	Enumerated int64
	Symlinks   int64
	Excluded   int64
}

func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		Applied:    s.Applied.Load(),
		Skipped:    s.Skipped.Load(),
		Errors:     s.Errors.Load(),
		Enumerated: s.Enumerated.Load(),
		Symlinks:   s.Symlinks.Load(),
		Excluded:   s.Excluded.Load(),
	}
}

func (s *Stats) IncApplied()    { s.Applied.Add(1) }
func (s *Stats) IncSkipped()    { s.Skipped.Add(1) }
func (s *Stats) IncError()      { s.Errors.Add(1) }
func (s *Stats) IncEnumerated() { s.Enumerated.Add(1) }
func (s *Stats) IncSymlinks()   { s.Symlinks.Add(1) }
func (s *Stats) IncExcluded()   { s.Excluded.Add(1) }

// Reporter prints progress to w every interval until stop is closed.
func (s *Stats) Reporter(w io.Writer, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			fmt.Fprintln(w)
			return
		case <-ticker.C:
			excl := s.Excluded.Load()
			if excl > 0 {
				fmt.Fprintf(w, "\r  applied=%d  skipped=%d  errors=%d  excluded=%d  enumerated=%d  ",
					s.Applied.Load(), s.Skipped.Load(), s.Errors.Load(), excl, s.Enumerated.Load())
			} else {
				fmt.Fprintf(w, "\r  applied=%d  skipped=%d  errors=%d  enumerated=%d  ",
					s.Applied.Load(), s.Skipped.Load(), s.Errors.Load(), s.Enumerated.Load())
			}
		}
	}
}
