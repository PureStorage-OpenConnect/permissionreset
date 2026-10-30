package run

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// handoffSet is Config.Handoff compiled for the walk: an exact-path set, since
// a partition root is one literal directory and never a pattern. The walk asks
// it about every candidate path, so the lookup is one map probe and no
// cleaning; the keys are cleaned once here instead.
type handoffSet struct {
	paths map[string]struct{}
	// sorted is the cleaned list, for the checkpoint binding.
	sorted []string
	// seen is which handoffs were reached. A handoff is rare (one per
	// partition) so the lock is off the hot path, and the list is what lets a
	// driver union several resumed attempts without counting one root twice.
	mu   sync.Mutex
	seen []string
}

func newHandoff(cfg Config) (*handoffSet, error) {
	if len(cfg.Handoff) == 0 {
		return nil, nil
	}
	if cfg.Pfind {
		// pfind has already enumerated a handed-off subtree by the time its
		// stream is read, and its ancestor filter cannot tell a handoff from an
		// exclusion; a partition never runs it.
		return nil, fmt.Errorf("a partitioned run cannot use --pfind")
	}
	root := filepath.Clean(cfg.Root)
	h := &handoffSet{paths: make(map[string]struct{}, len(cfg.Handoff))}
	for _, p := range cfg.Handoff {
		c := filepath.Clean(p)
		if rel, err := filepath.Rel(root, c); err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			return nil, fmt.Errorf("handoff %s is not under the run root %s", p, cfg.Root)
		}
		if _, dup := h.paths[c]; dup {
			return nil, fmt.Errorf("handoff %s is listed twice", p)
		}
		h.paths[c] = struct{}{}
		h.sorted = append(h.sorted, c)
	}
	slices.Sort(h.sorted)
	return h, nil
}

// take reports whether path is handed off, and counts it when it is. Nil-safe.
func (h *handoffSet) take(path string) bool {
	if h == nil {
		return false
	}
	if _, ok := h.paths[path]; !ok {
		return false
	}
	h.mu.Lock()
	h.seen = append(h.seen, path)
	h.mu.Unlock()
	return true
}

// reached returns the handoffs the walk pruned, sorted, one entry per prune.
func (h *handoffSet) reached() []string {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := slices.Clone(h.seen)
	slices.Sort(out)
	return out
}

// binding is the exclude list checkpoint.RunHash sees. A handoff changes what a
// completed directory means exactly as an exclude does, and so does the root
// slash excludes are anchored at; both are appended under prefixes no exclude
// pattern can carry (a pattern cannot start with "\x00"). A run with neither
// hashes exactly what it always did, so existing checkpoints stay valid.
func (h *handoffSet) binding(excludes []string, anchored bool, excludeRoot string) []string {
	if h == nil && !anchored {
		return excludes
	}
	out := slices.Clone(excludes)
	if anchored {
		out = append(out, "\x00exclude-root:"+excludeRoot)
	}
	if h != nil {
		for _, p := range h.sorted {
			out = append(out, "\x00handoff:"+p)
		}
	}
	return out
}
