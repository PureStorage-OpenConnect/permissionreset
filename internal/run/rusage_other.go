//go:build !unix

package run

import "time"

// processCPU has no portable implementation. The linger verdict reports the
// missing half explicitly rather than guessing, because a verdict computed from
// gather depth alone would recommend building a linger on a client with idle
// cores -- the one case where it is guaranteed to lose.
func processCPU() (time.Duration, bool) { return 0, false }
