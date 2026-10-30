//go:build unix

package run

import (
	"syscall"
	"time"
)

// processCPU returns this process's total CPU time, user plus system.
//
// getrusage rather than a /proc read: it is one syscall, needs no parsing, and
// counts the threads that have already exited, which matters because a repair
// run's worker goroutines are spread over every thread the scheduler ever
// created. RUSAGE_SELF already aggregates all of them.
func processCPU() (time.Duration, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	return timevalDuration(ru.Utime) + timevalDuration(ru.Stime), true
}

func timevalDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
}
