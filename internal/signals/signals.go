// Package signals owns the two-stage command signal policy shared by the
// long-running binaries.
package signals

import (
	"fmt"
	"io"
	"os"
	"os/signal"
)

// Escalate restores sig's default disposition and resends it to this process.
// Stop must unregister every channel before Reset; otherwise another registered
// channel can swallow the resent signal.
func Escalate(sig os.Signal, stop func(), channels ...chan<- os.Signal) {
	if stop != nil {
		stop()
	}
	for _, ch := range channels {
		signal.Stop(ch)
	}
	signal.Reset(sig)
	if proc, err := os.FindProcess(os.Getpid()); err == nil {
		_ = proc.Signal(sig)
	}
}

// Watch reports the first signal while the caller finishes in-flight work. A
// second signal invokes escalate so the command can restore and resend the
// default disposition instead of becoming immune to Ctrl-C.
func Watch(sigCh <-chan os.Signal, runDone <-chan struct{}, errOut io.Writer, escalate func(os.Signal)) {
	select {
	case sig := <-sigCh:
		fmt.Fprintf(errOut, "\n%s received — finishing in-flight work...\n", sig)
	case <-runDone:
		return
	}
	select {
	case sig := <-sigCh:
		escalate(sig)
	case <-runDone:
	}
}
