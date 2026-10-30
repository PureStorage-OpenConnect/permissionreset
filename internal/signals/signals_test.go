package signals

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSecondSignalEscalates(t *testing.T) {
	sigCh := make(chan os.Signal, 2)
	runDone := make(chan struct{})
	escalated := make(chan os.Signal, 1)
	watchDone := make(chan struct{})
	var errOut strings.Builder
	go func() {
		Watch(sigCh, runDone, &errOut, func(sig os.Signal) { escalated <- sig })
		close(watchDone)
	}()

	sigCh <- syscall.SIGINT
	sigCh <- syscall.SIGINT
	select {
	case got := <-escalated:
		if got != syscall.SIGINT {
			t.Fatalf("escalated signal = %v, want SIGINT", got)
		}
	case <-time.After(time.Second):
		t.Fatal("second signal did not escalate")
	}
	<-watchDone
	if want := "interrupt received — finishing in-flight work..."; !strings.Contains(errOut.String(), want) {
		t.Fatalf("stderr = %q, want %q", errOut.String(), want)
	}
}
