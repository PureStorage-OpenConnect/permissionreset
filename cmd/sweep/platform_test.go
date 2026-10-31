package main

import (
	"os"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
)

// The execute tests drive fake provisioners and trial runners through the
// Linux code path, so they pin the Linux capability matrix whatever the host.
// Tests about another platform's refusals swap caps themselves with
// cmdflagstest.With, which restores this value afterwards.
func TestMain(m *testing.M) {
	caps = platform.Linux()
	os.Exit(m.Run())
}
