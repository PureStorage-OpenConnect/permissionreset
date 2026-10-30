// Package cmdflagstest holds the test-only helper that swaps a command's
// platform matrix.
//
// It is its own package for one reason: a helper taking *testing.T that lived
// in cmdflags or in a command would link the testing package into every shipped
// binary. Test code importing test code costs nothing.
package cmdflagstest

import (
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
)

// With swaps a command's package-level caps for the duration of a test and
// restores it afterwards. Tests using it must not call t.Parallel: caps is
// process-global.
func With(t *testing.T, target *platform.Capabilities, c platform.Capabilities) {
	t.Helper()
	prev := *target
	*target = c
	t.Cleanup(func() { *target = prev })
}
