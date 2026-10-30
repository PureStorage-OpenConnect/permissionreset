package cmdflagstest_test

import (
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags/cmdflagstest"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
)

func TestWithRestores(t *testing.T) {
	caps := platform.Linux()
	before := caps
	t.Run("swapped", func(t *testing.T) {
		cmdflagstest.With(t, &caps, platform.Darwin())
		if caps.OS != "darwin" {
			t.Fatalf("caps.OS = %q inside the swap", caps.OS)
		}
	})
	if caps != before {
		t.Fatalf("caps = %+v after the subtest, want the original %+v", caps, before)
	}
}
