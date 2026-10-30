package platform

import (
	"runtime"
	"testing"
)

// capabilities names every constant this package must export on every platform
// it supports. The array exists to be compiled, not to be read: a platform file
// that forgets a constant fails to type-check for that GOOS, and `GOOS=darwin go
// vet ./...` in CI (see .github/workflows/ci.yml, the build job) type-checks test
// files, so the omission is caught on the Linux runner. There is nothing to
// assert about the values themselves -- they are declarations, and asserting
// that a constant equals itself tests the compiler.
var capabilityList = [...]bool{
	KernelTransport,
	Pfind,
	SMBBackend,
	LocalIdentityLookup,
	CredentialFromProcess,
}

func TestOSMatchesRuntime(t *testing.T) {
	if OS != runtime.GOOS {
		t.Fatalf("platform.OS = %q, want runtime.GOOS = %q", OS, runtime.GOOS)
	}
}

func TestEveryCapabilityIsDeclared(t *testing.T) {
	if got, want := len(capabilityList), 5; got != want {
		t.Fatalf("capabilityList names %d constants, want %d -- add the new one here too", got, want)
	}
}

// Current() is derived from the constants; Linux() and Darwin() are written by
// hand so a test can say which platform it is pretending to be. This asserts
// the two agree, which is the only thing standing between a forgotten field in
// a reference matrix and a whole suite of darwin-simulating tests that pass
// against a matrix no shipped darwin build has.
//
// LIMITATION, and it is not small: only the arm for the GOOS running this test
// executes, and CI runs Linux. The darwin arm is type-checked by
// `GOOS=darwin go vet ./...` and never run. Adding a capability therefore still
// requires editing Darwin() by hand and no test will catch the omission until
// somebody runs the suite on a Mac.
func TestCurrentMatchesTheReference(t *testing.T) {
	var want Capabilities
	switch OS {
	case "linux":
		want = Linux()
	case "darwin":
		want = Darwin()
	case "windows":
		want = Windows()
	default:
		t.Fatalf("no reference matrix for OS %q -- add one beside Linux(), Darwin(), and Windows()", OS)
	}
	if got := Current(); got != want {
		t.Fatalf("Current() = %+v, reference %s() = %+v -- the constants and the reference matrix disagree", got, OS, want)
	}
}
