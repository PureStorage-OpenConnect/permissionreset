package platform

// Capabilities is the platform matrix as a value rather than as constants.
//
// The constants stay the source of truth and nothing in production assigns a
// Capabilities. The value type exists so one Linux test binary can exercise
// both branches of every gate, which real build tags cannot do: a darwin binary
// is not runnable on the runner that runs the tests.
//
// The cost of the value form is that a gating site reading it is no longer
// dead-code eliminated. That is accepted for macOS, where every syscall the
// kernel transport uses exists anyway and there is nothing to eliminate. It is
// NOT accepted for the Windows follow-up: there the sites that must not link
// are behind build tags, and they read the CONSTANTS directly, never a
// Capabilities. Keep that distinction when adding a gate -- if a gate exists to
// stop a symbol being linked, it reads the constant.
type Capabilities struct {
	OS                    string
	KernelTransport       bool
	Pfind                 bool
	SMBBackend            bool
	LocalIdentityLookup   bool
	CredentialFromProcess bool
}

// Current is this build's matrix, read from the constants.
func Current() Capabilities {
	return Capabilities{
		OS:                    OS,
		KernelTransport:       KernelTransport,
		Pfind:                 Pfind,
		SMBBackend:            SMBBackend,
		LocalIdentityLookup:   LocalIdentityLookup,
		CredentialFromProcess: CredentialFromProcess,
	}
}

// Linux, Darwin, and Windows are the three matrices this version ships, named
// so a test says which platform it is pretending to be rather than spelling
// out five booleans and getting one wrong.
//
// They are hand-written, and they are the ONLY hand-written copy: no command
// declares its own. TestCurrentMatchesTheReference asserts the copy for the
// running GOOS agrees with the constants. Adding a capability means editing
// five places -- the three tagged files and these three functions -- and the
// test catches four of them.
func Linux() Capabilities {
	return Capabilities{
		OS: "linux", KernelTransport: true, Pfind: true, SMBBackend: true,
		LocalIdentityLookup: true, CredentialFromProcess: true,
	}
}

func Darwin() Capabilities {
	return Capabilities{
		OS: "darwin", KernelTransport: false, Pfind: false, SMBBackend: false,
		LocalIdentityLookup: true, CredentialFromProcess: true,
	}
}

func Windows() Capabilities {
	return Capabilities{
		OS: "windows", KernelTransport: false, Pfind: false, SMBBackend: false,
		LocalIdentityLookup: false, CredentialFromProcess: false,
	}
}
