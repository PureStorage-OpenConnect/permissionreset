//go:build windows

package platform

const (
	OS = "windows"

	// KernelTransport is false: Windows has no system.nfs4_acl extended attribute.
	KernelTransport = false

	// Pfind is false: RapidFile pfind is a Linux product.
	Pfind = false

	// SMBBackend is false on this build. See the Linux constant for details.
	SMBBackend = false

	// LocalIdentityLookup is false: Windows has no getpwnam and os/user resolves
	// against the local SAM, not a POSIX directory, so principal pre-resolution
	// would produce false failures for directory accounts.
	LocalIdentityLookup = false

	// CredentialFromProcess is false: os.Getuid and os.Getgid return -1 on
	// Windows. Casting -1 to uint32 gives 4294967295, which is not a usable
	// AUTH_SYS credential. Use --auth-uid and --auth-gid explicitly instead.
	CredentialFromProcess = false
)
