//go:build linux

// Package platform states, as build-tagged constants, which capabilities this
// build has. It exists so that every gating decision in the program reads one
// matrix instead of repeating a runtime.GOOS comparison, and so that the
// decisions compile away on platforms that cannot support them.
//
// The names describe capabilities, not operating systems. A platform that later
// gains one changes exactly one file.
package platform

const (
	OS = "linux"

	// KernelTransport is whether ACLs can be reached through
	// setxattr("system.nfs4_acl", ...) on a mounted export. That extended
	// attribute is a Linux NFS client invention and exists on no other operating
	// system, so this is the single largest platform difference in the program.
	KernelTransport = true

	// Pfind is whether RapidFile pfind can enumerate a mounted path.
	Pfind = true

	// SMBBackend is whether the smb protocol backend can shell out to smbcacls
	// against a UNC path.
	//
	// NOTHING READS THIS TODAY, deliberately. internal/spec rejects
	// `protocol: smb` at load time on every platform (spec.go:146-147, inside
	// (*Spec).validate), so apply.go's `case "smb"` is unreachable and a
	// platform gate placed after spec.Load could never fire. The constant is
	// declared anyway because it is part of the matrix this package exists to
	// state, and because the day the validator admits smb it is the gate's
	// condition. See Task 4 for why the gate itself was cut.
	SMBBackend = true

	// LocalIdentityLookup is whether os/user can resolve the principal names a
	// spec is likely to name. False where getpwnam has no directory behind it,
	// which turns principal pre-resolution from a safety check into a false
	// failure. It says nothing about whether the ARRAY can resolve them.
	LocalIdentityLookup = true

	// CredentialFromProcess is whether os.Getuid and os.Getgid return a usable
	// AUTH_SYS credential. False on Windows, where both return -1.
	CredentialFromProcess = true
)
