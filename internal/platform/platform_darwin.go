//go:build darwin

package platform

const (
	OS = "darwin"

	// KernelTransport is false because macOS has no system.nfs4_acl extended
	// attribute. Every syscall the kernel transport uses -- SYS_SETXATTR,
	// Getxattr, Lstat -- does exist on Darwin, so the backend compiles and runs
	// and then fails ENOTSUP per object. Compilation does not protect us here;
	// this constant does.
	//
	// It is also why macOS wants the userspace transport rather than merely
	// tolerating it: Apple's mount_nfs tops out at NFSv4.0 with no minor-version
	// support and cannot mount a 4.1 export at all.
	KernelTransport = false

	// Pfind is false: RapidFile is a Linux product and pfind enumerates a
	// mounted path, which is the thing macOS cannot have here.
	Pfind = false

	// SMBBackend is false: smbcacls is not shipped on macOS. Like its Linux
	// counterpart nothing reads it -- see the note there.
	SMBBackend = false

	// LocalIdentityLookup stays TRUE. A directory-bound Mac resolves principal
	// names through getpwnam exactly as Linux does. What differs is the
	// consequence of a miss, which is a KernelTransport question and not this
	// one: where the array is the authority, a local miss proves nothing.
	LocalIdentityLookup = true

	// CredentialFromProcess is true: os.Getuid and os.Getgid return the real
	// ids. Whether those ids MEAN anything to the array is a separate question,
	// answered by --auth-uid and the local-uid warning.
	CredentialFromProcess = true
)
