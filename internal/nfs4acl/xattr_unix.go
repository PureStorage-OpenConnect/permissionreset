//go:build !windows

package nfs4acl

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SetACL sets the NFSv4 ACL on a file/directory via setxattr syscall.
func SetACL(path string, aclData []byte) error {
	if len(aclData) == 0 {
		return fmt.Errorf("nfs4acl: refusing to set empty ACL on %s", path)
	}
	pathBytes := append([]byte(path), 0)
	attr := append([]byte("system.nfs4_acl"), 0)
	_, _, errno := unix.Syscall6(
		unix.SYS_SETXATTR,
		uintptr(unsafe.Pointer(&pathBytes[0])),
		uintptr(unsafe.Pointer(&attr[0])),
		uintptr(unsafe.Pointer(&aclData[0])),
		uintptr(len(aclData)),
		uintptr(0), // flags: 0 = create or replace
		0,
	)
	if errno != 0 {
		return fmt.Errorf("setxattr %s: %w", path, errno)
	}
	return nil
}

// getxattr is a seam over unix.Getxattr so tests can simulate ERANGE and
// resizing without a real mount. Production code leaves this as the real
// syscall wrapper.
var getxattr = unix.Getxattr

// GetACL reads the raw NFSv4 ACL bytes from a file/directory. The initial
// attempt uses a fixed 8192-byte buffer, which covers the common case
// without a size probe. If the ACL is larger and the kernel returns ERANGE,
// GetACL asks for the required size with a nil/zero-length getxattr,
// allocates a buffer of that size, and retries once. A second failure is
// returned to the caller.
func GetACL(path string) ([]byte, error) {
	buf := make([]byte, 8192)
	sz, err := getxattr(path, "system.nfs4_acl", buf)
	if err == nil {
		return buf[:sz], nil
	}
	if err != unix.ERANGE {
		return nil, fmt.Errorf("getxattr %s: %w", path, err)
	}

	need, err := getxattr(path, "system.nfs4_acl", nil)
	if err != nil {
		return nil, fmt.Errorf("getxattr %s: size probe: %w", path, err)
	}
	buf = make([]byte, need)
	sz, err = getxattr(path, "system.nfs4_acl", buf)
	if err != nil {
		return nil, fmt.Errorf("getxattr %s: retry after resize: %w", path, err)
	}
	return buf[:sz], nil
}
