//go:build !darwin

package treegen

import "golang.org/x/sys/unix"

// errNoAttr is what getxattr returns for an attribute the file does not have.
// Darwin names it ENOATTR; Linux reuses ENODATA.
const errNoAttr = unix.ENODATA
