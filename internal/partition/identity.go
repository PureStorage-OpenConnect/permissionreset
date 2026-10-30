package partition

import (
	"fmt"
	"os"
	"syscall"
)

// Identity is a partition root's device and inode as the kernel transport sees
// them. It is how a resume tells "the same directory" from "a directory now at
// the same path": a renamed-away and recreated partition root keeps its name
// and loses its inode.
type Identity struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
}

// lstat is a test seam.
var lstat = os.Lstat

// CheckIdentity stats the manifest root and every partition root on the kernel
// transport. It refuses a root that is missing, not a directory, or a symlink
// (a symlinked partition root is an alias, and the walk never follows
// symlinks); two partition roots that are one directory (a bind mount or a
// second mount of the same export); and, under oneFilesystem, a partition root
// on a different filesystem from the manifest root, which the residual would
// have stopped at.
//
// The userspace transport has no local view of the tree, so nothing here
// applies to it; those runs record no identity and say so.
func CheckIdentity(p *Plan, oneFilesystem bool) (map[string]Identity, error) {
	ids := make(map[string]Identity, len(p.Jobs))
	seen := map[Identity]string{}
	var rootDev uint64
	for _, j := range p.Jobs {
		fi, err := lstat(j.Root)
		if err != nil {
			return nil, fmt.Errorf("partition %q: %w", j.Name, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("partition %q: %s is a symlink; name the directory it points to", j.Name, j.Root)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("partition %q: %s is not a directory", j.Name, j.Root)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("partition %q: no device/inode for %s", j.Name, j.Root)
		}
		id := Identity{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}
		if other, dup := seen[id]; dup {
			return nil, fmt.Errorf("partitions %q and %q are the same directory (device %d inode %d): a bind mount or a second mount aliases one tree under two names",
				other, j.Name, id.Dev, id.Ino)
		}
		seen[id] = j.Name
		if j.Name == ResidualName {
			rootDev = id.Dev
		} else if oneFilesystem && id.Dev != rootDev {
			return nil, fmt.Errorf("partition %q: %s is on another filesystem (device %d, root %d), which --one-filesystem leaves out",
				j.Name, j.Root, id.Dev, rootDev)
		}
		ids[j.Name] = id
	}
	return ids, nil
}
