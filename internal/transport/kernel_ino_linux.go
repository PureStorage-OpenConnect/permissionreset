package transport

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// ReadDirIno lists r's children with each one's d_ino, read straight from
// getdents64: os.ReadDir has the id but does not expose it. Like ReadDir it
// costs no per-entry stat, except for an entry whose d_type is DT_UNKNOWN,
// which is resolved with one lstat (os.ReadDir does the same). Entries are
// sorted by name.
func (k *Kernel) ReadDirIno(r Ref) ([]Dirent, error) {
	fd, err := unix.Open(r.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: r.Path, Err: err}
	}
	defer unix.Close(fd)

	var out []Dirent
	buf := make([]byte, 64<<10)
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			return nil, &os.PathError{Op: "getdents64", Path: r.Path, Err: err}
		}
		if n <= 0 {
			break
		}
		ents, err := parseDirents64(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("getdents64 %s: %w", r.Path, err)
		}
		for _, e := range ents {
			d := Dirent{Name: e.name, Ref: Ref{Path: r.Path + "/" + e.name}, Ino: e.ino}
			typ := e.typ
			if typ == unix.DT_UNKNOWN {
				var st unix.Stat_t
				if err := unix.Lstat(d.Ref.Path, &st); err != nil {
					return nil, &os.PathError{Op: "lstat", Path: d.Ref.Path, Err: err}
				}
				switch st.Mode & unix.S_IFMT {
				case unix.S_IFDIR:
					typ = unix.DT_DIR
				case unix.S_IFLNK:
					typ = unix.DT_LNK
				default:
					typ = unix.DT_REG
				}
			}
			d.IsSymlink = typ == unix.DT_LNK
			d.IsDir = typ == unix.DT_DIR
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b Dirent) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

type rawDirent struct {
	ino  uint64
	typ  uint8
	name string
}

// parseDirents64 decodes a getdents64 buffer: struct linux_dirent64 { u64
// d_ino; s64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }, in host byte
// order. "." and ".." are dropped.
func parseDirents64(buf []byte) ([]rawDirent, error) {
	var out []rawDirent
	for len(buf) > 0 {
		if len(buf) < 19 {
			return nil, fmt.Errorf("truncated dirent header (%d bytes left)", len(buf))
		}
		reclen := int(binary.NativeEndian.Uint16(buf[16:18]))
		if reclen < 19 || reclen > len(buf) {
			return nil, fmt.Errorf("bad d_reclen %d (%d bytes left)", reclen, len(buf))
		}
		name := buf[19:reclen]
		if i := slices.Index(name, 0); i >= 0 {
			name = name[:i]
		}
		if s := string(name); s != "." && s != ".." {
			out = append(out, rawDirent{ino: binary.NativeEndian.Uint64(buf[0:8]), typ: buf[18], name: s})
		}
		buf = buf[reclen:]
	}
	return out, nil
}

var _ InoLister = (*Kernel)(nil)
