package transport

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadDirInoMatchesLstat(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "b-dir"), 0o755)
	os.WriteFile(filepath.Join(dir, "c-file"), nil, 0o644)
	os.Symlink("c-file", filepath.Join(dir, "a-link"))
	k, err := NewKernel(dir)
	if err != nil {
		t.Fatal(err)
	}
	ents, err := k.ReadDirIno(Ref{Path: k.root})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name         string
		dir, symlink bool
	}{{"a-link", false, true}, {"b-dir", true, false}, {"c-file", false, false}}
	if len(ents) != len(want) {
		t.Fatalf("got %d entries, want %d", len(ents), len(want))
	}
	for i, w := range want {
		e := ents[i]
		if e.Name != w.name || e.IsDir != w.dir || e.IsSymlink != w.symlink {
			t.Errorf("entry %d = %+v, want %+v", i, e, w)
		}
		var st syscall.Stat_t
		if err := syscall.Lstat(e.Ref.Path, &st); err != nil {
			t.Fatal(err)
		}
		if e.Ino == 0 || e.Ino != st.Ino {
			t.Errorf("%s: d_ino %d, st_ino %d", e.Name, e.Ino, st.Ino)
		}
		a, err := k.Stat(e.Ref)
		if err != nil || a.Ino != st.Ino {
			t.Errorf("%s: Stat Ino %d err %v", e.Name, a.Ino, err)
		}
	}
}

func TestReadDirInoManyEntries(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3000; i++ { // more than one 64 KiB getdents buffer
		os.WriteFile(filepath.Join(dir, "file-with-a-longish-name-"+string(rune('a'+i%26))+"-"+itoa(i)), nil, 0o644)
	}
	k, _ := NewKernel(dir)
	ents, err := k.ReadDirIno(Ref{Path: k.root})
	if err != nil || len(ents) != 3000 {
		t.Fatalf("got %d entries, err %v", len(ents), err)
	}
	for i := 1; i < len(ents); i++ {
		if ents[i-1].Name >= ents[i].Name {
			t.Fatalf("not sorted at %d", i)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestParseDirents64RejectsBadReclen(t *testing.T) {
	buf := make([]byte, 24)
	buf[16] = 200 // d_reclen past the buffer
	if _, err := parseDirents64(buf); err == nil {
		t.Error("accepted a d_reclen past the buffer")
	}
}
