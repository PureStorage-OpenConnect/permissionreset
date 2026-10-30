package evidence

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// faultFile wraps a real file and fails on cue.
type faultFile struct {
	f *os.File
	// failAfter fails the Write that would take the file past this many
	// bytes, with writeErr (nil means a silent short write).
	failAfter int64
	writeErr  error
	syncErr   error
	closeErr  error
	delay     time.Duration
	n         int64
}

func (ff *faultFile) Write(p []byte) (int, error) {
	if ff.delay > 0 {
		time.Sleep(ff.delay)
	}
	if ff.failAfter > 0 && ff.n+int64(len(p)) > ff.failAfter {
		k := int(ff.failAfter - ff.n)
		n, _ := ff.f.Write(p[:k])
		ff.n += int64(n)
		return n, ff.writeErr
	}
	n, err := ff.f.Write(p)
	ff.n += int64(n)
	return n, err
}

func (ff *faultFile) Sync() error {
	if ff.syncErr != nil {
		return ff.syncErr
	}
	return ff.f.Sync()
}

func (ff *faultFile) Close() error {
	err := ff.f.Close()
	if ff.closeErr != nil {
		return ff.closeErr
	}
	return err
}

// openWith opens a sink whose shard files are faultFiles built by mk.
func openWith(t *testing.T, o Options, mk func(n int) *faultFile) *Sink {
	t.Helper()
	if o.Dir == "" {
		o.Dir = filepath.Join(t.TempDir(), "ev")
	}
	var n int
	o.Create = func(path string) (File, error) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return nil, err
		}
		n++
		ff := mk(n)
		ff.f = f
		return ff, nil
	}
	s, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rec(i int) string { return fmt.Sprintf("OK: setxattr nfs4_acl /mnt/t/d%03d/f%06d", i%100, i) }

// readManifest returns the manifest on disk, which must match what Close returned.
func readManifest(t *testing.T, dir string, want Manifest) Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Status != want.Status || m.RecordsWritten != want.RecordsWritten || m.RecordsDropped != want.RecordsDropped {
		t.Fatalf("manifest on disk %+v differs from Close's %+v", m, want)
	}
	return m
}

// checkShards re-reads every listed shard and checks digest, size and records.
func checkShards(t *testing.T, dir string, m Manifest) []string {
	t.Helper()
	var all []string
	for _, sh := range m.Shards {
		b, err := os.ReadFile(filepath.Join(dir, sh.Path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != sh.SHA256 || int64(len(b)) != sh.Bytes {
			t.Fatalf("shard %s: digest/size do not match the manifest", sh.Path)
		}
		var r io.Reader = strings.NewReader(string(b))
		if strings.HasSuffix(sh.Path, ".gz") {
			zr, err := gzip.NewReader(r)
			if err != nil {
				t.Fatal(err)
			}
			r = zr
		}
		var n int64
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			all = append(all, sc.Text())
			n++
		}
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
		if n != sh.Records {
			t.Fatalf("shard %s holds %d records, manifest says %d", sh.Path, n, sh.Records)
		}
	}
	return all
}

func reconciles(t *testing.T, m Manifest) {
	t.Helper()
	if m.RecordsWritten+m.RecordsDropped != m.RecordsSubmitted {
		t.Fatalf("%d written + %d dropped != %d submitted", m.RecordsWritten, m.RecordsDropped, m.RecordsSubmitted)
	}
}

func TestCompleteRunRotatesAndVerifies(t *testing.T) {
	for _, compress := range []bool{false, true} {
		t.Run(fmt.Sprintf("gzip=%v", compress), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "ev")
			s, err := Open(Options{Dir: dir, ShardBytes: 4096, Compress: compress, RunID: "r1"})
			if err != nil {
				t.Fatal(err)
			}
			const n = 2000
			for i := range n {
				if !s.Write(rec(i)) {
					t.Fatal("healthy sink refused a record")
				}
			}
			m, err := s.Close(true)
			if err != nil {
				t.Fatal(err)
			}
			if m.Status != StatusComplete || m.RecordsWritten != n || m.RecordsDropped != 0 {
				t.Fatalf("manifest = %+v", m)
			}
			if len(m.Shards) < 2 {
				t.Fatalf("%d shards; 4 KiB shards should have rotated", len(m.Shards))
			}
			readManifest(t, dir, m)
			got := checkShards(t, dir, m)
			for i := range n {
				if got[i] != rec(i) {
					t.Fatalf("record %d = %q, want %q (order lost)", i, got[i], rec(i))
				}
			}
		})
	}
}

// Every injected I/O failure must leave the sink failed, later records
// refused, the manifest incomplete with the error named, and the counts
// reconciled. None of them may be swallowed.
func TestInjectedFailuresAreNeverSwallowed(t *testing.T) {
	cases := []struct {
		name string
		mk   func(n int) *faultFile
	}{
		{"disk full", func(int) *faultFile { return &faultFile{failAfter: 10000, writeErr: syscall.ENOSPC} }},
		{"short write", func(int) *faultFile { return &faultFile{failAfter: 10000} }},
		{"flush on sync", func(int) *faultFile { return &faultFile{syncErr: syscall.EIO} }},
		{"close", func(int) *faultFile { return &faultFile{closeErr: syscall.EIO} }},
		{"second shard full", func(n int) *faultFile {
			if n == 2 {
				return &faultFile{failAfter: 100, writeErr: syscall.ENOSPC}
			}
			return &faultFile{}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openWith(t, Options{ShardBytes: 64 << 10, QueueRecords: 16}, tc.mk)
			refused := false
			for i := range 20000 {
				if !s.Write(rec(i)) {
					refused = true
					break
				}
			}
			m, err := s.Close(true)
			if err == nil {
				t.Fatal("Close returned nil after an injected failure")
			}
			if m.Status != StatusIncomplete || m.Error == "" {
				t.Fatalf("manifest = %+v, want incomplete with the error", m)
			}
			if !s.Failed() || s.Write("late") {
				t.Fatal("sink accepted a record after failing")
			}
			if tc.name != "flush on sync" && tc.name != "close" && !refused {
				t.Fatal("Write never refused a record after the failure")
			}
			reconciles(t, readManifest(t, s.Dir(), m))
			checkShards(t, s.Dir(), m)
		})
	}
}

func TestShortWriteIsAnError(t *testing.T) {
	s := openWith(t, Options{}, func(int) *faultFile { return &faultFile{failAfter: 10} })
	s.Write(strings.Repeat("x", 100))
	_, err := s.Close(true)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("err = %v, want io.ErrShortWrite", err)
	}
}

func TestCancelledRunIsIncomplete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ev")
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		s.Write(rec(i))
	}
	m, err := s.Close(false, "interrupted")
	if err != nil {
		t.Fatalf("Close: %v (the sink itself did not fail)", err)
	}
	if m.Status != StatusIncomplete || m.RecordsWritten != 100 || len(m.Reasons) != 1 || m.Reasons[0] != "interrupted" {
		t.Fatalf("manifest = %+v", m)
	}
	readManifest(t, dir, m)
}

func TestRefusesUsedDirectory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "old"), nil, 0o644)
	if _, err := Open(Options{Dir: dir}); err == nil {
		t.Fatal("Open accepted a directory that already holds files")
	}
}

// Slow storage must block writers (backpressure) instead of growing memory:
// the heap stays near the queue size while many times that many records pass.
func TestSlowStorageAppliesBackpressure(t *testing.T) {
	const queue = 64
	s := openWith(t, Options{QueueRecords: queue}, func(int) *faultFile { return &faultFile{delay: 2 * time.Millisecond} })
	before := heapInUse()
	var wg sync.WaitGroup
	var peak uint64
	var mu sync.Mutex
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				s.Write(rec(w*100000+i) + strings.Repeat("p", 200))
				if i%500 == 0 {
					h := heapInUse()
					mu.Lock()
					peak = max(peak, h)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	m, err := s.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	if m.Stalls == 0 || m.StallSeconds == 0 {
		t.Fatalf("no queue stalls recorded on slow storage: %+v", m)
	}
	// 16,000 records of ~250 bytes is ~4 MB if they piled up in memory; the
	// bound is the queue plus the 1 MiB write buffer, with slack for the runtime.
	if grew := int64(peak) - int64(before); grew > 3<<20 {
		t.Fatalf("heap grew %d bytes; records are accumulating instead of blocking", grew)
	}
	reconciles(t, m)
}

func heapInUse() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}
