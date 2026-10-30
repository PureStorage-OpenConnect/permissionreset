package checkpoint

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"testing"
)

// writeFixture writes a checkpoint file the way a run leaves one: the header,
// then recs in order.
func writeFixture(tb testing.TB, path string, binding [32]byte, recs [][16]byte) {
	tb.Helper()
	f, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	var hdr [headerSize]byte
	copy(hdr[0:4], magic)
	binary.LittleEndian.PutUint16(hdr[4:6], version)
	copy(hdr[8:40], binding[:])
	w.Write(hdr[:])
	for i := range recs {
		w.Write(recs[i][:])
	}
	if err := w.Flush(); err != nil {
		tb.Fatal(err)
	}
	if err := f.Close(); err != nil {
		tb.Fatal(err)
	}
}

// randomRecords returns n hashes from a fixed seed, every seventh one a repeat
// of an earlier record, since a file can hold the same directory twice.
func randomRecords(n int, seed uint64) [][16]byte {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	recs := make([][16]byte, n)
	for i := range recs {
		if i > 0 && i%7 == 0 {
			recs[i] = recs[r.IntN(i)]
			continue
		}
		binary.LittleEndian.PutUint64(recs[i][0:8], r.Uint64())
		binary.LittleEndian.PutUint64(recs[i][8:16], r.Uint64())
	}
	return recs
}

// legacyLoad is the load path before PS-10: one 16-byte read per record, then
// a reflection sort by bytes. It is the reference the batched load must match.
func legacyLoad(path string) ([][16]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	n := (info.Size() - headerSize) / recordSize
	out := make([][16]byte, n)
	if _, err := f.Seek(headerSize, io.SeekStart); err != nil {
		return nil, err
	}
	for i := range out {
		if _, err := io.ReadFull(f, out[i][:]); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		for k := 0; k < 16; k++ {
			if out[i][k] != out[j][k] {
				return out[i][k] < out[j][k]
			}
		}
		return false
	})
	return out, nil
}

// An existing checkpoint loads to exactly the set, order and count the old
// loader produced, at sizes on and around the read-chunk boundary.
func TestLoadMatchesLegacy(t *testing.T) {
	h := specHash(t)
	for _, n := range []int{0, 1, 2, loadChunkRecords - 1, loadChunkRecords, loadChunkRecords + 1, 3*loadChunkRecords + 17} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ckpt.bin")
			recs := randomRecords(n, uint64(n)+1)
			writeFixture(t, path, h, recs)

			want, err := legacyLoad(path)
			if err != nil {
				t.Fatal(err)
			}
			c, err := Open(path, h, true)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			if !slices.Equal(c.completed, want) {
				t.Fatalf("loaded records differ from the legacy loader's (n=%d)", n)
			}
			if c.CompletedCount() != n {
				t.Errorf("CompletedCount = %d, want %d (duplicates are kept)", c.CompletedCount(), n)
			}
			for i := range recs {
				if !c.hasHash(recs[i]) {
					t.Fatalf("record %d not found after load", i)
				}
			}
			var absent [16]byte
			absent[0] = 0xff
			if !slices.Contains(recs, absent) && c.hasHash(absent) {
				t.Error("a hash not in the file was reported complete")
			}
		})
	}
}

// cmp128 must order exactly as a byte-by-byte comparison does: DirCompleted's
// binary search depends on the sort and the search agreeing.
func TestCmp128IsByteOrder(t *testing.T) {
	recs := randomRecords(2000, 99)
	// Hashes that differ only in the low half, and in a single high byte.
	recs = append(recs, [16]byte{0: 1}, [16]byte{0: 1, 15: 1}, [16]byte{7: 0x80}, [16]byte{8: 0x80}, [16]byte{})
	for i := range recs {
		for j := range recs {
			a, b := recs[i], recs[j]
			want := 0
			for k := 0; k < 16; k++ {
				if a[k] != b[k] {
					want = -1
					if a[k] > b[k] {
						want = 1
					}
					break
				}
			}
			if got := cmp128(a, b); got != want {
				t.Fatalf("cmp128(%x, %x) = %d, want %d", a, b, got, want)
			}
		}
	}
}

// countingReader counts the reads that reach the underlying file.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

// The loader reads in chunks, not one read per record.
func TestReadRecordsBatches(t *testing.T) {
	h := specHash(t)
	const n = 10*loadChunkRecords + 5
	path := filepath.Join(t.TempDir(), "ckpt.bin")
	recs := randomRecords(n, 7)
	writeFixture(t, path, h, recs)

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Seek(headerSize, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	cr := &countingReader{r: f}
	got, err := readRecords(cr, n)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, recs) {
		t.Fatal("readRecords returned different records than were written")
	}
	// io.ReadFull on a regular file is satisfied in one read per chunk.
	if want := (n + loadChunkRecords - 1) / loadChunkRecords; cr.reads != want {
		t.Errorf("reads = %d, want %d (one per %d records; the old loader made %d)", cr.reads, want, loadChunkRecords, n)
	}
}

// A file that ends before the count it was sized for is an error, never a
// short or zero-filled set.
func TestReadRecordsShortFileFails(t *testing.T) {
	recs := randomRecords(10, 3)
	var b []byte
	for i := range recs {
		b = append(b, recs[i][:]...)
	}
	r := io.LimitReader(&byteReader{b: b}, int64(len(b)-recordSize))
	if _, err := readRecords(r, int64(len(recs))); err == nil {
		t.Fatal("readRecords accepted a file shorter than its record count")
	}
}

type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// A checkpoint with a header and no records resumes empty.
func TestResumeHeaderOnly(t *testing.T) {
	h := specHash(t)
	path := filepath.Join(t.TempDir(), "ckpt.bin")
	writeFixture(t, path, h, nil)
	c, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.CompletedCount() != 0 || c.DirCompleted("/data") {
		t.Errorf("header-only checkpoint: CompletedCount = %d, DirCompleted = %v", c.CompletedCount(), c.DirCompleted("/data"))
	}
}

// hasHash is DirCompleted for a hash already computed.
func (c *Checkpoint) hasHash(h [16]byte) bool {
	_, found := slices.BinarySearchFunc(c.completed, h, cmp128)
	return found
}

// BenchmarkResumeLoad measures Open(resume) on a file of n directory records,
// against the pre-PS-10 loader. heap-MB is what the loaded set keeps resident
// (the loader's peak, since the set is allocated once at its final size and the
// read buffer is 64 KiB); allocs/op and B/op cover everything the load allocates.
//
//	go test ./internal/checkpoint -run '^$' -bench ResumeLoad -benchtime 3x
//
// CHECKPOINT_BENCH_100M=1 adds a 100M-record size. Its fixture is 1.6 GB on
// disk (set TMPDIR to a filesystem with room) and each load keeps 1.6 GB resident.
func BenchmarkResumeLoad(b *testing.B) {
	sizes := []int{1_000_000, 10_000_000}
	if os.Getenv("CHECKPOINT_BENCH_100M") != "" {
		sizes = append(sizes, 100_000_000)
	}
	for _, n := range sizes {
		dir := b.TempDir()
		path := filepath.Join(dir, "ckpt.bin")
		var binding [32]byte
		writeFixture(b, path, binding, randomRecords(n, uint64(n)))

		b.Run(fmt.Sprintf("batched/%dM", n/1_000_000), func(b *testing.B) {
			b.ReportAllocs()
			var heap uint64
			for b.Loop() {
				b.StopTimer()
				before := heapInUse()
				b.StartTimer()
				c, err := Open(path, binding, true)
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if a := heapInUse(); a > before {
					heap = max(heap, a-before)
				}
				c.Close()
				b.StartTimer()
			}
			b.ReportMetric(float64(heap)/(1<<20), "heap-MB")
		})
		b.Run(fmt.Sprintf("legacy/%dM", n/1_000_000), func(b *testing.B) {
			b.ReportAllocs()
			var heap uint64
			for b.Loop() {
				b.StopTimer()
				before := heapInUse()
				b.StartTimer()
				recs, err := legacyLoad(path)
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if a := heapInUse(); a > before {
					heap = max(heap, a-before)
				}
				runtime.KeepAlive(recs)
				b.StartTimer()
			}
			b.ReportMetric(float64(heap)/(1<<20), "heap-MB")
		})
	}
}

// heapInUse forces a GC, so callers stop the benchmark timer around it.
func heapInUse() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}
