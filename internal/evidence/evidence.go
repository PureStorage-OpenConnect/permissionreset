// Package evidence writes a run's per-object records to size-bounded shards
// behind a bounded queue, and closes them with a manifest that says whether the
// evidence is complete.
//
// What it promises: every write, flush, sync and close error is checked and
// recorded; once one happens the sink refuses further records (Write returns
// false) so the caller can stop mutating; and the manifest's status is
// "complete" only when every submitted record reached a closed, synced shard.
//
// What it does not promise: that a record survives a crash. Records sit in the
// queue and in buffers until a shard rotates or the sink closes, and nothing
// is fsynced per record. See docs/evidence.md for the crash-loss window.
package evidence

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ManifestName is the manifest's file name inside the evidence directory.
const ManifestName = "manifest.json"

// ManifestVersion is bumped whenever a manifest field changes meaning.
const ManifestVersion = 1

// Profile selects how much each record carries.
type Profile string

const (
	// ProfileCompact is one line per object: the outcome and the path.
	ProfileCompact Profile = "compact"
	// ProfileDetailed adds the object's state before the write. That costs a
	// read the compact profile does not make, except where the run already
	// read the object (rules that keep the DACL or the auditing).
	ProfileDetailed Profile = "detailed"
)

// ParseProfile accepts the --evidence-profile values.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileCompact, ProfileDetailed:
		return Profile(s), nil
	}
	return "", fmt.Errorf("unknown evidence profile %q (want compact or detailed)", s)
}

// Defaults for Options fields left zero.
const (
	DefaultShardBytes   = 256 << 20
	DefaultQueueRecords = 65536
	bufferBytes         = 1 << 20
)

// Options configures a Sink.
type Options struct {
	Dir     string
	Profile Profile
	RunID   string
	// ShardBytes rotates to a new shard once this many uncompressed record
	// bytes have gone into the current one. Negative means never rotate.
	ShardBytes int64
	// Compress gzips each shard.
	Compress bool
	// QueueRecords bounds the records waiting for the writer. A full queue
	// blocks Write, which is how slow storage slows the run down instead of
	// growing memory.
	QueueRecords int

	// Create opens a shard file; nil means os.OpenFile with O_EXCL. It is the
	// seam tests use to inject write, sync and close faults.
	Create func(path string) (File, error)
}

// File is what a shard is written to: *os.File in production.
type File interface {
	io.Writer
	Sync() error
	Close() error
}

// Shard describes one closed shard. SHA256 and Bytes are over the file as it
// sits on disk (compressed, when compression is on).
type Shard struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Records int64  `json:"records"`
	Bytes   int64  `json:"bytes"`
}

// Status values for Manifest.Status.
const (
	StatusComplete   = "complete"
	StatusIncomplete = "incomplete"
)

// Manifest is the closing record of a sink. RecordsSubmitted always equals
// RecordsWritten + RecordsDropped; a record is dropped when it arrives after
// the sink failed, or is lost in the shard whose write failed.
type Manifest struct {
	Version          int      `json:"manifest_version"`
	RunID            string   `json:"run_id,omitempty"`
	Status           string   `json:"status"`
	Reasons          []string `json:"reasons,omitempty"`
	Profile          Profile  `json:"profile"`
	Compress         string   `json:"compress"`
	ShardBytes       int64    `json:"shard_bytes"`
	QueueRecords     int      `json:"queue_records"`
	RecordsSubmitted int64    `json:"records_submitted"`
	RecordsWritten   int64    `json:"records_written"`
	RecordsDropped   int64    `json:"records_dropped"`
	// RecordsInFlight counts the dropped records that never reached a shard:
	// queued when the sink failed, or submitted after. Each is a change the
	// caller made with no record kept. A caller that stops on the first
	// refused Write bounds it at QueueRecords plus two per writing goroutine
	// (one blocked in Write, one more before its next Write is refused).
	RecordsInFlight int64   `json:"records_in_flight"`
	RecordBytes     int64   `json:"record_bytes"`
	Stalls          int64   `json:"queue_stalls"`
	StallSeconds    float64 `json:"queue_stall_seconds"`
	Error           string  `json:"error,omitempty"`
	Shards          []Shard `json:"shards"`
}

// Sink is safe for concurrent Write calls from many goroutines.
type Sink struct {
	opts  Options
	queue chan string
	done  chan struct{}

	// closeMu orders Write against Close: Write holds it shared while it
	// sends, Close holds it exclusively before closing the queue.
	closeMu sync.RWMutex
	closed  bool

	failed     atomic.Bool
	errMu      sync.Mutex
	err        error
	submitted  atomic.Int64
	dropped    atomic.Int64
	late       atomic.Int64
	stalls     atomic.Int64
	stallNanos atomic.Int64

	// Owned by the writer goroutine until done is closed.
	recordBytes int64
	shards      []Shard
	cur         *shard
}

// Open creates dir (it must not already hold a manifest) and starts the writer.
func Open(o Options) (*Sink, error) {
	if o.Dir == "" {
		return nil, errors.New("evidence: no directory")
	}
	if o.Profile == "" {
		o.Profile = ProfileCompact
	}
	if o.ShardBytes == 0 {
		o.ShardBytes = DefaultShardBytes
	}
	if o.QueueRecords <= 0 {
		o.QueueRecords = DefaultQueueRecords
	}
	if o.Create == nil {
		o.Create = func(path string) (File, error) {
			return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		}
	}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("evidence: create %s: %w", o.Dir, err)
	}
	// Refusing a used directory keeps two runs' shards from ever sharing a
	// manifest, and keeps O_EXCL below from failing halfway through a run.
	entries, err := os.ReadDir(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", o.Dir, err)
	}
	if len(entries) > 0 {
		return nil, fmt.Errorf("evidence: %s is not empty; give each run its own evidence directory", o.Dir)
	}
	s := &Sink{
		opts:  o,
		queue: make(chan string, o.QueueRecords),
		done:  make(chan struct{}),
	}
	go s.run()
	return s, nil
}

// Profile is the sink's record profile.
func (s *Sink) Profile() Profile { return s.opts.Profile }

// Dir is the evidence directory.
func (s *Sink) Dir() string { return s.opts.Dir }

// Write queues one record. It blocks while the queue is full. It returns false
// once the sink has failed or closed: the record was not kept, and a caller
// whose evidence is required must not make the change it describes.
func (s *Sink) Write(rec string) bool {
	s.submitted.Add(1)
	if s.failed.Load() {
		s.dropped.Add(1)
		s.late.Add(1)
		return false
	}
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		s.dropped.Add(1)
		return false
	}
	select {
	case s.queue <- rec:
	default:
		s.stalls.Add(1)
		t := time.Now()
		s.queue <- rec
		s.stallNanos.Add(int64(time.Since(t)))
	}
	return true
}

// Failed reports whether the sink has refused, or will refuse, records.
func (s *Sink) Failed() bool { return s.failed.Load() }

// Err is the first error the sink hit, or nil.
func (s *Sink) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

func (s *Sink) fail(err error) {
	s.errMu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.errMu.Unlock()
	s.failed.Store(true)
}

// run is the writer goroutine. It keeps draining the queue after a failure so
// Write never blocks forever on a dead sink; those records count as dropped.
func (s *Sink) run() {
	defer close(s.done)
	for rec := range s.queue {
		if s.failed.Load() {
			s.dropped.Add(1)
			s.late.Add(1)
			continue
		}
		if err := s.writeRecord(rec); err != nil {
			s.fail(err)
			s.dropCurrent()
			continue
		}
		// Flush when the queue runs dry, so a quiet run's records reach the
		// file promptly instead of waiting for the buffer to fill.
		if len(s.queue) == 0 && s.cur != nil {
			if err := s.cur.flush(); err != nil {
				s.fail(err)
				s.dropCurrent()
			}
		}
	}
	if !s.failed.Load() && s.cur != nil {
		if err := s.closeShard(); err != nil {
			s.fail(err)
			s.dropCurrent()
		}
	}
}

// writeRecord counts rec into the current shard before writing it, so a record
// whose own write fails is dropped along with the rest of that shard.
func (s *Sink) writeRecord(rec string) error {
	if s.cur == nil {
		if err := s.openShard(); err != nil {
			s.dropped.Add(1)
			return err
		}
	}
	s.cur.records++
	if err := s.cur.write(rec); err != nil {
		return err
	}
	s.recordBytes += int64(len(rec)) + 1
	if s.opts.ShardBytes > 0 && s.cur.raw >= s.opts.ShardBytes {
		return s.closeShard()
	}
	return nil
}

// dropCurrent counts the failed shard's records as dropped: the shard is not
// listed in the manifest, because a reader cannot trust a file whose write
// failed partway.
func (s *Sink) dropCurrent() {
	if s.cur == nil {
		return
	}
	s.dropped.Add(s.cur.records)
	s.cur.file.Close()
	s.cur = nil
}

func (s *Sink) openShard() error {
	name := fmt.Sprintf("shard-%06d.log", len(s.shards)+1)
	if s.opts.Compress {
		name += ".gz"
	}
	f, err := s.opts.Create(filepath.Join(s.opts.Dir, name))
	if err != nil {
		return fmt.Errorf("evidence: create shard %s: %w", name, err)
	}
	sh := &shard{name: name, file: f, sum: sha256.New()}
	sh.counted = &countingWriter{w: io.MultiWriter(f, sh.sum)}
	var w io.Writer = sh.counted
	if s.opts.Compress {
		sh.gz = gzip.NewWriter(sh.counted)
		w = sh.gz
	}
	sh.buf = bufio.NewWriterSize(w, bufferBytes)
	s.cur = sh
	return nil
}

func (s *Sink) closeShard() error {
	sh := s.cur
	if err := sh.flush(); err != nil {
		return err
	}
	if sh.gz != nil {
		if err := sh.gz.Close(); err != nil {
			return fmt.Errorf("evidence: finish gzip %s: %w", sh.name, err)
		}
	}
	if err := sh.file.Sync(); err != nil {
		return fmt.Errorf("evidence: sync %s: %w", sh.name, err)
	}
	if err := sh.file.Close(); err != nil {
		s.cur = nil // already closed; dropCurrent must not close it again
		s.dropped.Add(sh.records)
		return fmt.Errorf("evidence: close %s: %w", sh.name, err)
	}
	s.shards = append(s.shards, Shard{
		Path:    sh.name,
		SHA256:  hex.EncodeToString(sh.sum.Sum(nil)),
		Records: sh.records,
		Bytes:   sh.counted.n,
	})
	s.cur = nil
	return nil
}

// Close drains the queue, closes the last shard and writes the manifest.
// runComplete is the caller's word that the run reached its end: an
// interrupted or stopped run's evidence is incomplete even when every record
// it submitted was written. The returned error is the sink's own failure or
// the manifest write's; the manifest is written in either case when possible.
func (s *Sink) Close(runComplete bool, reasons ...string) (Manifest, error) {
	s.closeMu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.closeMu.Unlock()
	<-s.done

	m := Manifest{
		Version:          ManifestVersion,
		RunID:            s.opts.RunID,
		Profile:          s.opts.Profile,
		Compress:         "none",
		ShardBytes:       s.opts.ShardBytes,
		QueueRecords:     s.opts.QueueRecords,
		RecordsSubmitted: s.submitted.Load(),
		RecordsDropped:   s.dropped.Load(),
		RecordsInFlight:  s.late.Load(),
		RecordBytes:      s.recordBytes,
		Stalls:           s.stalls.Load(),
		StallSeconds:     time.Duration(s.stallNanos.Load()).Seconds(),
		Shards:           s.shards,
	}
	if s.opts.Compress {
		m.Compress = "gzip"
	}
	if m.Shards == nil {
		m.Shards = []Shard{}
	}
	for _, sh := range s.shards {
		m.RecordsWritten += sh.Records
	}
	m.Reasons = append(m.Reasons, reasons...)
	sinkErr := s.Err()
	if sinkErr != nil {
		m.Error = sinkErr.Error()
		m.Reasons = append(m.Reasons, "evidence write failed")
	}
	if !runComplete && len(reasons) == 0 {
		m.Reasons = append(m.Reasons, "run did not complete")
	}
	if m.RecordsWritten+m.RecordsDropped != m.RecordsSubmitted && sinkErr == nil {
		// Cannot happen without a bug here; refuse to call such a set complete.
		m.Reasons = append(m.Reasons, fmt.Sprintf("record accounting does not reconcile: %d written + %d dropped != %d submitted",
			m.RecordsWritten, m.RecordsDropped, m.RecordsSubmitted))
	}
	m.Status = StatusComplete
	if len(m.Reasons) > 0 {
		m.Status = StatusIncomplete
	}
	if err := writeManifest(filepath.Join(s.opts.Dir, ManifestName), m); err != nil {
		return m, errors.Join(sinkErr, err)
	}
	return m, sinkErr
}

// writeManifest writes atomically: temp file, fsync, rename, so a reader never
// sees a partial manifest.
func writeManifest(path string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence: encode manifest: %w", err)
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*")
	if err != nil {
		return fmt.Errorf("evidence: create manifest: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("evidence: write manifest: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("evidence: sync manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("evidence: close manifest: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("evidence: rename manifest: %w", err)
	}
	return nil
}

type shard struct {
	name    string
	file    File
	sum     hash.Hash
	counted *countingWriter
	gz      *gzip.Writer
	buf     *bufio.Writer
	raw     int64
	records int64
}

func (sh *shard) write(rec string) error {
	if _, err := sh.buf.WriteString(rec); err != nil {
		return fmt.Errorf("evidence: write %s: %w", sh.name, err)
	}
	if err := sh.buf.WriteByte('\n'); err != nil {
		return fmt.Errorf("evidence: write %s: %w", sh.name, err)
	}
	sh.raw += int64(len(rec)) + 1
	return nil
}

func (sh *shard) flush() error {
	if err := sh.buf.Flush(); err != nil {
		return fmt.Errorf("evidence: flush %s: %w", sh.name, err)
	}
	return nil
}

// countingWriter counts the bytes that reach the file, and turns a short write
// with no error into io.ErrShortWrite so it cannot pass unnoticed.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
