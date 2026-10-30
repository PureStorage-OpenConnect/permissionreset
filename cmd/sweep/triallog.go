package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

const trialLogPrefix = "permissionreset-trials-"

type trialLogParams struct {
	Connections       int `json:"connections"`
	Slots             int `json:"slots"`
	Workers           int `json:"workers"`
	BatchSize         int `json:"batch_size"`
	MaxOpsPerCompound int `json:"max_ops_per_compound"`
}

type trialLogClient struct {
	CPUPct        float64 `json:"cpu_pct"`
	CPUUserPct    float64 `json:"cpu_user_pct"`
	CPUSysPct     float64 `json:"cpu_sys_pct"`
	CPUSoftirqPct float64 `json:"cpu_softirq_pct"`
}

type trialLogRecord struct {
	Type      string          `json:"type"`
	Seq       int             `json:"seq"`
	T         time.Time       `json:"t"`
	DurationS float64         `json:"duration_s"`
	Phase     string          `json:"phase"`
	Knob      *string         `json:"knob"`
	Value     *int            `json:"value"`
	Params    trialLogParams  `json:"params"`
	OpsPerSec *float64        `json:"ops_per_sec"`
	Files     int64           `json:"files"`
	Error     *string         `json:"error"`
	Client    *trialLogClient `json:"client"`
}

type trialLogTreeShape struct {
	Scale           string `json:"scale"`
	Copies          int    `json:"copies"`
	SeedFiles       int    `json:"seed_files"`
	MaxDepth        int    `json:"max_depth"`
	Seed            int64  `json:"seed"`
	FilesPerSubtree int    `json:"files_per_subtree"`
}

type trialLogSummary struct {
	Type                     string            `json:"type"`
	Key                      string            `json:"key"`
	Clients                  []string          `json:"clients"`
	Server                   string            `json:"server"`
	Export                   string            `json:"export"`
	Transport                string            `json:"transport"`
	SweepCommit              string            `json:"sweep_commit"`
	TreeShape                trialLogTreeShape `json:"tree_shape"`
	TrialFiles               int64             `json:"trial_files"`
	Winner                   trialLogParams    `json:"winner"`
	ConfirmedMedianOpsPerSec float64           `json:"confirmed_median_ops_per_sec"`
	OpeningBaselineOpsPerSec float64           `json:"opening_baseline_ops_per_sec"`
	ClosingBaselineOpsPerSec float64           `json:"closing_baseline_ops_per_sec"`
	BaselineDrift            float64           `json:"baseline_drift"`
	Confidence               string            `json:"confidence"`
	ExitDisposition          string            `json:"exit_disposition"`
}

type trialMetadata struct {
	phase string
	knob  *string
	value *int
	files int64
}

type trialLogWriter struct {
	w      io.Writer
	closer io.Closer
	errOut io.Writer
	now    func() time.Time
	seq    int
	failed bool
	warned bool
	path   string
}

func newTrialLogWriter(w io.Writer, errOut io.Writer) *trialLogWriter {
	return &trialLogWriter{w: w, errOut: errOut, now: time.Now}
}

func openTrialLog(path string, errOut io.Writer) *trialLogWriter {
	log := newTrialLogWriter(nil, errOut)
	log.path = path
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.fail(fmt.Errorf("open %s: %w", path, err))
		return log
	}
	log.w = f
	log.closer = f
	return log
}

func (l *trialLogWriter) close() {
	if l.closer == nil {
		return
	}
	if err := l.closer.Close(); err != nil {
		l.fail(fmt.Errorf("close %s: %w", l.path, err))
	}
}

func (l *trialLogWriter) fail(err error) {
	l.failed = true
	// A full disk can fail every remaining trial. Warn once so an hours-long sweep
	// stays readable while still making the loss of its sidecar unmistakable.
	if l.warned {
		return
	}
	l.warned = true
	fmt.Fprintf(l.errOut, "warning: trial log: %v; continuing the sweep without further trial logging\n", err)
}

func (l *trialLogWriter) write(record any) {
	// Once a write fails, later writes cannot restore the missing sequence and tend
	// only to repeat the same disk error. The sweep continues; the sidecar stops.
	if l == nil || l.failed || l.w == nil {
		return
	}
	data, err := json.Marshal(record)
	if err != nil {
		l.fail(fmt.Errorf("encode record: %w", err))
		return
	}
	data = append(data, '\n')
	written, err := l.w.Write(data)
	if err != nil {
		l.fail(fmt.Errorf("append %s: %w", l.path, err))
		return
	}
	// io.Writer permits a nil error with a short count. Treat that as lost log
	// data rather than claiming the line was durable and writing later sequences.
	if written != len(data) {
		l.fail(fmt.Errorf("append %s: %w", l.path, io.ErrShortWrite))
	}
}

func (l *trialLogWriter) appendTrial(meta trialMetadata, params tuning.Params, rate float64, trialErr error,
	started time.Time, duration time.Duration, client *tuning.ClientMeasurement) {

	l.seq++
	record := trialLogRecord{
		Type:      "trial",
		Seq:       l.seq,
		T:         started.UTC(),
		DurationS: duration.Seconds(),
		Phase:     meta.phase,
		Knob:      meta.knob,
		Value:     meta.value,
		Params:    logParams(params),
		Files:     meta.files,
	}
	if trialErr != nil {
		message := trialErr.Error()
		record.Error = &message
	} else if math.IsNaN(rate) || math.IsInf(rate, 0) {
		message := fmt.Sprintf("trial returned non-finite rate %v", rate)
		record.Error = &message
	} else {
		record.OpsPerSec = &rate
	}
	if client != nil {
		record.Client = &trialLogClient{
			CPUPct:        client.CPUPct,
			CPUUserPct:    client.CPUUserPct,
			CPUSysPct:     client.CPUSysPct,
			CPUSoftirqPct: client.CPUSoftirqPct,
		}
	}
	l.write(record)
}

func logParams(params tuning.Params) trialLogParams {
	return trialLogParams{
		Connections:       params.Connections,
		Slots:             params.Slots,
		Workers:           params.Workers,
		BatchSize:         params.BatchSize,
		MaxOpsPerCompound: params.MaxOpsPerCompound,
	}
}

type loggingRunner struct {
	inner TrialRunner
	log   *trialLogWriter
	files int64
}

func (r *loggingRunner) Trial(ctx context.Context, params tuning.Params) (float64, error) {
	return r.trial(ctx, params, trialMetadata{phase: "ladder"})
}

func (r *loggingRunner) TrialWithMetadata(ctx context.Context, params tuning.Params, meta trialMetadata) (float64, error) {
	return r.trial(ctx, params, meta)
}

func (r *loggingRunner) trial(ctx context.Context, params tuning.Params, meta trialMetadata) (float64, error) {
	if meta.files == 0 {
		meta.files = r.files
	}
	var before tuning.ClientMeasurement
	var hadBefore bool
	measured, canMeasure := r.inner.(measuringRunner)
	if canMeasure {
		before, hadBefore = measured.LastMeasurement()
	}
	started := r.log.now()
	rate, err := r.inner.Trial(ctx, params)
	finished := r.log.now()
	var sample *tuning.ClientMeasurement
	if err == nil && canMeasure {
		if current, have := measured.LastMeasurement(); have && (!hadBefore || current != before) {
			// LastMeasurement retains its previous value when CPU sampling fails. Only
			// a newly observable value can be attributed to this trial without changing
			// the runner contract to expose a sample generation counter.
			sample = &current
		}
	}
	r.log.appendTrial(meta, params, rate, err, started, finished.Sub(started), sample)
	return rate, err
}

func (r *loggingRunner) LastMeasurement() (tuning.ClientMeasurement, bool) {
	measured, ok := r.inner.(measuringRunner)
	if !ok {
		return tuning.ClientMeasurement{}, false
	}
	return measured.LastMeasurement()
}

func (r *loggingRunner) SetExpectedPaths(n int64) {
	setExpectedPaths(r.inner, n)
}

func (r *loggingRunner) SetTrialLogFiles(n int64) { r.files = n }

func setTrialLogFiles(runner TrialRunner, n int64) {
	if logged, ok := runner.(interface{ SetTrialLogFiles(int64) }); ok {
		logged.SetTrialLogFiles(n)
	}
}

// trialWithMetadata keeps TrialRunner's contract unchanged. A logging decorator
// may consume phase metadata, while every existing runner still sees one ordinary
// Trial call and therefore makes exactly the same measurement and decision.
func trialWithMetadata(ctx context.Context, runner TrialRunner, params tuning.Params, meta trialMetadata) (float64, error) {
	if annotated, ok := runner.(interface {
		TrialWithMetadata(context.Context, tuning.Params, trialMetadata) (float64, error)
	}); ok {
		return annotated.TrialWithMetadata(ctx, params, meta)
	}
	return runner.Trial(ctx, params)
}

// deriveTrialLogPath retains a short key prefix for operators and a digest for
// collision resistance: replacing punctuation alone would otherwise make
// different server/export identities overwrite one another at the same instant.
func deriveTrialLogPath(tuningPath string, key tuning.Key, started time.Time) string {
	keyText := key.String()
	digest := sha256.Sum256([]byte(keyText))
	safe := sanitizeTrialLogKey(keyText)
	const maxSafeKey = 120
	if len(safe) > maxSafeKey {
		safe = strings.TrimRight(safe[:maxSafeKey], "_-")
	}
	name := trialLogPrefix + safe + "-" + hex.EncodeToString(digest[:6]) + "-" +
		started.UTC().Format("20060102T150405.000000000Z") + ".jsonl"
	return filepath.Join(filepath.Dir(tuningPath), name)
}

func sanitizeTrialLogKey(key string) string {
	var b strings.Builder
	underscore := false
	for _, r := range key {
		// Keep filenames portable across the Linux producer and common desktop
		// consumers: Unicode letters are valid on Linux but not an ASCII-safe name.
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
			b.WriteRune(r)
			underscore = false
			continue
		}
		if !underscore {
			b.WriteByte('_')
			underscore = true
		}
	}
	return strings.Trim(b.String(), "_-")
}
