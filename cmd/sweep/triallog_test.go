package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

func TestDeriveTrialLogPathIsSafeAndAccumulatesByStartTime(t *testing.T) {
	key, err := tuning.NewKey([]string{"clïent-a"}, "[2001:db8::1]:2049", "/team/data set", "userspace")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bin")
	tuningPath := filepath.Join(dir, tuning.FileName)
	start := time.Date(2026, 8, 24, 1, 2, 3, 456789000, time.UTC)
	got := deriveTrialLogPath(tuningPath, key, start)
	if filepath.Dir(got) != dir {
		t.Fatalf("trial log directory = %q, want %q", filepath.Dir(got), dir)
	}
	name := filepath.Base(got)
	if strings.ContainsAny(name, `/\\: []`) {
		t.Fatalf("derived filename is not filesystem-safe: %q", name)
	}
	for _, r := range name {
		if r > 127 {
			t.Fatalf("derived filename is not ASCII-safe: %q", name)
		}
	}
	if !strings.HasPrefix(name, "permissionreset-trials-") || !strings.HasSuffix(name, ".jsonl") {
		t.Fatalf("derived filename = %q", name)
	}
	if !strings.Contains(name, "20260824T010203.456789000Z") {
		t.Fatalf("derived filename = %q, want UTC start timestamp", name)
	}
	later := deriveTrialLogPath(tuningPath, key, start.Add(time.Nanosecond))
	if later == got {
		t.Fatalf("distinct sweep starts produced the same path %q", got)
	}
}

func TestLoggingRunnerWritesOneIndependentLinePerTrial(t *testing.T) {
	var dst bytes.Buffer
	log := newTrialLogWriter(&dst, io.Discard)
	start := time.Date(2026, 8, 24, 1, 2, 3, 0, time.UTC)
	clock := []time.Time{start, start.Add(2 * time.Second), start.Add(3 * time.Second), start.Add(7 * time.Second)}
	log.now = func() time.Time {
		v := clock[0]
		clock = clock[1:]
		return v
	}
	calls := 0
	inner := trialFunc(func(context.Context, tuning.Params) (float64, error) {
		calls++
		if calls == 2 {
			return 0, errors.New("boom")
		}
		return 125, nil
	})
	params := baselineParams()
	runner := &loggingRunner{inner: inner, log: log, files: 900}
	meta := trialMetadata{phase: "future_phase"}

	if rate, err := runner.TrialWithMetadata(context.Background(), params, meta); err != nil || rate != 125 {
		t.Fatalf("first trial = (%v, %v)", rate, err)
	}
	if _, err := runner.TrialWithMetadata(context.Background(), params, meta); err == nil {
		t.Fatal("failed trial returned nil error")
	}

	lines := strings.Split(strings.TrimSuffix(dst.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want one per trial", len(lines))
	}
	for i, line := range lines {
		var record trialLogRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if record.Seq != i+1 || record.Phase != "future_phase" || record.Files != 900 || record.Params != logParams(params) {
			t.Fatalf("record %d = %+v", i+1, record)
		}
	}
	var failed map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &failed); err != nil {
		t.Fatal(err)
	}
	if failed["error"] != "boom" || failed["ops_per_sec"] != nil {
		t.Fatalf("failed record = %#v", failed)
	}
}

func TestTrialWithMetadataFallsBackToPlainRunner(t *testing.T) {
	calls := 0
	runner := trialFunc(func(context.Context, tuning.Params) (float64, error) {
		calls++
		return 7, nil
	})
	rate, err := trialWithMetadata(context.Background(), runner, baselineParams(), trialMetadata{phase: "future"})
	if err != nil || rate != 7 || calls != 1 {
		t.Fatalf("fallback trial = (%v, %v), calls = %d", rate, err, calls)
	}
}

func TestLoggingRunnerDoesNotReuseUnchangedClientSample(t *testing.T) {
	var dst bytes.Buffer
	log := newTrialLogWriter(&dst, io.Discard)
	runner := &loggingRunner{inner: &unchangedSampleTrialRunner{}, log: log, files: 10}
	if _, err := runner.Trial(context.Background(), baselineParams()); err != nil {
		t.Fatal(err)
	}
	var record trialLogRecord
	if err := json.Unmarshal(bytes.TrimSpace(dst.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.Client != nil {
		t.Fatalf("trial attributed an unchanged stale sample: %+v", record.Client)
	}
}

type unchangedSampleTrialRunner struct{}

func (*unchangedSampleTrialRunner) Trial(context.Context, tuning.Params) (float64, error) {
	return 1, nil
}
func (*unchangedSampleTrialRunner) LastMeasurement() (tuning.ClientMeasurement, bool) {
	return tuning.ClientMeasurement{CPUPct: 99}, true
}

func TestLoggingRunnerDoesNotReuseClientSampleForFailedTrial(t *testing.T) {
	var dst bytes.Buffer
	log := newTrialLogWriter(&dst, io.Discard)
	runner := &loggingRunner{inner: &failedSampledTrialRunner{}, log: log, files: 10}
	if _, err := runner.Trial(context.Background(), baselineParams()); err == nil {
		t.Fatal("failed trial returned nil error")
	}
	var record trialLogRecord
	if err := json.Unmarshal(bytes.TrimSpace(dst.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.Client != nil {
		t.Fatalf("failed trial reused a stale client sample: %+v", record.Client)
	}
}

type failedSampledTrialRunner struct{}

func (*failedSampledTrialRunner) Trial(context.Context, tuning.Params) (float64, error) {
	return 0, errors.New("failed")
}
func (*failedSampledTrialRunner) LastMeasurement() (tuning.ClientMeasurement, bool) {
	return tuning.ClientMeasurement{CPUPct: 99}, true
}

func TestLoggingRunnerUsesCurrentClientSampleWithoutChangingRunnerContract(t *testing.T) {
	var dst bytes.Buffer
	log := newTrialLogWriter(&dst, io.Discard)
	runner := &loggingRunner{
		inner: &sampledTrialRunner{},
		log:   log,
		files: 10,
	}
	if _, err := runner.Trial(context.Background(), baselineParams()); err != nil {
		t.Fatal(err)
	}
	var record trialLogRecord
	if err := json.Unmarshal(bytes.TrimSpace(dst.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.Client == nil || record.Client.CPUPct != 37 || record.Client.CPUUserPct != 21 ||
		record.Client.CPUSysPct != 12 || record.Client.CPUSoftirqPct != 4 {
		t.Fatalf("client = %+v", record.Client)
	}
}

type sampledTrialRunner struct{ sampled bool }

func (r *sampledTrialRunner) Trial(context.Context, tuning.Params) (float64, error) {
	r.sampled = true
	return 1, nil
}
func (r *sampledTrialRunner) LastMeasurement() (tuning.ClientMeasurement, bool) {
	if !r.sampled {
		return tuning.ClientMeasurement{}, false
	}
	return tuning.ClientMeasurement{CPUPct: 37, CPUUserPct: 21, CPUSysPct: 12, CPUSoftirqPct: 4}, true
}

func TestTrialLogWriterWarnsOnceAndStopsAfterMidstreamWriteFailure(t *testing.T) {
	var errOut strings.Builder
	dst := &alwaysFailWriter{}
	log := newTrialLogWriter(dst, &errOut)
	log.closer = errorCloser{}
	log.write(trialLogRecord{Type: "trial", Phase: "ladder"})
	log.write(trialLogRecord{Type: "trial", Phase: "ladder"})
	log.write(trialLogRecord{Type: "trial", Phase: "ladder"})
	log.close()
	if got := strings.Count(errOut.String(), "warning: trial log"); got != 1 {
		t.Fatalf("warnings = %d, want one; stderr = %q", got, errOut.String())
	}
	if dst.calls != 1 {
		t.Fatalf("writes = %d, want writer disabled after the first failure", dst.calls)
	}
}

type alwaysFailWriter struct{ calls int }

func (w *alwaysFailWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, errors.New("disk full")
}

type errorCloser struct{}

func (errorCloser) Close() error { return errors.New("close failed") }

func TestTrialLogWriterTreatsShortWriteAsFailure(t *testing.T) {
	var errOut strings.Builder
	log := newTrialLogWriter(shortWriter{}, &errOut)
	log.write(trialLogRecord{Type: "trial", Phase: "ladder"})
	if !strings.Contains(errOut.String(), io.ErrShortWrite.Error()) {
		t.Fatalf("stderr = %q, want short write warning", errOut.String())
	}
	if !log.failed {
		t.Fatal("short write did not disable the trial log")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestTrialLogWriterWarnsOnceWhenCloseFails(t *testing.T) {
	var errOut strings.Builder
	log := newTrialLogWriter(io.Discard, &errOut)
	log.closer = errorCloser{}
	log.close()
	if got := strings.Count(errOut.String(), "warning: trial log"); got != 1 || !strings.Contains(errOut.String(), "close failed") {
		t.Fatalf("stderr = %q, want one close warning", errOut.String())
	}
}

func TestOpenTrialLogAppendsRatherThanOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trials.jsonl")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var errOut strings.Builder
	log := openTrialLog(path, &errOut)
	log.write(trialLogRecord{Type: "trial", Phase: "ladder"})
	log.close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "old\n") {
		t.Fatalf("existing log was overwritten: %q", data)
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q", errOut.String())
	}
}
