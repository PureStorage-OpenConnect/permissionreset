package main

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

func knobNamed(name string) knob {
	for _, k := range knobs {
		if k.name == name {
			return k
		}
	}
	panic("unknown knob " + name)
}

var connectionKnob = knobNamed("connections")

type trialFunc func(context.Context, tuning.Params) (float64, error)

func (f trialFunc) Trial(ctx context.Context, params tuning.Params) (float64, error) {
	return f(ctx, params)
}

func knobValue(name string, params tuning.Params) int {
	switch name {
	case "connections":
		return params.Connections
	case "slots":
		return params.Slots
	case "workers":
		return params.Workers
	case "batch-size":
		return params.BatchSize
	case "max-ops-per-compound":
		return params.MaxOpsPerCompound
	default:
		return -1
	}
}

func TestSearchFreezesEachWinnerBeforeTheNextKnob(t *testing.T) {
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		// Connections peaks at 8. Workers peaks at 256 only after connections=8.
		return 1000 - math.Abs(float64(p.Connections-8))*20 - math.Abs(float64(p.Workers-256)), nil
	})
	got, err := search(context.Background(), "userspace", r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Best.Connections != 8 || got.Best.Workers != 256 {
		t.Fatalf("best = %+v, want connections=8 workers=256", got.Best)
	}
	if len(got.Points) == 0 {
		t.Fatal("search recorded no trial points")
	}
	for _, point := range got.Points {
		if point.Value != knobValue(point.Knob, point.Params) {
			t.Fatalf("point value = %d, params = %+v", point.Value, point.Params)
		}
	}
}

func TestSearchFreezesEveryKnobWinnerIntoFollowingTrials(t *testing.T) {
	want := tuning.Params{
		Connections:       8,
		Slots:             16,
		Workers:           256,
		BatchSize:         100,
		MaxOpsPerCompound: 32,
	}
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		return 1000 - math.Abs(float64(p.Connections-want.Connections))*100 -
			math.Abs(float64(p.Slots-want.Slots))*10 -
			math.Abs(float64(p.Workers-want.Workers)) -
			math.Abs(float64(p.BatchSize-want.BatchSize)) -
			math.Abs(float64(p.MaxOpsPerCompound-want.MaxOpsPerCompound)), nil
	})
	got, err := search(context.Background(), "userspace", r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Best != want {
		t.Fatalf("best = %+v, want %+v", got.Best, want)
	}
}

func TestPlanSearchDropsDescriptorUnsafeRungsAndUsesAFittingBaseline(t *testing.T) {
	plan, err := newSearchPlan("kernel", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if plan.baseline.Workers != 128 {
		t.Fatalf("baseline workers = %d, want the kernel default 128", plan.baseline.Workers)
	}
	var workers []int
	for _, k := range plan.knobs {
		if k.name == "workers" {
			workers = k.values
		}
	}
	if want := []int{64, 128, 256, 512}; !slices.Equal(workers, want) {
		t.Fatalf("workers ladder = %v, want %v", workers, want)
	}

	// Use a limit that fits workers=64 but not workers=128, regardless
	// of the live descriptor reserve.
	reserve := tuning.LiveDescriptorReserve()
	tightLimit := uint64(64) + reserve + 1
	plan, err = newSearchPlan("kernel", tightLimit)
	if err != nil {
		t.Fatal(err)
	}
	if plan.baseline.Workers != 64 {
		t.Fatalf("adjusted baseline workers = %d, want sole fitting rung 64", plan.baseline.Workers)
	}
}

func TestPlanSearchRefusesWhenNoDescriptorRungFits(t *testing.T) {
	// Use a limit below the smallest rung (64) plus the live reserve.
	reserve := tuning.LiveDescriptorReserve()
	tooLow := uint64(64) + reserve - 1
	_, err := newSearchPlan("kernel", tooLow)
	if err == nil || !strings.Contains(err.Error(), "no workers ladder value fits") || !strings.Contains(err.Error(), "raise ulimit -n") {
		t.Fatalf("error = %v, want an actionable no-rung refusal", err)
	}
}

func TestKernelSkipsUserspaceOnlyKnobs(t *testing.T) {
	var seen []tuning.Params
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		seen = append(seen, p)
		return float64(p.Workers), nil
	})
	got, err := search(context.Background(), "kernel", r, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range seen {
		if p.Connections != 16 || p.Slots != 0 || p.MaxOpsPerCompound != 0 {
			t.Fatalf("kernel trial changed userspace knobs: %+v", p)
		}
	}

	var order []string
	for _, point := range got.Points {
		if len(order) == 0 || order[len(order)-1] != point.Knob {
			order = append(order, point.Knob)
		}
	}
	wantOrder := []string{"workers", "batch-size"}
	if !slices.Equal(order, wantOrder) {
		t.Fatalf("kernel ladder order = %v, want %v", order, wantOrder)
	}
}

func TestKneeNeedsTwoConsecutiveSuccessfulPointsBelowPeak(t *testing.T) {
	wantValues := []int{1, 2, 4, 8, 16}
	i := 0
	rates := map[int]float64{1: 10, 2: 20, 8: 19, 16: 18}
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		if i >= len(wantValues) || p.Connections != wantValues[i] {
			t.Fatalf("connections call %d = %d, want sequence %v", i, p.Connections, wantValues)
		}
		i++
		if p.Connections == 4 {
			return 0, errors.New("transient")
		}
		return rates[p.Connections], nil
	})
	best, _, _ := sweepKnob(context.Background(), baselineParams(), connectionKnob, r, nil)
	if i != len(wantValues) {
		t.Fatalf("calls = %d, want %d", i, len(wantValues))
	}
	if best.Connections != 2 {
		t.Fatalf("winner = %d, want 2", best.Connections)
	}
}

func TestFailedPointIsRecordedAndNeverRanksAsZero(t *testing.T) {
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		if p.Connections == 16 {
			return 0, errors.New("session teardown")
		}
		// Negative rates on purpose: a failed trial ranked as 0 ops/sec would
		// become the running peak here and win, so this fake fails under the
		// mistake the test is named for.
		return -(math.Abs(float64(p.Connections-64)) + 1), nil
	})
	best, points, err := sweepKnob(context.Background(), baselineParams(), connectionKnob, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if best.Connections != 64 {
		t.Fatalf("winner = %d, want 64", best.Connections)
	}
	if len(points) != 9 {
		t.Fatalf("points = %d, want 9", len(points))
	}
	if points[4].Err == nil {
		t.Fatalf("failed point not retained: %+v", points[4])
	}
}

func TestSearchConfirmsWinnerWithMedianOfThreeNewTrials(t *testing.T) {
	winner := tuning.Params{
		Connections:       1024,
		Slots:             128,
		Workers:           4096,
		BatchSize:         500,
		MaxOpsPerCompound: 128,
	}
	confirmation := []float64{90, 120, 100}
	winnerCalls := 0
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		if p == winner {
			if winnerCalls >= 1 {
				v := confirmation[winnerCalls-1]
				winnerCalls++
				return v, nil
			}
			winnerCalls++
		}
		return float64(p.Connections + p.Slots + p.Workers + p.BatchSize + p.MaxOpsPerCompound), nil
	})
	got, err := search(context.Background(), "userspace", r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfirmedOpsPerSec != 100 || winnerCalls != 4 {
		t.Fatalf("confirmed=%v winner calls=%d, want 100 and one ladder plus three confirmation calls", got.ConfirmedOpsPerSec, winnerCalls)
	}
}

func TestSearchReturnsBestSoFarOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		calls++
		if calls == 3 {
			cancel()
		}
		return float64(p.Connections), nil
	})
	got, err := search(ctx, "userspace", r, nil)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("error = %v", err)
	}
	if got.Best.Connections != 4 {
		t.Fatalf("best = %+v, want current-ladder value 4", got.Best)
	}
	if got.ConfirmedOpsPerSec != 0 {
		t.Fatalf("confirmation ran after cancellation: %+v", got)
	}
}

func TestSearchRunsLaddersInSpecifiedOrder(t *testing.T) {
	r := trialFunc(func(context.Context, tuning.Params) (float64, error) {
		return 1, nil
	})
	got, err := search(context.Background(), "userspace", r, nil)
	if err != nil {
		t.Fatal(err)
	}

	var gotOrder []string
	for _, point := range got.Points {
		if len(gotOrder) == 0 || gotOrder[len(gotOrder)-1] != point.Knob {
			gotOrder = append(gotOrder, point.Knob)
		}
	}
	wantOrder := []string{"connections", "slots", "workers", "batch-size", "max-ops-per-compound"}
	if !slices.Equal(gotOrder, wantOrder) {
		t.Fatalf("ladder order = %v, want %v", gotOrder, wantOrder)
	}
}

func TestKnobLadders(t *testing.T) {
	want := []struct {
		name          string
		values        []int
		userspaceOnly bool
	}{
		{name: "connections", values: []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}, userspaceOnly: true},
		{name: "slots", values: []int{0, 8, 16, 32, 64, 128}, userspaceOnly: true},
		{name: "workers", values: []int{64, 128, 256, 512, 1024, 2048, 4096}},
		{name: "batch-size", values: []int{10, 50, 100, 500}},
		{name: "max-ops-per-compound", values: []int{0, 8, 16, 32, 64, 128}, userspaceOnly: true},
	}
	if len(knobs) != len(want) {
		t.Fatalf("knobs = %d, want %d", len(knobs), len(want))
	}
	for i := range want {
		if knobs[i].name != want[i].name || knobs[i].userspaceOnly != want[i].userspaceOnly || !slices.Equal(knobs[i].values, want[i].values) {
			t.Fatalf("knob %d = {%q %v userspaceOnly=%t}, want {%q %v userspaceOnly=%t}", i, knobs[i].name, knobs[i].values, knobs[i].userspaceOnly, want[i].name, want[i].values, want[i].userspaceOnly)
		}
	}
}

func TestBaselineParams(t *testing.T) {
	want := tuning.Params{
		Connections:       16,
		Slots:             0,
		Workers:           1024,
		BatchSize:         50,
		MaxOpsPerCompound: 0,
	}
	if got := baselineParams(); got != want {
		t.Fatalf("baseline = %+v, want %+v", got, want)
	}
}

func TestSweepKnobKeepsFirstPointOnTie(t *testing.T) {
	r := trialFunc(func(context.Context, tuning.Params) (float64, error) {
		return 1, nil
	})
	best, _, err := sweepKnob(context.Background(), baselineParams(), connectionKnob, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if best.Connections != 1 {
		t.Fatalf("winner = %d, want first tied value 1", best.Connections)
	}
}

func TestSuccessfulTieBreaksBelowPeakStreak(t *testing.T) {
	wantValues := []int{1, 2, 4, 8, 16}
	i := 0
	rates := map[int]float64{1: 10, 2: 9, 4: 10, 8: 9, 16: 8}
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		if i >= len(wantValues) || p.Connections != wantValues[i] {
			t.Fatalf("connections call %d = %d, want sequence %v", i, p.Connections, wantValues)
		}
		i++
		return rates[p.Connections], nil
	})
	_, _, _ = sweepKnob(context.Background(), baselineParams(), connectionKnob, r, nil)
	if i != len(wantValues) {
		t.Fatalf("calls = %d, want %d", i, len(wantValues))
	}
}

func TestNewPeakResetsBelowPeakStreak(t *testing.T) {
	wantValues := []int{1, 2, 4, 8, 16, 32, 64}
	i := 0
	rates := map[int]float64{1: 10, 2: 9, 4: 20, 8: 9, 16: 30, 32: 29, 64: 28}
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		if i >= len(wantValues) || p.Connections != wantValues[i] {
			t.Fatalf("connections call %d = %d, want sequence %v", i, p.Connections, wantValues)
		}
		i++
		return rates[p.Connections], nil
	})
	best, _, err := sweepKnob(context.Background(), baselineParams(), connectionKnob, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if best.Connections != 16 {
		t.Fatalf("winner = %d, want 16", best.Connections)
	}
	if i != len(wantValues) {
		t.Fatalf("calls = %d, want %d", i, len(wantValues))
	}
}

func TestFailedPointDoesNotResetBelowPeakStreak(t *testing.T) {
	wantValues := []int{1, 2, 4, 8}
	i := 0
	rates := map[int]float64{1: 20, 2: 19, 8: 18}
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		if i >= len(wantValues) || p.Connections != wantValues[i] {
			t.Fatalf("connections call %d = %d, want sequence %v", i, p.Connections, wantValues)
		}
		i++
		if p.Connections == 4 {
			return 0, errors.New("transient")
		}
		return rates[p.Connections], nil
	})
	_, _, _ = sweepKnob(context.Background(), baselineParams(), connectionKnob, r, nil)
	if i != len(wantValues) {
		t.Fatalf("calls = %d, want %d", i, len(wantValues))
	}
}

func TestCancellationAfterFailedTrialIsInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	r := trialFunc(func(context.Context, tuning.Params) (float64, error) {
		calls++
		if calls == len(connectionKnob.values) {
			cancel()
		}
		return 0, errors.New("trial failed")
	})
	_, _, err := sweepKnob(ctx, baselineParams(), connectionKnob, r, nil)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("error = %v, want ErrInterrupted", err)
	}
}

func TestSearchStopsBeforeTrialWhenContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	r := trialFunc(func(context.Context, tuning.Params) (float64, error) {
		calls++
		return 1, nil
	})
	got, err := search(ctx, "userspace", r, nil)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("error = %v, want ErrInterrupted", err)
	}
	if calls != 0 {
		t.Fatalf("trial calls = %d, want 0", calls)
	}
	if got.Best != baselineParams() {
		t.Fatalf("best = %+v, want baseline %+v", got.Best, baselineParams())
	}
}

func TestSearchReturnsErrorWhenLadderHasNoSuccessfulPoint(t *testing.T) {
	calls := 0
	r := trialFunc(func(context.Context, tuning.Params) (float64, error) {
		calls++
		return 0, errors.New("trial failed")
	})
	got, err := search(context.Background(), "userspace", r, nil)
	if err == nil {
		t.Fatal("search returned nil error")
	}
	// A ladder that never succeeded is not an interruption. Orchestration persists
	// a partial result on ErrInterrupted and discards one otherwise, so the two
	// must not be confusable.
	if errors.Is(err, ErrInterrupted) {
		t.Fatalf("error = %v, want a trial failure rather than ErrInterrupted", err)
	}
	if calls != len(connectionKnob.values) {
		t.Fatalf("trial calls = %d, want all %d connection values", calls, len(connectionKnob.values))
	}
	if got.Best != baselineParams() || got.ConfirmedOpsPerSec != 0 {
		t.Fatalf("result = %+v, want unconfirmed baseline", got)
	}
}

func TestSearchReturnsErrorWhenConfirmationFails(t *testing.T) {
	confirmErr := errors.New("confirmation failed")
	winner := tuning.Params{
		Connections:       1024,
		Slots:             128,
		Workers:           4096,
		BatchSize:         500,
		MaxOpsPerCompound: 128,
	}
	winnerCalls := 0
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		if p == winner {
			winnerCalls++
			if winnerCalls == 3 {
				return 0, confirmErr
			}
		}
		return float64(p.Connections + p.Slots + p.Workers + p.BatchSize + p.MaxOpsPerCompound), nil
	})
	got, err := search(context.Background(), "userspace", r, nil)
	if !errors.Is(err, confirmErr) {
		t.Fatalf("error = %v, want confirmation failure", err)
	}
	if errors.Is(err, ErrInterrupted) {
		t.Fatalf("error = %v, want a confirmation failure rather than ErrInterrupted", err)
	}
	if winnerCalls != 3 {
		t.Fatalf("winner calls = %d, want one ladder plus two confirmation calls", winnerCalls)
	}
	if got.Best != winner || got.ConfirmedOpsPerSec != 0 {
		t.Fatalf("result = %+v, want unconfirmed winner %+v", got, winner)
	}
}

func TestSearchReturnsInterruptedWhenConfirmationIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	winner := tuning.Params{
		Connections:       1024,
		Slots:             128,
		Workers:           4096,
		BatchSize:         500,
		MaxOpsPerCompound: 128,
	}
	winnerCalls := 0
	r := trialFunc(func(ctx context.Context, p tuning.Params) (float64, error) {
		if p == winner {
			winnerCalls++
			if winnerCalls == 3 {
				cancel()
				return 0, ctx.Err()
			}
		}
		return float64(p.Connections + p.Slots + p.Workers + p.BatchSize + p.MaxOpsPerCompound), nil
	})
	got, err := search(ctx, "userspace", r, nil)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("error = %v, want ErrInterrupted", err)
	}
	if winnerCalls != 3 {
		t.Fatalf("winner calls = %d, want one ladder plus two confirmation calls", winnerCalls)
	}
	if got.Best != winner || got.ConfirmedOpsPerSec != 0 {
		t.Fatalf("result = %+v, want interrupted winner %+v", got, winner)
	}
}

func TestNonFiniteTrialRatesAreFailedPoints(t *testing.T) {
	for _, tc := range []struct {
		name string
		rate float64
	}{
		{name: "NaN", rate: math.NaN()},
		{name: "positive infinity", rate: math.Inf(1)},
		{name: "negative infinity", rate: math.Inf(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			r := trialFunc(func(context.Context, tuning.Params) (float64, error) {
				calls++
				return tc.rate, nil
			})
			best, points, err := sweepKnob(context.Background(), baselineParams(), connectionKnob, r, nil)
			if err == nil {
				t.Fatal("sweepKnob returned nil error")
			}
			if calls != len(connectionKnob.values) || len(points) != len(connectionKnob.values) {
				t.Fatalf("calls=%d points=%d, want %d each", calls, len(points), len(connectionKnob.values))
			}
			if best != baselineParams() {
				t.Fatalf("winner = %+v, want baseline %+v", best, baselineParams())
			}
			for _, point := range points {
				if point.Err == nil {
					t.Fatalf("non-finite point recorded as successful: %+v", point)
				}
			}
		})
	}
}

func TestSearchRejectsNonFiniteConfirmationRate(t *testing.T) {
	winner := tuning.Params{
		Connections:       1024,
		Slots:             128,
		Workers:           4096,
		BatchSize:         500,
		MaxOpsPerCompound: 128,
	}
	winnerCalls := 0
	r := trialFunc(func(_ context.Context, p tuning.Params) (float64, error) {
		if p == winner {
			winnerCalls++
			if winnerCalls == 3 {
				return math.Inf(1), nil
			}
		}
		return float64(p.Connections + p.Slots + p.Workers + p.BatchSize + p.MaxOpsPerCompound), nil
	})
	got, err := search(context.Background(), "userspace", r, nil)
	if err == nil {
		t.Fatal("search returned nil error")
	}
	if errors.Is(err, ErrInterrupted) {
		t.Fatalf("error = %v, want a non-finite rate rather than ErrInterrupted", err)
	}
	if got.Best != winner || got.ConfirmedOpsPerSec != 0 {
		t.Fatalf("result = %+v, want unconfirmed winner %+v", got, winner)
	}
}
