package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

type TrialRunner interface {
	Trial(context.Context, tuning.Params) (float64, error)
}

type Point struct {
	Knob      string
	Value     int
	Params    tuning.Params
	OpsPerSec float64
	Err       error
}

type SearchResult struct {
	Best               tuning.Params
	Points             []Point
	ConfirmedOpsPerSec float64
}

var ErrInterrupted = errors.New("sweep interrupted")

type knob struct {
	name          string
	values        []int
	userspaceOnly bool
	get           func(tuning.Params) int
	set           func(*tuning.Params, int)
}

var knobs = []knob{
	{
		name:          "connections",
		values:        []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024},
		userspaceOnly: true,
		get:           func(p tuning.Params) int { return p.Connections },
		set:           func(p *tuning.Params, value int) { p.Connections = value },
	},
	{
		name:          "slots",
		values:        []int{0, 8, 16, 32, 64, 128},
		userspaceOnly: true,
		get:           func(p tuning.Params) int { return p.Slots },
		set:           func(p *tuning.Params, value int) { p.Slots = value },
	},
	{
		name:   "workers",
		values: []int{64, 128, 256, 512, 1024, 2048, 4096},
		get:    func(p tuning.Params) int { return p.Workers },
		set:    func(p *tuning.Params, value int) { p.Workers = value },
	},
	{
		name:   "batch-size",
		values: []int{10, 50, 100, 500},
		get:    func(p tuning.Params) int { return p.BatchSize },
		set:    func(p *tuning.Params, value int) { p.BatchSize = value },
	},
	{
		name:          "max-ops-per-compound",
		values:        []int{0, 8, 16, 32, 64, 128},
		userspaceOnly: true,
		get:           func(p tuning.Params) int { return p.MaxOpsPerCompound },
		set:           func(p *tuning.Params, value int) { p.MaxOpsPerCompound = value },
	},
}

type searchPlan struct {
	baseline tuning.Params
	knobs    []knob
}

func baselineParams() tuning.Params {
	return tuning.Params{
		Connections:       16,
		Slots:             0,
		Workers:           1024,
		BatchSize:         50,
		MaxOpsPerCompound: 0,
	}
}

func newSearchPlan(transport string, softNofile uint64) (searchPlan, error) {
	plan := searchPlan{baseline: baselineParams()}
	if transport == "kernel" {
		// Kernel's own untuned default is 128. Starting its stock baseline at the
		// userspace-measured 1024 both mislabels that number and can exceed the live
		// descriptor limit before the workers ladder gets a chance to correct it.
		plan.baseline.Workers = 128
	}
	field := tuning.DescriptorField(transport)
	for _, source := range knobs {
		if transport == "kernel" && source.userspaceOnly {
			continue
		}
		candidate := source
		candidate.values = append([]int(nil), source.values...)
		if candidate.name == field {
			fitting := candidate.values[:0]
			for _, value := range candidate.values {
				if tuning.FitsDescriptorLimit(field, value, softNofile) == nil {
					fitting = append(fitting, value)
				}
			}
			candidate.values = fitting
			if len(candidate.values) == 0 {
				return searchPlan{}, fmt.Errorf("no %s ladder value fits soft RLIMIT_NOFILE %d; raise ulimit -n before sweeping", field, softNofile)
			}
		}
		plan.knobs = append(plan.knobs, candidate)
	}
	if err := tuning.ValidateParams(plan.baseline, transport, nil, softNofile); err != nil {
		if field == "" || !strings.Contains(err.Error(), "file descriptors") {
			return searchPlan{}, fmt.Errorf("stock baseline is not writable: %w", err)
		}
		for _, k := range plan.knobs {
			if k.name == field {
				if field == "connections" {
					plan.baseline.Connections = k.values[0]
				} else {
					plan.baseline.Workers = k.values[0]
				}
				break
			}
		}
		if err := tuning.ValidateParams(plan.baseline, transport, nil, softNofile); err != nil {
			return searchPlan{}, fmt.Errorf("no stock baseline fits soft RLIMIT_NOFILE %d: %w", softNofile, err)
		}
	}
	return plan, nil
}

// search runs the unconstrained plan used by focused search tests. The command
// builds a plan against the host's live descriptor limit and calls
// runSearchPlan directly.
func search(ctx context.Context, transport string, runner TrialRunner, onPoint func(Point)) (SearchResult, error) {
	plan, err := newSearchPlan(transport, ^uint64(0))
	if err != nil {
		return SearchResult{}, err
	}
	return runSearchPlan(ctx, plan, runner, onPoint)
}

// runSearchPlan runs the ladders. onPoint, when non-nil, is called with each
// point as soon as it is measured — a sweep is long enough that an operator
// needs to see it progress, and an interrupted sweep must still show what it
// learned.
func runSearchPlan(ctx context.Context, plan searchPlan, runner TrialRunner, onPoint func(Point)) (SearchResult, error) {
	best := plan.baseline
	result := SearchResult{Best: best}

	for _, k := range plan.knobs {

		winner, points, err := sweepKnob(ctx, best, k, runner, onPoint)
		result.Points = append(result.Points, points...)
		result.Best = winner
		if err != nil {
			return result, err
		}
		// Coordinate ascent freezes this winner into every following ladder.
		best = winner
	}

	confirmed := make([]float64, 0, 3)
	for len(confirmed) < 3 {
		if ctx.Err() != nil {
			return result, fmt.Errorf("%w: %v", ErrInterrupted, ctx.Err())
		}
		rate, err := trialWithMetadata(ctx, runner, best, trialMetadata{phase: "confirmation"})
		if ctx.Err() != nil {
			// Cancellation outranks the trial's own error: the operator asked for
			// this, so reporting a failure would describe their array falsely. Keep
			// the trial error in the message anyway — watching a sweep fail is the
			// likeliest reason to interrupt one, so it is the moment that text is
			// worth most. Confirmation returns no Points, so this is its only home.
			if err != nil {
				return result, fmt.Errorf("%w: %v (last trial error: %v)", ErrInterrupted, ctx.Err(), err)
			}
			return result, fmt.Errorf("%w: %v", ErrInterrupted, ctx.Err())
		}
		if err != nil {
			return result, fmt.Errorf("confirm winner: %w", err)
		}
		if math.IsNaN(rate) || math.IsInf(rate, 0) {
			return result, fmt.Errorf("confirm winner: non-finite rate %v", rate)
		}
		confirmed = append(confirmed, rate)
	}
	sort.Float64s(confirmed)
	result.Best = best
	result.ConfirmedOpsPerSec = confirmed[1]
	return result, nil
}

func sweepKnob(ctx context.Context, base tuning.Params, k knob, runner TrialRunner, onPoint func(Point)) (tuning.Params, []Point, error) {
	var points []Point
	winner := base
	var bestRate float64
	haveWinner := false
	belowPeak := 0

	for _, value := range k.values {
		if ctx.Err() != nil {
			return winner, points, fmt.Errorf("%w: %v", ErrInterrupted, ctx.Err())
		}

		candidate := base
		k.set(&candidate, value)
		name, candidateValue := k.name, k.get(candidate)
		rate, err := trialWithMetadata(ctx, runner, candidate, trialMetadata{
			phase: "ladder", knob: &name, value: &candidateValue,
		})
		if err == nil && (math.IsNaN(rate) || math.IsInf(rate, 0)) {
			err = fmt.Errorf("trial returned non-finite rate %v", rate)
		}
		point := Point{
			Knob:      k.name,
			Value:     k.get(candidate),
			Params:    candidate,
			OpsPerSec: rate,
			Err:       err,
		}
		points = append(points, point)
		if onPoint != nil {
			onPoint(point)
		}
		// Failed and non-finite points are no data: they neither rank nor alter
		// the consecutive-successful-points streak.
		if err == nil {
			switch {
			case !haveWinner || rate > bestRate:
				// haveWinner, not a nonzero bestRate, is what admits the first point:
				// a ladder whose every rate is negative must still crown one, and
				// comparing against a zero-valued bestRate would crown none. Strict >
				// then keeps the first point of an exact tie, and any new peak starts
				// a fresh below-peak streak.
				winner = candidate
				bestRate = rate
				haveWinner = true
				belowPeak = 0
			case rate < bestRate:
				belowPeak++
			default:
				// An exact tie is not below the peak and breaks the streak without
				// replacing the first point that attained the peak.
				belowPeak = 0
			}
		}
		if ctx.Err() != nil {
			return winner, points, fmt.Errorf("%w: %v", ErrInterrupted, ctx.Err())
		}
		if belowPeak == 2 {
			break
		}
	}

	if !haveWinner {
		return winner, points, fmt.Errorf("sweep %s: no successful trial", k.name)
	}
	return winner, points, nil
}
