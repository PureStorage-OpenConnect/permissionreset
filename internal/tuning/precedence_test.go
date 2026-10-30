package tuning

import (
	"flag"
	"fmt"
	"testing"
)

func TestApplyOverlaysFiveFieldsInStableOrder(t *testing.T) {
	got, applied := Apply(Params{}, Params{
		Connections:       32,
		Slots:             0,
		Workers:           1024,
		BatchSize:         100,
		MaxOpsPerCompound: 0,
	}, nil)
	want := Params{
		Connections:       32,
		Slots:             0,
		Workers:           1024,
		BatchSize:         100,
		MaxOpsPerCompound: 0,
	}
	if got != want {
		t.Fatalf("Apply() = %+v, want %+v", got, want)
	}
	if diff := cmpStrings(applied, []string{"connections", "slots", "workers", "batch-size", "max-ops-per-compound"}); diff != "" {
		t.Fatal(diff)
	}
}

func TestApplyKeepsExplicitStockValues(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	connections := fs.Int("connections", 16, "")
	workers := fs.Int("workers", 128, "")
	if err := fs.Parse([]string{"--connections=16"}); err != nil {
		t.Fatal(err)
	}

	base := Params{Connections: *connections, Workers: *workers, BatchSize: 50}
	got, applied := Apply(base, Params{
		Connections:       32,
		Slots:             0,
		Workers:           1024,
		BatchSize:         100,
		MaxOpsPerCompound: 0,
	}, Explicit(fs))
	if got.Connections != 16 {
		t.Fatalf("explicit connections = %d, want 16", got.Connections)
	}
	if got.Workers != 1024 || got.BatchSize != 100 {
		t.Fatalf("untyped tuning not applied: %+v", got)
	}
	if diff := cmpStrings(applied, []string{"slots", "workers", "batch-size", "max-ops-per-compound"}); diff != "" {
		t.Fatal(diff)
	}
}

func cmpStrings(got, want []string) string {
	if len(got) != len(want) {
		return fmt.Sprintf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			return fmt.Sprintf("got %v, want %v", got, want)
		}
	}
	return ""
}
