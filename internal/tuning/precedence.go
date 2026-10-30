package tuning

import "flag"

// Explicit returns the command-line flags that were actually present, including
// flags whose typed values equal their defaults.
func Explicit(fs *flag.FlagSet) map[string]bool {
	typed := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		typed[f.Name] = true
	})
	return typed
}

// Apply overlays tuned values on fields the operator did not set explicitly.
// The applied-name list lets callers report which defaults came from the file.
func Apply(base, tuned Params, typed map[string]bool) (Params, []string) {
	var applied []string
	apply := func(name string, dst *int, value int) {
		if typed[name] {
			return
		}
		*dst = value
		applied = append(applied, name)
	}
	apply("connections", &base.Connections, tuned.Connections)
	apply("slots", &base.Slots, tuned.Slots)
	apply("workers", &base.Workers, tuned.Workers)
	apply("batch-size", &base.BatchSize, tuned.BatchSize)
	apply("max-ops-per-compound", &base.MaxOpsPerCompound, tuned.MaxOpsPerCompound)
	return base, applied
}
