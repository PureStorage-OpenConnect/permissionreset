package tuning

import (
	"strings"
	"testing"
)

func TestValidateParamsRanges(t *testing.T) {
	validKernel := Params{Workers: 128, BatchSize: 50}
	validUserspace := Params{Connections: 16, Workers: 128, BatchSize: 50}

	cases := []struct {
		name      string
		params    Params
		transport string
		explicit  map[string]bool
		soft      uint64
		wantErr   bool
		wantSub   string
	}{
		{
			name:      "valid kernel params, no error",
			params:    validKernel,
			transport: "kernel",
			soft:      1024,
		},
		{
			name:      "valid userspace params, no error",
			params:    validUserspace,
			transport: "userspace",
			soft:      1024,
		},
		{
			name:      "zero workers rejected on kernel",
			params:    Params{Workers: 0, BatchSize: 50},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "workers absent or zero",
		},
		{
			name:      "zero batch-size rejected",
			params:    Params{Workers: 128, BatchSize: 0},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "batch_size absent or zero",
		},
		{
			name:      "zero connections accepted on kernel (inert)",
			params:    Params{Connections: 0, Workers: 128, BatchSize: 50},
			transport: "kernel",
			soft:      1024,
		},
		{
			name:      "zero connections rejected on userspace",
			params:    Params{Connections: 0, Workers: 128, BatchSize: 50},
			transport: "userspace",
			soft:      1024,
			wantErr:   true,
			wantSub:   "connections absent or zero",
		},
		{
			name:      "connections at max boundary accepted",
			params:    Params{Connections: MaxConnections, Workers: 128, BatchSize: 50},
			transport: "userspace",
			soft:      1 << 20,
		},
		{
			name:      "connections over max rejected",
			params:    Params{Connections: MaxConnections + 1, Workers: 128, BatchSize: 50},
			transport: "userspace",
			soft:      1 << 20,
			wantErr:   true,
			wantSub:   "connections must be between",
		},
		{
			name:      "connections negative rejected",
			params:    Params{Connections: -1, Workers: 128, BatchSize: 50},
			transport: "userspace",
			soft:      1024,
			wantErr:   true,
			wantSub:   "connections must be between",
		},
		{
			name:      "workers at max boundary accepted",
			params:    Params{Workers: MaxWorkers, BatchSize: 50},
			transport: "kernel",
			soft:      1 << 20,
		},
		{
			name:      "workers over max rejected",
			params:    Params{Workers: MaxWorkers + 1, BatchSize: 50},
			transport: "kernel",
			soft:      1 << 20,
			wantErr:   true,
			wantSub:   "workers must be between",
		},
		{
			name:      "workers negative rejected",
			params:    Params{Workers: -1, BatchSize: 50},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "workers must be between",
		},
		{
			name:      "batch-size at max boundary accepted",
			params:    Params{Workers: 128, BatchSize: MaxBatchSize},
			transport: "kernel",
			soft:      1024,
		},
		{
			name:      "batch-size over max rejected",
			params:    Params{Workers: 128, BatchSize: MaxBatchSize + 1},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "batch-size must be between",
		},
		{
			name:      "batch-size negative rejected",
			params:    Params{Workers: 128, BatchSize: -1},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "batch-size must be between",
		},
		{
			name:      "max-ops-per-compound zero accepted (means default)",
			params:    Params{Workers: 128, BatchSize: 50, MaxOpsPerCompound: 0},
			transport: "kernel",
			soft:      1024,
		},
		{
			name:      "max-ops-per-compound at boundary accepted",
			params:    Params{Workers: 128, BatchSize: 50, MaxOpsPerCompound: MaxOpsPerCompound},
			transport: "kernel",
			soft:      1024,
		},
		{
			name:      "max-ops-per-compound over max rejected",
			params:    Params{Workers: 128, BatchSize: 50, MaxOpsPerCompound: MaxOpsPerCompound + 1},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "max-ops-per-compound must be between",
		},
		{
			name:      "max-ops-per-compound negative rejected",
			params:    Params{Workers: 128, BatchSize: 50, MaxOpsPerCompound: -1},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "max-ops-per-compound must be between",
		},
		{
			name:      "slots zero accepted",
			params:    Params{Workers: 128, BatchSize: 50, Slots: 0},
			transport: "kernel",
			soft:      1024,
		},
		{
			name:      "slots negative rejected",
			params:    Params{Workers: 128, BatchSize: 50, Slots: -1},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "slots must be between",
		},
		{
			name:      "descriptor budget exceeded on kernel workers",
			params:    Params{Workers: MaxWorkers, BatchSize: 50},
			transport: "kernel",
			soft:      1024,
			wantErr:   true,
			wantSub:   "file descriptors but soft RLIMIT_NOFILE is",
		},
		{
			name:      "descriptor budget exceeded on userspace connections",
			params:    Params{Connections: MaxConnections, Workers: 128, BatchSize: 50},
			transport: "userspace",
			soft:      1024,
			wantErr:   true,
			wantSub:   "file descriptors but soft RLIMIT_NOFILE is",
		},
		{
			name:      "descriptor budget skipped when field is explicit",
			params:    Params{Workers: MaxWorkers, BatchSize: 50},
			transport: "kernel",
			explicit:  map[string]bool{"workers": true},
			soft:      1024,
		},
		{
			name:      "unknown transport skips descriptor budget entirely",
			params:    Params{Connections: 0, Workers: 128, BatchSize: 50},
			transport: "neither-kernel-nor-userspace",
			soft:      1024,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateParams(tc.params, tc.transport, tc.explicit, tc.soft)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateParams() = nil, want error containing %q", tc.wantSub)
				}
				if !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("ValidateParams() error = %q, want substring %q", err.Error(), tc.wantSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateParams() = %v, want nil", err)
			}
		})
	}
}
