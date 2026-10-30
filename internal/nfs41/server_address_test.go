package nfs41

import "testing"

// TestNormalizeServerAddress pins the default port that --server's usage string
// has always promised. Before this existed, 2049 appeared exactly once in the
// whole repository -- in that usage string -- and `--server 192.0.2.50` died
// with "missing port in address" before a single RPC.
//
// The IPv6 cases are the reason net.SplitHostPort is the detector rather than a
// colon count, and net.JoinHostPort the builder rather than concatenation. A
// bare IPv6 literal is nothing but colons, so any counting scheme reads "::1" as
// host ":" plus port "1"; and appending ":2049" to "::1" yields "::1:2049",
// which parses as a different address entirely.
func TestNormalizeServerAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"bare IPv4 gets the default port", "192.0.2.50", "192.0.2.50:2049"},
		{"explicit default port is untouched", "192.0.2.50:2049", "192.0.2.50:2049"},
		{"a non-default port is preserved", "192.0.2.50:20490", "192.0.2.50:20490"},
		{"hostname gets the default port", "fb-lab-01", "fb-lab-01:2049"},
		{"bare IPv6 literal is bracketed and defaulted", "::1", "[::1]:2049"},
		{"bracketed IPv6 with no port keeps one pair of brackets", "[::1]", "[::1]:2049"},
		{"bracketed IPv6 with a port is untouched", "[::1]:2049", "[::1]:2049"},
		{"full IPv6 literal is bracketed and defaulted", "fd00::10:10:33:50", "[fd00::10:10:33:50]:2049"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeServerAddress(tc.in)
			if err != nil {
				t.Fatalf("normalizeServerAddress(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeServerAddress(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeServerAddressRejectsAnEmptyHost(t *testing.T) {
	// ":2049" and "" both parse to an empty host. Dialing an empty host silently
	// means localhost, which is the one wrong answer that looks like it worked.
	for _, in := range []string{"", ":2049"} {
		if got, err := normalizeServerAddress(in); err == nil {
			t.Errorf("normalizeServerAddress(%q) = %q, want an error: an empty host dials localhost", in, got)
		}
	}
}

// TestNewAppliesTheDefaultPortBeforeDialing is the assertion that actually
// matters. normalizeConfig runs inside newClientWithDialer, by which point
// TCPDialer has already captured the address string, so normalizing only there
// would correct cfg.Server while the dialer still held the portless original.
// This test fails if the normalization is moved back down.
func TestNewAppliesTheDefaultPortBeforeDialing(t *testing.T) {
	cfg, err := normalizeConfig(Config{Server: "192.0.2.50", Export: "/e", Connections: 1})
	if err != nil {
		t.Fatalf("normalizeConfig: %v", err)
	}
	if cfg.Server != "192.0.2.50:2049" {
		t.Errorf("normalizeConfig left Server = %q, want the port supplied", cfg.Server)
	}
}
