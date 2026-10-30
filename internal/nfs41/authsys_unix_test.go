//go:build !windows

package nfs41

import (
	"os"
	"testing"
)

// CurrentAuthSys has no error return and no seams: it reads the real process
// (hostname, uid/gid, group list). These tests validate the contract on
// whatever account is running, rather than asserting specific values.
func TestCurrentAuthSysHostnameWithinLimit(t *testing.T) {
	got := CurrentAuthSys()
	if got.Machine == "" {
		t.Fatal("Machine is empty, want a hostname (or the localhost fallback)")
	}
	if len(got.Machine) > maxMachineName {
		t.Fatalf("Machine is %d bytes, want <= %d (AUTH_SYS limit)", len(got.Machine), maxMachineName)
	}
}

// A truncated hostname must be a prefix of the real one, not something else
// entirely, so a truncated credential still identifies the right host as far
// as it goes.
func TestCurrentAuthSysHostnameIsPrefixOfRealHostname(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Skipf("os.Hostname: %v", err)
	}
	want := host
	if len(want) > maxMachineName {
		want = want[:maxMachineName]
	}
	got := CurrentAuthSys()
	if got.Machine != want {
		t.Fatalf("Machine = %q, want %q", got.Machine, want)
	}
}

func TestCurrentAuthSysUIDAndGIDMatchProcess(t *testing.T) {
	got := CurrentAuthSys()
	if got.UID != uint32(os.Getuid()) {
		t.Fatalf("UID = %d, want %d (os.Getuid)", got.UID, os.Getuid())
	}
	if got.GID != uint32(os.Getgid()) {
		t.Fatalf("GID = %d, want %d (os.Getgid)", got.GID, os.Getgid())
	}
}

// The 16-gid cap is RFC 5531's, not a suggestion: AuxGIDs must never exceed it
// regardless of how many groups this account actually belongs to.
func TestCurrentAuthSysAuxGIDsCappedAtSixteen(t *testing.T) {
	got := CurrentAuthSys()
	if len(got.AuxGIDs) > maxAuxGIDs {
		t.Fatalf("AuxGIDs has %d entries, want <= %d", len(got.AuxGIDs), maxAuxGIDs)
	}
}

// AuxGIDs must be a straight uint32 conversion of os.Getgroups(), truncated to
// the same cap CurrentAuthSys applies, in the same order.
func TestCurrentAuthSysAuxGIDsMatchProcessGroups(t *testing.T) {
	gids, err := os.Getgroups()
	if err != nil {
		t.Skipf("os.Getgroups: %v", err)
	}
	if len(gids) > maxAuxGIDs {
		gids = gids[:maxAuxGIDs]
	}

	got := CurrentAuthSys()
	if len(got.AuxGIDs) != len(gids) {
		t.Fatalf("AuxGIDs has %d entries, want %d (matching os.Getgroups, capped)", len(got.AuxGIDs), len(gids))
	}
	for i, gid := range gids {
		if got.AuxGIDs[i] != uint32(gid) {
			t.Fatalf("AuxGIDs[%d] = %d, want %d", i, got.AuxGIDs[i], gid)
		}
	}
}
