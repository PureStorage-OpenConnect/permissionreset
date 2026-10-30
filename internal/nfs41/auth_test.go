package nfs41

import (
	"os"
	"testing"
)

// A Config.Auth overrides the process credential entirely. Without this the
// only identity the userspace transport can present is the one the process
// happens to run as, which on a Mac is a local account the array never heard of.
func TestConfigAuthOverridesProcessCredential(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))

	want := AuthSys{Machine: "lab-client", UID: 10010, GID: 10000, AuxGIDs: []uint32{10020, 10021}}
	c, err := newClientWithDialer(t.Context(), Config{
		Export: "/",
		Auth:   &want,
	}, srv.Dialer())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()

	if c.auth.UID != want.UID || c.auth.GID != want.GID || c.auth.Machine != want.Machine {
		t.Fatalf("client auth = %+v, want %+v", c.auth, want)
	}
	if len(c.auth.AuxGIDs) != len(want.AuxGIDs) {
		t.Fatalf("aux gids = %v, want %v", c.auth.AuxGIDs, want.AuxGIDs)
	}
}

// A nil Auth keeps the existing behaviour exactly: the credential comes from the
// process, matching what the kernel client would send from the same account.
func TestNilConfigAuthUsesProcessCredential(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))

	c, err := newClientWithDialer(t.Context(), Config{Export: "/"}, srv.Dialer())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()

	if want := CurrentAuthSys(); c.auth.UID != want.UID || c.auth.GID != want.GID {
		t.Fatalf("client auth = %+v, want the process credential %+v", c.auth, want)
	}
}

// ProcessCredentialNotes must say nothing for an ordinary account. It is the
// only thing standing between a truncated credential and a silent one, so a
// note on every run would be worth as little as no note at all.
func TestProcessCredentialNotesIsQuietForAnOrdinaryAccount(t *testing.T) {
	gids, err := os.Getgroups()
	if err != nil {
		t.Skipf("os.Getgroups: %v", err)
	}
	notes := ProcessCredentialNotes()
	if len(gids) <= maxAuxGIDs && len(notes) != 0 {
		t.Fatalf("notes = %v, want none: this account is in %d groups, under the %d cap",
			notes, len(gids), maxAuxGIDs)
	}
	if len(gids) > maxAuxGIDs && len(notes) == 0 {
		t.Fatalf("this account is in %d groups, over the %d cap, and nothing was reported",
			len(gids), maxAuxGIDs)
	}
}

// The cap the note is about is the wire format's, not ours: RFC 5531 gives
// AUTH_SYS sixteen auxiliary gids. A change here means the encoder changed too,
// and the note's arithmetic is wrong.
func TestAuxGIDCapMatchesTheWireFormat(t *testing.T) {
	if maxAuxGIDs != 16 {
		t.Fatalf("maxAuxGIDs = %d, want 16 (RFC 5531 AUTH_SYS)", maxAuxGIDs)
	}
}
