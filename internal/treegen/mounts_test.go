package treegen

import (
	"errors"
	"strings"
	"testing"
)

// A Linux /proc/mounts fixture. The same bytes drive every case below, so a
// test that changes answer between cases changed because of the target, not
// because of the table.
const mountFixture = `proc /proc proc rw,nosuid 0 0
192.0.2.50:/fb-perms /mnt/fb-perms nfs4 rw,vers=4.1,nconnect=16 0 0
192.0.2.50:/other-export /mnt/other nfs4 rw,vers=4.1 0 0
/dev/sda1 / ext4 rw,relatime 0 0
`

// A target under a mount of the right export is a local path, and gets
// translated. This is every Linux invocation that works today and it must not
// move: /mnt/fb-perms/bigdata on a mount of /fb-perms is bigdata under
// the export. The export's own name must not be in it: the client is rooted at
// the export, so "fb-perms/bigdata" creates <export>/fb-perms/bigdata.
func TestResolveExportRelTargetTranslatesALocalMountPath(t *testing.T) {
	rel, note, err := resolveExportRelTarget(
		"/mnt/fb-perms/bigdata_named", "/fb-perms", strings.NewReader(mountFixture))
	if err != nil {
		t.Fatalf("resolveExportRelTarget: %v", err)
	}
	if want := "bigdata_named"; rel != want {
		t.Fatalf("rel = %q, want %q", rel, want)
	}
	if note != "" {
		t.Fatalf("note = %q, want none: a resolved mount is the ordinary case and says nothing", note)
	}
}

// No mount table at all is macOS: no /proc, and no way to mount a 4.1 export
// even if there were. The target is taken as a path on the server.
func TestResolveExportRelTargetWithNoMountTableTakesTheTargetAsServerSide(t *testing.T) {
	rel, note, err := resolveExportRelTarget("/bigdata_named", "/fb-perms", nil)
	if err != nil {
		t.Fatalf("resolveExportRelTarget: %v", err)
	}
	if want := "bigdata_named"; rel != want {
		t.Fatalf("rel = %q, want %q", rel, want)
	}
	if note == "" {
		t.Fatal("no note; taking the target as server-side is an inference and must be stated")
	}
}

// The parity requirement: a Linux host whose target is under no NFS mount gets
// the SAME answer a Mac gets. Mount-free is a property of the run, not of the
// platform -- the userspace transport needs no mount on either one, so a Linux
// operator who has not mounted the export is not doing anything unsupported.
func TestResolveExportRelTargetIsIdenticalMountFreeOnEveryPlatform(t *testing.T) {
	withTable, noteLinux, err := resolveExportRelTarget(
		"/bigdata_named", "/fb-perms", strings.NewReader(mountFixture))
	if err != nil {
		t.Fatalf("with a mount table: %v", err)
	}
	withoutTable, noteMac, err := resolveExportRelTarget("/bigdata_named", "/fb-perms", nil)
	if err != nil {
		t.Fatalf("with no mount table: %v", err)
	}
	if withTable != withoutTable {
		t.Fatalf("Linux gave %q and macOS gave %q for the same target; "+
			"mount-free runs must not depend on the platform", withTable, withoutTable)
	}
	if noteLinux == "" || noteMac == "" {
		t.Fatalf("notes = %q / %q, want both set", noteLinux, noteMac)
	}
}

// An absence and a contradiction are different. A target under a mount of a
// DIFFERENT export is not a mount-free run -- it is an operator naming a path
// this invocation cannot mean, and falling back would generate the tree
// somewhere they did not ask for. That stays fatal.
func TestResolveExportRelTargetRefusesAMountOfTheWrongExport(t *testing.T) {
	_, _, err := resolveExportRelTarget(
		"/mnt/other/bigdata_named", "/fb-perms", strings.NewReader(mountFixture))
	if err == nil {
		t.Fatal("a target on a mount of /other-export was accepted against --export /fb-perms")
	}
	for _, want := range []string{"other-export", "fb-perms"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to name %q so the operator can see the mismatch", err, want)
		}
	}
}

// The typo case, which is why the fallback announces itself. /mnt/fb-perm
// (no trailing s) is under no mount, so it is taken as server-side and the
// tree lands at <export>/mnt/fb-perm. That is a legal request and must not
// be refused -- but the operator has to be able to see it happened.
func TestResolveExportRelTargetNoteNamesTheResolvedTarget(t *testing.T) {
	rel, note, err := resolveExportRelTarget(
		"/mnt/fb-perm/bigdata", "/fb-perms", strings.NewReader(mountFixture))
	if err != nil {
		t.Fatalf("resolveExportRelTarget: %v", err)
	}
	if want := "mnt/fb-perm/bigdata"; rel != want {
		t.Fatalf("rel = %q, want %q", rel, want)
	}
	if !strings.Contains(note, "mnt/fb-perm/bigdata") {
		t.Fatalf("note = %q, want it to name the path the tree will be created at", note)
	}
}

// A malformed mount table is neither an absence nor a contradiction: we do not
// know whether the target is local, so guessing would be the one thing worse
// than failing.
func TestResolveExportRelTargetPropagatesAMalformedTable(t *testing.T) {
	_, _, err := resolveExportRelTarget(
		"/mnt/fb-perms/x", "/fb-perms",
		// A mount point with an invalid octal escape: \9 is not \040.
		strings.NewReader("192.0.2.1:/e /mnt/fb-perms\\9x nfs4 rw 0 0\n"))
	if err == nil {
		t.Fatal("a malformed mount table was accepted")
	}
	if errors.Is(err, errNoMountTable) {
		t.Fatalf("error = %v, want the parse failure and not the mount-free path", err)
	}
}

// The parity claim has to hold for a relative TARGET too. tuning.ResolveMount
// rejects a non-absolute path with an error that is not ErrNoMountForTarget,
// so a relative target used to be fatal on a host with a mount table and fine
// on one without -- the platform difference the mount-free branch exists to
// remove, reintroduced one layer down.
func TestResolveExportRelTargetIsIdenticalForARelativeTarget(t *testing.T) {
	withTable, noteWith, errWith := resolveExportRelTarget(
		"bigdata", "/fb-perms", strings.NewReader(mountFixture))
	if errWith != nil {
		t.Fatalf("with a mount table: %v; a relative TARGET must not be fatal on one platform only", errWith)
	}
	withoutTable, noteWithout, errWithout := resolveExportRelTarget("bigdata", "/fb-perms", nil)
	if errWithout != nil {
		t.Fatal(errWithout)
	}
	if withTable != withoutTable {
		t.Fatalf("relTarget = %q with a table, %q without; the answer must not depend on the platform",
			withTable, withoutTable)
	}
	if noteWith == "" || noteWithout == "" {
		t.Fatal("both branches must say the target was taken as server-side")
	}
}

// resolveExportRelTarget, userspaceTargetIsEmpty and the fan-out each normalise
// the target, and they must reach the same place. They did not: a leading ".."
// survived filepath.Clean here, was collapsed by path.Clean in the emptiness
// check, and was sent as a literal component name by the fan-out -- three
// different directories, with the note naming a fourth.
func TestResolveExportRelTargetCollapsesDotDotLikeTheFanOut(t *testing.T) {
	rel, note, err := resolveExportRelTarget("../foo", "/fb-perms", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rel != "foo" {
		t.Fatalf("relTarget = %q, want %q -- the fan-out would send %q as a component name", rel, "foo", "..")
	}
	if !strings.Contains(note, "/fb-perms/foo") {
		t.Fatalf("note = %q, want it to name /fb-perms/foo, where the tree is actually created", note)
	}
}
