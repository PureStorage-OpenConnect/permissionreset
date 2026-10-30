package stats

import "testing"

func TestSnapshotCopiesEveryCounter(t *testing.T) {
	st := &Stats{}
	st.Applied.Store(11)
	st.Skipped.Store(12)
	st.Errors.Store(13)
	st.Enumerated.Store(14)
	st.Symlinks.Store(15)

	got := st.Snapshot()
	want := Snapshot{Applied: 11, Skipped: 12, Errors: 13, Enumerated: 14, Symlinks: 15}
	if got != want {
		t.Fatalf("Snapshot() = %+v, want %+v", got, want)
	}

	st.Applied.Store(99)
	if got.Applied != 11 {
		t.Fatalf("snapshot changed after source mutation: Applied = %d", got.Applied)
	}
}
