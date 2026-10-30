package idmap

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// scriptedLookup wraps Lookup with call counters guarded by a mutex, so
// concurrency tests can assert call counts without a data race.
type scriptedLookup struct {
	mu           sync.Mutex
	nameByIDFn   func(id string, isGroup bool) (string, error)
	idByNameFn   func(name string, isGroup bool) (string, error)
	nameByIDCall int
	idByNameCall int
}

func (s *scriptedLookup) lookup() Lookup {
	return Lookup{
		NameByID: func(id string, isGroup bool) (string, error) {
			s.mu.Lock()
			s.nameByIDCall++
			s.mu.Unlock()
			return s.nameByIDFn(id, isGroup)
		},
		IDByName: func(name string, isGroup bool) (string, error) {
			s.mu.Lock()
			s.idByNameCall++
			s.mu.Unlock()
			return s.idByNameFn(name, isGroup)
		},
	}
}

func (s *scriptedLookup) counts() (nameByID, idByName int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nameByIDCall, s.idByNameCall
}

func TestForms_WellKnownSpecials(t *testing.T) {
	for _, who := range []string{"OWNER@", "GROUP@", "EVERYONE@"} {
		s := &scriptedLookup{
			nameByIDFn: func(string, bool) (string, error) { return "", errors.New("should not be called") },
			idByNameFn: func(string, bool) (string, error) { return "", errors.New("should not be called") },
		}
		n := newWith(s.lookup(), "corp.example.com")

		got := n.Forms(who, false)
		if len(got) != 1 || got[0] != who {
			t.Errorf("Forms(%q) = %v, want [%q]", who, got, who)
		}
		nameByID, idByName := s.counts()
		if nameByID != 0 || idByName != 0 {
			t.Errorf("Forms(%q) invoked scripted lookup: nameByID=%d idByName=%d", who, nameByID, idByName)
		}
	}
}

func TestForms_NumericToName(t *testing.T) {
	s := &scriptedLookup{
		nameByIDFn: func(id string, isGroup bool) (string, error) {
			if id == "10001" && !isGroup {
				return "jdoe", nil
			}
			return "", errors.New("not found")
		},
		idByNameFn: func(string, bool) (string, error) { return "", errors.New("unused") },
	}
	n := newWith(s.lookup(), "corp.example.com")

	got := n.Forms("10001", false)
	if !contains(got, "10001") || !contains(got, "jdoe@corp.example.com") {
		t.Errorf("Forms(10001) = %v, missing expected forms", got)
	}
}

func TestForms_NumericGroup(t *testing.T) {
	var sawIsGroup bool
	s := &scriptedLookup{
		nameByIDFn: func(id string, isGroup bool) (string, error) {
			sawIsGroup = isGroup
			if id == "10002" && isGroup {
				return "domain admins", nil
			}
			return "", errors.New("not found")
		},
		idByNameFn: func(string, bool) (string, error) { return "", errors.New("unused") },
	}
	n := newWith(s.lookup(), "corp.example.com")

	got := n.Forms("10002", true)
	if !contains(got, "domain admins@corp.example.com") {
		t.Errorf("Forms(10002, group) = %v, missing name@domain form", got)
	}
	if !sawIsGroup {
		t.Error("isGroup=true was not passed through to NameByID")
	}
}

func TestForms_NameDomainToNumeric(t *testing.T) {
	s := &scriptedLookup{
		nameByIDFn: func(string, bool) (string, error) { return "", errors.New("unused") },
		idByNameFn: func(name string, isGroup bool) (string, error) {
			if name == "jdoe" && !isGroup {
				return "10001", nil
			}
			return "", errors.New("not found")
		},
	}
	n := newWith(s.lookup(), "corp.example.com")

	got := n.Forms("jdoe@corp.example.com", false)
	if !contains(got, "10001") {
		t.Errorf("Forms(jdoe@domain) = %v, missing numeric form", got)
	}
}

// sssd with use_fully_qualified_names (the example.net lab client): NSS answers
// "sacl-map2@example.net" for uid 1000003 and resolves only that full string, not
// "sacl-map2". FlashBlade returns the same identity as "sacl-map2@example.net", so
// both directions must land on it (#50 RC regression, FB --validate).
func TestForms_FullyQualifiedNSSNames(t *testing.T) {
	s := &scriptedLookup{
		nameByIDFn: func(id string, isGroup bool) (string, error) {
			if id == "1000003" && !isGroup {
				return "sacl-map2@example.net", nil
			}
			return "", errors.New("not found")
		},
		idByNameFn: func(name string, isGroup bool) (string, error) {
			if name == "sacl-map2@example.net" && !isGroup {
				return "1000003", nil
			}
			return "", errors.New("not found")
		},
	}
	n := newWith(s.lookup(), "example.net")

	got := n.Forms("1000003", false)
	if !contains(got, "sacl-map2@example.net") || contains(got, "sacl-map2@example.net@example.net") {
		t.Errorf("Forms(1000003) = %v, want sacl-map2@example.net with no second domain", got)
	}
	if got := n.Forms("sacl-map2@example.net", false); !contains(got, "1000003") {
		t.Errorf("Forms(sacl-map2@example.net) = %v, missing numeric form", got)
	}
	// NSS already qualified the name, so no idmapd domain is needed.
	if got := newWith(s.lookup(), "").Forms("1000003", false); !contains(got, "sacl-map2@example.net") {
		t.Errorf("Forms(1000003) with no domain = %v, want sacl-map2@example.net", got)
	}
}

func TestForms_Unresolvable(t *testing.T) {
	s := &scriptedLookup{
		nameByIDFn: func(string, bool) (string, error) { return "", errors.New("boom") },
		idByNameFn: func(string, bool) (string, error) { return "", errors.New("boom") },
	}
	n := newWith(s.lookup(), "corp.example.com")

	for _, who := range []string{"99999", "ghost@corp.example.com"} {
		got := n.Forms(who, false)
		if len(got) != 1 || got[0] != who {
			t.Errorf("Forms(%q) = %v, want exactly [%q]", who, got, who)
		}
	}
}

func TestForms_EmptyDomain(t *testing.T) {
	s := &scriptedLookup{
		nameByIDFn: func(id string, isGroup bool) (string, error) {
			return "jdoe", nil
		},
		idByNameFn: func(string, bool) (string, error) { return "", errors.New("unused") },
	}
	n := newWith(s.lookup(), "")

	got := n.Forms("10001", false)
	if len(got) != 1 || got[0] != "10001" {
		t.Errorf("Forms(10001) with empty domain = %v, want [10001]", got)
	}
}

func TestForms_Memoization(t *testing.T) {
	s := &scriptedLookup{
		nameByIDFn: func(id string, isGroup bool) (string, error) { return "jdoe", nil },
		idByNameFn: func(string, bool) (string, error) { return "", errors.New("unused") },
	}
	n := newWith(s.lookup(), "corp.example.com")

	n.Forms("10001", false)
	n.Forms("10001", false)
	nameByID, _ := s.counts()
	if nameByID != 1 {
		t.Errorf("Forms called scripted lookup %d times for same who+isGroup, want 1", nameByID)
	}

	n.Forms("10001", true)
	nameByID, _ = s.counts()
	if nameByID != 2 {
		t.Errorf("flipping isGroup should invoke lookup again, got %d total calls, want 2", nameByID)
	}
}

func TestForms_NegativeCaching(t *testing.T) {
	s := &scriptedLookup{
		nameByIDFn: func(string, bool) (string, error) { return "", errors.New("not found") },
		idByNameFn: func(string, bool) (string, error) { return "", errors.New("unused") },
	}
	n := newWith(s.lookup(), "corp.example.com")

	n.Forms("55555", false)
	n.Forms("55555", false)
	nameByID, _ := s.counts()
	if nameByID != 1 {
		t.Errorf("negative result invoked scripted lookup %d times, want 1", nameByID)
	}
}

func TestDomainFromIdmapConf(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	normal := write("normal.conf", "[General]\nDomain = example.com\n")
	noSpace := write("nospace.conf", "[General]\ndomain=example.com\n")
	commented := write("commented.conf", "# Domain = commented.com\nDomain = real.com\n")
	noKey := write("nokey.conf", "[General]\nVerbosity = 0\n")

	cases := []struct {
		name string
		path string
		want string
	}{
		{"normal spacing", normal, "example.com"},
		{"no spaces lowercase key", noSpace, "example.com"},
		{"commented line ignored, later real wins", commented, "real.com"},
		{"no domain key", noKey, ""},
		{"nonexistent path", filepath.Join(dir, "does-not-exist.conf"), ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DomainFromIdmapConf(c.path)
			if got != c.want {
				t.Errorf("DomainFromIdmapConf(%s) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestForms_Concurrency(t *testing.T) {
	s := &scriptedLookup{
		nameByIDFn: func(id string, isGroup bool) (string, error) {
			if id == "10001" {
				return "jdoe", nil
			}
			return "", errors.New("not found")
		},
		idByNameFn: func(name string, isGroup bool) (string, error) {
			if name == "jdoe" {
				return "10001", nil
			}
			return "", errors.New("not found")
		},
	}
	n := newWith(s.lookup(), "corp.example.com")

	inputs := []struct {
		who     string
		isGroup bool
	}{
		{"10001", false},
		{"jdoe@corp.example.com", false},
		{"OWNER@", false},
		{"99999", true},
		{"10001", true},
	}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		in := inputs[i%len(inputs)]
		go func() {
			defer wg.Done()
			forms := n.Forms(in.who, in.isGroup)
			if len(forms) == 0 {
				t.Errorf("Forms(%q, %v) returned empty", in.who, in.isGroup)
			}
		}()
	}
	wg.Wait()
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
