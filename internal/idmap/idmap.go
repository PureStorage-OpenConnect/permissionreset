// Package idmap resolves NFSv4 ACL "who" strings between numeric form
// ("10001") and name@domain form ("jdoe@corp.example.com")
// so callers can tell whether two who strings from different transports
// (kernel idmapd vs userspace verbatim) name the same identity.
package idmap

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resolver returns the set of forms a who string could legitimately take.
// A comparison then only needs case-insensitive set membership, not a
// canonical form, because canonicalizing would require the same NSS/idmapd
// data the caller may not have on both sides of the comparison.
type Resolver interface {
	Forms(who string, isGroup bool) []string
}

// Lookup is the seam between NSS resolution and its callers, so tests can
// script identity resolution without touching the host's NSS/sssd config.
type Lookup struct {
	NameByID func(id string, isGroup bool) (string, error)
	IDByName func(name string, isGroup bool) (string, error)
}

// NSS is the production Resolver. Results are memoized because Forms is
// called once per ACE per comparison and NSS/getent round trips (getent
// especially, which forks a process) are too slow to repeat at that rate.
type NSS struct {
	lookup Lookup
	domain string
	cache  sync.Map // key: "<isGroup>:<who>" -> cacheEntry
}

type cacheEntry struct {
	forms []string
}

// NewNSS builds the production resolver: real NSS/getent lookups, and the
// NFSv4 domain read from the standard idmapd config path.
func NewNSS() *NSS {
	return newWith(Lookup{
		NameByID: nameByID,
		IDByName: idByName,
	}, DomainFromIdmapConf("/etc/idmapd.conf"))
}

// newWith builds an NSS resolver from an injected lookup seam, so tests
// never depend on the host's NSS or idmapd configuration.
func newWith(l Lookup, domain string) *NSS {
	return &NSS{lookup: l, domain: domain}
}

// Forms never returns nil or an empty slice: a caller comparing two who
// strings needs at least "who itself" to compare against even when
// resolution fails, so failure degrades to a single-element slice rather
// than an error the caller must special-case.
func (n *NSS) Forms(who string, isGroup bool) []string {
	// RFC 7530 well-known specials are never a name or an id, and resolving
	// them through NSS would either fail or (worse) coincidentally match
	// some unrelated numeric/named identity. Recognize by "ends in @ with
	// an empty local part" rather than an enum, so any future special
	// (e.g. ANONYMOUS@) is covered without a code change.
	if isWellKnown(who) {
		return []string{who}
	}

	key := cacheKey(who, isGroup)
	if v, ok := n.cache.Load(key); ok {
		return v.(cacheEntry).forms
	}

	forms := n.resolve(who, isGroup)

	// LoadOrStore rather than Store: two goroutines racing on the same
	// who+isGroup should agree on one cached answer, not thrash the map.
	actual, _ := n.cache.LoadOrStore(key, cacheEntry{forms: forms})
	return actual.(cacheEntry).forms
}

func (n *NSS) resolve(who string, isGroup bool) []string {
	if _, err := strconv.Atoi(who); err == nil {
		name, err := n.lookup.NameByID(who, isGroup)
		if err != nil || name == "" {
			return []string{who}
		}
		// sssd with use_fully_qualified_names already answers "user@domain";
		// appending the domain again would yield a form no array ever returns.
		if strings.Contains(name, "@") {
			return []string{who, name}
		}
		if n.domain == "" {
			return []string{who}
		}
		return []string{who, name + "@" + n.domain}
	}

	if idx := strings.LastIndex(who, "@"); idx > 0 {
		// The full string first: under fully qualified names NSS knows only
		// "user@domain", and the bare local part does not resolve at all.
		for _, name := range []string{who, who[:idx]} {
			if id, err := n.lookup.IDByName(name, isGroup); err == nil && id != "" {
				return []string{who, id}
			}
		}
		return []string{who}
	}

	id, err := n.lookup.IDByName(who, isGroup)
	if err != nil || id == "" {
		return []string{who}
	}
	return []string{who, id}
}

// isWellKnown matches OWNER@, GROUP@, EVERYONE@ and any other who whose
// only "@" is its final character (an empty local part) - RFC 7530
// specials never carry a domain.
func isWellKnown(who string) bool {
	if !strings.HasSuffix(who, "@") {
		return false
	}
	return strings.Count(who, "@") == 1
}

func cacheKey(who string, isGroup bool) string {
	// isGroup is part of the identity namespace: a numeric id can name
	// either a user or a group under a different name, so the two must
	// never share a cache slot.
	if isGroup {
		return "g:" + who
	}
	return "u:" + who
}

// nameByID is the real NameByID: os/user first, getent as fallback. The
// fallback is mandatory, not defensive: CGO_ENABLED=0 Go cannot see sssd
// groups through os/user on the target hosts, so os/user alone would make
// group resolution silently useless there.
func nameByID(id string, isGroup bool) (string, error) {
	if isGroup {
		if g, err := user.LookupGroupId(id); err == nil {
			return g.Name, nil
		}
	} else {
		if u, err := user.LookupId(id); err == nil {
			return u.Username, nil
		}
	}
	return getentField(id, isGroup, 0)
}

// idByName is the real IDByName: os/user first, getent as fallback.
func idByName(name string, isGroup bool) (string, error) {
	if isGroup {
		if g, err := user.LookupGroup(name); err == nil {
			return g.Gid, nil
		}
	} else {
		if u, err := user.Lookup(name); err == nil {
			return u.Uid, nil
		}
	}
	return getentField(name, isGroup, 2)
}

// NumericID returns the POSIX id NSS gives a who string: the full name@domain
// first (what SSSD with a domain suffix answers to), then its local part. ok is
// false when neither resolves. Results are memoized per who and kind.
func NumericID(who string, isGroup bool) (string, bool) {
	key := cacheKey(who, isGroup)
	if v, ok := numericCache.Load(key); ok {
		e := v.(numericEntry)
		return e.id, e.ok
	}
	id, err := idByName(who, isGroup)
	if (err != nil || id == "") && strings.Contains(who, "@") {
		id, err = idByName(who[:strings.LastIndex(who, "@")], isGroup)
	}
	e := numericEntry{id: id, ok: err == nil && id != ""}
	numericCache.Store(key, e)
	return e.id, e.ok
}

type numericEntry struct {
	id string
	ok bool
}

var numericCache sync.Map

// getentField shells out to getent as the sssd-aware fallback and returns
// one colon-separated field of the matching passwd/group line. A short
// timeout matters here: getent talking to a wedged sssd should fail fast
// rather than hang the caller's ACE comparison.
func getentField(arg string, isGroup bool, field int) (string, error) {
	db := "passwd"
	if isGroup {
		db = "group"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "getent", db, arg).Output()
	if err != nil {
		// Exit status 2 means "not found" for getent, same as any other
		// failure mode here: the caller only distinguishes success/failure.
		return "", err
	}

	line := strings.TrimRight(string(out), "\n")
	// getent can print more than one line only for group members it does
	// not split further, and passwd/group entries are always single-line -
	// take the first line defensively.
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	parts := strings.Split(line, ":")
	if field >= len(parts) {
		return "", os.ErrNotExist
	}
	return parts[field], nil
}

// DomainFromIdmapConf reads an idmapd.conf-style file and returns its
// Domain value, or "" if the file is missing, unreadable, or has no such
// key. A missing domain degrades Forms to id-only or name-only comparison
// rather than an error, since the domain is advisory (only needed to
// build the name@domain form).
func DomainFromIdmapConf(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		if !strings.EqualFold(key, "Domain") {
			continue
		}
		return strings.TrimSpace(line[idx+1:])
	}
	return ""
}

// LookupUID resolves a username to a numeric UID using os/user with a
// getent fallback for sssd-only identities in CGO_ENABLED=0 builds.
func LookupUID(name string) (int, error) {
	id, err := idByName(name, false)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(id)
}

// LookupGID resolves a group name to a numeric GID using os/user with a
// getent fallback for sssd-only identities in CGO_ENABLED=0 builds.
func LookupGID(name string) (int, error) {
	id, err := idByName(name, true)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(id)
}

// CanResolveUser reports whether a username can be resolved to a UID.
func CanResolveUser(name string) error {
	_, err := idByName(name, false)
	return err
}

// CanResolveGroup reports whether a group name can be resolved to a GID.
func CanResolveGroup(name string) error {
	_, err := idByName(name, true)
	return err
}
