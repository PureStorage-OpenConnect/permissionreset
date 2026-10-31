package main

// Support bundle collection.
//
// A support engineer handed a failed run needs four things at once: which build
// ran, what it was told to do, what the kernel and the mount table looked like
// underneath it, and what the run itself reported. Today those live in four
// places an operator has to be talked through collecting, one at a time, over
// mail -- and the two most useful of them (the spec and the error log) are the
// two most likely to be trimmed, retyped, or refused outright because nobody
// can say what is in them.
//
// So this mode collects them itself, into one tar.gz, and states in the bundle
// exactly what it put there. The bundle is deliberately NOT a dump of
// everything reachable: credentials never enter it, the environment never
// enters it, and the checkpoint's body -- which is megabytes of path hashes and
// says nothing a header does not -- never enters it either.
//
// Principal names are hashed by default. That is the one redaction that pays
// for itself: a spec's ACL lines are the part a customer is most likely to
// object to sharing, and the shape of the spec (how many ACEs, which flags,
// which permission letters, whether two rules name the SAME principal) is
// preserved exactly by a stable hash of each name. Paths are NOT redacted --
// an error log without paths cannot be diagnosed -- and the README says so, in
// those words, so the operator reviews before sending rather than discovering
// it afterwards.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// bundleTailLines is how much of an error log is carried. A log large enough to
// need trimming is a log whose interesting part is at the end: the run failed,
// and the failure is the last thing it said.
const bundleTailLines = 1000

// bundleInputs is everything the mode was told, resolved. Nothing in here is
// read at construction time, so a caller can build one from flags and hand it
// straight to writeSupportBundle.
type bundleInputs struct {
	SpecPath       string
	SummaryPath    string
	CheckpointPath string
	LogPath        string
	NoRedact       bool

	Version string
	Commit  string
	Date    string

	// procMounts and procVersion are the /proc files to read, overridable so a
	// test does not depend on the kernel it runs on.
	procMounts  string
	procVersion string
}

// bundleFile is one member of the archive, assembled in memory. Every member is
// small by construction -- the log is tailed and the checkpoint body is never
// read -- so there is no streaming case to handle.
type bundleFile struct {
	name string
	data []byte
}

// credentialName reports whether a path must never be copied into a bundle,
// whatever flag named it. The rule is on the name rather than the contents
// because a file called .fb-credentials is off limits even when it happens to
// be empty, and because a caller pointing --spec at a credential file is a
// mistake to refuse, not a file to inspect.
func credentialName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, frag := range []string{"credential", "password", "secret", ".netrc", "id_rsa", ".pem"} {
		if strings.Contains(base, frag) {
			return true
		}
	}
	return false
}

// redactor maps principal and identity names to stable placeholders within one
// bundle. A per-bundle random salt prevents cross-bundle correlation and
// dictionary attacks; within the bundle, the same name always produces the same
// placeholder so structural reasoning ("these two ACEs name the same principal")
// is preserved.
type redactor struct {
	salt [16]byte
}

func newRedactor() *redactor {
	r := &redactor{}
	if _, err := rand.Read(r.salt[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return r
}

func (r *redactor) token(name string) string {
	h := sha256.New()
	h.Write(r.salt[:])
	h.Write([]byte(name))
	return "user-" + hex.EncodeToString(h.Sum(nil)[:6])
}

// redactToken is the legacy unsalted form, kept only for tests that need a
// deterministic placeholder. Bundle collection uses redactor.token instead.
func redactToken(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "user-" + hex.EncodeToString(sum[:])[:6]
}

// wellKnownPrincipals are the NFSv4 special identities. They name no person and
// carry no information about the customer's directory, so hashing them would
// only make the spec unreadable -- an ACL whose subjects are all opaque cannot
// be reasoned about at all.
var wellKnownPrincipals = map[string]bool{
	"OWNER@":         true,
	"GROUP@":         true,
	"EVERYONE@":      true,
	"ANONYMOUS@":     true,
	"AUTHENTICATED@": true,
	"INTERACTIVE@":   true,
	"NETWORK@":       true,
	"DIALUP@":        true,
	"BATCH@":         true,
	"SERVICE@":       true,
}

var (
	// A YAML sequence item, with the value optionally quoted and an optional
	// trailing comment: "  - \"A::OWNER@:rwx\"  # note".
	reSeqItem = regexp.MustCompile(`^(\s*-\s+)(["']?)([^"'#]*?)(["']?)(\s*(?:#.*)?)$`)
	// A scalar mapping entry: "  owner: alice  # note".
	reMapEntry = regexp.MustCompile(`^(\s*)([A-Za-z_][A-Za-z0-9_-]*)(:\s+)(["']?)([^"'#]*?)(["']?)(\s*(?:#.*)?)$`)
)

// credentialKeys are spec keys whose value is a secret rather than a name. Their
// values are dropped outright rather than hashed: a hash of a password is still
// a fact about the password, and nothing in a bundle needs to correlate two
// occurrences of one.
var credentialKeys = map[string]bool{
	"credentials": true, "credential": true, "password": true, "passwd": true,
	"secret": true, "token": true, "api_key": true, "apikey": true, "key": true,
	"passphrase": true,
}

// identityKeys are spec keys whose value names a person or a group.
var identityKeys = map[string]bool{"owner": true, "group": true}

// redactSpec rewrites a spec's text so it can be shared, and reports what it
// changed.
//
// It works on the text rather than on a parsed Spec and a re-marshal, which
// would be the shorter implementation and the wrong one: comments are frequently
// the only record of WHY a rule exists, key order is how the author reads their
// own file, and a spec that failed to parse -- the case a support bundle is most
// often collected for -- has no parsed form to re-marshal at all.
func redactSpec(data []byte, r *redactor) (out []byte, notes []string) {
	var b strings.Builder
	principals := map[string]string{}
	identities := map[string]string{}
	creds := map[string]int{}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		if m := reMapEntry.FindStringSubmatch(line); m != nil {
			indent, key, sep, q1, val, q2, tail := m[1], m[2], m[3], m[4], m[5], m[6], m[7]
			lower := strings.ToLower(key)
			switch {
			case credentialKeys[lower] && strings.TrimSpace(val) != "":
				creds[lower]++
				b.WriteString(indent + key + sep + "<redacted>" + tail)
				continue
			case identityKeys[lower] && strings.TrimSpace(val) != "":
				name := strings.TrimSpace(val)
				tok := r.token(name)
				identities[tok] = lower
				b.WriteString(indent + key + sep + q1 + tok + q2 + tail)
				continue
			}
			b.WriteString(line)
			continue
		}
		if m := reSeqItem.FindStringSubmatch(line); m != nil {
			prefix, q1, val, q2, tail := m[1], m[2], m[3], m[4], m[5]
			if ace, name, ok := redactACEWith(val, r); ok {
				principals[strings.SplitN(ace, ":", 4)[2]] = name
				b.WriteString(prefix + q1 + ace + q2 + tail)
				continue
			}
			b.WriteString(line)
			continue
		}
		b.WriteString(line)
	}

	if n := len(principals); n > 0 {
		notes = append(notes, fmt.Sprintf("ACL/DACL principal names: %d distinct name(s) replaced with salted placeholders.", n))
	}
	if n := len(identities); n > 0 {
		notes = append(notes, fmt.Sprintf("owner/group values: %d distinct name(s) replaced with salted placeholders.", n))
	}
	if len(creds) > 0 {
		keys := make([]string, 0, len(creds))
		for k := range creds {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		notes = append(notes, fmt.Sprintf("credential-looking keys replaced with <redacted>: %s.", strings.Join(keys, ", ")))
	}
	return []byte(b.String()), notes
}

// redactACE rewrites the principal field of one ACE line, returning the rewrite,
// the original name, and whether the value looked like an ACE at all.
//
// "Looked like an ACE" is exactly four colon-separated fields. Anything else --
// a mode string, a glob, a plain word -- is left alone, because guessing wrong
// on a non-ACE line silently corrupts a spec the reader is trying to diagnose.
func redactACE(val string) (redacted, name string, ok bool) {
	v := strings.TrimSpace(val)
	parts := strings.Split(v, ":")
	if len(parts) != 4 {
		return "", "", false
	}
	name = parts[2]
	if name == "" || wellKnownPrincipals[strings.ToUpper(name)] {
		return "", "", false
	}
	parts[2] = redactToken(name)
	return strings.Join(parts, ":"), name, true
}

func redactACEWith(val string, r *redactor) (redacted, name string, ok bool) {
	v := strings.TrimSpace(val)
	parts := strings.Split(v, ":")
	if len(parts) != 4 {
		return "", "", false
	}
	name = parts[2]
	if name == "" || wellKnownPrincipals[strings.ToUpper(name)] {
		return "", "", false
	}
	parts[2] = r.token(name)
	return strings.Join(parts, ":"), name, true
}

// systemFacts describes the host, and only through files and the runtime -- no
// environment, no hostname, no network identity. Kernel version and the Go
// build are what actually explain a syscall behaving differently on one host
// than another; the rest is identifying information a bundle does not need.
func systemFacts(procVersion string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "go version:   %s\n", runtime.Version())
	fmt.Fprintf(&b, "GOOS/GOARCH:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "NumCPU:       %d\n", runtime.NumCPU())
	if procVersion != "" {
		if data, err := os.ReadFile(procVersion); err == nil {
			fmt.Fprintf(&b, "kernel:       %s\n", strings.TrimSpace(string(data)))
		} else {
			fmt.Fprintf(&b, "kernel:       unavailable (%v)\n", err)
		}
	}
	return b.String()
}

// nfsMounts filters a mount table down to the NFS lines. The full table names
// every filesystem on the host, most of which have nothing to do with the run
// and some of which name unrelated systems.
func nfsMounts(procMounts string) string {
	if procMounts == "" {
		return "mount table not collected\n"
	}
	data, err := os.ReadFile(procMounts)
	if err != nil {
		return fmt.Sprintf("mount table unavailable (%v)\n", err)
	}
	var b strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && (f[2] == "nfs" || f[2] == "nfs4") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		return "no nfs or nfs4 mounts present\n"
	}
	return b.String()
}

// checkpointMeta reads a checkpoint's header and size and says nothing else
// about it.
//
// The body is deliberately not read. It is one 16-byte path hash per completed
// directory -- tens of megabytes on a large tree -- and a reader learns nothing
// from the hashes that the count does not already tell them. The header is
// parsed here rather than through internal/checkpoint because opening a
// checkpoint through that package means resuming it: it truncates a partial
// trailing record and takes a write lock on a file that may belong to a run
// still in flight. A bundle must never modify what it collects.
func checkpointMeta(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	var hdr [48]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return "", fmt.Errorf("read header: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "path:          %s\n", path)
	fmt.Fprintf(&b, "size_bytes:    %d\n", info.Size())
	fmt.Fprintf(&b, "modified:      %s\n", info.ModTime().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "magic:         %q\n", string(hdr[0:4]))
	fmt.Fprintf(&b, "format_version: %d\n", binary.LittleEndian.Uint16(hdr[4:6]))
	fmt.Fprintf(&b, "flags:         %d\n", binary.LittleEndian.Uint16(hdr[6:8]))
	fmt.Fprintf(&b, "run_hash:      %s\n", hex.EncodeToString(hdr[8:40]))
	body := info.Size() - int64(len(hdr))
	if body < 0 {
		body = 0
	}
	fmt.Fprintf(&b, "completed_dirs: %d\n", body/16)
	if rem := body % 16; rem != 0 {
		fmt.Fprintf(&b, "partial_trailing_bytes: %d\n", rem)
	}
	b.WriteString("\nThe completed-directory records themselves are NOT included: they are\n")
	b.WriteString("128-bit path hashes, one per directory, and the count above is everything\n")
	b.WriteString("they say that a reader can act on.\n")
	return b.String(), nil
}

// tailFile returns the whole file, or its last n lines with a marker line if it
// was longer. The ring buffer bounds memory at n lines regardless of file size.
func tailFile(path string, n int) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	ring := make([]string, n)
	total := 0
	pos := 0
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := r.ReadString('\n')
		if line != "" || err == nil {
			ring[pos%n] = line
			pos++
			total++
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, false, err
		}
	}

	var b bytes.Buffer
	truncated := total > n
	if truncated {
		fmt.Fprintf(&b, "*** truncated: showing the last %d of %d lines ***\n", n, total)
	}
	count := total
	if count > n {
		count = n
	}
	for i := 0; i < count; i++ {
		b.WriteString(ring[(pos-count+i)%n])
	}
	return b.Bytes(), truncated, nil
}

// reACEInLine matches a 4-field colon-separated ACE embedded in a log line.
// It is intentionally generous — a false positive is a harmless placeholder,
// while a false negative leaks a principal name.
var reACEInLine = regexp.MustCompile(`\b([AD]):([a-z]*):([^:\s]+):([rwxdDaAtTnNcCoyepRWX]+)\b`)

// redactLogLine replaces principal names inside ACE strings embedded in a
// log line (e.g., "MISMATCH: /path want acl A::bob@domain:rwx").
func redactLogLine(line string, r *redactor) string {
	return reACEInLine.ReplaceAllStringFunc(line, func(m string) string {
		parts := strings.SplitN(m, ":", 4)
		if len(parts) != 4 {
			return m
		}
		name := parts[2]
		if name == "" || wellKnownPrincipals[strings.ToUpper(name)] {
			return m
		}
		parts[2] = r.token(name)
		return strings.Join(parts, ":")
	})
}

// redactLog redacts all ACE principal names in a log's contents.
func redactLog(data []byte, r *redactor) []byte {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		lines[i] = redactLogLine(line, r)
	}
	return []byte(strings.Join(lines, "\n"))
}

// collectBundle assembles every member of the archive plus the README that
// explains what is and is not there. It touches the filesystem but writes
// nothing, which is what makes it testable without a tar reader.
func collectBundle(in bundleInputs) ([]bundleFile, error) {
	var files []bundleFile
	var included []string
	var skipped []string
	var redactions []string

	r := newRedactor()

	add := func(name string, data []byte) {
		files = append(files, bundleFile{name: "bundle/" + name, data: data})
		included = append(included, name)
	}

	version := fmt.Sprintf("permissionreset %s\ncommit: %s\nbuilt:  %s\n", in.Version, in.Commit, in.Date)
	add("version.txt", []byte(version))
	add("system.txt", []byte(systemFacts(in.procVersion)+"\nNFS mounts:\n"+nfsMounts(in.procMounts)))

	// Spec.
	switch {
	case in.SpecPath == "":
		skipped = append(skipped, "spec.yaml — no --spec given")
	case credentialName(in.SpecPath):
		skipped = append(skipped, "spec.yaml — refused: "+filepath.Base(in.SpecPath)+" looks like a credential file")
	default:
		data, err := os.ReadFile(in.SpecPath)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("spec.yaml — unreadable: %v", err))
			break
		}
		header := fmt.Sprintf("# source: %s\n", in.SpecPath)
		if in.NoRedact {
			add("spec.yaml", append([]byte(header), data...))
		} else {
			red, notes := redactSpec(data, r)
			redactions = append(redactions, notes...)
			add("spec.yaml", append([]byte(header+"# principal names redacted; see REDACTIONS.txt\n"), red...))
		}
	}

	// JSON summary. Copied verbatim: it holds no principal names, and its
	// digests and counts are the point of collecting it.
	addOptional := func(flagName, member, path string) {
		if path == "" {
			skipped = append(skipped, member+" — no "+flagName+" given")
			return
		}
		if credentialName(path) {
			skipped = append(skipped, member+" — refused: "+filepath.Base(path)+" looks like a credential file")
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s — unreadable: %v", member, err))
			return
		}
		add(member, data)
	}
	addOptional("--json-summary", "summary.json", in.SummaryPath)

	// Checkpoint metadata.
	switch {
	case in.CheckpointPath == "":
		skipped = append(skipped, "checkpoint-meta.txt — no --checkpoint given")
	default:
		meta, err := checkpointMeta(in.CheckpointPath)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("checkpoint-meta.txt — unreadable: %v", err))
			break
		}
		add("checkpoint-meta.txt", []byte(meta))
	}

	// Error log, tailed.
	logTruncated := false
	switch {
	case in.LogPath == "":
		skipped = append(skipped, "errors.log — no --log given")
	case credentialName(in.LogPath):
		skipped = append(skipped, "errors.log — refused: "+filepath.Base(in.LogPath)+" looks like a credential file")
	default:
		data, truncated, err := tailFile(in.LogPath, bundleTailLines)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("errors.log — unreadable: %v", err))
			break
		}
		logTruncated = truncated
		if !in.NoRedact {
			data = redactLog(data, r)
			redactions = append(redactions, "ACE principal names in errors.log replaced with salted placeholders.")
		}
		add("errors.log", data)
	}

	files = append(files, bundleFile{name: "bundle/README.txt", data: []byte(bundleREADME(in, included, skipped, logTruncated))})
	files = append(files, bundleFile{name: "bundle/REDACTIONS.txt", data: []byte(bundleRedactions(in, redactions))})
	return files, nil
}

func bundleREADME(in bundleInputs, included, skipped []string, logTruncated bool) string {
	var b strings.Builder
	b.WriteString("permissionreset support bundle\n")
	b.WriteString("=========================\n\n")
	fmt.Fprintf(&b, "collected: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "tool:      permissionreset %s (%s)\n\n", in.Version, in.Commit)

	b.WriteString("Contents\n--------\n")
	sort.Strings(included)
	for _, n := range included {
		fmt.Fprintf(&b, "  %s\n", n)
	}
	if len(skipped) > 0 {
		b.WriteString("\nNot included\n------------\n")
		for _, n := range skipped {
			fmt.Fprintf(&b, "  %s\n", n)
		}
	}

	b.WriteString("\nBefore you send this\n--------------------\n")
	b.WriteString("FILESYSTEM PATHS ARE PRESENT in errors.log, summary.json, version/system\n")
	b.WriteString("notes and the spec header. They are kept deliberately: an error that names\n")
	b.WriteString("no path cannot be diagnosed. Review those files if directory names in your\n")
	b.WriteString("tree are themselves sensitive.\n\n")
	if in.NoRedact {
		b.WriteString("This bundle was collected with --no-redact: principal and owner/group names\n")
		b.WriteString("appear verbatim in spec.yaml.\n\n")
	} else {
		b.WriteString("Principal and owner/group names in spec.yaml were replaced with stable\n")
		b.WriteString("placeholders. See REDACTIONS.txt.\n\n")
	}
	if logTruncated {
		fmt.Fprintf(&b, "errors.log holds only the last %d lines of the source log; the marker at\n"+
			"the top of the file records the original line count.\n\n", bundleTailLines)
	}

	b.WriteString("Never collected\n---------------\n")
	b.WriteString("  - credential files (any path whose name suggests one is refused, and the\n")
	b.WriteString("    refusal is listed above rather than passed over in silence)\n")
	b.WriteString("  - environment variables\n")
	b.WriteString("  - the checkpoint body (only its header and record count are included)\n")
	return b.String()
}

func bundleRedactions(in bundleInputs, notes []string) string {
	var b strings.Builder
	b.WriteString("Redactions\n==========\n\n")
	if in.NoRedact {
		b.WriteString("--no-redact was passed: nothing was redacted. spec.yaml is verbatim.\n")
		return b.String()
	}
	if len(notes) == 0 {
		b.WriteString("Redaction was enabled, but nothing in the collected files needed it.\n\n")
	} else {
		b.WriteString("What was changed:\n")
		for _, n := range notes {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
		b.WriteString("\n")
	}
	b.WriteString("How to read a placeholder\n-------------------------\n")
	b.WriteString("A placeholder is user- followed by 12 hex digits of a salted SHA-256 of the\n")
	b.WriteString("original name. A random per-bundle salt prevents reversing the hash by\n")
	b.WriteString("dictionary; the salt is not included in the bundle.\n\n")
	b.WriteString("Within THIS bundle the mapping is stable: the SAME placeholder always means\n")
	b.WriteString("the SAME identity, so two ACEs naming user-a1b2c3d4e5f6 name one principal,\n")
	b.WriteString("and two different placeholders name two identities. Across bundles the same\n")
	b.WriteString("name produces different placeholders (different salt).\n\n")
	b.WriteString("What is redacted\n----------------\n")
	b.WriteString("  - Principal names in ACE strings (spec.yaml AND errors.log)\n")
	b.WriteString("  - owner/group identity values in the spec\n")
	b.WriteString("  - Credential-looking keys (dropped entirely, not hashed)\n\n")
	b.WriteString("What is NOT redacted\n--------------------\n")
	b.WriteString("  - Filesystem paths (kept deliberately; see README.txt)\n")
	b.WriteString("  - ACE flags, permission letters, ordering, and rule structure\n")
	b.WriteString("  - summary.json counts, digests, and option values\n")
	b.WriteString("  - System facts (kernel version, Go version, mount table)\n")
	return b.String()
}

// writeSupportBundle collects the bundle and writes it as a gzipped tar to path.
func writeSupportBundle(in bundleInputs, path string) error {
	if in.procMounts == "" {
		in.procMounts = "/proc/mounts"
	}
	if in.procVersion == "" {
		in.procVersion = "/proc/version"
	}
	files, err := collectBundle(in)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create bundle %s: %w", path, err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	now := time.Now()
	for _, bf := range files {
		hdr := &tar.Header{
			Name:     bf.name,
			Mode:     0o644,
			Size:     int64(len(bf.data)),
			ModTime:  now,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header %s: %w", bf.name, err)
		}
		if _, err := tw.Write(bf.data); err != nil {
			return fmt.Errorf("write tar body %s: %w", bf.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync bundle: %w", err)
	}
	return nil
}
