// Package tuning persists transport settings measured for an exact set of
// clients and an exact NFS target.
package tuning

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const Version = 1
const FileName = "permissionreset-tuning.yaml"

// Key identifies one measured configuration. The client side is a set of hosts,
// because a result belongs to the machines that produced it together. Build one
// only through NewKey, which sorts and dedupes; a Key holding an unsorted Clients
// slice compares unequal to the same set and silently misses a lookup.
//
// Key therefore contains a slice and is not comparable with == and is not usable
// as a map key. Compare with Equal, index with String.
type Key struct {
	Clients                   []string
	Server, Export, Transport string
}

// NewKey canonicalizes the client set and export path.
func NewKey(clients []string, server, export, transport string) (Key, error) {
	if len(clients) == 0 {
		return Key{}, fmt.Errorf("tuning key needs at least one client")
	}
	seen := make(map[string]struct{}, len(clients))
	canon := make([]string, 0, len(clients))
	for _, c := range clients {
		if c == "" {
			return Key{}, fmt.Errorf("tuning key has an empty client name")
		}
		if strings.ContainsAny(c, ",@") {
			return Key{}, fmt.Errorf("tuning key client name %q contains a reserved delimiter", c)
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		canon = append(canon, c)
	}
	sort.Strings(canon)
	if server == "" || export == "" || transport == "" {
		return Key{}, fmt.Errorf("tuning key needs server, export and transport")
	}
	if transport != "kernel" && transport != "userspace" {
		return Key{}, fmt.Errorf("tuning key transport must be kernel or userspace")
	}
	return Key{Clients: canon, Server: server, Export: filepath.Clean(export), Transport: transport}, nil
}

// Equal reports exact set equality, not client membership. Both keys must have
// been built with NewKey so their Clients slices are canonical; invalid keys are
// never equal, including two zero Keys produced by failed construction.
func (k Key) Equal(other Key) bool {
	if !validKey(k) || !validKey(other) {
		return false
	}
	if len(k.Clients) != len(other.Clients) {
		return false
	}
	for i := range k.Clients {
		if k.Clients[i] != other.Clients[i] {
			return false
		}
	}
	return k.Server == other.Server && k.Export == other.Export && k.Transport == other.Transport
}

// String renders the canonical key for announcements or string-keyed indexes.
func (k Key) String() string {
	return strings.Join(k.Clients, ",") + "@" + k.Server + ":" + k.Export + "/" + k.Transport
}

// Params are PER-CLIENT values, never cluster totals. Four clients at
// Connections 32 produce 128 connections at the array.
type Params struct {
	Connections       int `yaml:"connections"`
	Slots             int `yaml:"slots"`
	Workers           int `yaml:"workers"`
	BatchSize         int `yaml:"batch_size"`
	MaxOpsPerCompound int `yaml:"max_ops_per_compound"`
}

func (p *Params) UnmarshalYAML(node *yaml.Node) error {
	// This guard is narrower than it looks: an absent or null params -- "params:",
	// "params: ~", "params: {}" -- never reaches here at all, because yaml.v3
	// leaves the field zero without calling the unmarshaler. The resulting zero
	// Params is discarded later by the command's absent-or-zero check. So what
	// this rejects is a scalar or a sequence written where a mapping belongs.
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("tuning params must be a mapping")
	}
	fields := map[string]struct{}{
		"connections": {}, "slots": {}, "workers": {},
		"batch_size": {}, "max_ops_per_compound": {},
	}
	for i := 0; i < len(node.Content); i += 2 {
		name := node.Content[i].Value
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("tuning params has unknown field %q", name)
		}
		if err := checkPlainInteger(name, node.Content[i+1]); err != nil {
			return err
		}
	}
	type plainParams Params
	var decoded plainParams
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*p = Params(decoded)
	return nil
}

// checkPlainInteger requires a parameter to be written as a plain base-10
// integer, reading the literal text rather than the resolved YAML tag.
//
// The tag is not enough, because !!int is not only decimal: YAML resolves 0x20
// as 32, 0o17 as 15, 1_000 as 1000, and the zero-padded 0100 as octal 64. A tag
// comparison accepts every one of them, so the value used is not the number
// written in the file -- and permissionreset announces the values it applied, which is
// the only thing that makes an applied tuning auditable. An announcement reading
// "workers=64" for a file saying "workers: 0100" asserts something the operator
// never wrote. Requiring the literal to render back to itself is what keeps the
// announcement and the file identical.
//
// An alias is rejected here too, and named as one. An alias node carries no tag
// of its own, so the previous tag-based message rendered as a dangling "got "
// with nothing after it.
func checkPlainInteger(name string, value *yaml.Node) error {
	const quotedStyles = yaml.SingleQuotedStyle | yaml.DoubleQuotedStyle | yaml.LiteralStyle | yaml.FoldedStyle
	if value.Kind != yaml.ScalarNode || value.Style&quotedStyles != 0 {
		return fmt.Errorf("tuning param %s must be a plain base-10 integer, got %s", name, describeParam(value))
	}
	// Base 10 and the canonical-rendering check below overlap on purpose. Base 10
	// alone would still accept 0100, which parses here as 100 and decodes in YAML
	// as 64; the rendering check alone would reject 0x20 with a less specific
	// message. Neither leaves a hole in the outcome, so mutating the base is not
	// observable -- the rendering check is the load-bearing half.
	n, err := strconv.ParseInt(value.Value, 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return fmt.Errorf("tuning param %s is out of range for a 64-bit integer, got %s", name, describeParam(value))
		}
		return fmt.Errorf("tuning param %s must be a plain base-10 integer, got %s", name, describeParam(value))
	}
	if strconv.FormatInt(n, 10) != value.Value {
		return fmt.Errorf("tuning param %s must be a plain base-10 integer without leading zeros or a sign, got %s", name, describeParam(value))
	}
	return nil
}

// describeParam renders a rejected parameter value for an operator. It never
// returns the empty string: the message it feeds ends in "got %s", and a null,
// an alias, or a collection would otherwise leave that sentence unfinished.
func describeParam(value *yaml.Node) string {
	switch value.Kind {
	case yaml.AliasNode:
		return fmt.Sprintf("a YAML alias to %q", value.Value)
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a sequence"
	}
	const quotedStyles = yaml.SingleQuotedStyle | yaml.DoubleQuotedStyle | yaml.LiteralStyle | yaml.FoldedStyle
	if value.Style&quotedStyles != 0 {
		return fmt.Sprintf("the quoted string %q", value.Value)
	}
	if value.Value == "" {
		return "an empty value"
	}
	return fmt.Sprintf("%q", value.Value)
}

// ClientMeasurement is one host's share of a trial. A list, not averaged
// fields: with several clients the actionable fact is which host saturated,
// and an average erases one pinned machine among several idle ones.
type ClientMeasurement struct {
	Client        string  `yaml:"client"`
	CPUPct        float64 `yaml:"cpu_pct"`
	CPUUserPct    float64 `yaml:"cpu_user_pct"`
	CPUSysPct     float64 `yaml:"cpu_sys_pct"`
	CPUSoftirqPct float64 `yaml:"cpu_softirq_pct"`
	RlimitNofile  uint64  `yaml:"rlimit_nofile"`
	Bound         bool    `yaml:"bound"`
}

type Measured struct {
	OpsPerSec         float64             `yaml:"ops_per_sec"`
	BaselineOpsPerSec float64             `yaml:"baseline_ops_per_sec"`
	TrialFiles        int64               `yaml:"trial_files"`
	Confidence        string              `yaml:"confidence"`
	ClientBound       bool                `yaml:"client_bound"`
	SweptAt           time.Time           `yaml:"swept_at"`
	SweepCommit       string              `yaml:"sweep_commit"`
	PerClient         []ClientMeasurement `yaml:"per_client,omitempty"`
}

// Entry stores a tuning measured for its exact client set and target. Clients
// is a list from the first file version so widening beyond today's singleton
// entries never requires reinterpreting an older scalar value.
type Entry struct {
	Clients   []string `yaml:"clients"`
	Server    string   `yaml:"server"`
	Export    string   `yaml:"export"`
	Transport string   `yaml:"transport"`
	// Params are PER-CLIENT values, never cluster totals: four clients at
	// Connections 32 means 128 connections at the array.
	Params   Params   `yaml:"params"`
	Measured Measured `yaml:"measured"`
}

// Key returns the entry's canonical identity. An invalid entry returns a zero
// key, which cannot equal a valid key built through NewKey.
func (e Entry) Key() Key {
	k, err := NewKey(e.Clients, e.Server, e.Export, e.Transport)
	if err != nil {
		return Key{}
	}
	return k
}

type File struct {
	Version int     `yaml:"version"`
	Tunings []Entry `yaml:"tunings"`
}

// PathForExecutable returns the tuning file beside executable.
func PathForExecutable(executable string) string {
	return filepath.Join(filepath.Dir(executable), FileName)
}

// DefaultPath returns the tuning file beside the running executable.
func DefaultPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find executable: %w", err)
	}
	return PathForExecutable(executable), nil
}

// Load reads and strictly validates a versioned tuning file.
func Load(path string) (File, error) {
	if _, err := os.Lstat(path); err != nil {
		return File{}, fmt.Errorf("inspect tuning file: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		// Lstat succeeded, so ENOENT here means a configured but dangling
		// symlink, not an absent tuning path. Keep it out of the os.ErrNotExist
		// chain so callers warn instead of classifying it as ordinary absence.
		return File{}, fmt.Errorf("inspect tuning file target: %v", err)
	}
	if !info.Mode().IsRegular() {
		return File{}, fmt.Errorf("inspect tuning file: %s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		// Lstat established that the path was configured. Do not preserve a
		// later ENOENT through a rename race as ordinary "never configured".
		//
		// %v, deliberately, and deliberately without a test. Every Open failure
		// reachable after a successful Stat and IsRegular is EACCES, which is not
		// in the os.ErrNotExist chain either way, so no test can tell %v from %w
		// here without staging a filesystem race inside Load. This is defence in
		// depth for the unreachable case, not decoration: the shape it guards
		// against -- a configured-but-broken tuning path classified as absence and
		// going silent -- is real, and is pinned one branch up at the Stat site,
		// whose %v a test does hold in place. Do not "simplify" either to %w.
		return File{}, fmt.Errorf("open tuning file: %v", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var file File
	if err := dec.Decode(&file); err != nil {
		return File{}, fmt.Errorf("decode tuning file: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return File{}, fmt.Errorf("decode tuning file: multiple YAML documents")
		}
		return File{}, fmt.Errorf("decode tuning file: %w", err)
	}
	if err := validateVersion(file.Version); err != nil {
		return File{}, err
	}
	if err := canonicalizeEntries(file.Tunings); err != nil {
		return File{}, err
	}
	return file, nil
}

// Save atomically replaces path with file using a synchronized sibling file.
func Save(path string, file File) error {
	file, err := canonicalFile(file)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temporary tuning file: %w", err)
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	enc := yaml.NewEncoder(tmp)
	if err := enc.Encode(file); err != nil {
		_ = enc.Close()
		return fmt.Errorf("encode tuning file: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("finish tuning file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary tuning file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary tuning file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return fmt.Errorf("set tuning file permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace tuning file: %w", err)
	}
	keep = true
	return nil
}

// Lookup finds the entry measured for exactly key.
func (f File) Lookup(key Key) (Entry, bool) {
	if !validKey(key) {
		return Entry{}, false
	}
	for _, entry := range f.Tunings {
		entryKey := entry.Key()
		if validKey(entryKey) && entryKey.Equal(key) {
			return cloneEntry(entry), true
		}
	}
	return Entry{}, false
}

// Upsert replaces an exact key in place or appends a new key.
func (f *File) Upsert(entry Entry) {
	key := entry.Key()
	if validKey(key) {
		for i := range f.Tunings {
			entryKey := f.Tunings[i].Key()
			if validKey(entryKey) && entryKey.Equal(key) {
				f.Tunings[i] = cloneEntry(entry)
				return
			}
		}
	}
	f.Tunings = append(f.Tunings, cloneEntry(entry))
}

func cloneEntry(entry Entry) Entry {
	entry.Clients = append([]string(nil), entry.Clients...)
	entry.Measured.PerClient = append([]ClientMeasurement(nil), entry.Measured.PerClient...)
	return entry
}

func validKey(key Key) bool {
	if len(key.Clients) == 0 || key.Server == "" || key.Export == "" {
		return false
	}
	validTransport := key.Transport == "kernel" || key.Transport == "userspace"
	if !validTransport || !sort.StringsAreSorted(key.Clients) {
		return false
	}
	for i, client := range key.Clients {
		empty := client == ""
		badChar := strings.ContainsAny(client, ",@")
		duplicate := i > 0 && client == key.Clients[i-1]
		if empty || badChar || duplicate {
			return false
		}
	}
	return key.Export == filepath.Clean(key.Export)
}

// canonicalizeEntries builds a canonical Key for each entry, checks for
// duplicates, and writes the canonical fields back. Used by both Load and Save.
func canonicalizeEntries(tunings []Entry) error {
	seen := make(map[string]struct{}, len(tunings))
	for i := range tunings {
		entry := &tunings[i]
		key, err := NewKey(entry.Clients, entry.Server, entry.Export, entry.Transport)
		if err != nil {
			return fmt.Errorf("tuning %d: %w", i, err)
		}
		if _, duplicate := seen[key.String()]; duplicate {
			return fmt.Errorf("tuning %d duplicates key %s", i, key.String())
		}
		seen[key.String()] = struct{}{}
		entry.Clients = key.Clients
		entry.Server = key.Server
		entry.Export = key.Export
		entry.Transport = key.Transport
	}
	return nil
}

func canonicalFile(file File) (File, error) {
	if err := validateVersion(file.Version); err != nil {
		return File{}, err
	}
	file.Tunings = append([]Entry(nil), file.Tunings...)
	if err := canonicalizeEntries(file.Tunings); err != nil {
		return File{}, err
	}
	return file, nil
}

func validateVersion(version int) error {
	if version != Version {
		return fmt.Errorf("unsupported tuning file version %d; want %d", version, Version)
	}
	return nil
}
