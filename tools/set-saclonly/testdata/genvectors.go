//go:build ignore

// genvectors writes glob-vectors.json: Go's answer for pattern x name, so the Pester tests can
// check that GoGlob (SaclOnly.cs) matches the way internal/spec does. internal/spec calls
// filepath.Match, which on Linux is path.Match.
//
//	go run tools/set-saclonly/testdata/genvectors.go > tools/set-saclonly/testdata/glob-vectors.json
package main

import (
	"encoding/json"
	"os"
	"path"
)

func main() {
	patterns := []string{
		"", "*", "**x", "?", "??", "a*", "*.tmp", "*.TMP", "a*b", "a*b*c", "*x*", "a?c", "audit*",
		".snapshot", ".*", "[abc]", "[a-c]x", "[^a-c]x", "[]]", "[a-]", `[\]]`, `[\-]`, `\*`, `a\?`,
		`x\`, "[", "[a", "[a-", "[]", "[^]", "a[", "logs/*.gz", "logs/*", "*/b", "a/*/c", "*/*",
		"日本*", "?本", "[日-語]", "\U0001F600*", "?",
	}
	names := []string{
		"", "a", "b", "x", "ab", "abc", "abbc", "abxbc", "ac", "a.tmp", "A.TMP", "a.tmpx", ".tmp",
		"audit", "audit-2026", "Audit", ".snapshot", "snapshot", ".hidden", "ax", "bx", "dx", "]", "-",
		"*", "a?", "a", "logs/old.gz", "logs/a/old.gz", "logs/", "a/b", "a/b/c", "a/x/c", "x/b",
		"日本語", "本", "語x", "\U0001F600.txt", "\U0001F600", "a/",
	}
	type vec struct {
		Pattern string `json:"pattern"`
		Name    string `json:"name"`
		Match   bool   `json:"match"`
	}
	var out []vec
	for _, p := range patterns {
		for _, n := range names {
			ok, _ := path.Match(p, n)
			out = append(out, vec{p, n, ok})
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	enc.SetEscapeHTML(false)
	enc.Encode(out)
}
