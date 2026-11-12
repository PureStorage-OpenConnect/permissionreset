package nfs41

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGateMethodStaysOutOfTheDocs: documentation and other tracked non-source
// files may say the userspace transport is gated to FlashBlade, but not what
// the gate reads. That lives only in the Go source (client.go). The check
// normalizes case, spaces, hyphens, underscores and Markdown emphasis, so
// "max file size", "max-file-size" and the attribute's XDR name all match.
func TestGateMethodStaysOutOfTheDocs(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		t.Skipf("git ls-files unavailable: %v", err)
	}
	leaks := []string{"maxfilesize", "70368744177664"}
	norm := strings.NewReplacer(" ", "", "-", "", "_", "", "\n", "", "\t", "", "`", "", "*", "")
	for _, rel := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// Source is where the method is meant to live: Go files and the XDR
		// protocol definition the generated code comes from.
		if strings.HasSuffix(rel, ".go") || strings.HasPrefix(rel, "internal/nfs41/xdr/") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // deleted in the working tree, or not a regular file
		}
		text := strings.ToLower(norm.Replace(string(b)))
		for _, leak := range leaks {
			if strings.Contains(text, leak) {
				t.Errorf("%s mentions the server gate's method (%q); keep it in the Go source only", rel, leak)
			}
		}
	}
}
