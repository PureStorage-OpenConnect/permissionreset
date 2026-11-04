package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
)

// documentedCommands returns every build-spec invocation in the fenced code
// blocks of a Markdown file, with shell (\) and PowerShell (`) continuations
// joined and the program name dropped.
func documentedCommands(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var cmds [][]string
	var cur []string
	inFence, inCmd := false, false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "```") {
			inFence, inCmd, cur = !inFence, false, nil
			continue
		}
		if !inFence {
			continue
		}
		if !inCmd {
			fields := strings.Fields(line)
			if len(fields) == 0 || (fields[0] != "build-spec" && fields[0] != `.\build-spec.exe`) {
				continue
			}
			inCmd, cur, line = true, nil, strings.Join(fields[1:], " ")
		}
		more := strings.HasSuffix(line, `\`) || strings.HasSuffix(line, "`")
		line = strings.TrimRight(line, "\\` ")
		cur = append(cur, strings.Fields(line)...)
		if !more {
			cmds = append(cmds, cur)
			inCmd, cur = false, nil
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return cmds
}

// TestDocumentedCaptureCommandsRun runs each build-spec command published in
// README.md, INSTALL.md and the getting-started guide, verbatim except that --output is redirected to
// stdout, against fake transports. It proves the documented flag order parses,
// the audit-bypass proof runs before the read, and a spec comes out.
func TestDocumentedCaptureCommandsRun(t *testing.T) {
	for doc, min := range map[string]int{"README.md": 3, "INSTALL.md": 3, "docs/field-preview/getting-started.md": 2} {
		cmds := documentedCommands(t, filepath.Join("..", "..", doc))
		if len(cmds) < min {
			t.Fatalf("%s: found %d build-spec commands, want at least %d", doc, len(cmds), min)
		}
		for _, args := range cmds {
			args := append([]string(nil), args...)
			t.Run(doc+"/"+strings.Join(args, " "), func(t *testing.T) {
				if len(args) < 2 {
					t.Fatalf("command has no DIRECTORY FILE: %q", args)
				}
				sawOutput := false
				userspace := false
				for i, a := range args {
					switch a {
					case "--output":
						if i+1 < len(args) {
							args[i+1] = "-"
							sawOutput = true
						}
					case "--server":
						userspace = true
					}
				}
				if !sawOutput {
					t.Fatalf("documented command has no --output: %q", args)
				}
				dirPath, filePath := args[len(args)-2], args[len(args)-1]

				old := caps
				defer func() { caps = old }()
				var d deps
				if userspace {
					// The userspace examples are for macOS and Windows, where it
					// is the default transport.
					caps = platform.Darwin()
					d = fakeDepsWithUserspace(dirPath, filePath, nil, t)
				} else {
					caps = platform.Linux()
					d = fakeDepsWithKernel(dirPath, filePath, "/mnt/fb", t)
				}

				var out, errBuf bytes.Buffer
				if code := run(args, &out, &errBuf, d); code != 0 {
					t.Fatalf("exit %d; stderr:\n%s", code, errBuf.String())
				}
				if !strings.Contains(out.String(), "protocol: nfsv4") {
					t.Errorf("stdout missing spec YAML:\n%s", out.String())
				}
				if strings.Contains(errBuf.String(), "no audit-bypass proof") {
					t.Errorf("documented command read without the audit-bypass proof:\n%s", errBuf.String())
				}
				if !strings.Contains(errBuf.String(), "ACL identity") {
					t.Errorf("stderr missing the identity report:\n%s", errBuf.String())
				}
			})
		}
	}
}
