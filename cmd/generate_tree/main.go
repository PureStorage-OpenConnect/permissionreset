package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/treegen"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

// version, commit and date are set with -ldflags -X, as they are for the other binaries.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// genTreeFlags holds every flag this command registers, plus the gate that
// decides which of them this build will honour.
type genTreeFlags struct {
	principals      *string
	scale           *string
	workers         *int
	beastMode       *bool
	seed            *int64
	aclsOnly        *bool
	noACLs          *bool
	dryRun          *bool
	safetyPrincipal *string
	filesPerSubtree *int
	copies          *int
	seedFiles       *int
	maxDepth        *int
	transport       *string
	server          *string
	export          *string
	showVersion     *bool
	connections     *int
	manifestPath    *string

	auth *cmdflags.AuthFlags
	gate *cmdflags.Gate
}

// registerGenTreeFlags is split out of run so the flag-classification test can
// enumerate the flag set without executing the command.
func registerGenTreeFlags(fs *flag.FlagSet, errOut io.Writer) (*flag.FlagSet, *genTreeFlags) {
	f := &genTreeFlags{gate: &cmdflags.Gate{OS: caps.OS, Arch: runtime.GOARCH}}

	f.principals = fs.String("principals", "", "JSON roster mapping roles to NFS principal names (required)")
	f.scale = fs.String("scale", "small", "Tree size: small, medium, large, xlarge, huge, colossal")
	f.workers = fs.Int("workers", 128, "Concurrent goroutines for fan-out and ACL stamping")
	f.beastMode = fs.Bool("beastmode", false, "Auto-tune workers for maximum NFS throughput")
	f.seed = fs.Int64("seed", 42, "Random seed")
	f.aclsOnly = fs.Bool("acls-only", false, "Skip tree creation; stamp ACLs on an existing tree")
	f.noACLs = fs.Bool("no-acls", false, "Build the tree but do not stamp ACLs")
	f.dryRun = fs.Bool("dry-run", false, "Print plan without changing anything")
	f.safetyPrincipal = fs.String("safety-principal", "", "Override safety ACE principal (default: detect from current user)")
	f.filesPerSubtree = fs.Int("files-per-subtree", 4, "Explicit-ACE file outliers per project subtree")
	f.copies = fs.Int("copies", 0, "Override copy count from scale")
	f.seedFiles = fs.Int("seed-files", 0, "Override seed file count from scale")
	f.maxDepth = fs.Int("max-depth", 0, "Override max depth from scale")

	// Registered by value, not by presence: --transport=userspace is exactly
	// the value that works where the kernel transport does not, so the flag
	// stays visible and keeps its usage string. Only the value is refused.
	f.transport = fs.String("transport", defaultGenTreeTransport(), "Transport: kernel or userspace")
	f.gate.Value("transport", "kernel", cmdflags.KernelTransport(caps))

	f.server = fs.String("server", "", "NFS server hostname (userspace transport)")
	f.export = fs.String("export", "", "NFS export path (userspace transport)")
	f.showVersion = fs.Bool("version", false, "print version and exit")
	f.connections = fs.Int("connections", 8, "TCP connections to server (userspace transport)")
	f.manifestPath = fs.String("manifest", "", "Local path for acl_manifest.json (default: beside TARGET, or ./acl_manifest.json when TARGET is not local)")

	f.auth = cmdflags.RegisterAuth(fs, func(s string) string { return s + " (--transport=userspace only)" })

	fs.Usage = func() {
		fmt.Fprintf(errOut, "Usage: generate-tree [flags] TARGET\n\n")
		fmt.Fprintf(errOut, "Generate a test file tree with named-principal NFSv4 ACLs.\n\n")
		// A gated flag is hidden by blanking its usage string, so skip those.
		fs.VisitAll(func(fl *flag.Flag) {
			if fl.Usage == "" {
				return
			}
			// UnquoteUsage recovers the type name flag.PrintDefaults would
			// have printed; without it -workers loses its "int".
			typeName, usage := flag.UnquoteUsage(fl)
			if typeName != "" {
				typeName = " " + typeName
			}
			fmt.Fprintf(errOut, "  -%s%s\n    \t%s", fl.Name, typeName, usage)
			if fl.DefValue != "" && fl.DefValue != "false" && fl.DefValue != "0" {
				fmt.Fprintf(errOut, " (default %s)", fl.DefValue)
			}
			fmt.Fprintln(errOut)
		})
	}
	return fs, f
}

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("generate-tree", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs, f := registerGenTreeFlags(fs, errOut)

	if err := fs.Parse(args); err != nil {
		// flag.ErrHelp included: --help is not an error, but it is not a run
		// either, and 2 is what an unparseable command line has always been.
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if *f.showVersion {
		fmt.Fprintf(out, "generate-tree %s (%s) built %s\n", version, commit, date)
		return 0
	}

	explicit := tuning.Explicit(fs)
	if f.gate.Reject(explicit, map[string]string{"transport": *f.transport}, errOut) {
		return 1
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return 1
	}
	target := fs.Arg(0)

	if *f.principals == "" {
		fmt.Fprintf(errOut, "ERROR: --principals is required\n")
		return 1
	}

	data, err := os.ReadFile(*f.principals)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: reading principals: %v\n", err)
		return 1
	}
	var roster treegen.Roster
	if err := json.Unmarshal(data, &roster); err != nil {
		fmt.Fprintf(errOut, "ERROR: parsing principals: %v\n", err)
		return 1
	}
	if roster.Domain == "" || len(roster.Roles) == 0 {
		fmt.Fprintf(errOut, "ERROR: principals must have 'domain' and 'roles'\n")
		return 1
	}

	s, ok := treegen.Scales[*f.scale]
	if !ok {
		fmt.Fprintf(errOut, "ERROR: unknown scale %q (small, medium, large, xlarge, huge, colossal)\n", *f.scale)
		return 1
	}
	if *f.copies > 0 {
		s.Copies = *f.copies
	}
	if *f.seedFiles > 0 {
		s.SeedFiles = *f.seedFiles
	}
	if *f.maxDepth > 0 {
		s.MaxDepth = *f.maxDepth
	}

	// Transport-dependent argument checks sit after the roster and the scale so
	// that a bad --scale or an unreadable --principals still reports itself as
	// what it is. On macOS the default transport is userspace, so anything
	// checked ahead of these would answer every one of those invocations with a
	// transport complaint instead.
	if *f.transport == "userspace" {
		// A dry run prints the plan and returns before it would connect, so it
		// has no server to name.
		if !*f.dryRun && (*f.server == "" || *f.export == "") {
			fmt.Fprintf(errOut, "ERROR: --server and --export are required with --transport=userspace\n")
			return 1
		}
		// Both of these reach only the kernel code paths -- a local setxattr of
		// system.nfs4_acl, and a fan-out that copies through a mount. Neither
		// exists on a host that has to use the userspace transport, and running
		// them anyway builds the tree in the wrong place or fails at the first
		// xattr. Refuse rather than silently ignore the transport.
		if *f.aclsOnly || *f.noACLs {
			which := "--acls-only"
			if *f.noACLs {
				which = "--no-acls"
			}
			fmt.Fprintf(errOut, "ERROR: %s is not supported with --transport=userspace: "+
				"it runs through the kernel transport, which needs a local NFSv4 mount "+
				"and the system.nfs4_acl extended attribute\n", which)
			return 1
		}
	}

	workers := *f.workers
	if *f.beastMode {
		workers = runtime.NumCPU() * 3
		fmt.Fprintf(errOut, "Beast mode: %d workers (%d CPUs x 3)\n", workers, runtime.NumCPU())
	}

	// A generate-tree run is the most expensive place to discover a wrong
	// credential: it creates objects rather than fixing them, so a squashed or
	// unmapped identity is found after the tree exists.
	authCred, authWarnings, authErr := f.auth.Resolve(explicit, *f.transport)
	if authErr != nil {
		fmt.Fprintf(errOut, "error: %v\n", authErr)
		return 1
	}
	for _, w := range authWarnings {
		fmt.Fprintln(errOut, w)
	}

	cfg := treegen.Config{
		Target:          target,
		Roster:          roster,
		Scale:           s,
		Workers:         workers,
		Seed:            *f.seed,
		ACLsOnly:        *f.aclsOnly,
		NoACLs:          *f.noACLs,
		DryRun:          *f.dryRun,
		SafetyPrincipal: *f.safetyPrincipal,
		FilesPerSubtree: *f.filesPerSubtree,
		Transport:       *f.transport,
		Server:          *f.server,
		Export:          *f.export,
		Connections:     *f.connections,
		ManifestPath:    *f.manifestPath,
		Auth:            authCred,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := treegen.RunContext(ctx, cfg); err != nil {
		if ctx.Err() != nil {
			fmt.Fprintf(errOut, "\nInterrupted, partial tree left in place.\n")
			return 130
		}
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}
	return 0
}
