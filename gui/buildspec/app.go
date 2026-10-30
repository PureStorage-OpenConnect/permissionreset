// Command buildspec is a Wails v2 desktop wrapper around
// internal/session.Session, giving build-spec's capture/verify workflow a
// point-and-click UI instead of the CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/saclplan"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/session"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
)

// idle is how long a session may sit unused before the app closes it and
// tells the frontend to reconnect.
const idle = 15 * time.Minute

// logCap bounds the in-memory ring the app keeps of session log lines.
const logCap = 200

// caps is platform.Current(), held in a package var so tests can override it
// to exercise the branch a single test binary cannot reach via build tags.
var caps = platform.Current()

// version is stamped by ldflags: -X main.version=<value>.
var version = "dev"

// sess is the narrow surface App needs from *session.Session. Session is a
// concrete type; this interface lets tests inject a fake without a network.
type sess interface {
	Root() string
	Transport() session.Transport
	ListDir(string, int) ([]session.Entry, bool, error)
	Exports(context.Context) ([]string, bool, error)
	Capture(string, string, speccapture.Options) (*speccapture.Result, error)
	Verify(string, string, string, speccapture.Options) (*speccapture.Result, error)
	Expired() bool
	Close() error
}

// connect is a package var wrapping session.Connect so tests can substitute a
// fake session without a network or a mount.
var connect = func(ctx context.Context, req session.ConnectRequest, idle time.Duration, now func() time.Time) (sess, error) {
	return session.Connect(ctx, req, idle, now)
}

// runtimeSeam is the slice of wails runtime functions App uses, narrowed so
// tests can inject a fake instead of a real Wails context.
type runtimeSeam interface {
	EventsEmit(ctx context.Context, eventName string, data ...interface{})
	SaveFileDialog(ctx context.Context, options wailsruntime.SaveDialogOptions) (string, error)
	OpenDirectoryDialog(ctx context.Context, options wailsruntime.OpenDialogOptions) (string, error)
	OpenFileDialog(ctx context.Context, options wailsruntime.OpenDialogOptions) (string, error)
}

// wailsSeam implements runtimeSeam over the real github.com/wailsapp/wails/v2/pkg/runtime package.
type wailsSeam struct{}

func (wailsSeam) EventsEmit(ctx context.Context, eventName string, data ...interface{}) {
	wailsruntime.EventsEmit(ctx, eventName, data...)
}

func (wailsSeam) SaveFileDialog(ctx context.Context, options wailsruntime.SaveDialogOptions) (string, error) {
	return wailsruntime.SaveFileDialog(ctx, options)
}

func (wailsSeam) OpenDirectoryDialog(ctx context.Context, options wailsruntime.OpenDialogOptions) (string, error) {
	return wailsruntime.OpenDirectoryDialog(ctx, options)
}

func (wailsSeam) OpenFileDialog(ctx context.Context, options wailsruntime.OpenDialogOptions) (string, error) {
	return wailsruntime.OpenFileDialog(ctx, options)
}

// App is the bound backend for the frontend. Every exported method takes mu,
// so calls from concurrent UI actions serialize rather than race the session.
type App struct {
	mu   sync.Mutex
	ctx  context.Context
	rt   runtimeSeam
	sess sess

	logMu sync.Mutex
	log   []string

	stopTicker chan struct{}
}

// NewApp constructs an App bound to the real Wails runtime.
func NewApp() *App {
	return &App{rt: wailsSeam{}}
}

func (a *App) startup(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.stopTicker = make(chan struct{})
	stop := a.stopTicker
	a.mu.Unlock()

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				a.tick()
			}
		}
	}()
}

// tick checks session idle expiry. Broken out from the ticker goroutine so
// tests can drive it directly with a fake session whose Expired() returns
// true, without waiting on a real timer.
func (a *App) tick() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess != nil && a.sess.Expired() {
		_ = a.sess.Close()
		a.sess = nil
		a.emitLocked("session:lost", "idle timeout")
	}
}

func (a *App) shutdown(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopTicker != nil {
		close(a.stopTicker)
		a.stopTicker = nil
	}
	if a.sess != nil {
		_ = a.sess.Close()
		a.sess = nil
	}
}

// emitLocked emits a Wails event. Callers must hold a.mu (or call it before
// mu is taken, during startup/shutdown where no other goroutine touches rt).
func (a *App) emitLocked(name string, data ...interface{}) {
	if a.rt != nil && a.ctx != nil {
		a.rt.EventsEmit(a.ctx, name, data...)
	}
}

func (a *App) addLog(line string) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	a.log = append(a.log, line)
	if len(a.log) > logCap {
		a.log = a.log[len(a.log)-logCap:]
	}
}

// Logs returns the last logCap lines the session backend has logged.
func (a *App) Logs() []string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	out := make([]string, len(a.log))
	copy(out, a.log)
	return out
}

// CapabilitiesResult reports what this build can do, for the frontend to
// gate userspace-only or kernel-only UI affordances.
type CapabilitiesResult struct {
	OS                    string `json:"os"`
	KernelTransport       bool   `json:"kernelTransport"`
	CredentialFromProcess bool   `json:"credentialFromProcess"`
	Version               string `json:"version"`
}

// Capabilities reports the platform matrix and build version.
func (a *App) Capabilities() CapabilitiesResult {
	return CapabilitiesResult{
		OS:                    caps.OS,
		KernelTransport:       caps.KernelTransport,
		CredentialFromProcess: caps.CredentialFromProcess,
		Version:               version,
	}
}

// ConnectRequest is the frontend-facing connection form.
type ConnectRequest struct {
	Transport    string `json:"transport"`
	Server       string `json:"server"`
	Export       string `json:"export"`
	MountPath    string `json:"mountPath"`
	AuthUid      int    `json:"authUid"`
	AuthGid      int    `json:"authGid"`
	AuthGids     string `json:"authGids"`
	RpcTimeoutMs int    `json:"rpcTimeoutMs"`
	RetryBudget  int    `json:"retryBudget"`
	RetryBaseMs  int    `json:"retryBaseMs"`
}

// ConnectResult is returned on a successful Connect.
type ConnectResult struct {
	Root     string   `json:"root"`
	Warnings []string `json:"warnings"`
}

// Connect opens a new session, closing any existing one first.
func (a *App) Connect(req ConnectRequest) (ConnectResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.sess != nil {
		_ = a.sess.Close()
		a.sess = nil
	}

	a.emitLocked("busy", "connecting")
	defer a.emitLocked("busy", "")

	transport := session.Transport(req.Transport)

	var warnings []string
	var auth *nfs41.AuthSys

	typed := req.AuthUid >= 0 || req.AuthGid >= 0 || req.AuthGids != ""
	nothingTyped := req.AuthUid < 0 && req.AuthGid < 0 && req.AuthGids == ""

	if nothingTyped {
		if !caps.CredentialFromProcess && transport == session.Userspace {
			return ConnectResult{}, fmt.Errorf(
				"--auth-uid and --auth-gid are required on this platform: " +
					"the process uid/gid are not available (os.Getuid and os.Getgid return -1). " +
					"Provide both flags to identify yourself to the array")
		}
		auth = nil
	} else if typed {
		var base nfs41.AuthSys
		if caps.CredentialFromProcess {
			base = nfs41.CurrentAuthSys()
		} else {
			host, err := os.Hostname()
			if err != nil {
				host = "localhost"
			}
			base = nfs41.AuthSys{Machine: host}
		}
		if req.AuthUid >= 0 {
			base.UID = uint32(req.AuthUid)
		}
		if req.AuthGid >= 0 {
			base.GID = uint32(req.AuthGid)
		}
		if req.AuthGids != "" {
			parsed, err := cmdflags.ParseGIDList(req.AuthGids)
			if err != nil {
				return ConnectResult{}, err
			}
			base.AuxGIDs = parsed
		}
		auth = &base
	}

	if transport == session.Userspace && req.AuthGids == "" {
		warnings = append(warnings, cmdflags.ProcessCredentialNotes()...)
	}
	// credentialWarnings (the low-uid heuristic in internal/cmdflags) is
	// unexported, so this build cannot reproduce it; see report deviations.

	rpcTimeout := req.RpcTimeoutMs
	if rpcTimeout == 0 {
		rpcTimeout = 30000
	}
	retryBudget := req.RetryBudget
	if retryBudget == 0 {
		retryBudget = 5
	}
	retryBaseMs := req.RetryBaseMs
	if retryBaseMs == 0 {
		retryBaseMs = 100
	}

	sreq := session.ConnectRequest{
		Transport:      transport,
		Server:         req.Server,
		Export:         req.Export,
		Auth:           auth,
		RPCTimeout:     time.Duration(rpcTimeout) * time.Millisecond,
		RetryBudget:    retryBudget,
		RetryBaseDelay: time.Duration(retryBaseMs) * time.Millisecond,
		MountPath:      req.MountPath,
		Log:            a.addLog,
	}

	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	s, err := connect(ctx, sreq, idle, time.Now)
	if err != nil {
		return ConnectResult{}, err
	}
	a.sess = s

	return ConnectResult{Root: s.Root(), Warnings: warnings}, nil
}

// handleSessionErr classifies err: if it is ErrSessionLost or ErrExpired, the
// session is closed, nilled, and a "session:lost" event is emitted. Callers
// must hold a.mu. err is returned unchanged either way.
func (a *App) handleSessionErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, session.ErrSessionLost) || errors.Is(err, session.ErrExpired) {
		if a.sess != nil {
			_ = a.sess.Close()
			a.sess = nil
		}
		a.emitLocked("session:lost", err.Error())
	}
	return err
}

var errNoSession = errors.New("no active session; connect first")

// ExportsResult is the outcome of Exports.
type ExportsResult struct {
	Exports   []string `json:"exports"`
	Supported bool     `json:"supported"`
}

// Exports lists the exports visible from the session's server.
func (a *App) Exports() (ExportsResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil {
		return ExportsResult{}, errNoSession
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	names, supported, err := a.sess.Exports(ctx)
	if err != nil {
		return ExportsResult{}, a.handleSessionErr(err)
	}
	return ExportsResult{Exports: names, Supported: supported}, nil
}

// Entry is one child of a listed directory.
type Entry struct {
	Name      string `json:"name"`
	IsDir     bool   `json:"isDir"`
	IsSymlink bool   `json:"isSymlink"`
}

// ListDirResult is the outcome of ListDir.
type ListDirResult struct {
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
}

// ListDir lists the children of path.
func (a *App) ListDir(path string, limit int) (ListDirResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil {
		return ListDirResult{}, errNoSession
	}
	a.emitLocked("busy", "listing")
	defer a.emitLocked("busy", "")

	entries, truncated, err := a.sess.ListDir(path, limit)
	if err != nil {
		return ListDirResult{}, a.handleSessionErr(err)
	}
	out := make([]Entry, len(entries))
	for i, e := range entries {
		out[i] = Entry{Name: e.Name, IsDir: e.IsDir, IsSymlink: e.IsSymlink}
	}
	return ListDirResult{Entries: out, Truncated: truncated}, nil
}

// Identity mirrors speccapture.IdentityReport with camelCase JSON tags. The
// top-level counts are distinct DACL principals; Sacl counts the audit ACEs'.
type Identity struct {
	Special      int         `json:"special"`
	Named        int         `json:"named"`
	NumericUser  int         `json:"numericUser"`
	NumericGroup int         `json:"numericGroup"`
	Sacl         KindCounts  `json:"sacl"`
	Principals   []Principal `json:"principals"`
	Verified     bool        `json:"verified"`
}

// KindCounts mirrors speccapture.KindCounts.
type KindCounts struct {
	Special      int `json:"special"`
	Named        int `json:"named"`
	NumericUser  int `json:"numericUser"`
	NumericGroup int `json:"numericGroup"`
}

// Principal mirrors speccapture.Principal, with Where precomputed.
type Principal struct {
	Who   string `json:"who"`
	Group bool   `json:"group"`
	Kind  string `json:"kind"`
	Where string `json:"where"`
}

func toIdentity(r speccapture.IdentityReport) Identity {
	ps := make([]Principal, len(r.Principals))
	for i, p := range r.Principals {
		ps[i] = Principal{Who: p.Who, Group: p.Group, Kind: p.Kind, Where: p.Where()}
	}
	return Identity{
		Special:      r.Special,
		Named:        r.Named,
		NumericUser:  r.NumericUser,
		NumericGroup: r.NumericGroup,
		Sacl: KindCounts{
			Special:      r.SACL.Special,
			Named:        r.SACL.Named,
			NumericUser:  r.SACL.NumericUser,
			NumericGroup: r.SACL.NumericGroup,
		},
		Principals: ps,
		Verified:   r.Verified,
	}
}

// CaptureResult mirrors speccapture.Result with camelCase JSON tags.
type CaptureResult struct {
	Yaml     string   `json:"yaml"`
	DirAces  []string `json:"dirAces"`
	FileAces []string `json:"fileAces"`
	DirSacl  []string `json:"dirSacl"`
	FileSacl []string `json:"fileSacl"`
	// HasSacl is true when either exemplar carried an audit (U) ACE.
	HasSacl bool `json:"hasSacl"`
	// KeepsDacl is true when the spec's rules are sacl:-only, so applying it
	// leaves every object's own DACL in place.
	KeepsDacl bool     `json:"keepsDacl"`
	Notes     []string `json:"notes"`
	Identity  Identity `json:"identity"`
}

func toCaptureResult(r *speccapture.Result) CaptureResult {
	return CaptureResult{
		Yaml:      string(r.YAML),
		DirAces:   r.DirACEs,
		FileAces:  r.FileACEs,
		DirSacl:   r.DirSACL,
		FileSacl:  r.FileSACL,
		HasSacl:   r.HasSACL(),
		KeepsDacl: r.KeepsDACL,
		Notes:     r.Notes,
		Identity:  toIdentity(r.Identity),
	}
}

// Capture reads the ACLs from dir and file and returns the generated spec.
// withDACL is build-spec's --with-dacl: when the exemplars carry audit ACEs,
// also write their DACLs as acl: instead of keeping each object's own.
func (a *App) Capture(dir, file string, withDACL bool) (CaptureResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil {
		return CaptureResult{}, errNoSession
	}
	a.emitLocked("busy", "capturing")
	defer a.emitLocked("busy", "")

	res, err := a.sess.Capture(dir, file, speccapture.Options{WithDACL: withDACL})
	if err != nil {
		return CaptureResult{}, a.handleSessionErr(err)
	}
	return toCaptureResult(res), nil
}

// Verify captures dir and file, then replays the result through scratch.
// withDACL is as for Capture.
func (a *App) Verify(scratch, dir, file string, withDACL bool) (CaptureResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil {
		return CaptureResult{}, errNoSession
	}
	a.emitLocked("busy", "verifying")
	defer a.emitLocked("busy", "")

	res, err := a.sess.Verify(scratch, dir, file, speccapture.Options{WithDACL: withDACL})
	if err != nil {
		return CaptureResult{}, a.handleSessionErr(err)
	}
	return toCaptureResult(res), nil
}

// SaveResult is the outcome of SaveSpec and ChooseScratch.
type SaveResult struct {
	Path string `json:"path"`
}

// SaveSpec writes yaml to a location chosen through a save dialog. It never
// overwrites an existing file.
func (a *App) SaveSpec(yaml, suggestedName string) (SaveResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveNewLocked(yaml, wailsruntime.SaveDialogOptions{
		DefaultFilename: suggestedName,
		Title:           "Save spec",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "YAML spec", Pattern: "*.yaml;*.yml"},
		},
	})
}

// SavePlan writes a SACL plan's JSON to a location chosen through a save
// dialog, with the same never-overwrite rule as SaveSpec.
func (a *App) SavePlan(json, suggestedName string) (SaveResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveNewLocked(json, wailsruntime.SaveDialogOptions{
		DefaultFilename: suggestedName,
		Title:           "Save SACL plan",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "SACL plan", Pattern: "*.json"},
		},
	})
}

// saveNewLocked asks for a path and writes content to it as a new file. An
// empty path means the dialog was cancelled. Callers must hold a.mu.
func (a *App) saveNewLocked(content string, options wailsruntime.SaveDialogOptions) (SaveResult, error) {
	a.emitLocked("busy", "saving")
	defer a.emitLocked("busy", "")

	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	path, err := a.rt.SaveFileDialog(ctx, options)
	if err != nil {
		return SaveResult{}, err
	}
	if path == "" {
		return SaveResult{Path: ""}, nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			return SaveResult{}, fmt.Errorf("refusing to overwrite existing file %s: build-spec never overwrites", path)
		}
		return SaveResult{}, err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{Path: path}, nil
}

// SaclPlanResult is the outcome of SaclPlan: build-spec --sacl-plan's JSON
// for one spec, plus what the frontend needs to summarize it.
type SaclPlanResult struct {
	SpecPath string `json:"specPath"`
	JSON     string `json:"json"`
	Rules    int    `json:"rules"`
	// Refused lists the rules (by plan label) that carry acl: or dacl:.
	// Set-SaclOnly refuses a plan with any of them, since such a spec is for
	// permissionreset.
	Refused []string `json:"refused"`
}

// SaclPlan asks for a permissionreset spec and returns its SACL plan, the JSON
// Set-SaclOnly -Plan reads. It reads only the chosen file, needs no session,
// and an empty SpecPath means the dialog was cancelled.
func (a *App) SaclPlan() (SaclPlanResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	path, err := a.rt.OpenFileDialog(ctx, wailsruntime.OpenDialogOptions{
		Title: "Choose a permissionreset spec",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "YAML spec", Pattern: "*.yaml;*.yml"},
		},
	})
	if err != nil || path == "" {
		return SaclPlanResult{}, err
	}
	a.emitLocked("busy", "planning")
	defer a.emitLocked("busy", "")
	return saclPlanFor(path)
}

// saclPlanFor is build-spec --sacl-plan for path: full spec validation, then
// the plan, rendered exactly as the CLI prints it.
func saclPlanFor(path string) (SaclPlanResult, error) {
	s, err := spec.Load(path)
	if err != nil {
		return SaclPlanResult{}, err
	}
	plan, err := saclplan.Build(s, path)
	if err != nil {
		return SaclPlanResult{}, err
	}
	out, err := plan.Marshal()
	if err != nil {
		return SaclPlanResult{}, fmt.Errorf("encode plan: %w", err)
	}
	res := SaclPlanResult{SpecPath: path, JSON: string(out), Rules: len(plan.Rules), Refused: []string{}}
	for _, r := range append([]saclplan.Rule{plan.Default}, plan.Rules...) {
		if r.HasACL || r.HasDACL {
			res.Refused = append(res.Refused, r.Label)
		}
	}
	return res, nil
}

// ChooseScratch opens a directory chooser for the Verify scratch directory.
// Only meaningful on the kernel transport, since userspace has no local
// filesystem to browse for one.
func (a *App) ChooseScratch() (SaveResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil || a.sess.Transport() != session.Kernel {
		return SaveResult{}, errors.New("scratch chooser is only available on the kernel transport")
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	path, err := a.rt.OpenDirectoryDialog(ctx, wailsruntime.OpenDialogOptions{
		Title: "Choose scratch directory",
	})
	if err != nil {
		return SaveResult{}, err
	}
	return SaveResult{Path: path}, nil
}

// Disconnect closes the active session, if any.
func (a *App) Disconnect() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil {
		return nil
	}
	err := a.sess.Close()
	a.sess = nil
	return err
}
