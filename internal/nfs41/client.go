package nfs41

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// cryptoRandRead is crypto/rand.Read, named so probeName's fallback comment
// reads clearly next to the var that wraps it.
func cryptoRandRead(b []byte) (int, error) { return cryptorand.Read(b) }

const (
	defaultRPCTimeout     = 30 * time.Second
	defaultRetryBudget    = 5
	defaultRetryBaseDelay = 100 * time.Millisecond
)

// The reply bytes a READDIR COMPOUND spends outside the READDIR4resok that
// rd_maxcount bounds. ca_maxresponsesize bounds the whole reply, so this is what
// has to come off it before the remainder can be offered as rd_maxcount.
//
// Every term is an exact XDR size, not an estimate, so the sum can be checked by
// reading the wire format rather than trusted.
const (
	// rpcReplyHeaderSize: record marker, xid, mtype, reply_stat, verifier flavor,
	// verifier length, accept_stat.
	rpcReplyHeaderSize = 28
	// compoundReplyHeaderSize: status, tag length, empty tag, resarray count.
	compoundReplyHeaderSize = 12
	// sequenceReplySize: opnum, status, sessionid, sequenceid, slotid, highest
	// slotid, target highest slotid, status flags.
	sequenceReplySize = 4 + 4 + 16 + 4 + 4 + 4 + 4 + 4
	// putfhReplySize: opnum, status.
	putfhReplySize = 8
	// readdirReplyFixedSize: opnum, status, cookieverf, the first entry-present
	// discriminator, and eof.
	//
	// The last three are deliberately over-counted. RFC 7530 section 16.24.4 puts
	// cookieverf, the dirlist4 discriminators and eof INSIDE the READDIR4resok that
	// rd_maxcount already bounds -- only opnum and status sit outside it -- so this
	// term subtracts 16 bytes twice. Sixteen bytes of a half-megabyte reply buys a
	// margin against the fact that servers disagree about what rd_maxcount bounds
	// at all, which is the same disagreement the NFS4ERR_REP_TOO_BIG arm below
	// exists for. Do not "fix" this by dropping the terms without also relaxing
	// TestReadDirLeavesHeadroomForCompoundOverhead, which pins the exact cap.
	readdirReplyFixedSize = 4 + 4 + 8 + 4 + 4

	readdirCompoundOverhead = rpcReplyHeaderSize + compoundReplyHeaderSize + sequenceReplySize + putfhReplySize + readdirReplyFixedSize

	// readdirMinMaxcount is the smallest rd_maxcount worth asking for. Below
	// roughly this there is no room for one entry plus the dirlist4 framing, which
	// is the condition NFS4ERR_TOOSMALL names, so shrinking further on
	// NFS4ERR_REP_TOO_BIG would only trade one permanent failure for the other.
	readdirMinMaxcount = 1024
)

// Known Pure NFS max-file-size values, used as a server-identification heuristic.
// See docs/superpowers/specs/2026-08-20-nfsv41-userspace-transport-design.md section 7.
// Verified against Everpure product documentation 2026-08-20.
//
// The heuristic exists because EXCHANGE_ID yields no product identification on
// FlashBlade. That is still true of FlashBlade and is NOT true of FlashArray,
// which populates eir_server_impl_id with its product name and version -- see
// ServerIdentity in session.go for the measured strings. Whenever this gate is
// revisited, the shape to reach for is impl_id where the server supplies it and
// this table only as the fallback, which is strictly better than either alone.
// It is not done here because FlashArray is deliberately not a supported target
// for this transport yet: an FA runs the kernel path until there is a reason it
// should not.
//
// The client does reach an FA. What stopped it was a zeroed
// csa_back_chan_attrs, which FA refuses with NFS4ERR_TOOSMALL and FlashBlade
// accepts; populating the back channel is the whole fix, and session.go does
// -- see backChannelSize there, which also records the earlier misdiagnosis
// that blamed ca_maxresponsesize_cached. CREATE_SESSION completes, measured
// against fa-lab-01 (Purity//FA 6.10.6); the FlashArray rows in
// RFC-Deviations.md were all collected through this client.
//
// Reaching an FA still needs the non-Pure server override, because the table
// below does not carry FA File 6.6.10+'s max file size. That is the whole of
// what stands between here and FA support, and it is a measurement, not a
// design: the value is undocumented, so it has to be read off an array.
var pureMaxFileSizes = map[uint64]string{
	1 << 46: "FlashBlade (all models, Purity//FB 4.3.x-4.8.x+); FA File pre-6.6.10", // 64 TiB
	// FA File 6.6.10+ raised this to "4 PB" (PURE-316110, PURE-322426). The exact
	// byte value is NOT documented -- 2^52 and 4e15 are both plausible readings.
	// Measure it against a real array before adding it here.
	//
	// Better still, do not add it. That FA answers two different sizes depending
	// on release is precisely why this table is the wrong primary signal for
	// FlashArray: every future raise needs another row, and a missing row reads
	// as "not a Pure array" rather than "a Pure array I lack a row for".
	//
	// The gate no longer relies on it for that. isFlashArrayIdentity reads
	// eir_server_impl_id first and refuses a FlashArray by name, so this table is
	// consulted only for servers that identify themselves as nothing -- which is
	// the FlashBlade case, and the reason it still exists. See RFC-Deviations.md,
	// "Identifying the platform".
}

// gateCodeKey and gateCodeRotate make the override warning's diagnostic code
// opaque. The code is shown to operators, and the attribute the gate reads, and
// its value, are not to be volunteered in output or documentation -- only here
// in the source. It is obfuscation, not secrecy: decodeGateCode reverses it.
const (
	gateCodeKey    = 0x9e3779b97f4a7c15
	gateCodeRotate = 23
)

// gateCode encodes the gate's observed reading as an opaque code for the
// unsafe-override warning, so support can still learn the value when a
// firmware release moves it. Decode one with
//
//	PERMISSIONRESET_GATE_CODE=<code> go test ./internal/nfs41 -run TestDecodeGateCode -v
func gateCode(v uint64) string {
	return strings.ToUpper(strconv.FormatUint(bits.RotateLeft64(v, gateCodeRotate)^gateCodeKey, 36))
}

// decodeGateCode reverses gateCode.
func decodeGateCode(code string) (uint64, error) {
	n, err := strconv.ParseUint(strings.ToLower(strings.TrimSpace(code)), 36, 64)
	if err != nil {
		return 0, fmt.Errorf("not a gate code: %q", code)
	}
	return bits.RotateLeft64(n^gateCodeKey, -gateCodeRotate), nil
}

// Platform names the server family the max-file-size gate recognized. It is a
// by-product of the gate, not a second probe: the same lookup that decides
// whether to refuse also decides this value, so callers that want to tune
// themselves to the hardware (worker counts, batch sizes) can read it without
// asking the server anything further.
type Platform string

const (
	// PlatformUnknown is reported when the gate did not recognize the server,
	// which today can only happen under the unsafe server override.
	PlatformUnknown Platform = ""
	// PlatformFlashBlade is reported when the gate accepted the server.
	PlatformFlashBlade Platform = "flashblade"
	// PlatformFlashArray is reported when EXCHANGE_ID identified a FlashArray.
	// Reaching a client with this platform set requires the unsafe server
	// override, because the gate refuses FlashArray outright without it.
	PlatformFlashArray Platform = "flasharray"
)

// ErrNotPureServer is returned when the target fails the gate.
//
// The message is deliberately uninformative. It names neither the observed value
// nor, above all, the expected one: an error reading "expected 70368744177664" is
// a working instruction for defeating the gate. The observed value goes to the
// log instead, so a support engineer with log access can still diagnose a
// firmware bump that moves the constant.
var ErrNotPureServer = errors.New("--transport=userspace requires a FlashBlade; refusing to continue")

// ErrFlashArrayNotSupported is returned when EXCHANGE_ID identifies the target as
// a FlashArray. FlashArray runs the kernel transport; see RFC-Deviations.md.
//
// This check exists because the max-file-size table cannot distinguish the two
// products. FA File raised its max file size at 6.6.10, so an FA on an earlier
// release reports the same value FlashBlade reports, passes the size gate, and is
// then labelled PlatformFlashBlade -- which is how it would draw a worker default
// measured on a FlashBlade against an array that saturates two orders lower.
// eir_server_impl_id names the product, so asking it first closes that hole.
//
// Deliberately a distinct sentinel rather than a variant of ErrNotPureServer: a
// FlashArray IS a Pure array, and "requires a FlashBlade" read against one is
// misleading enough to send someone checking their cabling. It also marks the
// exact place a future FlashArray path attaches -- this refusal becomes that
// branch, and nothing else about the gate has to move.
var ErrFlashArrayNotSupported = errors.New("--transport=userspace does not support FlashArray File; use the default kernel transport")

// isFlashArrayIdentity reports whether EXCHANGE_ID identified a FlashArray.
//
// Substring match on the implementation NAME, which is measured as
// "PureStorage FlashArray <version> ..." -- see ServerIdentity in session.go.
// Deliberately not the domain: "purestorage.com" names the vendor, not the
// product, so a future FlashBlade that starts populating impl_id would almost
// certainly carry it too, and a domain-keyed gate would refuse the one platform
// this transport supports.
// Matching loosely is the right bias here: a false positive costs a refusal on a
// platform this transport does not support anyway, while a false negative puts an
// unsupported array on a code path tuned for different hardware.
//
// Returns false when the server supplies no implementation ID, which is the
// FlashBlade case and the reason the size table below still exists.
func isFlashArrayIdentity(id *ServerIdentity) bool {
	if id == nil {
		return false
	}
	return strings.Contains(strings.ToLower(id.ImplName), "flasharray")
}

// Config controls the userspace NFSv4.1 client.
type Config struct {
	Server string
	Export string
	// Target is the subtree to operate on; empty means the export root.
	Target string

	Connections int
	Slots       int
	// MaxOpsPerCompound is validated but NOT YET ENFORCED. Phase 1 issues only
	// fixed two- and three-operation COMPOUNDs, so there is nothing to cap; the
	// batching that needs it lands with the phase 4 pool. Do not read this field
	// as an active limit.
	MaxOpsPerCompound  int
	RPCTimeout         time.Duration
	RetryBudget        int
	RetryBaseDelay     time.Duration
	AllowNonPureServer bool

	// Auth is the AUTH_SYS credential every call carries. Nil means "build one
	// from the running process", which is CurrentAuthSys and is what the kernel
	// client would send from the same account.
	//
	// It is settable because a process credential is only meaningful where the
	// client's uid namespace is the array's. On a Mac bound to no directory the
	// local uid is typically 501 and means nothing to the export; the operator
	// has to say who they are.
	Auth *AuthSys

	Log func(string)
}

// poolEntry owns one connection, its own client registration, its session, and
// the lock that serializes a rebuild against operations on that connection.
// Operations on other entries do not take this lock and continue independently.
type poolEntry struct {
	lifecycle  sync.RWMutex
	conn       *Conn
	session    *Session
	generation uint64
}

// Client implements transport.Transport over a pool of NFSv4.1 sessions, one
// per TCP connection. The dialer is client-owned; everything else — connection,
// client registration and session — belongs to the pool entry.
//
// Each entry carries its OWN EXCHANGE_ID, so the pool is N independent clients
// rather than one client with N sessions. That is not a preference. MEASURED
// 2026-08-21 against an S200 on Purity 4.8.0: a FlashBlade permits exactly one
// session per clientid and answers the second CREATE_SESSION with
// NFS4ERR_INVAL, whether it arrives on a second connection or on the very
// connection that carried the first. See trunkprobe_live_test.go for the four
// arms and testdata/create_session_diff.go's captured byte diff proving the two
// calls differ only in csa_sequence.
//
// RFC 8881 section 2.10.5 says a server that supports session trunking for an
// address MUST support client ID trunking for it, and this array supports
// session trunking — the kernel mounts it nconnect=16. So the shared-clientid
// design was legal and simply does not work here.
//
// The cost of independent clients is that locking state is not shared across
// sessions. This client never sends OPEN or LOCK — only SETATTR, GETATTR and
// READDIR — so it pays nothing today, but any future feature needing state
// shared across the pool is foreclosed by this shape and would have to trunk
// with BIND_CONN_TO_SESSION, which is not in the XDR subset.
type Client struct {
	cfg      Config
	dialer   Dialer
	auth     AuthSys
	identity *ServerIdentity
	platform Platform

	pool      []*poolEntry
	nextEntry atomic.Uint64
	closed    atomic.Bool

	cacheMu sync.RWMutex
	// fhCache maps a cleaned absolute path to a filehandle for the two callers
	// that genuinely have only a path: the export and target roots resolved at
	// Init, and stale-filehandle recovery, which re-resolves a path whose
	// filehandle the server rejected and must make that new handle stick for
	// later operations on a caller's now-outdated Ref.
	//
	// It is NOT a whole-tree index. It used to become one: internal/apply called
	// every transport method with transport.Ref{Path: path} and no filehandle, so
	// the first touch of each object resolved by LOOKUP and cached the result,
	// and READDIR seeded the same map with every child it returned. With
	// 70-character paths and the measured 28-byte filehandle that is on the order
	// of 190 bytes per entry, so ~200 MB at 1.1M objects against 24 MB for the
	// whole kernel transport, and up to 1.5x transiently while the map doubles.
	// (The figure the Task 11 review recorded here assumed a 32-byte filehandle;
	// 28 is what the server actually returns, which moves the total by a percent
	// and changes nothing about the conclusion.) Task 12b
	// removed the cause rather than the symptom: apply now forwards the
	// filehandle READDIR already returned, so steady state populates nothing
	// here at all.
	//
	// What remains is bounded by the roots plus however many objects hit
	// NFS4ERR_STALE, a fault-path quantity rather than a tree-sized one. A mass
	// re-export could still make that every object, so entries are capped at
	// fhCacheMax and the map is dropped wholesale on overflow. That is safe
	// because a miss is not an error: filehandleForRef falls back to the
	// caller's Ref.FH and then to a re-resolve, which is what it would have done
	// before the entry was ever cached.
	fhCache    map[string][]byte
	root       transport.Ref
	exportRoot transport.Ref

	retry RetryPolicy

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

var clientOwnerSequence atomic.Uint64

// New connects to cfg.Server over plain TCP and constructs the phase-1 client.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Server == "" {
		return nil, errors.New("nfs41: empty server address")
	}
	// The address is normalized HERE and not left to normalizeConfig, because
	// TCPDialer captures the string it is given: normalizeConfig runs inside
	// newClientWithDialer, by which time the dialer already holds the raw value
	// and fixing cfg.Server would fix nothing that dials.
	addr, err := normalizeServerAddress(cfg.Server)
	if err != nil {
		return nil, err
	}
	cfg.Server = addr
	return newClientWithDialer(ctx, cfg, TCPDialer(addr))
}

// defaultNFSPort is the IANA port for NFS, and the default --server has always
// documented. It lives in the library rather than in main.go so the live probe
// tests here, which take a raw PERMISSIONRESET_TEST_SERVER, get the same treatment as
// the command.
const defaultNFSPort = "2049"

// normalizeServerAddress supplies the default port when the address carries none.
//
// net.SplitHostPort is the detector rather than a colon count, because a bare
// IPv6 literal is nothing but colons and would be read as host:port by any
// counting scheme -- "::1" would come apart into host ":" and port "1". Its
// failure is therefore not an error but the interesting case: no port.
//
// net.JoinHostPort builds the result for the mirror-image reason. An IPv6 address
// needs brackets before a port can be appended to it, so "::1" has to become
// "[::1]:2049" and string concatenation would produce "::1:2049", which parses as
// a different address entirely.
func normalizeServerAddress(server string) (string, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		// No port. Treat the whole value as the host; if it is malformed in some
		// other way, Dial reports that far better than a guess here could.
		host, port = server, defaultNFSPort
		// A bracketed IPv6 literal with no port arrives with its brackets still
		// on, and JoinHostPort would add a second pair.
		if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
			host = host[1 : len(host)-1]
		}
	}
	if host == "" {
		return "", fmt.Errorf("nfs41: server address has no host: %q", server)
	}
	if port == "" {
		port = defaultNFSPort
	}
	return net.JoinHostPort(host, port), nil
}

// newClientWithDialer is the single constructor behind production and fake
// servers. In particular, it keeps every connection on the Dialer injection
// point reserved for future RPC-with-TLS support.
func newClientWithDialer(ctx context.Context, cfg Config, d Dialer) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("nfs41: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var err error
	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	auth := CurrentAuthSys()
	if cfg.Auth != nil {
		auth = *cfg.Auth
	}
	conn, err := NewConn(ctx, d, auth)
	if err != nil {
		return nil, err
	}

	owner := []byte(fmt.Sprintf("permissionreset-%x-%d", processClientVerifier, clientOwnerSequence.Add(1)))
	exchangeCtx, cancel := context.WithTimeout(ctx, cfg.RPCTimeout)
	reg, err := ExchangeID(exchangeCtx, conn, owner)
	cancel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	sessionCtx, cancel := context.WithTimeout(ctx, cfg.RPCTimeout)
	session, err := NewSession(sessionCtx, conn, reg, uint32(cfg.Slots), cfg.Log)
	cancel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	c := &Client{
		cfg:       cfg,
		dialer:    d,
		auth:      auth,
		pool:      []*poolEntry{{conn: conn, session: session}},
		fhCache:   make(map[string][]byte),
		closeDone: make(chan struct{}),
		retry: RetryPolicy{
			Budget:    cfg.RetryBudget,
			BaseDelay: cfg.RetryBaseDelay,
		},
	}
	if id := reg.Identity(); id != nil {
		copyID := *id
		c.identity = &copyID
	}

	fail := func(cause error) (*Client, error) {
		if closeErr := c.Close(); closeErr != nil {
			cfg.Log(fmt.Sprintf("nfs41: cleanup after client construction failed: %v", closeErr))
		}
		return nil, cause
	}

	serverName := cfg.Server
	if serverName == "" {
		serverName = "the configured server"
	}

	// Gate on product identity first, where the server supplies one.
	//
	// This runs before the export is even resolved: EXCHANGE_ID has already
	// happened, so the answer is in hand and a refusal here costs no further round
	// trip. Ordering it ahead of the size probe is the whole point -- the size
	// table cannot tell an older FlashArray from a FlashBlade, so a size-first gate
	// admits one and mislabels it. See ErrFlashArrayNotSupported.
	if isFlashArrayIdentity(c.identity) {
		cfg.Log(fmt.Sprintf("nfs41: server %s identified itself as %q", serverName, c.identity.ImplName))
		if !cfg.AllowNonPureServer {
			return fail(ErrFlashArrayNotSupported)
		}
		// The override is what the FlashArray protocol probes run under. Record the
		// platform truthfully so nothing downstream tunes itself as if this were a
		// FlashBlade -- workerDefaults keys on exactly this value.
		cfg.Log(fmt.Sprintf("WARNING: server %s is a FlashArray, which this transport does not support; continuing under the unsafe server override", serverName))
		c.platform = PlatformFlashArray
	}

	// Resolve and gate the export on the first connection. No other connection is
	// dialed until the gate accepts, so a refused server observes exactly one.
	exportFH, err := c.resolvePath(ctx, cfg.Export)
	if err != nil {
		return fail(fmt.Errorf("nfs41: resolve export %s: %w", cfg.Export, err))
	}
	c.exportRoot = transport.Ref{Path: cfg.Export, FH: append([]byte(nil), exportFH...)}

	attrs, err := c.getAttributes(ctx, c.exportRoot, "server gate", fattr4MaxFileSize)
	if err != nil {
		return fail(err)
	}
	maxFileSize, err := decodeUint64Attribute(attrs, fattr4MaxFileSize)
	if err != nil {
		// Not wrapped: decodeUint64Attribute's text names the attribute number.
		return fail(fmt.Errorf("nfs41: server gate: %s sent an unusable reply", serverName))
	}

	// The gate logs nothing about what it checks, accepted or refused: the
	// transport's log is shown on stderr (#47), and the attribute and its value
	// are not to be volunteered in output. The override warning below carries
	// the value only as an opaque gateCode, for support to diagnose a firmware
	// release that moves it.
	if _, known := pureMaxFileSizes[maxFileSize]; !known {
		if !cfg.AllowNonPureServer {
			return fail(ErrNotPureServer)
		}
		cfg.Log(fmt.Sprintf("WARNING: server %s is not a recognized FlashBlade (gate code %s); continuing under the unsafe server override", serverName, gateCode(maxFileSize)))
	} else if c.platform == PlatformUnknown {
		// The accepted gate IS the platform signal. Recording it here is what
		// keeps callers from growing a second, independent probe.
		//
		// Guarded on PlatformUnknown so a size match cannot overwrite an identity
		// the impl_id check already established. A FlashArray under the override
		// reaches here with the size of a FlashBlade on releases before FA File
		// 6.6.10, and relabelling it here would undo the point of asking impl_id
		// first.
		c.platform = PlatformFlashBlade
	}

	if cfg.Target == cfg.Export {
		c.root = cloneRef(c.exportRoot)
	} else {
		targetFH, err := c.resolvePath(ctx, cfg.Target)
		if err != nil {
			return fail(fmt.Errorf("nfs41: resolve target %s: %w", cfg.Target, err))
		}
		c.root = transport.Ref{Path: cfg.Target, FH: append([]byte(nil), targetFH...)}
	}

	// Only the first connection is allowed to reach the gate. Once accepted, add
	// the remaining connections, each registering itself: one EXCHANGE_ID and one
	// CREATE_SESSION per connection.
	for len(c.pool) < cfg.Connections {
		entry, err := c.newPoolEntry(ctx)
		if err != nil {
			return fail(fmt.Errorf("nfs41: open pool connection %d: %w", len(c.pool)+1, err))
		}
		c.pool = append(c.pool, entry)
	}
	return c, nil
}

// newPoolEntry dials, registers a client of its own, and creates that client's
// single session.
//
// The EXCHANGE_ID here is what makes the entry independent, and it is mandatory
// rather than tidy: sharing a registration across entries is what produced
// NFS4ERR_INVAL on every connection after the first. The owner string carries a
// fresh clientOwnerSequence value, so no two entries — and no re-registration
// during recovery — can collide on a client owner and be folded back onto one
// clientid by the server.
func (c *Client) newPoolEntry(ctx context.Context) (*poolEntry, error) {
	connCtx, cancel := context.WithTimeout(ctx, c.cfg.RPCTimeout)
	conn, err := NewConn(connCtx, c.dialer, c.auth)
	cancel()
	if err != nil {
		return nil, err
	}

	owner := []byte(fmt.Sprintf("permissionreset-%x-%d", processClientVerifier, clientOwnerSequence.Add(1)))
	exchangeCtx, cancel := context.WithTimeout(ctx, c.cfg.RPCTimeout)
	reg, err := ExchangeID(exchangeCtx, conn, owner)
	cancel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	sessionCtx, cancel := context.WithTimeout(ctx, c.cfg.RPCTimeout)
	session, err := NewSession(sessionCtx, conn, reg, uint32(c.cfg.Slots), c.cfg.Log)
	cancel()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &poolEntry{conn: conn, session: session}, nil
}

func normalizeConfig(cfg Config) (Config, error) {
	// An empty Server is legitimate here and only here: newClientWithDialer is
	// also reached with an injected dialer, which needs no address at all. New
	// rejects it before this runs.
	if cfg.Server != "" {
		addr, err := normalizeServerAddress(cfg.Server)
		if err != nil {
			return Config{}, err
		}
		cfg.Server = addr
	}
	if cfg.Connections < 0 {
		return Config{}, fmt.Errorf("nfs41: connections must not be negative: %d", cfg.Connections)
	}
	if cfg.Connections == 0 {
		cfg.Connections = 1
	}
	if cfg.Slots < 0 || uint64(cfg.Slots) > uint64(^uint32(0)) {
		return Config{}, fmt.Errorf("nfs41: slot count is out of range: %d", cfg.Slots)
	}
	if cfg.MaxOpsPerCompound < 0 {
		return Config{}, fmt.Errorf("nfs41: max operations per COMPOUND must not be negative: %d", cfg.MaxOpsPerCompound)
	}
	if cfg.RPCTimeout < 0 {
		return Config{}, fmt.Errorf("nfs41: RPC timeout must not be negative: %s", cfg.RPCTimeout)
	}
	if cfg.RPCTimeout == 0 {
		cfg.RPCTimeout = defaultRPCTimeout
	}
	if cfg.RetryBudget < 0 {
		return Config{}, fmt.Errorf("nfs41: retry budget must not be negative: %d", cfg.RetryBudget)
	}
	if cfg.RetryBudget == 0 {
		cfg.RetryBudget = defaultRetryBudget
	}
	if cfg.RetryBaseDelay < 0 {
		return Config{}, fmt.Errorf("nfs41: retry base delay must not be negative: %s", cfg.RetryBaseDelay)
	}
	if cfg.RetryBaseDelay == 0 {
		cfg.RetryBaseDelay = defaultRetryBaseDelay
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}

	exportPath, err := normalizeAbsolutePath("export", cfg.Export, "/")
	if err != nil {
		return Config{}, err
	}
	targetPath, err := normalizeAbsolutePath("target", cfg.Target, exportPath)
	if err != nil {
		return Config{}, err
	}
	if !pathWithinExport(exportPath, targetPath) {
		return Config{}, fmt.Errorf("nfs41: target %s is outside export %s", targetPath, exportPath)
	}
	cfg.Export = exportPath
	cfg.Target = targetPath
	return cfg, nil
}

func normalizeAbsolutePath(field, value, fallback string) (string, error) {
	if value == "" {
		value = fallback
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("nfs41: %s path contains a NUL byte", field)
	}
	if !strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("nfs41: %s path must be absolute: %q", field, value)
	}
	return path.Clean(value), nil
}

func pathWithinExport(exportPath, targetPath string) bool {
	return exportPath == "/" || targetPath == exportPath || strings.HasPrefix(targetPath, exportPath+"/")
}

// Platform returns the server family the construction-time gate recognized, or
// PlatformUnknown if it did not recognize one.
func (c *Client) Platform() Platform {
	if c == nil {
		return PlatformUnknown
	}
	return c.platform
}

// ServerIdentity returns a copy of the identity reported by EXCHANGE_ID.
func (c *Client) ServerIdentity() *ServerIdentity {
	if c == nil || c.identity == nil {
		return nil
	}
	id := *c.identity
	return &id
}

// Root returns the target resolved during construction. The cache lookup matters
// after stale-filehandle recovery: it makes a subsequent Root call return the
// replacement rather than the handle originally negotiated.
func (c *Client) Root() (transport.Ref, error) {
	if c == nil {
		return transport.Ref{}, errors.New("nfs41: nil client")
	}
	if err := c.checkOpen(); err != nil {
		return transport.Ref{}, err
	}
	return c.currentRef(c.root), nil
}

// ReadDir enumerates one directory, following the cookie chain to the end.
//
// The bitmask asks for TYPE, MODE, FILEHANDLE, and FSID. FATTR4_FILEHANDLE is
// what removes LOOKUP from steady state: every child arrives with the handle
// needed to address it. Type, mode, and FSID ride along in the same reply, but
// AttrsKnown is set only when all three were actually returned.
//
// A single directory is inherently serial, since each call needs the previous
// reply's cookie. Parallelism comes from many directories in flight, which is
// what the walk's token pool already provides.
//
// Two errors are handled here rather than by the generic classifier, because
// their recovery is specific to enumeration:
//
//	NFS4ERR_TOOSMALL      grow the buffer and retry the same cookie
//	NFS4ERR_NOT_SAME      discard the partial listing and restart from cookie 0
//
// The result is sorted by name. os.ReadDir sorts, server order is arbitrary, and
// a differing order between transports would surface as nondeterministic log and
// checkpoint output for no benefit.
func (c *Client) ReadDir(ref transport.Ref) ([]transport.Dirent, error) {
	out, _, _, err := c.readDirInternal(ref, nil, 0)
	return out, err
}

// ReadDirLimited enumerates ref like ReadDir but stops after limit entries.
// truncated reports whether the directory held more entries than were
// returned. limit <= 0 means no cap. Used by interactive browsers that must
// not pull a million-entry directory into a tree view.
func (c *Client) ReadDirLimited(ref transport.Ref, limit int) ([]transport.Dirent, bool, error) {
	out, _, truncated, err := c.readDirInternal(ref, nil, limit)
	return out, truncated, err
}

// ReadDirSetACL folds a SETATTR(ACL) into the READDIR COMPOUND, saving one
// round-trip per directory. The SETATTR is appended to the first READDIR page's
// COMPOUND; subsequent pages (rare — most directories fit in one page) omit it.
// READDIR does not change the current filehandle, so SETATTR operates on the
// same directory.
//
// This is one mutation per COMPOUND, which FlashBlade permits.
//
// If the READDIR succeeds but the SETATTR fails, the dirents are returned with
// aclApplied=false and no error. The caller falls back to the normal apply path.
func (c *Client) ReadDirSetACL(ref transport.Ref, acl []byte) ([]transport.Dirent, bool, error) {
	out, aclApplied, _, err := c.readDirInternal(ref, acl, 0)
	return out, aclApplied, err
}

func (c *Client) readDirInternal(ref transport.Ref, acl []byte, limit int) ([]transport.Dirent, bool, bool, error) {
	fh, err := c.filehandleForRef(context.Background(), ref)
	if err != nil {
		return nil, false, false, fmt.Errorf("nfs41: read directory %s: %w", ref.Path, err)
	}

	entry, err := c.pickEntry()
	if err != nil {
		return nil, false, false, fmt.Errorf("nfs41: read directory %s: %w", ref.Path, err)
	}
	entry.lifecycle.RLock()
	maxResponse := entry.session.ChannelAttrs().MaxResponseSize
	entry.lifecycle.RUnlock()
	if maxResponse == 0 {
		return nil, false, false, fmt.Errorf("nfs41: read directory %s: session has a zero maximum response size", ref.Path)
	}
	// rd_maxcount bounds the READDIR4resok alone, but ca_maxresponsesize bounds
	// the whole reply -- so growing maxcount all the way to ca_maxresponsesize
	// asks for a reply that legitimately exceeds it once SEQUENCE and PUTFH have
	// had their say, and a strict server answers NFS4ERR_REP_TOO_BIG. Reachable
	// after seven consecutive TOOSMALLs from 64 KiB. Subtracting the overhead is
	// the fix; handling REP_TOO_BIG below covers servers that draw the line
	// somewhere else.
	if maxResponse <= readdirCompoundOverhead+readdirMinMaxcount {
		return nil, false, false, fmt.Errorf("nfs41: read directory %s: negotiated maximum response size %d leaves no room for a READDIR reply", ref.Path, maxResponse)
	}
	maxcountCap := maxResponse - readdirCompoundOverhead
	// Start small so NFS4ERR_TOOSMALL has room to grow, while never asking the
	// server for a reply beyond the negotiated fore-channel limit.
	maxcount := min(maxcountCap, uint32(64<<10))
	dircount := maxcount
	// growLimit is the largest rd_maxcount TOOSMALL is still allowed to grow to.
	// It starts at the cap and drops to whatever REP_TOO_BIG most recently forced,
	// which is what makes the two recoveries terminate as a pair rather than only
	// individually. Growing to a size the server has already refused, and then
	// shrinking away from it again, is a cycle neither arm's own boundary can
	// break: TOOSMALL exits only AT the cap and REP_TOO_BIG only AT the floor, and
	// an oscillation between two interior values reaches neither. Every REP_TOO_BIG
	// lowers this, so the interval maxcount lives in shrinks monotonically and the
	// loop is bounded by log2 of the cap.
	growLimit := maxcountCap

	hasSetACL := len(acl) > 0
	var aclApplied bool

	var (
		cookie           uint64
		verf             [8]byte
		out              []transport.Dirent
		verifierRestarts int
	)
	for {
		ops := []xdr.Nfs_argop4{
			OpPutFH(append([]byte(nil), fh...)),
			OpReadDir(cookie, verf, dircount, maxcount, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		}
		if hasSetACL && !aclApplied {
			ops = append(ops, OpSetACL(append([]byte(nil), acl...)))
		}

		var (
			status uint32
			reply  readDirReply
		)
		reply, err = retryCall(c, context.Background(), entry, "read directory "+ref.Path, func(callCtx context.Context) (uint32, readDirReply, error) {
			var callErr error
			status, reply, callErr = c.sessionDoFast(callCtx, entry, ops)
			if callErr != nil {
				return status, reply, callErr
			}
			// When SETATTR is folded in and READDIR succeeds but SETATTR fails,
			// the compound status is the SETATTR error. Distinguish by result
			// count: READDIR failure stops the COMPOUND before SETATTR executes,
			// producing fewer results than a READDIR-OK + SETATTR-fail.
			if hasSetACL && !aclApplied && status != NFS4_OK {
				n := replyResultCount(reply)
				if n >= 4 {
					// READDIR succeeded (result[2] is OK), SETATTR failed.
					// Present as success so retryCall does not classify the
					// SETATTR error as a transport failure.
					status = NFS4_OK
					return NFS4_OK, reply, nil
				}
			}
			// These statuses need the enumeration state in this function. Present
			// them as successful attempts so retryCall does not classify them.
			if status == NFS4ERR_TOOSMALL || status == NFS4ERR_NOT_SAME || status == NFS4ERR_REP_TOO_BIG {
				return NFS4_OK, reply, nil
			}
			return status, reply, callErr
		}, func(recoveryCtx context.Context) error {
			resolved, resolveErr := c.resolvePath(recoveryCtx, ref.Path)
			if resolveErr != nil {
				return resolveErr
			}
			fh = resolved
			return nil
		})
		if err != nil {
			return nil, false, false, err
		}

		// Check SETATTR result if we sent it and READDIR succeeded.
		if hasSetACL && !aclApplied {
			aclApplied = replySetACLOK(reply)
		}

		switch status {
		case NFS4ERR_TOOSMALL:
			if maxcount >= growLimit {
				if growLimit < maxcountCap {
					// growLimit was lowered by a REP_TOO_BIG, so this server has
					// refused this directory both ways: too small to hold an
					// entry here, too big for ca_maxresponsesize above. There is
					// no rd_maxcount left to try and growing back would loop.
					return nil, false, false, fmt.Errorf("nfs41: read directory %s: server returned NFS4ERR_TOOSMALL at rd_maxcount %d and NFS4ERR_REP_TOO_BIG above it, so no reply size satisfies both (negotiated maximum response size %d)", ref.Path, maxcount, maxResponse)
				}
				return nil, false, false, fmt.Errorf("nfs41: read directory %s: server returned NFS4ERR_TOOSMALL at the largest READDIR reply the negotiated maximum response size %d allows (%d)", ref.Path, maxResponse, maxcountCap)
			}
			maxcount = min(growLimit, maxcount*2)
			dircount = maxcount
			continue
		case NFS4ERR_REP_TOO_BIG:
			// The mirror image of TOOSMALL: this server accounts the reply
			// against ca_maxresponsesize more strictly than the headroom above
			// allows for, so shrink rather than fail the directory.
			if maxcount <= readdirMinMaxcount {
				return nil, false, false, fmt.Errorf("nfs41: read directory %s: server returned NFS4ERR_REP_TOO_BIG at the smallest usable READDIR reply size %d", ref.Path, readdirMinMaxcount)
			}
			maxcount = max(readdirMinMaxcount, maxcount/2)
			// Never let a later TOOSMALL grow back to a size this server has
			// already refused. Without this the two arms form a cycle with no
			// exit: the refused size is below the cap and the shrunk size is
			// above the floor, so neither hard exit is ever reached.
			growLimit = maxcount
			dircount = maxcount
			continue
		case NFS4ERR_NOT_SAME:
			verifierRestarts++
			if verifierRestarts >= c.retry.Budget {
				return nil, false, false, fmt.Errorf("nfs41: read directory %s changed during %d enumeration attempts", ref.Path, verifierRestarts)
			}
			cookie = 0
			verf = [8]byte{}
			out = nil
			continue
		}

		page, err := reply.page(ref.Path)
		if err != nil {
			return nil, false, false, fmt.Errorf("nfs41: read directory %s: %w", ref.Path, err)
		}
		if cookie != 0 && page.verf != verf {
			verifierRestarts++
			if verifierRestarts >= c.retry.Budget {
				return nil, false, false, fmt.Errorf("nfs41: read directory %s changed during %d enumeration attempts", ref.Path, verifierRestarts)
			}
			cookie = 0
			verf = [8]byte{}
			out = nil
			continue
		}
		verf = page.verf
		if limit > 0 {
			remaining := limit - len(out)
			if remaining < 0 {
				remaining = 0
			}
			appendCount := len(page.entries)
			if appendCount > remaining {
				appendCount = remaining
			}
			for _, entry := range page.entries[:appendCount] {
				entry.Ref = cloneRef(entry.Ref)
				out = append(out, entry)
			}
			if len(out) >= limit {
				truncated := appendCount < len(page.entries) || !page.eof
				sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
				return out, aclApplied, truncated, nil
			}
		} else {
			for _, entry := range page.entries {
				entry.Ref = cloneRef(entry.Ref)
				out = append(out, entry)
			}
		}
		if page.eof {
			sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
			return out, aclApplied, false, nil
		}
		if page.raw == 0 {
			return nil, false, false, fmt.Errorf("nfs41: read directory %s: non-EOF reply contained no entries", ref.Path)
		}
		if page.cookie == cookie {
			return nil, false, false, fmt.Errorf("nfs41: read directory %s: non-EOF reply did not advance cookie %d", ref.Path, cookie)
		}
		cookie = page.cookie
	}
}

type readDirPage struct {
	entries []transport.Dirent
	// raw is how many entries the reply's chain held, including the "." and ".."
	// that never reach entries. The progress check in ReadDir is about whether
	// the SERVER made progress, so it has to read this and not len(entries): a
	// non-EOF page consisting only of "." and ".." is a page the server did
	// advance through, and treating it as an empty reply would fail a directory
	// the enumeration was walking correctly.
	raw    int
	cookie uint64
	verf   [8]byte
	eof    bool
}

func readDirResult(results []xdr.Nfs_resop4, parentPath string) (page readDirPage, err error) {
	defer recoverXDR(&err)

	if len(results) < 3 || results[2].Resop != xdr.OP_READDIR {
		return readDirPage{}, errors.New("server returned an unexpected result sequence")
	}
	res := results[2].Opreaddir()
	if uint32(res.Status) != NFS4_OK {
		return readDirPage{}, fmt.Errorf("READDIR result status %s (%d)", res.Status, res.Status)
	}
	ok := res.Resok4()
	page.verf = ok.Cookieverf
	page.eof = ok.Reply.Eof

	for entry := ok.Reply.Entries; entry != nil; entry = entry.Nextentry {
		attrs, decodeErr := DecodeAttrList(entry.Attrs.Attrmask, entry.Attrs.Attr_vals)
		if decodeErr != nil {
			return readDirPage{}, fmt.Errorf("entry %q attributes: %w", entry.Name, decodeErr)
		}
		// The generated decoder still produces a map, and converting per entry
		// costs an allocation. That is acceptable here and not on the fast path:
		// this loop runs only when the fast decoder declined the reply, which is
		// the exception, and DecodeAttrList is shared with callers outside this
		// file that want the map.
		list := make(attrList, 0, len(attrs))
		for bit, value := range attrs {
			list = append(list, attrPair{bit: bit, value: value})
		}
		if err := page.addEntry(parentPath, []byte(entry.Name), uint64(entry.Cookie), list); err != nil {
			return readDirPage{}, err
		}
	}
	return page, nil
}

// addEntry turns one decoded READDIR entry into a transport.Dirent.
//
// Both decoders funnel through here on purpose. Everything below is a rule about
// what the SERVER may send rather than about how the bytes were parsed, so a
// second copy for the fast path would be a second place for a server quirk to be
// handled differently -- and the "." / ".." rule in particular is the kind that
// gets dropped when code is retyped rather than shared.
func (page *readDirPage) addEntry(parentPath string, rawName []byte, cookie uint64, attrs attrList) error {
	page.raw++
	// "." and ".." are skipped before anything else, including the cookie
	// bookkeeping below, which still advances -- dropping the entry must not
	// drop the position it occupied in the chain.
	//
	// Only this transport is exposed to them. os.ReadDir never returns them,
	// so the kernel path is structurally immune and no shared test can catch
	// this. RFC 8881 reserves cookie values 1 and 2 precisely because some
	// servers do emit them, and the consequence here is not cosmetic:
	// path.Join(parent, "..") yields the PARENT with IsDir true, and
	// walk.go's descent is gated on IsDir alone, so a single such entry is
	// either unbounded recursion or a subtree re-walked from a shallower
	// point. FlashBlade's behaviour is unmeasured; the skip costs nothing and
	// removes the class either way.
	if name := string(rawName); name == "." || name == ".." {
		page.cookie = cookie
		return nil
	}

	fileTypeValue, haveType := attrs.get(fattr4Type)
	modeValue, haveMode := attrs.get(fattr4Mode)
	fsidValue, haveFSID := attrs.get(fattr4FSID)
	fhValue, haveFH := attrs.get(fattr4Filehandle)
	if !haveType {
		return fmt.Errorf("entry %q: server omitted FATTR4_TYPE", rawName)
	}
	if len(fileTypeValue) != 4 {
		return fmt.Errorf("entry %q: FATTR4_TYPE is %d bytes, want 4", rawName, len(fileTypeValue))
	}
	if !haveFH {
		return fmt.Errorf("entry %q: server omitted FATTR4_FILEHANDLE", rawName)
	}
	fh, decodeErr := decodeFilehandleAttribute(fhValue)
	if decodeErr != nil {
		return fmt.Errorf("entry %q: %w", rawName, decodeErr)
	}

	fileType := xdr.Nfs_ftype4(binary.BigEndian.Uint32(fileTypeValue))
	isSymlink := fileType == xdr.NF4LNK
	isDir := !isSymlink && fileType == xdr.NF4DIR
	// The name is copied, not aliased. On the fast path rawName points into the
	// reply buffer, which the next READDIR in this loop overwrites.
	name := string(rawName)
	child := transport.Dirent{
		Name:      name,
		Ref:       transport.Ref{Path: path.Join(parentPath, name), FH: fh},
		IsDir:     isDir,
		IsSymlink: isSymlink,
	}
	if haveMode && haveFSID {
		if len(modeValue) != 4 {
			return fmt.Errorf("entry %q: FATTR4_MODE is %d bytes, want 4", rawName, len(modeValue))
		}
		if len(fsidValue) != 16 {
			return fmt.Errorf("entry %q: FATTR4_FSID is %d bytes, want 16", rawName, len(fsidValue))
		}
		child.AttrsKnown = true
		child.Mode = binary.BigEndian.Uint32(modeValue) & 0o7777
		child.FSID = foldFSID(binary.BigEndian.Uint64(fsidValue[:8]), binary.BigEndian.Uint64(fsidValue[8:]))
	}
	page.entries = append(page.entries, child)
	page.cookie = cookie
	return nil
}

// readDirReply is a READDIR COMPOUND reply in whichever form decoded it. Exactly
// one field is populated; page() hides which.
type readDirReply struct {
	fast []fastResult
	gen  []xdr.Nfs_resop4
}

// page decodes the reply into the enumeration state ReadDir walks. The reply
// may have 3 results (SEQUENCE+PUTFH+READDIR) or 4 (with a trailing SETATTR
// from the readdir-fold); page() reads result[2] in both cases.
func (r readDirReply) page(parentPath string) (readDirPage, error) {
	if r.fast == nil {
		return readDirResult(r.gen, parentPath)
	}
	if len(r.fast) < 3 || r.fast[2].Op != uint32(xdr.OP_READDIR) {
		return readDirPage{}, errors.New("server returned an unexpected result sequence")
	}
	res := r.fast[2]
	if res.Status != NFS4_OK {
		return readDirPage{}, fmt.Errorf("READDIR result status %s (%d)", xdr.Nfsstat4(res.Status), res.Status)
	}
	var page readDirPage
	page.verf = res.Verifier
	page.eof = res.EOF
	for _, entry := range res.Entries {
		if err := page.addEntry(parentPath, entry.Name, entry.Cookie, entry.Attrs); err != nil {
			return readDirPage{}, err
		}
	}
	return page, nil
}

// replyResultCount returns the number of per-operation results in the reply.
func replyResultCount(r readDirReply) int {
	if r.fast != nil {
		return len(r.fast)
	}
	return len(r.gen)
}

// replySetACLOK returns true if the reply contains a successful SETATTR result
// at position 3 (after SEQUENCE, PUTFH, READDIR).
func replySetACLOK(r readDirReply) bool {
	if r.fast != nil {
		return len(r.fast) >= 4 &&
			r.fast[3].Op == uint32(xdr.OP_SETATTR) &&
			r.fast[3].Status == NFS4_OK
	}
	if r.gen != nil {
		return len(r.gen) >= 4 &&
			r.gen[3].Resop == xdr.OP_SETATTR &&
			uint32(r.gen[3].Opsetattr().Status) == NFS4_OK
	}
	return false
}

// sessionDoFast is sessionDo with the hand-written decoder. The reply it returns
// aliases the connection's read buffer, so it is only valid until the next call
// on this session -- page() copies everything it keeps.
func (c *Client) sessionDoFast(ctx context.Context, entry *poolEntry, ops []xdr.Nfs_argop4) (uint32, readDirReply, error) {
	if err := c.checkOpen(); err != nil {
		return 0, readDirReply{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, c.cfg.RPCTimeout)
	defer cancel()
	status, fast, gen, err := entry.session.DoFast(callCtx, ops)
	return status, readDirReply{fast: fast, gen: gen}, err
}

func decodeFilehandleAttribute(value []byte) ([]byte, error) {
	if len(value) < 4 {
		return nil, errors.New("FATTR4_FILEHANDLE is truncated before its length")
	}
	n := uint64(binary.BigEndian.Uint32(value[:4]))
	padded := n + xdrPadding(n)
	if padded > uint64(len(value)-4) {
		return nil, fmt.Errorf("FATTR4_FILEHANDLE is truncated: need %d bytes, have %d", padded, len(value)-4)
	}
	if uint64(len(value)-4) != padded {
		return nil, fmt.Errorf("FATTR4_FILEHANDLE has %d trailing bytes", uint64(len(value)-4)-padded)
	}
	// DecodeAttrList returns a complete XDR field. Strip its opaque length and
	// copy the payload so the retained filehandle cannot pin the READDIR reply.
	return append([]byte(nil), value[4:4+int(n)]...), nil
}

// Stat reads the object's mode, two-word filesystem ID, and NFS object type
// without following a cached filehandle through any path operation.
func (c *Client) Stat(ref transport.Ref) (transport.Attr, error) {
	attrs, err := c.getAttributes(context.Background(), ref, "stat", fattr4Mode, fattr4FSID, fattr4Type)
	if err != nil {
		return transport.Attr{}, err
	}
	mode, err := decodeUint32Attribute(attrs, fattr4Mode)
	if err != nil {
		return transport.Attr{}, fmt.Errorf("nfs41: stat %s: %w", ref.Path, err)
	}
	fsidValue, ok := attrs[fattr4FSID]
	if !ok {
		return transport.Attr{}, fmt.Errorf("nfs41: stat %s: server omitted FATTR4_FSID", ref.Path)
	}
	if len(fsidValue) != 16 {
		return transport.Attr{}, fmt.Errorf("nfs41: stat %s: FATTR4_FSID is %d bytes, want 16", ref.Path, len(fsidValue))
	}
	major := binary.BigEndian.Uint64(fsidValue[:8])
	minor := binary.BigEndian.Uint64(fsidValue[8:])
	fileType, err := decodeUint32Attribute(attrs, fattr4Type)
	if err != nil {
		return transport.Attr{}, fmt.Errorf("nfs41: stat %s: %w", ref.Path, err)
	}
	return transport.Attr{
		Mode:      mode & 0o7777,
		FSID:      foldFSID(major, minor),
		IsDir:     xdr.Nfs_ftype4(fileType) == xdr.NF4DIR,
		IsSymlink: xdr.Nfs_ftype4(fileType) == xdr.NF4LNK,
		Kind:      kindFromNFSType(xdr.Nfs_ftype4(fileType)),
	}, nil
}

// SetACL writes one complete fattr4_acl encoding with the anonymous stateid.
func (c *Client) SetACL(ref transport.Ref, acl []byte) error {
	if len(acl) == 0 {
		return errors.New("nfs41: SetACL requires a non-empty ACL")
	}
	return c.setAttributes(context.Background(), ref, "set ACL", []uint32{fattr4ACL}, [][]byte{append([]byte(nil), acl...)})
}

// GetACL reads one complete fattr4_acl encoding.
func (c *Client) GetACL(ref transport.Ref) ([]byte, error) {
	attrs, err := c.getAttributes(context.Background(), ref, "get ACL", fattr4ACL)
	if err != nil {
		return nil, err
	}
	acl, ok := attrs[fattr4ACL]
	if !ok {
		return nil, fmt.Errorf("nfs41: get ACL %s: server omitted FATTR4_ACL", ref.Path)
	}
	return append([]byte(nil), acl...), nil
}

// maxGetAttrsPerCompound is the FlashBlade-imposed ceiling on GETATTR operations
// in a single COMPOUND, confirmed on S200 and S500R1 (RFC-Deviations.md §3).
const maxGetAttrsPerCompound = 4

// GetACLBatch reads ACLs for multiple refs, packing up to 4 PUTFH+GETATTR(ACL)
// pairs per COMPOUND. Results are positional: acls[i] corresponds to refs[i].
func (c *Client) GetACLBatch(refs []transport.Ref) ([][]byte, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	ctx := context.Background()

	filehandles := make([][]byte, len(refs))
	for i, ref := range refs {
		fh, err := c.filehandleForRef(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("nfs41: get ACL batch: resolve %s: %w", ref.Path, err)
		}
		filehandles[i] = fh
	}

	acls := make([][]byte, len(refs))
	for start := 0; start < len(refs); start += maxGetAttrsPerCompound {
		end := start + maxGetAttrsPerCompound
		if end > len(refs) {
			end = len(refs)
		}
		n := end - start

		ops := make([]xdr.Nfs_argop4, 0, n*2)
		for i := start; i < end; i++ {
			ops = append(ops, OpPutFH(filehandles[i]), OpGetAttr(fattr4ACL))
		}

		entry, err := c.pickEntry()
		if err != nil {
			return nil, err
		}
		results, err := c.retryCallOn(ctx, entry, "get ACL batch",
			func(callCtx context.Context) (uint32, []xdr.Nfs_resop4, error) {
				return c.sessionDo(callCtx, entry, ops)
			},
			nil,
		)
		if err != nil {
			return nil, err
		}

		// Results: SEQUENCE + N×(PUTFH + GETATTR)
		expected := 1 + n*2
		if len(results) != expected {
			return nil, fmt.Errorf("nfs41: get ACL batch: expected %d results, got %d", expected, len(results))
		}
		for i := 0; i < n; i++ {
			getAttrIdx := 1 + i*2 + 1 // skip SEQUENCE, then pairs of (PUTFH, GETATTR)
			putFHIdx := 1 + i*2
			if results[putFHIdx].Resop != xdr.OP_PUTFH {
				return nil, fmt.Errorf("nfs41: get ACL batch [%d]: expected PUTFH, got op %d", start+i, results[putFHIdx].Resop)
			}
			if uint32(results[putFHIdx].Opputfh().Status) != NFS4_OK {
				return nil, fmt.Errorf("nfs41: get ACL batch %s: PUTFH status %d",
					refs[start+i].Path, results[putFHIdx].Opputfh().Status)
			}
			attrs, err := getAttrResult(results[getAttrIdx])
			if err != nil {
				return nil, fmt.Errorf("nfs41: get ACL batch %s: %w", refs[start+i].Path, err)
			}
			acl, ok := attrs[fattr4ACL]
			if !ok {
				return nil, fmt.Errorf("nfs41: get ACL batch %s: server omitted FATTR4_ACL", refs[start+i].Path)
			}
			acls[start+i] = append([]byte(nil), acl...)
		}
	}
	return acls, nil
}

// Chmod writes mode in one COMPOUND: PUTFH + SETATTR(FATTR4_MODE), addressing
// the same filehandle every other method on this client uses.
//
// The Transport contract says Chmod follows symlinks, and on the kernel it does,
// because syscall.Chmod does. This transport cannot reproduce that by resolving
// the path, and an earlier revision of this method claimed otherwise: NFSv4
// LOOKUP does not follow symbolic links (RFC 8881 section 18.25). For a final
// component it returns the link's own filehandle, and for an intermediate one it
// returns NFS4ERR_SYMLINK. So a PUTROOTFH + LOOKUP* + GETFH chain yields exactly
// the handle ref.FH already carries, at a cost proportional to path depth, and
// buys no following at all. Real following would need READLINK plus client-side
// re-resolution per component.
//
// Nothing here needs it. Traversal tags symlinks and skips them (see the
// Transport doc comment and walk.go's IsSymlink-first check), so no symlink path
// reaches this method. If that ever changes, the fix is READLINK, not a LOOKUP
// chain.
func (c *Client) Chmod(ref transport.Ref, mode uint32) error {
	if ref.Path == "" {
		return errors.New("nfs41: chmod requires a path")
	}
	return c.setAttributes(context.Background(), ref, "chmod", []uint32{fattr4Mode}, [][]byte{encodeUint32Attribute(mode & 0o7777)})
}

// Chown addresses the supplied filehandle directly, matching lchown's no-follow
// behavior. Decimal owner strings are the NFSv4 numeric-owner fallback.
func (c *Client) Chown(ref transport.Ref, uid, gid int) error {
	if uid < -1 || gid < -1 {
		return fmt.Errorf("nfs41: chown %s: uid and gid must be -1 or non-negative", ref.Path)
	}
	var bits []uint32
	var values [][]byte
	if uid != -1 {
		bits = append(bits, fattr4Owner)
		values = append(values, encodeOpaqueAttribute([]byte(strconv.Itoa(uid))))
	}
	if gid != -1 {
		bits = append(bits, fattr4OwnerGroup)
		values = append(values, encodeOpaqueAttribute([]byte(strconv.Itoa(gid))))
	}
	if len(bits) == 0 {
		return nil
	}
	return c.setAttributes(context.Background(), ref, "chown", bits, values)
}

// probeDirPrefix marks a disposable probe directory as permissionreset's own, the
// same convention os.CreateTemp uses on the kernel transport.
const probeDirPrefix = ".permissionreset-probe-"

// probeName returns a collision-safe disposable probe directory name. It is a
// var, not a plain function call inside ProbeTarget, so probeTargetWith's
// tests can supply their own deterministic sequence without touching
// crypto/rand.
func probeName() string {
	var b [16]byte
	if _, err := cryptorandRead(b[:]); err != nil {
		// crypto/rand failing is effectively unrecoverable on any real host;
		// fall back to a timestamp-based name rather than panicking -- a
		// collision here just costs one extra retry in probeTargetWith.
		return fmt.Sprintf("%s%d", probeDirPrefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s%x", probeDirPrefix, b)
}

// probeTargetWith implements ProbeTarget's policy -- resolve the probe
// directory, create a disposable child under it with a collision-safe name,
// retry on a name collision, and fail closed (never falling back to a live
// object) on any other create failure -- against injectable seams, so the
// policy itself is testable without a live or fake RPC server.
//
// mkdir and remove operate on (dirRef, name) rather than a single combined
// path so a fake can assert exactly which directory a probe was created
// under without parsing a joined path back apart.
func probeTargetWith(
	resolveDir func() (transport.Ref, error),
	mkdir func(dirRef transport.Ref, name string) (transport.Ref, error),
	remove func(dirRef transport.Ref, name string) error,
	newName func() string,
) (transport.Ref, bool, func() error, error) {
	dirRef, err := resolveDir()
	if err != nil {
		return transport.Ref{}, false, nil, fmt.Errorf("nfs41: resolve probe directory: %w", err)
	}

	const maxAttempts = 8
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		name := newName()
		child, err := mkdir(dirRef, name)
		if err == nil {
			return child, true, func() error {
				if err := remove(dirRef, name); err != nil {
					return fmt.Errorf("nfs41: remove disposable probe %s/%s: %w", dirRef.Path, name, err)
				}
				return nil
			}, nil
		}
		if IsExist(err) {
			lastErr = err
			continue
		}
		// Any failure other than a name collision is reported and the probe
		// fails closed here: it never substitutes the export root, the
		// requested directory, or any other existing object as the probe
		// target. Restoring an NFS ACL on a real object cannot reconstruct
		// SMB inheritance metadata lost in translation (PS-01), so a target
		// this client cannot safely dispose of is not a target at all.
		return transport.Ref{}, false, nil, fmt.Errorf(
			"nfs41: create disposable probe in %s: %w (disposable probing is required; refusing to fall back to a live object)",
			dirRef.Path, err)
	}
	return transport.Ref{}, false, nil, fmt.Errorf(
		"nfs41: create disposable probe in %s: exhausted %d collision attempts: %w",
		dirRef.Path, maxAttempts, lastErr)
}

// cryptorandRead is a var so tests could, if ever needed, force the
// time-based fallback path without actually breaking crypto/rand for the
// process.
var cryptorandRead = cryptoRandRead

// ProbeTarget returns a disposable probe directory for the caller to apply
// the real spec to, never the live export root or the requested directory
// itself: this client implements Mkdir and Remove, so unlike the design this
// replaces it needs no live-object fallback. The probe directory is created
// under the resolved target directory (or the export root when ref.Path is
// empty) with a collision-safe throwaway name and removed by the returned
// cleanup.
//
// isDir is always true: the probe is a directory, matching the kernel
// transport's isDir=false-for-a-file contract in spirit (an object the
// caller may safely apply either file or directory spec rules to, per which
// isDir says) but using a directory here because Mkdir, not CreateFile, is
// what this client already uses to seed test trees under
// internal/treegen -- one creation path, already exercised against real
// arrays.
//
// If disposable probing is unsupported on this target (the create fails for
// any reason other than a name collision, including cancellation, denial, or
// a path that does not resolve), ProbeTarget fails before any live-object ACL
// mutation, with an actionable error. It never degrades to probing a real,
// existing object.
func (c *Client) ProbeTarget(ref transport.Ref) (transport.Ref, bool, func() error, error) {
	if c == nil {
		return transport.Ref{}, false, nil, errors.New("nfs41: nil client")
	}
	if err := c.checkOpen(); err != nil {
		return transport.Ref{}, false, nil, err
	}
	return probeTargetWith(
		func() (transport.Ref, error) {
			if ref.Path == "" {
				return c.currentRef(c.exportRoot), nil
			}
			fh, err := c.resolvePath(context.Background(), ref.Path)
			if err != nil {
				return transport.Ref{}, err
			}
			return transport.Ref{Path: ref.Path, FH: fh}, nil
		},
		func(dirRef transport.Ref, name string) (transport.Ref, error) {
			return c.Mkdir(dirRef, name, nil, 0o700)
		},
		func(dirRef transport.Ref, name string) error {
			return c.Remove(dirRef, name)
		},
		probeName,
	)
}

// CreateFile creates a regular file in dirRef with its ACL and mode set in one
// COMPOUND: PUTFH(dir) + OPEN(CREATE,GUARDED4) + GETFH + CLOSE(current-stateid).
// Returns the new file's Ref with filehandle populated.
func (c *Client) CreateFile(dirRef transport.Ref, name string, acl []byte, mode uint32) (transport.Ref, error) {
	entry, err := c.pickEntry()
	if err != nil {
		return transport.Ref{}, err
	}
	dirFH, err := c.filehandleForRef(context.Background(), dirRef)
	if err != nil {
		return transport.Ref{}, fmt.Errorf("nfs41: create file %s/%s: %w", dirRef.Path, name, err)
	}

	clientID := xdr.Clientid4(entry.session.reg.id)
	owner := entry.session.reg.owner

	var bits []uint32
	var values [][]byte
	if len(acl) > 0 {
		bits = append(bits, fattr4ACL)
		values = append(values, acl)
	}
	bits = append(bits, fattr4Mode)
	values = append(values, encodeUint32Attribute(mode&0o7777))

	ops := []xdr.Nfs_argop4{
		OpPutFH(dirFH),
		OpOpenCreate(name, clientID, owner, bits, values),
		OpGetFH(),
		OpCloseCurrent(),
	}

	label := "create file " + name
	results, err := c.retryCallOn(context.Background(), entry, label, func(ctx context.Context) (uint32, []xdr.Nfs_resop4, error) {
		return c.sessionDo(ctx, entry, ops)
	}, nil)
	if err != nil {
		return transport.Ref{}, fmt.Errorf("nfs41: %s in %s: %w", label, dirRef.Path, err)
	}

	// results: [SEQUENCE, PUTFH, OPEN, GETFH, CLOSE]
	if len(results) < 5 {
		return transport.Ref{}, fmt.Errorf("nfs41: %s in %s: short result (%d ops)", label, dirRef.Path, len(results))
	}
	if s := uint32(results[3].Resop); s != uint32(xdr.OP_GETFH) {
		return transport.Ref{}, fmt.Errorf("nfs41: %s in %s: expected GETFH at position 3, got op %d", label, dirRef.Path, s)
	}
	fh := append([]byte(nil), results[3].Opgetfh().Resok4().Object...)
	childPath := path.Join(dirRef.Path, name)
	return transport.Ref{Path: childPath, FH: fh}, nil
}

// Mkdir creates a directory in dirRef with its ACL and mode set in one
// COMPOUND: PUTFH(dir) + CREATE(NF4DIR) + GETFH. Returns the new dir's Ref.
func (c *Client) Mkdir(dirRef transport.Ref, name string, acl []byte, mode uint32) (transport.Ref, error) {
	dirFH, err := c.filehandleForRef(context.Background(), dirRef)
	if err != nil {
		return transport.Ref{}, fmt.Errorf("nfs41: mkdir %s/%s: %w", dirRef.Path, name, err)
	}
	entry, err := c.pickEntry()
	if err != nil {
		return transport.Ref{}, err
	}

	var bits []uint32
	var values [][]byte
	if len(acl) > 0 {
		bits = append(bits, fattr4ACL)
		values = append(values, acl)
	}
	bits = append(bits, fattr4Mode)
	values = append(values, encodeUint32Attribute(mode&0o7777))

	ops := []xdr.Nfs_argop4{
		OpPutFH(dirFH),
		OpCreateDir(name, bits, values),
		OpGetFH(),
	}

	label := "mkdir " + name
	results, err := c.retryCallOn(context.Background(), entry, label, func(ctx context.Context) (uint32, []xdr.Nfs_resop4, error) {
		return c.sessionDo(ctx, entry, ops)
	}, nil)
	if err != nil {
		return transport.Ref{}, fmt.Errorf("nfs41: %s in %s: %w", label, dirRef.Path, err)
	}

	// results: [SEQUENCE, PUTFH, CREATE, GETFH]
	if len(results) < 4 {
		return transport.Ref{}, fmt.Errorf("nfs41: %s in %s: short result (%d ops)", label, dirRef.Path, len(results))
	}
	fh := append([]byte(nil), results[3].Opgetfh().Resok4().Object...)
	childPath := path.Join(dirRef.Path, name)
	return transport.Ref{Path: childPath, FH: fh}, nil
}

// Remove removes a file or empty directory in dirRef by name.
func (c *Client) Remove(dirRef transport.Ref, name string) error {
	dirFH, err := c.filehandleForRef(context.Background(), dirRef)
	if err != nil {
		return fmt.Errorf("nfs41: remove %s/%s: %w", dirRef.Path, name, err)
	}
	entry, err := c.pickEntry()
	if err != nil {
		return err
	}

	ops := []xdr.Nfs_argop4{OpPutFH(dirFH), OpRemove(name)}

	label := "remove " + name
	_, err = c.retryCallOn(context.Background(), entry, label, func(ctx context.Context) (uint32, []xdr.Nfs_resop4, error) {
		return c.sessionDo(ctx, entry, ops)
	}, nil)
	if err != nil {
		return fmt.Errorf("nfs41: %s in %s: %w", label, dirRef.Path, err)
	}
	return nil
}

// Close prevents new operations, then destroys every session best-effort,
// closes every RPC connection, and returns the same result on every invocation.
// Concurrent callers wait for the one teardown to finish before reading it.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		// No client-wide lock is needed to serialize against recovery any more.
		// Recovery used to replace a shared registration and publish a whole fresh
		// pool, so Close had to exclude it; now it replaces one entry while holding
		// that entry's lifecycle lock, and the loop below takes the same lock per
		// entry. A rebuild in flight therefore either completes before Close reaches
		// its entry — and the replacement is torn down here — or observes
		// checkOpen's closed flag and abandons.
		var errs []error
		for _, entry := range c.pool {
			entry.lifecycle.Lock()
			if entry.session != nil {
				ctx, cancel := context.WithTimeout(context.Background(), c.cfg.RPCTimeout)
				errs = append(errs, entry.session.Destroy(ctx))
				cancel()
			}
			if entry.conn != nil {
				errs = append(errs, entry.conn.Close())
			}
			entry.lifecycle.Unlock()
		}
		c.closeErr = errors.Join(errs...)
		close(c.closeDone)
	})
	<-c.closeDone
	return c.closeErr
}

func (c *Client) checkOpen() error {
	if c.closed.Load() {
		return errors.New("nfs41: client is closed")
	}
	return nil
}

// fhCacheMax bounds fhCache. Steady state holds the export and target roots and
// nothing else, so this is headroom for a stale-filehandle storm rather than a
// working-set estimate: 4096 entries is well under a megabyte at the ~190 bytes
// per entry noted on the field, small enough not to matter and large enough that
// no realistic recovery burst reaches it.
const fhCacheMax = 4096

func (c *Client) currentRef(base transport.Ref) transport.Ref {
	out := cloneRef(base)
	if fh, ok := c.cachedFilehandle(base.Path); ok {
		out.FH = fh
	}
	return out
}

func cloneRef(ref transport.Ref) transport.Ref {
	return transport.Ref{Path: ref.Path, FH: append([]byte(nil), ref.FH...)}
}

func (c *Client) cachedFilehandle(objectPath string) ([]byte, bool) {
	key := path.Clean(objectPath)
	c.cacheMu.RLock()
	fh, ok := c.fhCache[key]
	c.cacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	return append([]byte(nil), fh...), true
}

func (c *Client) cacheFilehandle(objectPath string, fh []byte) {
	key := path.Clean(objectPath)
	copyFH := append([]byte(nil), fh...)
	c.cacheMu.Lock()
	// Dropping the whole map beats evicting one entry chosen at random: without
	// an access order there is nothing to choose by, and a miss costs one
	// re-resolve rather than a wrong answer. Reaching this at all means a
	// fault-path storm, not steady state.
	//
	// The two roots survive the drop. Every other entry can be reconstructed by
	// the caller, which still holds the object's filehandle in its own Ref and
	// hands it back on the next call; the roots' entries are the only ones with
	// no other durable home, because Root and ProbeTarget read them through
	// currentRef and c.root/c.exportRoot still hold the handle negotiated at
	// Init. Dropping a root's refreshed handle therefore un-recovers it
	// permanently, and every later call on it pays NFS4ERR_STALE plus a backoff
	// before resolving again.
	if len(c.fhCache) >= fhCacheMax {
		if _, present := c.fhCache[key]; !present {
			fresh := make(map[string][]byte, fhCacheMax/4)
			for _, rootPath := range [...]string{c.exportRoot.Path, c.root.Path} {
				if rootPath == "" {
					continue
				}
				rootKey := path.Clean(rootPath)
				if fh, ok := c.fhCache[rootKey]; ok {
					fresh[rootKey] = fh
				}
			}
			c.fhCache = fresh
		}
	}
	c.fhCache[key] = copyFH
	c.cacheMu.Unlock()
}

func (c *Client) filehandleForRef(ctx context.Context, ref transport.Ref) ([]byte, error) {
	if ref.Path == "" {
		return nil, errors.New("nfs41: object reference has an empty path")
	}
	if !strings.HasPrefix(ref.Path, "/") {
		return nil, fmt.Errorf("nfs41: object path must be absolute: %q", ref.Path)
	}
	// The cache wins over a caller's old Ref.FH so stale-filehandle recovery
	// persists across later operations on the same Ref. READDIR deliberately does
	// NOT seed it: the filehandles it returns reach the apply workers inside the
	// Dirent, and caching them here as well is what made this map O(tree).
	if fh, ok := c.cachedFilehandle(ref.Path); ok {
		return fh, nil
	}
	if len(ref.FH) != 0 {
		// Not cached. The caller already holds this filehandle and hands it back
		// on every subsequent call, so storing a second copy per object buys
		// nothing and is exactly what made this map tree-sized.
		return append([]byte(nil), ref.FH...), nil
	}
	return c.resolvePath(ctx, ref.Path)
}

// resolvePath performs one PUTROOTFH + LOOKUP* + GETFH chain and caches a copy
// of the returned handle rather than retaining a slice into the RPC reply.
func (c *Client) resolvePath(ctx context.Context, objectPath string) ([]byte, error) {
	cleaned, err := normalizeAbsolutePath("object", objectPath, "")
	if err != nil {
		return nil, err
	}
	// Resolve from the export root's filehandle whenever it is known, which is
	// every call except the one at Init that resolves the export itself.
	//
	// This is not an optimisation. MEASURED 2026-08-21 on an S200 (Purity 4.8.0):
	// a FlashBlade refuses the LOOKUP that follows the pseudo-filesystem crossing
	// inside one COMPOUND, so PUTROOTFH + LOOKUP export + LOOKUP child returns
	// NFS4ERR_NOENT and no path below the export root could be addressed at all.
	// Chaining WITHIN a filesystem is fine, and Init already holds the export
	// root's filehandle, so starting from PUTFH costs nothing and never crosses.
	if base, rel, ok := c.resolveBaseFor(cleaned); ok {
		return c.resolveComponents(ctx, cleaned, cleaned, OpPutFH(base), rel)
	}

	// No export root yet: walk from the pseudo-filesystem root, ONE component per
	// COMPOUND, carrying the filehandle forward with PUTFH. One round trip per
	// component rather than one in total, which is affordable only because this
	// path runs once per client for a shallow export path.
	components := []string{}
	if cleaned != "/" {
		components = strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	}
	if len(components) == 0 {
		return c.resolveComponents(ctx, cleaned, cleaned, OpPutRootFH(), nil)
	}
	// Only the LAST step is cached under `cleaned`. Caching an intermediate step
	// there would file a parent directory's filehandle under the full path and
	// hand it to every later operation on that path.
	position := OpPutRootFH()
	for i, component := range components {
		cacheAs := ""
		if i == len(components)-1 {
			cacheAs = cleaned
		}
		fh, err := c.resolveComponents(ctx, cleaned, cacheAs, position, []string{component})
		if err != nil {
			return nil, err
		}
		if i == len(components)-1 {
			return fh, nil
		}
		position = OpPutFH(fh)
	}
	return nil, fmt.Errorf("nfs41: resolve %s: no components walked", cleaned)
}

// resolveBaseFor returns the export root filehandle and the components of
// objectPath below it, when objectPath lies within a known export root.
func (c *Client) resolveBaseFor(objectPath string) (base []byte, components []string, ok bool) {
	root := c.exportRoot
	if len(root.FH) == 0 || root.Path == "" {
		return nil, nil, false
	}
	rootPath := path.Clean(root.Path)
	if objectPath == rootPath {
		return append([]byte(nil), root.FH...), nil, true
	}
	prefix := rootPath
	if prefix != "/" {
		prefix += "/"
	}
	if !strings.HasPrefix(objectPath, prefix) {
		return nil, nil, false
	}
	rest := strings.TrimPrefix(objectPath, prefix)
	if rest == "" {
		return append([]byte(nil), root.FH...), nil, true
	}
	return append([]byte(nil), root.FH...), strings.Split(rest, "/"), true
}

// resolveComponents issues one COMPOUND: the supplied positioning operation,
// a LOOKUP per component, then GETFH. label names the whole resolution for error
// messages; cacheAs is the path the resulting filehandle is cached under, and is
// empty for an intermediate step that resolves only part of label.
func (c *Client) resolveComponents(ctx context.Context, label, cacheAs string, position xdr.Nfs_argop4, components []string) ([]byte, error) {
	ops := make([]xdr.Nfs_argop4, 0, len(components)+2)
	ops = append(ops, position)
	for _, component := range components {
		ops = append(ops, OpLookup(component))
	}
	ops = append(ops, OpGetFH())

	entry, err := c.pickEntry()
	if err != nil {
		return nil, err
	}
	results, err := c.retryCallOn(ctx, entry, "resolve "+label, func(callCtx context.Context) (uint32, []xdr.Nfs_resop4, error) {
		return c.sessionDo(callCtx, entry, ops)
	}, nil)
	if err != nil {
		return nil, err
	}
	if len(results) != len(ops)+1 {
		return nil, fmt.Errorf("nfs41: resolve %s returned %d results for %d operations", label, len(results), len(ops)+1)
	}
	last := results[len(results)-1]
	if last.Resop != xdr.OP_GETFH {
		return nil, fmt.Errorf("nfs41: resolve %s ended with result %s, want GETFH", label, last.Resop)
	}
	fh, err := getFHResult(last)
	if err != nil {
		return nil, fmt.Errorf("nfs41: resolve %s: %w", label, err)
	}
	if cacheAs != "" {
		c.cacheFilehandle(cacheAs, fh)
	}
	return append([]byte(nil), fh...), nil
}

func getFHResult(result xdr.Nfs_resop4) (fh []byte, err error) {
	defer recoverXDR(&err)
	res := result.Opgetfh()
	if uint32(res.Status) != NFS4_OK {
		return nil, fmt.Errorf("GETFH result status %s (%d)", res.Status, res.Status)
	}
	return append([]byte(nil), res.Resok4().Object...), nil
}

func (c *Client) getAttributes(ctx context.Context, ref transport.Ref, label string, bits ...uint32) (map[uint32][]byte, error) {
	reply, err := c.callRefFast(ctx, ref, label, func(fh []byte) []xdr.Nfs_argop4 {
		return []xdr.Nfs_argop4{OpPutFH(fh), OpGetAttr(bits...)}
	})
	if err != nil {
		return nil, err
	}
	if reply.fast != nil {
		if len(reply.fast) != 3 || reply.fast[2].Op != uint32(xdr.OP_GETATTR) {
			return nil, fmt.Errorf("nfs41: %s %s returned an unexpected result sequence", label, ref.Path)
		}
		if reply.fast[2].Status != NFS4_OK {
			return nil, fmt.Errorf("nfs41: %s %s: GETATTR result status %s (%d)", label, ref.Path,
				xdr.Nfsstat4(reply.fast[2].Status), reply.fast[2].Status)
		}
		// The values alias the reply buffer, which the next call on this session
		// overwrites. Callers keep these -- the gate keeps a max file size, Stat
		// keeps a mode -- so the map is copied out here rather than trusting every
		// caller to remember.
		attrs := make(map[uint32][]byte, len(reply.fast[2].Attrs))
		for _, pair := range reply.fast[2].Attrs {
			attrs[pair.bit] = append([]byte(nil), pair.value...)
		}
		return attrs, nil
	}
	results := reply.gen
	if len(results) != 3 || results[2].Resop != xdr.OP_GETATTR {
		return nil, fmt.Errorf("nfs41: %s %s returned an unexpected result sequence", label, ref.Path)
	}
	attrs, err := getAttrResult(results[2])
	if err != nil {
		return nil, fmt.Errorf("nfs41: %s %s: %w", label, ref.Path, err)
	}
	return attrs, nil
}

func getAttrResult(result xdr.Nfs_resop4) (attrs map[uint32][]byte, err error) {
	defer recoverXDR(&err)
	res := result.Opgetattr()
	if uint32(res.Status) != NFS4_OK {
		return nil, fmt.Errorf("GETATTR result status %s (%d)", res.Status, res.Status)
	}
	got := res.Resok4().Obj_attributes
	return DecodeAttrList(got.Attrmask, got.Attr_vals)
}

func (c *Client) setAttributes(ctx context.Context, ref transport.Ref, label string, bits []uint32, values [][]byte) error {
	reply, err := c.callRefFast(ctx, ref, label, func(fh []byte) []xdr.Nfs_argop4 {
		return []xdr.Nfs_argop4{OpPutFH(fh), OpSetAttr(bits, values)}
	})
	if err != nil {
		return err
	}
	if reply.fast != nil {
		if len(reply.fast) != 3 || reply.fast[2].Op != uint32(xdr.OP_SETATTR) {
			return fmt.Errorf("nfs41: %s %s returned an unexpected result sequence", label, ref.Path)
		}
		res := reply.fast[2]
		if res.Status != NFS4_OK {
			return fmt.Errorf("nfs41: %s %s result status %s (%d)", label, ref.Path,
				xdr.Nfsstat4(res.Status), res.Status)
		}
		for _, bit := range bits {
			if !slices.Contains(res.SetBits, bit) {
				return fmt.Errorf("nfs41: %s %s: server did not report attribute %d as set", label, ref.Path, bit)
			}
		}
		return nil
	}
	results := reply.gen
	if len(results) != 3 || results[2].Resop != xdr.OP_SETATTR {
		return fmt.Errorf("nfs41: %s %s returned an unexpected result sequence", label, ref.Path)
	}
	res := results[2].Opsetattr()
	if uint32(res.Status) != NFS4_OK {
		return fmt.Errorf("nfs41: %s %s result status %s (%d)", label, ref.Path, res.Status, res.Status)
	}
	for _, bit := range bits {
		if !attributeBitmapHas(res.Attrsset, bit) {
			return fmt.Errorf("nfs41: %s %s: server did not report attribute %d as set", label, ref.Path, bit)
		}
	}
	return nil
}

func attributeBitmapHas(bitmap []uint32, bit uint32) bool {
	word := int(bit / 32)
	return word < len(bitmap) && bitmap[word]&(uint32(1)<<(bit%32)) != 0
}

// callRefFast issues one COMPOUND against ref's filehandle, re-resolving the
// path and retrying once if the filehandle turns out to be stale.
//
// The reply comes back decoded by the hand-written decoder where it can be and by
// the generated one otherwise, so callers must handle both shapes; see
// Session.DoFast. There was a generated-only twin of this alongside it, kept for
// operations the fast decoder had not been taught. It outlived its last caller,
// so it is gone: every per-object operation now goes through here, and the
// generated decoder is reached only via Session.Do (session setup) and
// resolveComponents (path resolution).
func (c *Client) callRefFast(ctx context.Context, ref transport.Ref, label string, build func([]byte) []xdr.Nfs_argop4) (readDirReply, error) {
	fh, err := c.filehandleForRef(ctx, ref)
	if err != nil {
		return readDirReply{}, fmt.Errorf("nfs41: %s %s: %w", label, ref.Path, err)
	}
	entry, err := c.pickEntry()
	if err != nil {
		return readDirReply{}, fmt.Errorf("nfs41: %s %s: %w", label, ref.Path, err)
	}

	return retryCall(c, ctx, entry, label+" "+ref.Path, func(callCtx context.Context) (uint32, readDirReply, error) {
		return c.sessionDoFast(callCtx, entry, build(append([]byte(nil), fh...)))
	}, func(recoveryCtx context.Context) error {
		resolved, err := c.resolvePath(recoveryCtx, ref.Path)
		if err != nil {
			return err
		}
		fh = resolved
		return nil
	})
}

func (c *Client) pickEntry() (*poolEntry, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if len(c.pool) == 0 {
		return nil, errors.New("nfs41: client has no connections")
	}
	index := (c.nextEntry.Add(1) - 1) % uint64(len(c.pool))
	return c.pool[index], nil
}

func (c *Client) sessionDo(ctx context.Context, entry *poolEntry, ops []xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4, error) {
	if err := c.checkOpen(); err != nil {
		return 0, nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, c.cfg.RPCTimeout)
	defer cancel()
	return entry.session.Do(callCtx, ops)
}

func (c *Client) retryCallOn(
	ctx context.Context,
	entry *poolEntry,
	label string,
	attempt func(context.Context) (uint32, []xdr.Nfs_resop4, error),
	recoverStale func(context.Context) error,
) ([]xdr.Nfs_resop4, error) {
	return retryCall(c, ctx, entry, label, attempt, recoverStale)
}

// retryCall is retryCallOn with the result type as a parameter, so the READDIR
// fast path shares this loop rather than owning a second copy of it. Go does not
// allow type parameters on methods, which is the only reason it is a function.
//
// Everything subtle lives here: which statuses retry, which rebuild the session,
// how a stale filehandle is recovered, and the generation check that stops two
// failed callers rebuilding the same session twice. A duplicate of this loop for
// the fast path would be the most likely place for the two paths to drift.
func retryCall[T any](
	c *Client,
	ctx context.Context,
	entry *poolEntry,
	label string,
	attempt func(context.Context) (uint32, T, error),
	recoverStale func(context.Context) error,
) (T, error) {
	var zero T
	if ctx == nil {
		return zero, errors.New("nfs41: nil context")
	}
	var lastErr error
	for attemptNumber := 0; attemptNumber < c.retry.Budget; attemptNumber++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		entry.lifecycle.RLock()
		failedGeneration, failedRegistration := entry.generation, entry.session.reg
		status, results, callErr := attempt(ctx)
		entry.lifecycle.RUnlock()
		if callErr == nil && status == NFS4_OK {
			return results, nil
		}
		if callErr != nil {
			lastErr = callErr
		} else {
			lastErr = &StatusError{Op: label, Status: status}
		}

		if attemptNumber+1 == c.retry.Budget {
			return zero, fmt.Errorf("nfs41: %s failed after %d attempts: %w", label, c.retry.Budget, lastErr)
		}

		if callErr == nil && (status == NFS4ERR_STALE || status == NFS4ERR_BADHANDLE) {
			if recoverStale == nil {
				return zero, fmt.Errorf("nfs41: %s: %w", label, lastErr)
			}
			if err := waitForBackoff(ctx, c.retry.backoff(attemptNumber)); err != nil {
				return zero, err
			}
			if err := recoverStale(ctx); err != nil {
				return zero, fmt.Errorf("nfs41: %s: recover stale filehandle: %w", label, err)
			}
			continue
		}

		switch classify(status, callErr) {
		case dispRetry:
			if err := waitForBackoff(ctx, c.retry.backoff(attemptNumber)); err != nil {
				return zero, err
			}
		case dispRebuild:
			if err := c.rebuildEntry(ctx, entry, failedGeneration, failedRegistration); err != nil {
				return zero, fmt.Errorf("nfs41: %s: rebuild session after %v: %w", label, lastErr, err)
			}
		case dispFail:
			return zero, fmt.Errorf("nfs41: %s: %w", label, lastErr)
		}
	}
	return zero, fmt.Errorf("nfs41: %s: retry budget exhausted", label)
}

func (c *Client) rebuildEntry(ctx context.Context, entry *poolEntry, failedGeneration uint64, failedRegistration *ClientRegistration) error {
	// Only operations on this entry wait. A dead session or connection must not
	// stall calls using the rest of the pool.
	entry.lifecycle.Lock()
	if err := c.checkOpen(); err != nil {
		entry.lifecycle.Unlock()
		return err
	}
	// Another failed caller may have rebuilt while this caller waited for the
	// entry lock. Its failure describes the old session, not the replacement.
	if entry.generation != failedGeneration {
		entry.lifecycle.Unlock()
		return nil
	}

	observedRegistration := entry.session.reg
	if observedRegistration != failedRegistration {
		entry.lifecycle.Unlock()
		return nil
	}
	rebuildCtx, cancel := context.WithTimeout(ctx, c.cfg.RPCTimeout)
	err := entry.session.Rebuild(rebuildCtx)
	cancel()
	if err == nil {
		entry.generation++
		entry.lifecycle.Unlock()
		return nil
	}
	// A dead connection and a stale clientid now have the SAME remedy: replace
	// this entry, which re-registers it. Under a shared registration a stale
	// clientid invalidated every session at once and needed a coordinated
	// whole-pool rebuild; with one clientid per entry it invalidates exactly one
	// entry, and the other entries' clientids are untouched and still valid.
	if !errors.Is(err, ErrConnClosed) && !isStaleClientID(err) {
		entry.lifecycle.Unlock()
		return err
	}

	replacement, err := c.newPoolEntry(ctx)
	if err != nil {
		entry.lifecycle.Unlock()
		return err
	}
	oldConn := entry.conn
	entry.conn = replacement.conn
	entry.session = replacement.session
	entry.generation++
	entry.lifecycle.Unlock()
	return oldConn.Close()
}

func isStaleClientID(err error) bool {
	var createErr *SessionCreateError
	return errors.As(err, &createErr) && createErr.Status == NFS4ERR_STALE_CLIENTID
}

func waitForBackoff(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func decodeUint32Attribute(attrs map[uint32][]byte, bit uint32) (uint32, error) {
	value, ok := attrs[bit]
	if !ok {
		return 0, fmt.Errorf("server omitted attribute %d", bit)
	}
	if len(value) != 4 {
		return 0, fmt.Errorf("attribute %d is %d bytes, want 4", bit, len(value))
	}
	return binary.BigEndian.Uint32(value), nil
}

func decodeUint64Attribute(attrs map[uint32][]byte, bit uint32) (uint64, error) {
	value, ok := attrs[bit]
	if !ok {
		return 0, fmt.Errorf("server omitted attribute %d", bit)
	}
	if len(value) != 8 {
		return 0, fmt.Errorf("attribute %d is %d bytes, want 8", bit, len(value))
	}
	return binary.BigEndian.Uint64(value), nil
}

func encodeUint32Attribute(value uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, value)
}

func encodeOpaqueAttribute(value []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(value)))
	out = append(out, value...)
	return append(out, make([]byte, xdrPad(len(value)))...)
}

// foldFSID preserves both words of fsid4 in the single equality token exposed
// by transport.Attr. A zero minor leaves the common readable major unchanged.
func foldFSID(major, minor uint64) uint64 {
	return major ^ (minor * 0x9E3779B97F4A7C15)
}

func kindFromNFSType(ft xdr.Nfs_ftype4) transport.Kind {
	switch ft {
	case xdr.NF4REG:
		return transport.KindRegular
	case xdr.NF4DIR:
		return transport.KindDirectory
	case xdr.NF4LNK:
		return transport.KindSymlink
	default:
		return transport.KindOther
	}
}

var _ transport.Transport = (*Client)(nil)

// WriteStats sums the write-gathering counters across the connection pool. See
// Conn.WriteStats for what the numbers mean and what they do not.
func (c *Client) WriteStats() (batches, records uint64) {
	if c == nil {
		return 0, 0
	}
	for _, entry := range c.pool {
		entry.lifecycle.RLock()
		conn := entry.conn
		entry.lifecycle.RUnlock()
		if conn == nil {
			continue
		}
		b, r := conn.WriteStats()
		batches += b
		records += r
	}
	return batches, records
}
