# Transports

The `--transport` flag selects how permissionreset reaches the target:

- `kernel` (default) uses the mounted-export path. This is the path that has always existed: `TARGET` is a local path on an NFS mount.
- `userspace` connects directly to NFSv4.1 without using a local mount. This transport requires a FlashBlade and refuses to run against other servers.

For `userspace`, `--server` and `--export` are required. `--server` is the NFS server in `HOST[:PORT]` form; the port defaults to `2049`. IPv6 literals may be given bare (`fd00::1`) or bracketed (`[fd00::1]:2049`). `--export` is the export path on that server. Both flags are rejected with `--transport=kernel`.

With `--transport=userspace`, `TARGET` is a **server-side path** interpreted relative to the server, not a local mounted path. Give the path as it exists on the server; permissionreset does not look it up through the local filesystem.

The userspace transport tunables are:

| Flag | Meaning and default |
|------|---------------------|
| `--connections` | TCP connections, one session each (default `16`). Each connection registers as an independent NFSv4.1 client, because a FlashBlade permits only one session per client ID. In-flight capacity is therefore `--connections` × granted slots. |
| `--slots` | Requested per-session slots; `0` requests the client default of 128 (default `0`). The server's `ca_maxrequests` grant caps the request either way, so this is a request and not a hard cap. |
| `--max-ops-per-compound` | `0` uses the server's `ca_maxoperations` (default `0`). **Not enforced yet** — the current phase issues only fixed two- and three-operation COMPOUNDs, so the value is validated and then unused. |
| `--rpc-timeout` | Per-COMPOUND deadline (default `30s`) |
| `--retry-budget` | Attempts before an object is failed (default `5`) |
| `--retry-base-delay` | Exponential backoff base (default `100ms`) |

The userspace transport rejects one thing, because it reaches the tree through a mounted path that userspace does not have:

- `--pfind` — pfind enumerates through a mounted path and cannot be fused with the fix.

`--validate` is fully supported under `--transport=userspace`, with COMPOUND batching that packs up to 4 PUTFH+GETATTR(ACL) pairs per RPC (the FlashBlade cap, confirmed on S200 and S500R1). Measured at 133–140K checks/sec on 1.13M objects.

Under `--transport=userspace`, `--resume` re-resolves directory filehandles by `LOOKUP` while descending to the checkpoint frontier — there is no persisted filehandle cache, so this cost is proportional to tree depth, not tree size.

## Platform availability

| | Linux | macOS |
| --- | --- | --- |
| `--transport=kernel` | yes, the default | refused by value; the flag stays in `--help` |
| `--transport=userspace` | yes | yes, the only option and the default |
| `--pfind` / `--no-pfind` | yes | gated: absent from `--help`, refused if typed |
| smb backend (`protocol: smb`) | no | no |
| `sweep` (any invocation) | yes | refused at startup |
| `generate-tree` | yes | not ported; it writes through a mounted path |
| `sec=krb5`/`krb5i`/`krb5p` | yes, kernel transport only | no |

Two different gates are in play, and they read differently to an operator.

A **gated flag** (`--pfind`, `--no-pfind`) is registered on every platform but carries no usage
text where it cannot work, so it is absent from `--help`, and typing it is refused. It is
registered rather than omitted so that a command line copied from a Linux host gets a refusal that
names the missing capability instead of the flag package's "flag provided but not defined", which
reads like a typo:

```
error: --pfind is unavailable on this build (darwin/arm64): it needs RapidFile pfind enumerating a mounted export
  drop the flag; the built-in parallel walk is the default and needs nothing installed
```

A **refused value** (`--transport=kernel`) keeps its flag in `--help`, because `--transport` has a
working value on every platform and the help text is where the operator chooses it. The refusal
names the value:

```
error: --transport=kernel is unavailable on this build (darwin/arm64): it needs the NFSv4 ACL extended attribute system.nfs4_acl, a Linux NFS client feature
  use --transport=userspace, which speaks NFSv4.1 to the array directly and needs no mount
```

Both refusals name the build (`GOOS/GOARCH`) and the missing capability rather than an operating
system, so a capability that is false on some future Linux build still explains itself correctly.
The value gate is checked against the flag's effective value whether or not it was typed: an
unsupported default is as broken as an unsupported argument.

**On macOS, `--server` and `--export` are mandatory.** There is no mounted path to infer them from.
That is a property of `--transport=userspace` on every platform, not of macOS — it is simply
unavoidable there.

**`sweep` has no working macOS invocation.** Every scratch backend it can build today reads and
writes the trial tree through a mounted path, so it refuses at startup rather than failing later:

```
error: sweep needs a kernel NFSv4.1 mount to read its trial tree, and this build (darwin/arm64)
cannot mount one. Every scratch backend sweep can use today goes through a mounted path, so
--reuse-scratch and --force do not help. Run sweep on a Linux host with the export mounted.
```

The refusal is keyed on the provisioner, not on `GOOS`: a userspace provisioner would return false
from `NeedsLocalMount` and the refusal would disappear with no edit.

The smb backend (`protocol: smb`) is unreachable on **every** platform: `internal/spec` rejects the
protocol at load time with `protocol "smb" is not yet supported; use posix or nfsv4`. It is not a
Linux-only feature.

## idmapd is a kernel-transport concern only

The NFSv4 ID mapping daemon maps between principal strings and local uids **for the Linux kernel
NFS client**. The userspace transport never involves it. `nfs4acl.Encode` copies the principal
string verbatim into the ACL's wire bytes and the client sends those bytes unchanged, so a spec
naming `alice@corp.example.com` reaches the array as exactly that string and the array
resolves it against its own directory.

Every idmapd requirement in `CLAUDE.md`, `COMPATIBILITY.md` and
`docs/field-preview/identity-checklist.md` applies to `--transport=kernel` only. A Mac needs no
idmapd, no sssd and no `nsswitch.conf` entry to write correct named-principal ACLs — it needs the
array to know the names.

This is why principal pre-resolution is **advisory whenever the selected transport is not kernel**,
including on Linux with `--transport=userspace`. A name this host cannot resolve draws a warning
and the run continues, because this host is not the authority for it. Under `--transport=kernel`
the same failure is fatal, since the kernel client is the thing doing the mapping. It is a
transport question, not a platform question.

## The AUTH_SYS credential

The userspace transport authenticates with AUTH_SYS, built by default from the running process:
`os.Getuid()`, `os.Getgid()`, `os.Getgroups()` and `os.Hostname()`. On a Linux lab client whose uids
come from the same directory the array uses, that is correct with nothing to configure.

On a Mac it is mechanically correct and semantically wrong: a local account is typically uid 501,
which means nothing to the array. Four flags make it explicit, and they work on every platform —
they are also how you run as a different identity on Linux without `sudo -u`:

```
--auth-uid N        AUTH_SYS uid (default: the running user)
--auth-gid N        AUTH_SYS gid (default: the running user)
--auth-gids a,b,c   AUTH_SYS auxiliary gids, comma-separated (default: the running user's groups)
--auth-hostname H   AUTH_SYS machine name (default: os.Hostname)
```

Naming any one of them fills the rest from the process, so `--auth-uid 10010` alone does not blank
the group list. Both `sweep` and `permissionreset` carry all four.

Two warnings inspect the credential that will actually go on the wire, typed or not. They fire only
under `--transport=userspace`, because AUTH_SYS is what that transport puts on the wire, and they
never block — a lab export may well accept either:

- uid 0 warns that exports commonly squash root to nobody, so a repair that connects can still be
  denied on every object.
- a uid below 1000 warns that it looks like a local account rather than a directory one.

**Get this wrong and the failure is late and misleading.** A wrong uid connects, negotiates a
session, enumerates the tree, and then denies or misapplies at scale with errors that look like an
export or ACL problem. The preflight probe performs a real ACL write before the walk starts, which
turns most credential mistakes into an immediate startup failure — but it runs **only under
`--apply`**. A dry run never exercises the credential, and says so:

```
note: this is a dry run, so the AUTH_SYS credential has not been exercised against the export; the
preflight ACL write happens only under --apply
```

## Kerberos

`internal/nfs41` implements AUTH_SYS only; there is no RPCSEC_GSS in the userspace client. The
consequence is transport-scoped, not platform-scoped:

- **Kernel transport, Linux:** `sec=krb5`, `krb5i` and `krb5p` work normally. The kernel mount
  performs the GSS negotiation and `permissionreset` only issues `setxattr` and `chmod` against an
  already-authenticated mount.
- **Userspace transport, every platform:** Kerberos-secured exports are unsupported. Only `sec=sys`
  works.

Since macOS has no kernel transport, it has no Kerberos path at all. That is a property of the
userspace transport it inherits rather than something the macOS port introduced, but a Mac operator
is far more likely to meet it.
