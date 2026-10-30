# nfs4acl

RFC 7530 NFSv4 ACE parser, binary encoder/decoder, and syscall layer.

## What this package does

Converts between human-readable ACE strings (`A:fd:OWNER@:rwaDxtTcCoy`) and the
binary format the `system.nfs4_acl` xattr expects. Also performs `setxattr`/`getxattr`
directly — no cgo, no `nfs4_setfacl` subprocess.

## Key functions

- `ParseACELine(string) (ACE, error)` — single ACE string to struct
- `ParseACLSpec([]string) ([]byte, error)` — multiple ACE lines to encoded binary (skips comments/blanks)
- `Encode([]ACE) []byte` — ACE structs to binary (big-endian XDR: u32 count + per-ACE header + padded who)
- `DecodeACL([]byte) ([]ACE, error)` — binary back to structs
- `ACLEqual(a, b []byte) bool` — structural comparison with case-insensitive who normalization
- `ACLEqualIdent(a, b []byte, r idmap.Resolver) bool` / `ACEsEqualIdent(a, b []ACE, r idmap.Resolver) bool` —
  identity-aware comparison; the `ACEs` form is for a caller that already has one or both sides
  decoded (e.g. `SplitACL`'s sacl return) and would otherwise re-encode just to call the other one.
  `ACLEqualIdent` decodes both sides and calls the shared `acesEqual`, which `ACEsEqualIdent`
  exports directly.
- `SplitACL(raw []byte) (daclRaw []byte, daclCount int, sacl []ACE, err error)` — splits a raw,
  count-prefixed nfsace4 stream into its DACL region (every A/D entry, sliced directly out of
  `raw` and never decoded+re-encoded, so a who field FA rendered oddly — a numeric principal,
  `GROUP@` with no `g` flag — round-trips exactly; `daclRaw` carries its own num_aces header, so
  it is itself a valid ACL) and its SACL entries (every U/L entry, decoded, wherever they appeared
  — not assumed to be at the tail). Used by `internal/apply`'s DACL-keeping apply (plan v3 commit 4).
- `IsUnmappedWho(who)` / `UnmappedPrincipals(raw)` — the nobody sentinel (65534, 4294967294, -2, nobody, nfsnobody, nobody@…) that FA renders for a SID with no RFC 2307 id; used by the DACL-keeping guard in `internal/apply`.
- `JoinACL(daclRaw []byte, saclACEs []ACE) []byte` — reassembles a full ACL from a DACL region (as
  `SplitACL` returns it) and a set of SACL ACEs encoded and appended at the tail; the DACL bytes
  are copied through unchanged, only the new SACL ACEs are encoded.
- `SetACL(path, data)` / `GetACL(path)` — raw syscall wrappers

## Binary format

```
u32 num_aces
per ACE:
  u32 type    (0=allow, 1=deny, 2=audit, 3=alarm)
  u32 flags   (file-inherit, dir-inherit, group, etc.)
  u32 mask    (rwaDxtTnNcCoyd bits)
  u32 who_len
  [who_len bytes, padded to 4-byte boundary]
```

## Gotchas

- `SetACL` uses raw `Syscall6` with unsafe pointers — `aclData` must be non-empty or it panics.
  Callers are expected to skip when spec has no ACEs.
- `ACLEqual`/`ACLEqualIdent`/`ACEsEqualIdent` normalize who case (`user@REALM.COM` ==
  `user@realm.com`) and, since PS-18 (#87), the `g` (group) flag on `GROUP@` only:
  FlashArray clears `ACE4_IDENTIFIER_GROUP` when it stores that one well-known who
  (RFC-Deviations.md §7), and RFC 7530 §6.2.1.5 defines `GROUP@` as the owning group by
  definition, so the flag is redundant there. A named user or group principal is not
  covered by that RFC special case, so a `g`-flag difference on a named principal still
  mismatches. Documented in `TestACLEqualGroupFlagNormalization`,
  `TestACEsEqualIdentGroupSpecialIgnoresGroupFlag` and
  `TestACLEqualIdentGroupFlagNormalizationWithResolver`.
- `GetACL` uses a fixed 8192-byte buffer. ACLs larger than this would truncate silently.
  In practice, even 64-ACE ACLs fit well under this.
- `ParseACLSpec` is deterministic — same input always produces same binary. Required for
  `--compare` to work (tested explicitly).

## Consumers

- `internal/apply` — calls `SetACL`/`GetACL` via kernel transport, `ACLEqual` for validate
- `internal/spec` — calls `ParseACLSpec` at spec load time to pre-encode ACLs
- `internal/nfs41` — userspace transport reimplements the encode/decode in XDR but references
  these constants; `Encode` is used by `generate-tree` for stamping test trees
- `internal/transport/kernel.go` — thin wrapper over `SetACL`/`GetACL`

## Tests

All offline, no mounts needed. Cover parsing, encoding round-trips, padding edge cases,
case-insensitive who comparison, 64-ACE stress test, and the group-flag normalization gap.
