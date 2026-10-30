# internal/spec

YAML spec loading, validation, rule matching, exclude patterns, and operator plan display.

## Files

- `spec.go` — Spec/Rule/RulePerms types, Load, validate, MatchRule, EffectivePerms
- `exclude.go` — Excluder (glob-based path exclusion), ValidateExcludePattern, MergeExcludes
- `plan.go` — PrintPlan (operator-visible pre-run summary)

## Key types

- `Spec` — protocol, default perms, rules, SMB config, exclude patterns
- `Rule` — match criteria (type, pattern) + RulePerms (inline)
- `RulePerms` — Mode, ACL, DACL, Owner, Group, `Sacl *[]string` (audit ACEs), plus unexported
  `encodedACL`/`saclACEs`
- `Excluder` — compiled pattern set with base-name and path-relative globs

## Key functions

- `Load(path)` — read YAML, decode with KnownFields(true), validate, pre-encode ACLs
- `EffectivePerms(path, isDir)` — first-match-wins rule lookup, falls back to default
- `EncodedACL()` — returns pre-encoded wire bytes (`acl:` ++ `sacl:`); falls back to on-demand for
  struct literals. Returns nil for a DACL-keeping rule (see below) -- there are no fixed bytes to
  cache when the wire form depends on each object's own DACL.
- `SaclACEs()` — this rule's `sacl:` lines, parsed; same on-demand fallback as `EncodedACL()`
- `KeepDACL()` — true when `sacl:` is set and `acl:` is empty: this rule's per-object apply
  (`internal/apply`'s `applyKeepDACL`, plan v3 commit 4) keeps the object's existing DACL and
  replaces only its audit ACEs
- `PreserveSACL()` — true when `acl:` is set and no `sacl:` key is: a DACL reset that keeps the
  object's existing audit ACEs (PS-04). Absent keeps, entries replace, `[]` clears.
- `Spec.UsesSacl()` — true if any rule (default included) carries at least one audit ACE
- `Spec.SaclRules()` — label every rule that names a `sacl:` key, `sacl: []` included; non-empty
  means the run needs `--sacl`
- `Spec.MissingSACL()` / `Spec.KeepDACLRules()` — label every rule (`"default"`/`"rule[N]"`) that
  sets `acl:` with no `sacl:` key at all, or that is `KeepDACL()`, respectively
- `NewExcluder(root, patterns)` — returns nil for empty list; nil receiver methods are safe
- `Match(path)` — true if excluded; root is never excluded
- `MatchOrUnder(path)` — true if path or any ancestor is excluded (for pfind stream filtering)

## `sacl:` and DACL-keeping rules

`sacl:` (`U` audit ACEs only, each carrying `S`, `F`, or both) is a separate field from `acl:`
because it is validated differently and always goes on the wire last. A rule with `acl:` and
`sacl:` together writes both blind, spec-DACL style, on every matching object (v2 behavior). A
rule with `sacl:` and **no** `acl:` is DACL-keeping: it has no `EncodedACL()` of its own, because a
SACL-only ACL written blind would remove all access, and its real apply is per-object
(`internal/apply/CLAUDE.md`'s "DACL-keeping apply" section) -- this package only parses, validates,
and labels it. SACL mode is opt-in: without `--sacl`, `internal/run.Run` refuses any spec that
names `sacl:` (`SaclRules`, `sacl: []` included) and runs `acl:` specs unguarded. With `--sacl`, it
refuses a spec that sets `acl:` with no `sacl:` key at all (`MissingSACL`), but a `KeepDACL()` rule is itself a complete answer to that
guard and is never reported by `MissingSACL`.

## Rule matching semantics

- First match wins. A matching rule REPLACES the default — no field inheritance.
- Match type: "file", "directory", or "" (matches both). Pattern: filepath.Match glob against basename.
- Empty type+pattern = unconditional match (catches everything).

## Validation at load time

- Protocol must be posix or nfsv4 (smb parsed but rejected as unsupported)
- POSIX: mode must be valid octal <= 07777; no acl/dacl fields
- NFSv4: no mode field; every ACE line parsed by nfs4acl.ParseACELine; full ACL encoded and cached in `encodedACL`
- Spec must have at least one effective operation (not all-empty)
- Exclude patterns validated: no empty, no absolute, no `**`, must compile under filepath.Match

## Exclude pattern rules

- No slash: matched against basename (works at any depth)
- With slash: matched against path relative to target root (anchored, fixed depth)
- Root is never excluded (would make the run a silent no-op)
- `**` is rejected — Go's filepath.Match has no recursive glob

## Gotchas

- `encodedACL` is unexported and untagged — YAML never reads/writes it. Only populated through validate().
- `EncodedACL()` fallback encode is deliberately uncached — avoids lock overhead on the hot path for Load-built specs.
- `KnownFields(true)` rejects unknown YAML keys, catching typos before traversal.
- `validatePerms` prints NOTE to stderr for owner/group fields (side effect during validation).
