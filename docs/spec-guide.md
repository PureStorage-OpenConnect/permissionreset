# Writing a permissionreset Spec File

A guide for anyone whose ACL experience starts and ends with right-click > Properties > Security tab in Windows.

## What this file does

When you right-click a folder in Windows and open the Security tab, you see a list of users and groups, each with Allow/Deny checkboxes for permissions like "Read", "Write", "Full Control." A permissionreset spec file is the text equivalent of that dialog — it describes what the permissions *should* look like, and permissionreset stamps them onto every file and folder in a directory tree.

The spec is a YAML file. You pass it with `--spec`:

```
permissionreset --spec myspec.yaml /mnt/data/share
```

permissionreset reads the spec, walks every file and directory under `/mnt/data/share`, and sets permissions to match.

---

## The skeleton

Every spec file has this shape:

```yaml
protocol: nfsv4          # or "posix"

default:
  acl:
    - "A::OWNER@:rwaTcCoy"
    - "A:g:GROUP@:rncy"
    - "A::EVERYONE@:rncy"

rules:
  - match:
      type: directory
    acl:
      - "A:fd:OWNER@:rwaDxtTcCoy"
      - "A:fdg:GROUP@:rxtncy"
      - "A:fd:EVERYONE@:rxtncy"

  - match:
      type: file
      pattern: "*.sh"
    acl:
      - "A::OWNER@:rwaxTcCoy"
      - "A:g:GROUP@:rxncy"

exclude:
  - ".snapshot"
  - "*.tmp"
```

Three sections:

| Section | Purpose |
|---------|---------|
| `protocol` | Which permission system to use |
| `default` + `rules` | What permissions to set on what |
| `exclude` | What to skip |

---

## Protocol

```yaml
protocol: nfsv4
```

Two choices:

- **`posix`** — Traditional Unix permissions (owner/group/other, the `chmod 0755` style). Simple but limited: three permission slots, no named users or groups beyond owner/group.
- **`nfsv4`** — NFSv4 ACLs. The NFS equivalent of what you see in the Windows Security tab: a list of entries, each granting or denying specific permissions to a specific user or group. This is what you want for FlashBlade multiprotocol shares.

The protocol determines which fields are valid. An `nfsv4` spec uses `acl:` lists. A `posix` spec uses `mode:`. Mixing them is an error — permissionreset rejects it before touching any files.

---

## POSIX specs (the simple case)

If you only need basic Unix permissions, POSIX specs are straightforward:

```yaml
protocol: posix

default:
  mode: "0664"
  owner: serviceaccount
  group: engineering

rules:
  - match:
      type: directory
    mode: "2775"

  - match:
      type: file
      pattern: "*.sh"
    mode: "0775"
```

### Mode strings

Mode is a four-digit octal number in quotes. If you have used `chmod`, this is the same thing:

| Digit position | Controls | Common values |
|----------------|----------|---------------|
| First (special) | setuid/setgid/sticky | `0` = none, `2` = setgid, `4` = setuid |
| Second (owner) | Owner permissions | `7` = rwx, `6` = rw-, `5` = r-x |
| Third (group) | Group permissions | `7` = rwx, `5` = r-x, `4` = r-- |
| Fourth (other) | Everyone else | `5` = r-x, `4` = r--, `0` = --- |

`"2775"` means: setgid + owner rwx + group rwx + other r-x. Setgid on a directory makes new files inherit the directory's group — useful for shared project folders.

### Owner and group

```yaml
owner: serviceaccount
group: engineering
```

These set the file owner and group. They require `--set-owner` on the command line (and root or `CAP_CHOWN` on the system). Without `--set-owner`, permissionreset ignores these fields.

---

## NFSv4 specs (the Windows-like ACLs)

This is where the real power is, and where the syntax needs explanation.

### How NFSv4 ACLs map to the Windows Security tab

In Windows, the Security tab shows:

```
Group or user names:
  Administrators        Allow: Full Control
  DOMAIN\ProjectTeam    Allow: Read & Execute
  DOMAIN\Auditors       Allow: Read
  Everyone              Deny: Write
```

Each row is an **Access Control Entry (ACE)**. The full list is the **Access Control List (ACL)**. NFSv4 ACLs work the same way — an ordered list of entries, each granting or denying permissions to someone.

The difference is the syntax. In Windows you click checkboxes; in an NFSv4 spec you write a compact string.

### Reading an ACE string

Every ACE is a colon-separated string with four fields:

```
A:fd:storageadmins@example.com:rwaDxtTcCoy
│ ││ │                         │
│ ││ │                         └─ Permissions (what they can do)
│ ││ └─ Who (which user or group)
│ │└─ Flags (inheritance behavior)
│ └─ More flags
└─ Type (Allow or Deny)
```

Let's break down each field.

### Field 1: Type — Allow or Deny

| Letter | Meaning | Windows equivalent |
|--------|---------|-------------------|
| `A` | Allow | A green checkmark in the Allow column |
| `D` | Deny | A green checkmark in the Deny column |
| `U` | Audit | "Auditing" entries in Advanced Security Settings — goes in `sacl:`, not `acl:` ([see below](#audit-aces-sacl-on-flasharray)) |
| `L` | Alarm | Not accepted |

You will almost always use `A` (Allow). Deny rules (`D`) go **before** Allow rules — order matters, just like in Windows Advanced Security Settings.

### Field 2: Flags — Inheritance

In Windows, when you open Advanced Security Settings and look at the "Applies to" column, you see values like "This folder, subfolders and files" or "This folder only." Flags are the NFSv4 way of expressing the same thing.

| Flag | Name | What it means |
|------|------|---------------|
| `f` | File inherit | New files in this directory inherit this ACE |
| `d` | Directory inherit | New subdirectories inherit this ACE |
| `g` | Group | This ACE applies to a group, not a user |
| `i` | Inherit-only | This ACE applies only to children, not to the directory itself |
| `n` | No-propagate | Children inherit this ACE but don't pass it to their children |

The flags you will use most:

| Flags | Windows "Applies to" equivalent |
|-------|--------------------------------|
| (empty) | This object only |
| `fd` | This folder, subfolders and files |
| `d` | This folder and subfolders |
| `f` | This folder and files |
| `fdi` | Subfolders and files only (not this folder) |
| `g` | (marks the principal as a group — see below) |

**The `g` flag is special.** It does not control inheritance. It tells the system that the principal is a group, not a user. The NFS kernel needs this to look up the name correctly. **Every group principal must have `g` in its flags.** Forgetting `g` on a group is a common mistake that causes silent lookup failures.

For directories, you almost always want `fd` (file and directory inherit) so permissions flow down to new files and subdirectories. For files, you use no inheritance flags (files cannot have children).

This is why most specs have separate rules for directories and files:

```yaml
rules:
  # Directories get inheritable ACEs
  - match:
      type: directory
    acl:
      - "A:fd:OWNER@:rwaDxtTcCoy"       # fd = inherit to files and dirs
      - "A:fdg:GROUP@:rxtncy"            # fdg = inherit + it's a group

  # Files get non-inheritable ACEs
  - match:
      type: file
    acl:
      - "A::OWNER@:rwaTcCoy"             # no flags = this object only
      - "A:g:GROUP@:rncy"                # g only = group, no inherit
```

### Field 3: Who — The principal

This is the user or group the ACE applies to. Three formats:

**Special principals** (work everywhere, no configuration needed):

| Principal | Windows equivalent |
|-----------|-------------------|
| `OWNER@` | The file's owner (like the "CREATOR OWNER" entry) |
| `GROUP@` | The file's primary group (like "CREATOR GROUP") |
| `EVERYONE@` | Everyone (like the "Everyone" group) |

**Named principals** (require idmapd/SSSD configured for the domain):

```
arraysvc@corp.example.com
storageadmins@corp.example.com
```

These are like `DOMAIN\username` in Windows but written as `name@domain`. They require the NFS client's identity-mapping service (idmapd) to resolve the name. If idmapd is not configured for the domain, setxattr fails with EINVAL.

**Numeric IDs** (always accepted, but may not round-trip cleanly):

```
10001
1000001138
```

These are raw UID/GID numbers. The kernel may resolve a numeric ID to `user@domain` before sending it to the server. If that happens, the stored form differs from what you wrote, and `--compare` and `--validate` report mismatches. **Recommendation:** after a test apply, run `nfs4_getfacl` on one object and use whatever form the server stored.

### Field 4: Permissions — What they can do

Each letter enables one permission. Here is the complete map, with the closest Windows equivalent:

| Letter | Permission | On files | On directories | Windows equivalent |
|--------|-----------|----------|---------------|-------------------|
| `r` | Read data | Read the file | List the directory | "List folder / read data" |
| `w` | Write data | Write to the file | Create files in the directory | "Create files / write data" |
| `a` | Append data | Append to the file | Create subdirectories | "Create folders / append data" |
| `x` | Execute | Execute the file | Enter (cd into) the directory | "Traverse folder / execute file" |
| `d` | Delete | Delete this object | Delete this object | "Delete" |
| `D` | Delete child | (not meaningful) | Delete items inside | "Delete subfolders and files" |
| `t` | Read attributes | Read metadata | Read metadata | "Read attributes" |
| `T` | Write attributes | Modify metadata | Modify metadata | "Write attributes" |
| `n` | Read named attrs | Read extended attributes | Read extended attributes | "Read extended attributes" |
| `N` | Write named attrs | Write extended attributes | Write extended attributes | "Write extended attributes" |
| `c` | Read ACL | Read this ACL | Read this ACL | "Read permissions" |
| `C` | Write ACL | Modify this ACL | Modify this ACL | "Change permissions" |
| `o` | Write owner | Change ownership | Change ownership | "Take ownership" |
| `y` | Synchronize | (NFS protocol detail) | (NFS protocol detail) | "Synchronize" |

**Common permission bundles** (compare to the Windows "basic permissions"):

| Windows basic permission | Equivalent letters |
|--------------------------|-------------------|
| Full Control | `rwaDdxtTnNcCoy` (everything) |
| Modify | `rwadxtTnNcy` (no delete-child, no write-ACL, no write-owner) |
| Read & Execute | `rxtncy` (read, execute, read attrs, read named attrs, read ACL, sync) |
| Read | `rtncy` (same but no execute) |
| Write | `watTnNcy` (write, append, write attrs, write named, read ACL, sync) |

Note: there is no single "Full Control" shorthand. You spell out every letter. This is intentional — it forces you to be explicit about what you are granting.

---

## The rules engine

### How matching works

permissionreset walks every file and directory. For each one, it checks the rules **in order, top to bottom**, and uses the **first match**. If nothing matches, it uses `default`.

This is exactly like Windows' inherited vs. explicit ACLs — more specific rules go first, catch-all at the bottom.

```yaml
default:
  acl: [...]        # catch-all: anything not matched by a rule

rules:
  - match:
      type: directory   # matches all directories
    acl: [...]

  - match:
      type: file
      pattern: "*.sh"   # matches only .sh files
    acl: [...]

  - match:
      type: file        # matches all remaining files
    acl: [...]
```

### Match criteria

Each rule has a `match:` block with two optional fields:

| Field | Values | Behavior |
|-------|--------|----------|
| `type` | `file`, `directory`, or omit | Restricts to files or directories. Omit to match both. |
| `pattern` | A glob like `*.sh`, `*.log` | Matched against the **base name** only (not the full path). Uses Go's `filepath.Match` syntax: `*` matches any sequence except `/`, `?` matches one character, `[abc]` matches a character class. |

If both are omitted, the rule matches everything — put it last or it will shadow all rules after it.

### Rules replace, they do not merge

This is the single most important thing to understand about the rules engine, and it trips people up:

> **A matching rule replaces the default entirely. It does not inherit anything from `default`.**

In Windows terms: imagine the Security tab where a subfolder has "Include inheritable permissions from this object's parent" unchecked. The subfolder's ACL is entirely its own.

Example of the trap:

```yaml
protocol: posix
default:
  mode: "0664"
  owner: serviceaccount
  group: engineering

rules:
  - match:
      type: file
      pattern: "*.sh"
    mode: "0775"
    # ⚠ owner and group are NOT inherited from default!
    # This rule sets mode only. Owner/group are left alone.
```

For `*.sh` files, the effective permissions are `mode: "0775"` and nothing else. If you want scripts to also get `owner: serviceaccount` and `group: engineering`, you must say so in the rule:

```yaml
  - match:
      type: file
      pattern: "*.sh"
    mode: "0775"
    owner: serviceaccount
    group: engineering
```

For NFSv4 specs this is less of a gotcha because the `acl:` list is self-contained — but the same principle applies: a rule's `acl` is not merged with the default's `acl`.

### Rule ordering strategy

Put rules in this order:

1. **Directory rules** — with inheritance flags (`fd`)
2. **Specific file rules** — pattern matches (`*.sh`, `*.dat`)
3. **General file rule** — catches remaining files
4. **Default** — catches anything not matched above

```yaml
default:
  acl: [...]          # 4. last resort

rules:
  - match:
      type: directory  # 1. directories
    acl: [...]

  - match:
      type: file
      pattern: "*.sh"  # 2. specific files
    acl: [...]

  - match:
      type: file       # 3. all other files
    acl: [...]
```

---

## Exclude patterns

Skip files or directories that should not be touched:

```yaml
exclude:
  - ".snapshot"
  - "*.tmp"
  - "logs/*.gz"
```

You can also add excludes on the command line with `--exclude`. Both sources are merged (neither overrides the other).

### Pattern matching rules

| Pattern | Behavior |
|---------|----------|
| No `/` in pattern | Matched against the **base name** at any depth. `.snapshot` matches every `.snapshot` directory anywhere in the tree. |
| Contains `/` | Matched against the **path relative to the target root**. `logs/*.gz` matches `.gz` files in the `logs/` directory directly under the target, but not in `data/logs/`. |

Excluded directories are **pruned** — permissionreset does not descend into them, saving traversal time. This is the right way to skip `.snapshot` directories on FlashBlade (they can contain millions of objects).

Restrictions:
- No `**` (Go's glob has no recursive wildcard)
- No absolute paths (patterns are always relative to the target root)

---

## Putting it all together: a worked example

Scenario: you have a shared project directory on FlashBlade accessed over NFS. Three groups need access:

- **storageadmins** — full control (they manage the share)
- **engineering** — read, write, execute
- **auditors** — read only

The NFS user running permissionreset is `arraysvc`.

```yaml
protocol: nfsv4

# Files that don't match any rule get this ACL.
# In practice, the file rule below catches all files,
# so this is a safety net.
default:
  acl:
    - "A::arraysvc@example.com:rwaDdxtTnNcCoy"
    - "A:g:storageadmins@example.com:rwaDdxtTnNcCoy"
    - "A:g:engineering@example.com:rwadxtTnNcy"
    - "A:g:auditors@example.com:rxtncy"

rules:
  # Directories: same principals, but with inheritance flags
  # so new files/subdirs pick up these ACEs automatically.
  - match:
      type: directory
    acl:
      - "A:fd:arraysvc@example.com:rwaDdxtTnNcCoy"
      - "A:fdg:storageadmins@example.com:rwaDdxtTnNcCoy"
      - "A:fdg:engineering@example.com:rwadxtTnNcy"
      - "A:fdg:auditors@example.com:rxtncy"

  # Shell scripts: engineering gets execute
  - match:
      type: file
      pattern: "*.sh"
    acl:
      - "A::arraysvc@example.com:rwaDdxtTnNcCoy"
      - "A:g:storageadmins@example.com:rwaDdxtTnNcCoy"
      - "A:g:engineering@example.com:rwaxdtTnNcy"
      - "A:g:auditors@example.com:rxtncy"

  # All other files: engineering can read and write but not execute
  - match:
      type: file
    acl:
      - "A::arraysvc@example.com:rwaDdxtTnNcCoy"
      - "A:g:storageadmins@example.com:rwaDdxtTnNcCoy"
      - "A:g:engineering@example.com:rwadtTnNcy"
      - "A:g:auditors@example.com:rtncy"

exclude:
  - ".snapshot"
```

Walk through what happens for each object type:

| Object | Matched by | ACL applied |
|--------|-----------|-------------|
| `/mnt/data/share/` (target root) | directory rule | 4 ACEs with `fd`/`fdg` flags |
| `/mnt/data/share/src/` | directory rule | Same 4 inheritable ACEs |
| `/mnt/data/share/deploy.sh` | `*.sh` file rule | 4 ACEs, engineering gets `x` |
| `/mnt/data/share/README.md` | generic file rule | 4 ACEs, engineering has no `x` |
| `/mnt/data/share/.snapshot/` | excluded | Skipped entirely (not descended) |

### Why arraysvc is listed first

The user running permissionreset needs traverse permission (`x` on directories, read on the ACL) throughout the tree. If permissionreset fixes a directory's ACL and the new ACL locks out the running user, it cannot descend into that directory to fix its children. Putting the running user first with full control prevents this.

---

## Common mistakes

### Forgetting `g` on group principals

```yaml
# WRONG — storageadmins is a group but has no g flag
- "A:fd:storageadmins@example.com:rwaDxtTcCoy"

# RIGHT
- "A:fdg:storageadmins@example.com:rwaDxtTcCoy"
```

Without `g`, the NFS kernel tries to look up `storageadmins` as a user, which either fails or maps to the wrong entity.

### Using inheritance flags on file rules

```yaml
# WRONG — files cannot have children, fd flags are meaningless
- match:
    type: file
  acl:
    - "A:fd:OWNER@:rwaTcCoy"

# RIGHT — no inheritance flags on files
- match:
    type: file
  acl:
    - "A::OWNER@:rwaTcCoy"
```

### Mixing protocol fields

```yaml
# WRONG — mode is a posix field, acl is an nfsv4 field
protocol: nfsv4
default:
  mode: "0755"
  acl:
    - "A::OWNER@:rwaDxtTcCoy"
```

permissionreset rejects this at load time. Pick one protocol.

### Relying on OWNER@ in production

`OWNER@` resolves to whoever owns the file right now. On Windows-written data imported to FlashBlade, that might be `nobody` or a numeric ID without traverse permission. Use named principals in production specs; reserve `OWNER@` / `GROUP@` / `EVERYONE@` for quick tests.

### Assuming the default inherits into rules

```yaml
default:
  acl:
    - "A::arraysvc@example.com:rwaDdxtTnNcCoy"
    - "A:g:storageadmins@example.com:rwaDdxtTnNcCoy"
    - "A:g:auditors@example.com:rxtncy"

rules:
  - match:
      type: directory
    acl:
      - "A:fd:OWNER@:rwaDxtTcCoy"
      # ⚠ arraysvc, storageadmins, auditors are NOT here.
      # Directories get ONLY the one OWNER@ ACE.
```

---

## Audit ACEs (SACL) on FlashArray

A FlashArray NFSv4 ACL holds two lists in one attribute: the DACL (`A` allow and `D` deny entries,
who may do what) and the SACL (`U` audit entries, which accesses get logged). permissionreset writes the
SACL from a separate `sacl:` key. `U` and `L` lines are refused in `acl:`.

Both FlashArray and FlashBlade (multiprotocol file systems, Purity//FB 4.8.0 measured) return audit
ACEs inside `system.nfs4_acl`, so on both a DACL write without them deletes them (RISKS.md #10, #51).
The section was written against FlashArray; FlashBlade SACL writes over NFS are stored but otherwise
untested. All of it needs [`--sacl`](#sacl-mode---sacl). Without `--sacl`, a DACL reset is refused
when the target root already carries audit ACEs.

### Writing an audit ACE

An audit ACE uses the same four fields as any other ACE, with type `U` and one or both of two
extra flags:

| Flag | Name | What it means |
|------|------|---------------|
| `S` | Successful access | Log accesses that were allowed |
| `F` | Failed access | Log accesses that were denied |

A `U` ACE must carry `S`, `F` or both. The permission letters say which accesses to log. The
inheritance flags work as they do for `A`/`D`: directories carry `fd` so new children inherit the
audit entry, and files carry none.

```yaml
sacl:
  - "U:fdSF:EVERYONE@:rwadxTNcCoy"   # directory: log every allowed and denied access, inherited
```

Only `U` is accepted in `sacl:`. `L` (alarm) ACEs cannot be written, and FlashArray does not act
on them.

### Two kinds of rule

| Rule has | What permissionreset writes on each object it matches |
|----------|-------------------------------------------------|
| `sacl:` and no `acl:` | **Keeps the object's own DACL** and replaces only its SACL. |
| `acl:` and `sacl:` | The spec's DACL and the spec's SACL, as given. The object's DACL is replaced. |

The first kind is the one to use on a migrated tree whose DACLs differ from object to object. For
each object, permissionreset reads the ACL, keeps every `A`/`D` entry byte for byte in its original
order, drops every `U`/`L` entry, adds the rule's SACL at the end, and writes the result. The
result depends only on the object's DACL and the spec, so a second run changes nothing (with
`--compare`, a rerun writes 0 objects).

`examples/nfsv4_sacl_keep_dacl.yaml` is a complete DACL-keeping spec:

```yaml
protocol: nfsv4
rules:
  - match: {type: directory}
    sacl:
      - "U:fdSF:EVERYONE@:rwadxTNcCoy"
  - match: {type: file}
    sacl:
      - "U:SF:EVERYONE@:rwadxTNcCoy"
```

An object whose ACL has no `A`/`D` entries is not written and is reported as failed: a SACL-only
ACL would take away all access.

`sacl: []` means "no audit ACEs". On a DACL-keeping rule it removes every audit ACE and keeps the
DACL. On a rule with `acl:` it writes the DACL with an empty SACL.

`--validate` on a DACL-keeping rule checks only the SACL: the object's `U` entries must match the
spec's, in order, at the end of the ACL. The DACL is not compared, because the spec does not define
one.

### SACL mode: `--sacl`

Writing audit ACEs is opt-in. Without `--sacl`, permissionreset refuses any spec that names `sacl:`
(`sacl: []` included, since it deletes audit ACEs):

```
ERROR: the following NFSv4 rule(s) set sacl: (audit ACEs):
  rule[0]
Writing audit ACEs is SACL mode. Pass --sacl to turn it on.
```

With `--sacl`, a second check applies. On FlashArray and FlashBlade, writing a DACL with no SACL
deletes the object's existing audit ACEs, so an NFSv4 rule (or `default:`) that sets `acl:` and has no `sacl:`
key at all is refused before anything is touched:

```
ERROR: the following NFSv4 rule(s) set acl: with no sacl: key:
  rule[0]
On FlashArray, writing the DACL without a SACL deletes the object's existing audit ACEs.
Add sacl: [] to that rule to say an empty audit ACL is intended, or run without --sacl if this is not a FlashArray SACL run.
```

`--sacl` also turns on [the preflight](#the-preflight) and the audit-policy NOTE.

**Without `--sacl`, a DACL reset refuses objects that carry audit ACEs.** Every object's ACL is
read. An object with audit or alarm entries is not written, and is counted as an error
(`ErrAuditedObject`), unless you pass `--allow-audited-dacl-reset`. The refusal exists because
FlashArray rewrites the descriptor's control flags on any NFS ACL write, even one that writes back
identical bytes: the SACL goes from auto-inherited to protected (`S:AI` → `S:P`) and the DACL is
flattened (`D:AI` → `D:P`, RISKS.md #11). The kernel transport cannot tell FlashArray from
FlashBlade, so the refusal applies on both. Reset audited objects over SMB instead.

With `--allow-audited-dacl-reset`, the spec's DACL is written with that object's existing audit and alarm entries appended byte for
byte (PS-04, RISKS.md #10). This holds for an audited subtree under an unaudited root too. An
object whose ACL cannot be read or parsed is not written, and neither is one whose audit ACEs name
`nobody` or an id at or above 1000000000 (`ErrUnpreservableAudit`); each is counted as an error.

What is kept is the audit entries the NFS view shows. That is not proof that the SMB descriptor is
unchanged: an inherited audit ACE written back over NFS may be stored as an explicit one. Check
SMB fidelity from SMB. A dry run reads no ACL, so it cannot report which objects carry auditing.

### Required privilege: the audit bypass

Writing audit ACEs needs the array's audit bypass. That means one of:

- root over AUTH_SYS with root squash off on the export (kernel transport: mount NFSv4.1 as root;
  userspace transport: `--auth-uid 0`), or
- an AD identity the array grants the bypass directly.

Domain Admins membership is not enough.

The bypass covers the read too. On Purity//FA 6.10.6, an ACL read by an identity without the
bypass emptied the SACL of an object that is still inheriting it, reproduced 3/3 on lab array A on
2026-10-15. **This is not confirmed as fixed only by 6.12.1**: the same repro failed to reproduce
on the same 6.10.6 array the next day, most likely (not proven) because of an intervening
controller role swap rather than a firmware difference, and the lab array B 6.12.1 non-repro was never
checked against its own controller state either (`benchmarks/sacl-item7-20261016/RESULTS.md`). So
the bypass is required, not optional, and there is no flag to skip the check, on any firmware
version until a controller-controlled retest confirms the boundary.

### The preflight

Any `--sacl` run of a spec with a `sacl:` key — `sacl: []` included, since that rule still reads
every object — runs a probe in apply, `--compare` and `--validate` alike, but not in `--dry-run`.
The probe runs before the walk: it writes a temporary file with a DACL and an audit ACE, then reads it back.

- If the write is refused, the run stops with
  `preflight: audit (SACL) ACE write was refused -- the running identity lacks the array's audit bypass`,
  followed by the list of identities that have the bypass.
- If the write is accepted but the read-back has no `U` entries, the run stops with
  `preflight: audit (SACL) ACEs were accepted but the array did not retain them`.

Every such run also prints this NOTE, whatever the preflight finds:

```
NOTE: sacl: writes audit ACEs, but logging them still needs an audit policy turned
      on for the managed directory -- permissionreset cannot check that over NFS.
```

### Limits

1. **New objects were not protected on Purity//FA 6.10.6.** Files and folders created after the
   run inherit from their parent, and one ACL read over NFSv4.1 by a user without the bypass
   emptied them of their inherited SACL — reproduced 3/3 on lab array A on 2026-10-15. SMB reads do not
   do this. **The claim that 6.12.1 fixes it is not confirmed**: the same repro stopped reproducing
   on the same 6.10.6 array the next day, most likely (not proven) because of an intervening
   controller role swap rather than a firmware difference, and lab array B's 6.12.1 non-reproduction was
   never checked against its own controller state either
   (`benchmarks/sacl-item7-20261016/RESULTS.md`). Until a controller-controlled retest confirms the
   boundary, rerun permissionreset on a schedule regardless of firmware version.
2. **Parent SACL edits do not reach stamped children.** Every object holds its own copy. To change
   the audit rule, change the spec and rerun.
3. **Logging needs an audit policy on the managed directory.** The SACL is stored without one, but
   nothing is logged. permissionreset cannot check this over NFS.
4. **64 KB ACL size.** `XATTR_SIZE_MAX` bounds the encoded ACL. A very large DACL plus SACL fails
   that object with `E2BIG`.
5. **The read-write gap (DACL-keeping rules).** A DACL change someone makes between permissionreset'
   read and its write of the same object is lost. The window is milliseconds per object. Run in a
   quiet window.
6. **Replacing a file avoids its SACL.** In place, a user without the bypass cannot remove the SACL
   (not by a DACL write, `chmod` or `nfs4_setfacl -x`) on 6.10.6 or 6.12.1. A file that is copied
   and renamed over the original, or re-created, carries only the parent's inherited SACL, so on
   6.10.6/6.11.x it is exposed to limit 1.

### Capturing a SACL spec with build-spec

`build-spec` reads one directory and one file and decides by what it finds:

- **No audit ACEs:** the same DACL spec as before, with no `sacl:` key. It runs without `--sacl`.
  To run it in SACL mode, add `sacl: []` (or the audit ACEs you want) to each rule.
- **Audit ACEs:** DACL-keeping `sacl:`-only rules, run with `--sacl`. An exemplar with none of its own gets `sacl: []`.
  `--with-dacl` adds the exemplars' DACLs as `acl:` as well, which turns the rules into ones that
  replace every object's DACL.

`L` ACEs are dropped with a NOTE. Capture FlashArray exemplars with the bypass: without it the
array returns no audit ACEs, and on 6.10.6 that read also emptied an inheriting SACL on the
exemplar (see the Limits section above for the unconfirmed 6.12.1 boundary).

To write a spec's `sacl:` rules over SMB instead, `build-spec --sacl-plan SPEC.yaml` prints them as JSON
for `tools/set-saclonly/Set-SaclOnly.ps1`: the same rule and exclude selection `permissionreset` makes, with
each `U` line translated to a Windows audit ACE.

---

## Validating your spec

Before running a real repair:

```bash
# Dry run — shows what would happen, changes nothing
permissionreset --spec myspec.yaml --dry-run /mnt/data/share

# Apply to a small test directory first
permissionreset --spec myspec.yaml /mnt/data/share/testdir

# Verify after applying — checks every object matches the spec
permissionreset --spec myspec.yaml --validate /mnt/data/share/testdir
```

For a spec with `sacl:`, add `--sacl` to each command (see [SACL mode](#sacl-mode---sacl)).

Spec validation happens at load time. If you have a typo in a permission letter, an invalid glob pattern, or a cross-protocol field, permissionreset tells you immediately and exits before touching anything.

---

## Quick reference: NFSv4 ACE format

```
TYPE : FLAGS : WHO : PERMISSIONS
 A   :  fdg  : storageadmins@example.com : rwaDxtTcCoy
```

**Types:** `A` Allow, `D` Deny (in `acl:`); `U` Audit (in `sacl:` only). `L` Alarm is not accepted.

**Flags:** `f` file-inherit, `d` dir-inherit, `g` group, `i` inherit-only, `n` no-propagate, `S` audit successful access, `F` audit failed access (`U` only)

**Permissions:** `r` read, `w` write, `a` append, `x` execute, `d` delete, `D` delete-child, `t` read-attrs, `T` write-attrs, `n` read-named-attrs, `N` write-named-attrs, `c` read-ACL, `C` write-ACL, `o` write-owner, `y` synchronize
