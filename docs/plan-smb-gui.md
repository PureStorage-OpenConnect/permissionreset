# Plan: permissionreset-smb Windows GUI

Status: **plan only. Nothing here is implemented.** Written against `main` at `2980615`.

This is the design brief for designers and developers. It defines what the GUI does, how it is
built, every screen, and the design system. Code planning (classes, tickets, order of work inside a
phase) is for the team that builds it.

Related plans:

- [plan-smb-dotnet10.md](plan-smb-dotnet10.md): the solution moves to .NET 10. The GUI starts on
  .NET 10.
- [plan-smb-run-control.md](plan-smb-run-control.md): state dir, stop, resume and status files in
  the CLI. The Run monitor (section 9) depends on it.
- [DESIGN-write-path.md](../smb/DESIGN-write-path.md): the write path. Apply in the GUI depends on
  its phase 2.

## 1. Purpose

An SMB share explorer for Windows administrators that:

1. Shows each file and directory of a share with a plain-language description of its DACL and SACL,
   updated as the selection changes.
2. Shows inherited entries on an object that only inherits, copied from the ancestor that defines
   them, and labeled as inherited.
3. Lets the operator craft a target ACL, or copy one from an existing object, as a permissionreset
   spec.
4. Drives the `permissionreset-smb` CLI with that spec: dry run (`check`), and apply when the write
   path allows it.
5. Tracks a run's progress, pauses and resumes it, and shows its results.
6. Runs as the Windows session user, or connects as a different user for admin rights, and can show
   what a target user can do.

Users: storage administrators and field engineers on Windows Server, with FlashArray SMB shares.
They are careful and they distrust tools that hide what they do. Every screen shows the exact CLI
command it drives.

Non-goals:

- It does not write ACLs itself. All writes go through the CLI, so the write path has one
  implementation, one set of guards and one qualification.
- It does not parse or interpret the spec YAML. Spec meaning lives in Go (`smb/CLAUDE.md`).
- It is not a general file manager: no copy, move, rename or delete of files.
- It does not replace the build-spec GUI (`gui/buildspec/`, Wails). That tool stays the NFS-first,
  multi-platform tool. This one is Windows-only and SMB-only.

## 2. Decisions and constraints

| Item | Decision |
|---|---|
| OS | Windows Server 2022 with Desktop Experience and later; Windows 10 22H2 and Windows 11 for admin workstations. Server Core is not supported (no desktop shell) |
| Architecture | `win-x64` only |
| Framework | WPF on .NET 10 LTS |
| Theme | the built-in WPF Fluent theme of .NET 10, with the token overrides in section 12 |
| Packaging | self-contained, single file, published with the CLI in the same release zip. The customer installs no runtime |
| Elevation | the app manifest uses `asInvoker`. The app offers "Restart as administrator" when a feature needs privileges (section 6.4) |
| DPI | per-monitor V2 |
| Development | on a Windows Server 2022 VM next to the arrays. No other OS is a target |

Rejected options, and why (recorded so they are not reopened without a new reason):

- **WinUI 3:** needs the Windows App SDK runtime, some Fluent effects do not show on Server, and the
  tooling is less mature than WPF's.
- **WinForms:** the ACE cards, chips and outcome tags are hard to style.
- **Avalonia:** its main benefit is other operating systems, which are not a target.
- **Wails, Tauri, Blazor Hybrid:** each needs WebView2, which Windows Server 2022 does not include.
  The Fixed Version runtime would add about 150 MB to every release.
- **.NET Framework 4.8.1:** already on every Server 2022 box and patched by Windows Update, but it
  forces `PermissionReset.Smb.Core` down to `netstandard2.0`. Reopen this only if customer security
  reviews reject a bundled runtime.
- **Framework-dependent .NET 10:** the customer must install the .NET 10 Desktop Runtime.

Security patching: the runtime inside the exe is never patched by Windows Update. Each applicable
.NET security release means a rebuild and a new release ([plan-smb-dotnet10.md](plan-smb-dotnet10.md),
section 5). The About box and `--version` print the runtime version.

## 3. Architecture

### 3.1 Processes

```text
+---------------------------- permissionreset-smb-gui.exe (WPF) ----------------------------+
|                                                                                            |
|  Explorer reads (in process)            Runs (child processes)         Spec conversion      |
|  - list directories                     - permissionreset-smb check    (child process)      |
|  - read descriptors (backup intent)     - permissionreset-smb apply    - build-spec.exe     |
|  - describe ACEs (Core)                   (phase 2 only)                 --smb-plan ...     |
|  - effective access (Authz)             reads: run.json, status.json,                       |
|                                         records.jsonl                                      |
|  uses PermissionReset.Smb.Core          writes: STOP                                       |
|       PermissionReset.Smb.Windows                                                          |
+--------------------------------------------------------------------------------------------+
```

Two rules decide where code runs:

1. **Display reads run in process.** Listing a directory and reading a descriptor for the inspector
   must be fast (under 200 ms for a directory of 1,000 entries over a LAN is the target; measure it).
   They use the same Win32 code as the CLI, moved into a shared library (3.2).
2. **Anything that writes, or that produces a result an operator relies on, runs in the CLI.**
   `check` and `apply` results come from the CLI binary, so the evidence names the qualified binary
   and its checksum. The GUI never computes a check outcome itself.

### 3.2 Projects

```text
smb/
  src/
    PermissionReset.Smb.Core/       portable: plan, rules, descriptor decode, inheritance,
                                    checker, and NEW: AceDescriber, RunState readers
    PermissionReset.Smb.Windows/    NEW: Win32Security, Win32Tree, principal lookup, moved out of
                                    the CLI; plus Authz effective access, LogonUser helpers
    PermissionReset.Smb/            the CLI; references Core and Windows
    PermissionReset.Smb.Gui/        NEW: WPF app; references Core and Windows
  tests/
    PermissionReset.Smb.Tests/      existing; gains AceDescriber and RunState tests (run on Linux)
    PermissionReset.Smb.Gui.Tests/  NEW: view-model tests; Windows CI only
```

Moving `Win32Security` and `Win32Tree` into `PermissionReset.Smb.Windows` is a refactor of the CLI.
Do it in its own PR before the GUI, with no behavior change, and check it the same way as the .NET 10
move: byte-identical `inspect` and `check` output before and after
([plan-smb-dotnet10.md](plan-smb-dotnet10.md), section 4.2).

### 3.3 Patterns

- MVVM with `CommunityToolkit.Mvvm` (source generators, no runtime reflection). It is the only
  third-party UI dependency the plan allows without review.
- One `ShellViewModel` owns navigation between the 5 sections (Explore, Target ACL, Runs, Results,
  Connections).
- All network I/O is async and cancellable. A slow array must never freeze the UI thread.
- Long lists (directory entries, results) use `VirtualizingStackPanel` with recycling. A results
  set has millions of rows.
- Settings (recent connections, window layout, column widths) go to
  `%APPDATA%\permissionreset-smb\gui.json`. Run state goes to the CLI's state dirs (section 9).
  Never write a password to either.

## 4. Data model (view side)

| Type | Fields | Source |
|---|---|---|
| `Connection` | server, share, UNC root, identity mode, display identity, privilege state, SMB dialect, signing | section 6 |
| `ObjectNode` | relative path, name, is directory, is reparse point, size, modified time, load state | directory listing |
| `DescriptorView` | owner SID and name, group SID and name, control flags, DACL form, SACL state, raw base64 | `Descriptor` (Core) |
| `AceView` | list (DACL or SACL), index, type, principal SID and name, mask, rights text, flags, applies-to text, is inherited, inherited-from path, raw SDDL fragment, description sentence | `AceDescriber` (5) |
| `SpecDocument` | file path, spec text, last plan JSON, validation result, dirty flag | section 8 |
| `RunInfo` | state dir, `run.json`, latest `status.json`, process handle if this GUI started it | section 9 |
| `ResultRow` | path, is directory, rule, form, outcome, detail | `records.jsonl` |

DACL form uses the 3 cases of `DESIGN-write-path.md`, section 2.1, with these display labels:

| Case | Label | Meaning shown to the user |
|---|---|---|
| `inherits` | inherits | only inherited entries |
| `explicit_plus_inherits` | explicit + inherited | its own entries and inherited entries |
| `protected` | protected | inheritance from the parent is blocked |

## 5. ACL description engine (`AceDescriber`, in Core)

The engine turns a decoded descriptor into the text the inspector shows. It is display only. The
raw descriptor is never normalized, sorted or SDDL-round-tripped (`smb/CLAUDE.md`); the raw form is
always shown beside the description.

### 5.1 Rights

Match the whole mask first; list individual rights only when no named set matches.

| Mask | Text |
|---|---|
| `0x001F01FF` (FA) | Full control |
| `0x001301BF` | Modify (read, write, delete) |
| `0x001200A9` | Read and execute |
| `0x00120089` | Read |
| `0x00100116` | Write |
| `0x10000000` (GA) | Full control (generic) |
| `0x80000000` (GR) / `0x40000000` (GW) / `0x20000000` (GX) | Read / Write / Execute (generic) |
| anything else | "Special: " plus the list of set bits by name, in this order: list folder / read data, create files / write data, create folders / append data, read extended attributes, write extended attributes, traverse / execute, delete subfolders and files, read attributes, write attributes, delete, read permissions, change permissions, take ownership, synchronize |

For a file, use "read data" and "write data"; for a directory, use "list folder" and "create files".

### 5.2 Applies to

From the inheritance flags. These are the strings Windows Explorer uses, so administrators already
know them.

| Flags | On a directory |
|---|---|
| (none) | This folder only |
| `CI` | This folder and subfolders |
| `OI` | This folder and files |
| `OI CI` | This folder, subfolders and files |
| `CI IO` | Subfolders only |
| `OI IO` | Files only |
| `OI CI IO` | Subfolders and files only |
| any of the above plus `NP` | the same text plus ", one level only" |

On a file, inheritance flags have no effect; show "This file".

### 5.3 Sentence

One sentence per ACE, built from parts:

```text
<Allow: "Can" | Deny: "Cannot" | Audit success: "Log successful" | Audit failure: "Log failed">
<rights text, lower case> on <applies-to text, lower case>.
```

Examples:

- "Can modify (read, write, delete) on this folder, subfolders and files."
- "Cannot read, write or list this folder or anything below it. A deny entry wins over any allow
  entry." (A deny ACE gets the second sentence once per DACL.)
- "Log failed delete and change permissions on this folder, subfolders and files."

Well-known SIDs get their Windows names (`CREATOR OWNER`, `Everyone`, `BUILTIN\Administrators`). A
SID that does not resolve shows the SID and the tag "unresolved"; never hide it.

### 5.4 Inherited entries

An ACE with the `ID` flag is inherited. For each one, the engine finds where it came from:

1. Walk up from the object's parent toward the share root, using descriptors already read (cache
   them; read missing ancestors on demand).
2. The source is the nearest ancestor that holds an ACE with the same type, SID and mask, with
   inheritable flags that reach this object, either explicit or itself inherited from further up.
   Follow inherited ones up to the first explicit one.
3. If none is found below the share root, the source is "above the share root".
4. If the array's stored entry does not match what `Inheritance.Inherit` predicts from the source,
   show the tag "differs from parent" on the ACE. This is information, not an error.

**Inherits-only objects.** When the object has no explicit entries (form `inherits`), the inspector
shows every inherited entry as a full card, copied from its source, with:

- the tag **Inherited**, and
- the line "Copied from `<source path>`. Not stored as its own entry here."

The SACL follows the same rules.

### 5.5 Unknown and special cases

- An ACE type the engine does not model (callback, object ACEs, mandatory label): show the type
  name, the raw SDDL fragment, and "This entry type is shown raw only." Never guess.
- No SACL read (the identity lacks `SeSecurityPrivilege`): the SACL section says "Not read. This
  identity lacks SeSecurityPrivilege." with a "Restart as administrator" link when that would help.
- A null DACL: "No DACL. Everyone has full access." in the error color.
- An empty DACL: "Empty DACL. Nobody has access, except the owner, who can change permissions."
- Non-canonical order: tag "non-canonical order" on the DACL heading.

### 5.6 Tests

Table tests in `PermissionReset.Smb.Tests`, on Linux, one row per mask set, per flag combination
in 5.2, and per case in 5.5. Inherited-source tests use a fake ancestor chain.

## 6. Identity and connection

### 6.1 Modes

| Mode | What it does | Windows mechanism | Use it for |
|---|---|---|---|
| **This Windows session** (default) | the GUI and its child processes use the user's own token | none | the normal case |
| **Another account** | network access to the array uses another account's credentials; the local token stays the user's own | in process: `LogonUserW(LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50)` and `ImpersonateLoggedOnUser` on the threads that do display reads. For runs: `CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY)`, the same as `runas /netonly` | an admin or backup-operator account, or an account with the FlashArray audit bypass |
| **View as a target user** (read-only) | computes what a user or group can do on the selected object | `AuthzInitializeContextFromSid` (S4U, needs a domain controller) and `AuthzAccessCheck` against the descriptor the GUI read | answering "can this user get in here, and why" |

Notes for the implementers:

- Backup intent over SMB is decided on the server, for the **network** identity, not for the local
  token. That is why "Another account" changes the network identity only. The plan must not promise
  that a local token change alone gives backup rights on the array.
- A new-credentials logon creates a new logon session, so Windows opens a new SMB session to the
  server. The user's own mapped drives to the same server are not affected.
- "View as" computes effective access from the descriptor only. It does not include share-level
  permissions or array-specific behavior. The result must be labeled "Computed from the ACL, not
  tested against the array." Effective access is a separate claim from structural ACL agreement
  (MAINTAINERS.md, section 4).

### 6.2 Credentials

- Prompt with `CredUIPromptForWindowsCredentialsW`, so the password field is the Windows one.
- Optional: save to Windows Credential Manager (`CredWriteW`, type `CRED_TYPE_DOMAIN_PASSWORD`,
  target `permissionreset-smb:<server>`). Off by default.
- Hold the password only as long as `LogonUserW` or `CreateProcessWithLogonW` needs it; clear the
  buffer after. Never put it on a command line, in an environment variable, in a log, or in a file.
- `run.json` records `network_identity` (the account name), never the secret.

### 6.3 Preflight

Run on Connect, and again before each run, and show each line in the Connect dialog and in the
title-bar identity chip:

1. SMB session established; show dialect and signing.
2. The share root descriptor reads.
3. `SeBackupPrivilege` enabled on the token (local) — needed for backup-intent opens.
4. `SeSecurityPrivilege` enabled — needed for SACL reads.
5. All principals in the current spec resolve to SIDs (only when a spec is open).
6. Audit bypass: "not proven yet". The CLI proves it with its own probe before any write
   (`DESIGN-write-path.md`, section 4). The GUI never claims it is proven unless a CLI run proved
   it, and then names that run.

### 6.4 Elevation

The GUI starts with `asInvoker`. When it is not elevated, privileges 3 and 4 are not on the token.
The identity chip says "not elevated" and the inspector shows the limits (no SACL, objects the user
cannot read show "access denied"). "Restart as administrator" relaunches with the `runas` verb and
reopens the same connection and path.

## 7. Screens

There are 5 screens, plus the shell around them. A clickable mockup of all 5 exists as a design
canvas; ask the maintainers for access. The wireframes below are the authority for layout; the
mockup is the authority for look.

### 7.0 Shell

```text
+--------------------------------------------------------------------------------------------+
| [shield] permissionreset-smb  Explore | Target ACL | Runs | Results     (AL) EXAMPLE\alice  |
|                                                                     Windows session·elevated|
|                                                      [SeBackup ✓] [SeSecurity ✓] [Audit ?]  |
+--------------------------------------------------------------------------------------------+
|  section content                                                                            |
+--------------------------------------------------------------------------------------------+
| Equivalent: permissionreset-smb inspect \\array01.example.com\eng\dept\projects             |
+--------------------------------------------------------------------------------------------+
```

- The title bar uses the Fluent window chrome. The identity chip opens the Connect dialog.
- Privilege chips: green with a check when held, gray with a dash when not, orange with "?" for the
  audit bypass until a CLI run proves it.
- The bottom CLI line always shows the command that gives the same result in a shell. A copy button
  sits at its right end.
- Window minimum size 1100 × 640. Below 1360 px wide the inspector becomes a resizable bottom pane.

### 7.1 Explore

Purpose: browse the share and read each object's ACLs in plain language.

```text
+----------------+--------------------------------------------------+-----------------------+
| CONNECTIONS  + | \\array01.example.com\eng\dept    [filter...] [⟳]| SELECTED              |
|                | 5 items · read with backup intent · reparse      | projects              |
| [srv] array01  |   points not followed                            | \\...\dept\projects   |
|   ▸ finance    +--------------------------------------------------+ [DACL: inherits]      |
|   ▾ eng        | NAME          DACL           SACL      OWNER  MOD| [Owner: EXAMPLE\bob]  |
|     ▾ dept     | [dir] dept    protected      1 expl.   BUILTIN\..| [SE_DACL_AUTO_INH...] |
|       ▸ proj.. | [dir] proj..  inherits       inherited EXAMPLE\..|                       |
|       ▸ hr     | [dir] hr      protected      1 expl.   EXAMPLE\..| This folder has no    |
|   ▸ home$      | [doc] q4.xlsx explicit+inh.  inherited EXAMPLE\..| entries of its own... |
| [srv] array02  | [doc] README  inherits       none      BUILTIN\..|                       |
|   as EXAMPLE\  |                                                  | DACL · WHO CAN DO WHAT|
|   svc-audit    |                                                  | [ALLOW] Domain Admins |
|                |                                                  |  Full control on ...  |
| LEGEND         |                                                  |  [Inherited]          |
| [inherits]     |                                                  |  Copied from dept...  |
| [explicit+inh] |                                                  |  A;OICIID;FA;;;DA     |
| [protected]    |                                                  | ...                   |
|                |                                                  | SACL · WHAT IS AUDITED|
|                |                                                  | ...                   |
|                |                                                  | [Copy as target ACL]  |
|                |                                                  | [Copy SDDL] [Effective|
|                |                                                  |  access...]           |
+----------------+--------------------------------------------------+-----------------------+
```

Regions and widths (resizable splitters, widths saved per user):

| Region | Default width | Content |
|---|---|---|
| Rail | 280 px (min 220) | connections, each with its share tree; a legend at the bottom |
| List | fills | address bar (editable UNC path), filter box, refresh; a table of entries |
| Inspector | 440 px (min 380) | the selected object's description |

List columns: Name (icon + name), DACL (form chip), SACL (none / N explicit / inherited / not
read), Owner, Modified. Sort by any column. The filter matches name and any principal in the
object's ACL (the principal filter needs the descriptors, so it filters only loaded rows and says
so).

Loading: list the directory first and show rows at once; then read descriptors in the background,
16 at a time, rows filling in as they arrive. A row whose read fails shows an "access denied" chip
in the DACL column with the Win32 error in its tooltip.

Inspector content, top to bottom:

1. "Selected" label, object name (19 px semibold), full UNC path (monospace).
2. Chips: DACL form, owner, control flags (monospace).
3. A summary box: 1 or 2 sentences on what the DACL means overall, for example "Inheritance from the
   share root is blocked. This folder defines its own entries, and every child below it inherits
   them."
4. DACL section: one ACE card per entry, in stored order. Card: type tag (ALLOW / DENY), principal
   (semibold), the Inherited tag when inherited, the sentence (5.3), the "Copied from" line when
   inherited, the raw SDDL fragment (monospace, small).
5. SACL section: the same card with an AUDIT tag (AUDIT SUCCESS / AUDIT FAIL), or the empty and
   not-read texts (5.5).
6. Actions: **Copy as target ACL** (primary, opens Target ACL with this object as the source),
   **Copy SDDL**, **Effective access…** (opens the View-as panel, 6.1).

Keyboard: arrow keys move the selection and the inspector follows; Enter opens a directory;
Backspace goes up; Ctrl+L focuses the address bar; Ctrl+F the filter; F5 refreshes; Ctrl+Shift+C
runs Copy as target ACL.

### 7.2 Connect (dialog)

```text
+------------------------------ Connect to a share ---------------------------------- [x] -+
| Share path  [ \\array01.example.com\eng\dept                                          ]   |
|                                                                                          |
| Connect as                                                                               |
| (•) This Windows session — EXAMPLE\alice                                                 |
|     Uses your sign-in token. The app runs elevated, so SeBackupPrivilege and             |
|     SeSecurityPrivilege are enabled.                                                     |
| ( ) Another account (admin or service identity)                                          |
|     [ EXAMPLE\svc-audit        ] [ ••••••••      ]                                       |
|     [x] Use Windows Credential Manager   [ ] Remember for this server                    |
| ( ) View as a target user (read-only)                                                    |
|     [ EXAMPLE\bob              ]                                                         |
|                                                                                          |
| PREFLIGHT FOR EXAMPLE\alice ON array01                                                   |
|  ✓ SMB 3.1.1 session, signing on       ✓ SeBackupPrivilege enabled                       |
|  ✓ SeSecurityPrivilege enabled         ✓ Share root descriptor read                      |
|  ✓ All spec principals resolve         ! Audit bypass: not proven yet                    |
|                                                                                          |
| A second account to the same server gets its own logon session, so your mapped drives    |
| are not affected.                                                                        |
|                                                          [ Cancel ]  [ Connect ]          |
+------------------------------------------------------------------------------------------+
```

- Width 760 px, modal. Radio cards: the selected one has the accent border and a light accent fill.
- Preflight runs as soon as the path and mode are valid, and reruns on change. Each line has a
  pass, fail or pending icon. Connect is enabled when lines 1 and 2 pass.
- A failed line has a short fix under it, for example "Restart as administrator to enable
  SeSecurityPrivilege."

### 7.3 Target ACL

Purpose: craft a spec, or copy one from an object, then validate it and start a dry run.

```text
+----------------+--------------------------------------------------+-----------------------+
| RULES · FIRST  | Rule 1 · directories under audit*      Match     | SPEC (YAML)           |
| MATCH WINS     | Copied from \\...\dept on 2026-11-27 10:42.      | protocol: nfsv4       |
|                |                                    [type ▾][glob]| exclude:              |
| [1 default   ] | Stored form after the reset                      |   - .snapshot         |
| [2 audit*    ] | ( ) inherits ( ) explicit + inherits (•) protect.| default:              |
| [3 dirs      ] |                                                  |   acl:                |
| [4 *.db      ] | DACL ENTRIES   order: deny first, explicit first  |     - "A:fd:EVERY..." |
| [5 files     ] | TYPE  PRINCIPAL      RIGHTS   APPLIES TO  SOURCE | rules:                |
| [Excludes    ] | ALLOW Domain Admins  Full     folder,sub..copied |   - match: ...        |
| [+ Add rule  ] | ALLOW eng-rw         Modify   folder,sub..copied |                       |
|                | [+ Add entry] [Paste from object...]             | PIPELINE              |
|                |                                                  | 1 build-spec          |
|                | (i) Inherited entries: copying from an object    |   --smb-plan spec.yaml|
|                | that only inherits copies its effective entries, | 2 permissionreset-smb |
|                | marked "inherited from dept". Choose inherits to |   plan plan.json      |
|                | keep them inherited, or protected to store them  | 3 permissionreset-smb |
|                | as explicit entries.                             |   check plan.json ROOT|
|                |                                                  |                       |
|                | SACL ENTRIES   [x] write SACL                    | ✓ Plan valid · 5 rules|
|                | AUDIT FAIL Everyone  delete, change perms  ...   | [Check (dry run)]     |
|                |                                                  | [Apply...] (locked)   |
+----------------+--------------------------------------------------+-----------------------+
```

How the spec is made, and why the GUI does not own spec meaning:

The spec format is permissionreset's YAML with NFSv4 ACE strings (for example
`"A:fd:EVERYONE@:rxtncy"`) and principals as `name@domain`
(`cmd/build_spec/testdata/smbplan.yaml` is a complete example). Translating a Windows ACE (SID,
mask, `OI`/`CI`/`IO` flags) into that string is spec meaning, so it must live in Go, next to the
code that translates the other way. The plan therefore needs 2 additions to `build-spec`, made and
tested in Go before the GUI uses them:

1. **`build-spec --from-smb-descriptor FILE`**: reads `inspect` JSON lines (raw base64
   descriptors) and writes a spec fragment (one rule's `acl:` and `sacl:` lists) as JSON on stdout.
   A round-trip test proves: descriptor → fragment → `--smb-plan` → the plan's desired DACL equals
   the explicit part of the descriptor.
2. **`build-spec --spec-json` / `--from-spec-json`**: converts a spec between YAML and a JSON form
   that Go defines and versions. The GUI edits the JSON form and asks Go for the YAML. This lets the
   GUI open an existing spec without parsing YAML.

Until both exist, the Target ACL screen can only start from "Copy as target ACL" output and save
YAML that Go produced; it cannot open an arbitrary spec file. That limit must show in the UI.

The rule editor shows the spec's own concepts: `match` (type and pattern), `acl`, `sacl`, `owner`,
`exclude`, `default`. The DACL table shows each entry translated back into Windows terms by the
same `AceDescriber` (5) applied to the plan JSON, so the operator reads Windows rights, not NFSv4
letters. The YAML pane shows the real text and is read-only.

Validation runs `build-spec --smb-plan` then `permissionreset-smb plan` on every change (debounced
500 ms). Errors from either tool show under the YAML pane verbatim, with the tool's name.

The "Stored form" radio maps to the 3 cases of section 4; the hint text under it explains each one.

Check (dry run) saves the spec and plan into a new state dir (9.1) and opens the Run monitor.
Apply is shown locked until the CLI reports write support (`permissionreset-smb version` lists
capabilities; to be added with phase 2) and the operator types the share name to confirm.

### 7.4 Runs (Run monitor)

Purpose: watch a run, pause it, resume it, stop it.

```text
+----------------+--------------------------------------------------+-----------------------+
| RUNS           | check · eng-dept-reset   [Mode: dry run]         | PROCESS               |
| [check · eng.. | \\...\dept · plan 9f3c…a1e2 · 16 workers         | PID 8412              |
|  ● Running 62%]|                         [⏸ Pause] [Stop]         | Identity EXAMPLE\alice|
| [check · fin.. | 1,284,550 objects   4,920 obj/s · 4m 21s elapsed  | Binary 0.2.0 (.NET 10)|
|  ⏸ Paused    ] | [████████████████████░░░░░░░░░░░] 62% of the     | Checkpoint 10:55:12   |
| [inspect · hr  |   previous run's 2,071,388                        | State dir %LOCALAPP...|
|  ✓ Done      ] | Now in dept\projects\2026\q3                      |                       |
|                |                                                  | PAUSE AND RESUME      |
|                | [ok 1,201,377][write 412][follows 80,915]        | Pause stops at the... |
|                | [keep 1,630][excluded 204][reparse 3][error 9]   |                       |
|                |                                                  | APPLY IS LOCKED       |
|                | LIVE RECORDS          [x] only write and error   | Writes need phase 2...|
|                | write    dept\...\vendor-sow.pdf  explicit ACE...|                       |
|                | error    dept\...\locked.vhdx  open: The proc... | COMMAND               |
|                | ...                                              | permissionreset-smb   |
|                |                                                  |  check --workers 16 ..|
|                |                                                  | [Open partial results]|
+----------------+--------------------------------------------------+-----------------------+
```

- Progress shows objects seen and rate always. A percentage, a bar and a time left show only when
  `status.json` has `previous_total`, labeled "of the previous run's N". Without it, the bar is an
  indeterminate bar and there is no time left. Never invent a total.
- Outcome tiles: one per outcome, in the order of the CLI's `Outcome` enum, each with its color
  (12.2) and a short note. Clicking a tile opens Results filtered to it.
- Live records: tail of `records.jsonl`, last 500 lines, filter "only write and error" on by
  default. Pause the tail when the user scrolls up; a "Jump to latest" button resumes it.
- Buttons by state:

| Run state | Buttons |
|---|---|
| running | Pause, Stop |
| stopping | (disabled) "Stopping at the next safe point…" |
| stopped | Resume, Discard |
| completed | Open results, Run again |
| failed | Open results, Show log, Resume (if the CLI says resumable) |

- Pause and Stop both create `STOP` (plan-smb-run-control.md, 5.1). The difference is the label
  only: a paused run is listed as paused and offers Resume; a stopped run is listed as stopped and
  offers Resume and Discard. Discard asks for confirmation and deletes the state dir.
- The GUI never kills a CLI process, except through a "Force stop" item in the run's context menu
  that asks for confirmation and says that the next resume repeats work since the last checkpoint.

### 7.5 Results

Purpose: understand a run's outcome and act on it.

```text
+----------------------------------------------------------------+---------------------------+
| check · eng-dept-reset · finished                              | SELECTED RECORD           |
| 2,071,388 objects in 7m 02s · exit 0 · 2026-11-27 10:58         | dept\projects\2026\q3\bud |
|            [Export JSON lines] [Export CSV] [Re-run errors only]| [WRITE]                   |
| [█████████████████████████████████████████████▓▓░] share bar    | NOW          AFTER RESET  |
| [write 871] [error 14] [follows 68,402] [ok 1,998,212] [keep..] | protected    inherits     |
|                                                                | ALLOW fin-rw  ALLOW DA    |
| OUTCOME  PATH                               WANT      REASON   | ...          (inherited)  |
| WRITE    dept\projects\2026\q3\budget       inherits  DACL pro.|                           |
| WRITE    dept\projects\2026\q3\vendor-sow   inherits  explicit.| The plan wants this folder|
| ERROR    dept\projects\2026\q3\locked.vhdx  —         open: ...| to inherit. It is ...     |
| ...                                                            | RAW RECORD                |
|                                                                | {"path":...}              |
|                                                                | [Show in explorer]        |
|                                                                | [Add exclude]             |
+----------------------------------------------------------------+---------------------------+
```

- The share bar shows outcome proportions, with a text equivalent for screen readers.
- Filter chips by outcome, multi-select; write and error are on by default.
- The table is virtualized and backed by the results store (9.2). Columns: outcome, path, want
  (form), reason (the CLI's `detail`), rule.
- The detail pane shows "Now" (read live from the array when the row is selected, with a "read at"
  time) and "After reset" (the plan's desired form, through `AceDescriber`), a 1-sentence
  explanation, and the raw record line.
- "Re-run errors only" starts a new `check` limited to the error paths. That needs a CLI option for
  a path list; record it as an open question (15) rather than building a GUI-side workaround.
- Export writes exactly what the CLI wrote (JSON lines), or a CSV of the visible columns.

## 8. Spec files and the pipeline

```text
Explore --Copy as target ACL--> build-spec --from-smb-descriptor --> spec JSON (Go-defined)
                                                                        |
Target ACL editor (edits spec JSON) --build-spec --from-spec-json--> spec.yaml
                                                                        |
                                  build-spec --smb-plan spec.yaml --> plan.json (schema 2)
                                                                        |
                                  permissionreset-smb plan plan.json --> valid / errors
                                                                        |
                         permissionreset-smb check --state-dir D plan.json ROOT --> run
```

- `build-spec.exe` ships in the same release zip. Its Windows build exists
  (`cmd/build_spec/kernel_windows.go`); confirm that `--smb-plan` works on Windows and add a CI
  check for it.
- The GUI writes `spec.yaml` and `plan.json` into the run's state dir before it starts the CLI, so
  a run always keeps the exact inputs it used.

## 9. Run management

### 9.1 State dirs

- Root: `%LOCALAPPDATA%\permissionreset-smb\runs\`. One directory per run, named by `run_id`.
- The Runs list is the set of state dirs under that root, read at start and watched with a
  `FileSystemWatcher`. Runs started from a shell with a state dir elsewhere can be added with
  "Open run folder…".
- The GUI reads `run.json` and `status.json` every second for the selected run, and every 5 seconds
  for the others.

### 9.2 Results store

`records.jsonl` can hold millions of lines. The GUI builds a SQLite index beside it
(`results.sqlite`, with `Microsoft.Data.Sqlite`, bundled native library):

- One row per path, last line wins (plan-smb-run-control.md, 4.3).
- Indexes on outcome and on path.
- Built incrementally while the run goes, from the last read offset.
- The index is a cache. Deleting it is safe; the GUI rebuilds it from `records.jsonl`. The JSON
  lines stay the record of truth.

### 9.3 Process lifetime

- The GUI starts the CLI as a normal child process with no job object that kills it on GUI exit.
  A run continues when the GUI closes. The GUI reattaches from the state dir when it opens again.
- On GUI close with a running run, ask: "Keep running in the background" (default) or "Pause and
  close".
- The child process gets no console window (`CreateNoWindow`). Its stderr goes to
  `segments/NNN.log`; the GUI shows it under "Show log".
- For "Another account" runs, start with `CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY)`.

## 10. Errors and empty states

| Situation | What the screen shows |
|---|---|
| no connection yet | Explore shows a centered card: "Connect to a share to start." with the Connect button |
| server unreachable | a banner over the list with the Win32 error text and code, and Retry |
| access denied on a directory | the list shows "You cannot list this folder as `<identity>`." with "Connect as another account…" |
| access denied on one object | the row's DACL chip says "access denied"; the inspector shows the error and the identity |
| privilege missing | the chip in the title bar is gray; the affected section says which privilege and offers "Restart as administrator" |
| CLI not found or wrong version | Runs shows "permissionreset-smb.exe was not found next to the GUI" or "needs version ≥ X"; Check is disabled |
| spec invalid | the YAML pane shows the tool's error verbatim; Check is disabled |
| run failed | the run's tile is red; Show log opens the segment log; Results opens what was recorded |

Never shorten an error message from Windows or from the CLI. Show it whole, with its code.

## 11. Accessibility and input

- Every control is a real WPF control with an `AutomationProperties.Name`; icon-only buttons get
  one too.
- Full keyboard use: Tab order follows the visual order; every action in a context menu also has a
  keyboard path.
- Colors meet WCAG 2.1 AA (12.1 lists the measured ratios). Outcome and form chips carry a text
  label, never color alone.
- Windows High Contrast themes: use system brushes when `SystemParameters.HighContrast` is true;
  test with "Night sky" and "Desert".
- Text scales with the Windows text-size setting.
- Minimum target size 32 × 32 px for mouse; primary buttons 40 px high.

## 12. Design system

The look keeps the build-spec GUI's palette (`gui/buildspec/frontend/app.css`) and layout (rail,
list, inspector, CLI line), on top of native Windows type and controls.

### 12.1 Color tokens

| Token | Hex | Use |
|---|---|---|
| `Surface.App` | `#F3F1EC` | window background |
| `Surface.Panel` | `#F7ECD8` | rail, inspector, title bar, CLI line (parchment) |
| `Surface.Content` | `#FFFFFF` | list, editor, cards |
| `Surface.Selected` | `#FFF5E3` | selected row, selected radio card |
| `Surface.Muted` | `#EFEDE8` | table header, neutral chip |
| `Border.Default` | `#E7E3DC` | panel and card borders |
| `Border.Strong` | `#C9C3B8` | input borders |
| `Text.Primary` | `#2D2A27` | body text |
| `Text.Secondary` | `#5C4A40` | secondary text |
| `Text.Label` | `#71584C` | uppercase section labels |
| `Accent.Fill` | `#B9471A` | primary button fill, selected border, progress bar |
| `Accent.Brand` | `#FF7023` | decorative only (logo mark); never behind text |
| `Link` | `#A8461A` | links |
| `Code.Background` | `#2D2A27` | YAML, log and raw-record panes |
| `Code.Text` | `#F7ECD8` | text in those panes |

Status pairs (background / text):

| Token | Background | Text | Use |
|---|---|---|---|
| `Form.Inherits` | `#C5E4CC` | `#24402C` | inherits chip, Inherited tag, privilege held |
| `Form.Mixed` | `#EFEDE8` | `#4A3A32` | explicit + inherited chip |
| `Form.Protected` | `#F2CDC4` | `#6B2F22` | protected chip, DENY tag, locked notice |
| `Ace.Allow` | `#DCEBDF` | `#24402C` | ALLOW tag |
| `Ace.Audit` | `#FDE3CF` | `#7D3412` | AUDIT tag, WRITE outcome tag |
| `Outcome.Error` | `#F8D3CF` | `#7A1F17` | ERROR outcome tag |
| `Warn.Text` | `#F7ECD8` | `#8A3A22` | warning text on panels ("not proven yet") |

Measured contrast (WCAG 2.1):

| Pair | Ratio |
|---|---|
| `Text.Primary` on `Surface.Content` | 14.27 |
| `Text.Primary` on `Surface.Panel` | 12.19 |
| `Text.Secondary` on `Surface.Content` | 8.37 |
| `Text.Secondary` on `Surface.Panel` | 7.15 |
| `Text.Label` on `Surface.Panel` | 5.60 |
| white on `Accent.Fill` | 5.28 |
| `Link` on `Surface.Content` | 5.91 |
| `Form.Inherits` pair | 8.32 |
| `Form.Mixed` pair | 9.24 |
| `Form.Protected` pair | 6.96 |
| `Ace.Allow` pair | 9.21 |
| `Ace.Audit` pair | 7.19 |
| `Outcome.Error` pair | 7.47 |
| `Warn.Text` pair | 6.62 |
| `Code.Text` on `Code.Background` | 12.19 |

`#FF7023` with white text is 2.77:1 and fails AA; that is why `Accent.Fill` is the darker
`#B9471A`.

Outcome swatch colors (small squares next to labels, never behind text): ok `#5A8F69`, write
`#B9471A`, follows `#8FA596`, keep `#95685D`, excluded `#C9BFAE`, reparse `#71584C`, error
`#C0392B`.

Dark theme: not in the first release. The Fluent theme's dark mode must be turned off
(`ThemeMode="Light"`) until a dark token set is designed and measured.

### 12.2 Type

| Style | Font | Size / weight | Use |
|---|---|---|---|
| Title | Segoe UI Variable Display | 20 px semibold | screen titles |
| Subtitle | Segoe UI Variable Display | 15–19 px semibold | inspector object name, dialog title |
| Body | Segoe UI Variable Text | 13 px regular | default |
| Body strong | Segoe UI Variable Text | 13 px semibold | principals, row names |
| Caption | Segoe UI Variable Text | 11.5–12 px regular | secondary lines |
| Label | Segoe UI Variable Text | 11 px bold, uppercase, 0.06 em tracking | section labels |
| Mono | Cascadia Mono, then Consolas | 11–12.5 px | paths, SIDs, SDDL, CLI lines, YAML |

Windows Server 2022 has Segoe UI but may not have Segoe UI Variable; fall back to Segoe UI.
Cascadia Mono is not on Server 2022 by default; bundle it (SIL Open Font License) or fall back to
Consolas.

### 12.3 Spacing, shape, icons

- Spacing scale: 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24 px. Panel padding 18–22 px. Card padding
  10 × 12 px. Gap between cards 8 px.
- Radius: chips and primary buttons 999 px (pill); cards and inputs 8 px; tags 4 px; dialogs 10 px.
- Borders: 1 px default; 1.5 px for inputs and the selected-card border.
- Icons: Segoe Fluent Icons (system font on Windows 11; bundle the font or use the matching line
  icons from the build-spec GUI for Server 2022). Line icons, 16 px, 1.7 px stroke. No emoji.

### 12.4 Components

| Component | Spec |
|---|---|
| Form chip | pill, 3 × 9 px padding, 11 px semibold, `Form.*` pair |
| ACE type tag | 4 px radius, 2 × 7 px padding, 10.5 px bold uppercase, `Ace.*` or `Form.Protected` pair |
| ACE card | `Surface.Content`, `Border.Default`, 8 px radius; rows: tag + principal + Inherited tag, sentence, "Copied from" line, raw SDDL |
| Identity chip | pill, white, avatar circle with initials on `#5A6359`, name and mode on 2 lines |
| Privilege chip | pill, `Form.Inherits` pair when held, `Surface.Muted` when not, `Ace.Audit` for unproven |
| Primary button | pill, 40 px high, `Accent.Fill`, white semibold text |
| Secondary button | pill, 40 px high, white, 1.5 px `Border.Default` |
| Radio card | 8 px radius, 1.5 px border; selected: `Accent.Fill` border, `Surface.Selected` fill |
| Outcome tile | 8 px radius, swatch + label, 20 px tabular number, caption |
| Code pane | `Code.Background`, `Code.Text`, Mono 11.5 px, 1.55 line height, 8 px radius |
| CLI line | `Surface.Panel`, top border, Mono 11.5 px, "Equivalent:" in `Text.Label`, copy button |

## 13. Packaging and release

- Output: `permissionreset-smb-gui.exe`, self-contained, single file,
  `IncludeNativeLibrariesForSelfExtract=true`. No trimming: WPF does not support trimming.
  Expect over 100 MB; measure it and record the size in the release notes.
- The release zip (`smb/release/pack.ps1`) holds `permissionreset-smb.exe`,
  `permissionreset-smb-gui.exe`, `build-spec.exe`, the README and the LICENSE, with all 3 checksums
  in `SHA256SUMS`. The GUI finds the other 2 exes next to itself and refuses to run checks if their
  versions do not match its own.
- Authenticode-sign all 3 exes. Conservative customers' application control (WDAC, AppLocker)
  commonly blocks unsigned binaries. Signing needs a certificate and a decision by the maintainers;
  record it as an open question (15) until then.
- The security scans the maintainers add to the release workflow must cover all 3 exes.
- Version: the GUI shares the `smb-vX.Y.Z` tag and version with the CLI.

## 14. Tests

| Level | What | Where |
|---|---|---|
| Unit | `AceDescriber`, inherited-source search, `RunState` readers, status and records parsing | `PermissionReset.Smb.Tests`, Linux and Windows CI |
| View model | screen state machines (run states, preflight, loading), with fake readers and a fake CLI runner | `PermissionReset.Smb.Gui.Tests`, Windows CI |
| UI smoke | start the app, open a fake connection, select a row, open each screen | FlaUI on the `windows-2022` runner; optional in phase G1, required by G3 |
| Lab | real shares on FlashArray: listing speed, descriptor reads, each identity mode, a check run with pause and resume | Windows Server 2022 VM; arranged by the maintainers |

Lab checks of the GUI are usability and display checks. The qualification of a check or apply result
stays with the CLI candidate that produced it (MAINTAINERS.md, section 4).

## 15. Open questions

1. `build-spec --from-smb-descriptor` and `--spec-json` / `--from-spec-json` (7.3): owners, schema
   for the spec JSON, round-trip tests. The Target ACL screen depends on them.
2. A CLI option to check a list of paths, for "Re-run errors only" (7.5).
3. A CLI capability report (`permissionreset-smb version --json` with a `capabilities` list), so the
   GUI can unlock Apply without parsing version numbers.
4. Code-signing certificate and process (13).
5. Fonts on Server 2022: bundle Segoe Fluent Icons and Cascadia Mono, or fall back (12.2, 12.3).
   Check the license terms of Segoe Fluent Icons before bundling it.
6. "View as a target user" needs a domain controller for S4U. Decide the behavior for local accounts
   and for a forest the client cannot reach.
7. Target listing speed: is in-process reading with 16 parallel descriptor reads fast enough on a
   directory of 100,000 entries? Measure in phase G1.

## 16. Phases

| Phase | Content | Depends on |
|---|---|---|
| G0 | move Win32 code into `PermissionReset.Smb.Windows` (no behavior change); .NET 10 | plan-smb-dotnet10.md |
| G1 | shell, Connect (all 3 modes), Explore with the description engine, Copy SDDL, Effective access | G0 |
| G2 | Target ACL from "Copy as target ACL", spec pipeline, validation, Check (dry run) without pause; Results | G1, open question 1 |
| G3 | Run monitor with pause, resume, reattach; results store | plan-smb-run-control.md built and qualified |
| G4 | Apply | DESIGN-write-path.md phase 2 built and qualified; open question 3 |

Each phase is its own PR or PR series. Report each one as "implementation done" and, where it
touches the CLI, "qualification pending" until the maintainers' run passes.
