# FA SACL behavior model — Purity//FA 6.10.6, NFSv4.1, observed 2026-10-14

Measured on `lab array A`, `sacl-test`, kernel NFSv4.1 AUTH_SYS from
`jdoe-linux01`. The actor is `jdoe` (uid 1402, rid 2685) unless a row says otherwise. Every
case uses a fresh object, a remount before the operation (so the client caches nothing), and a
read of the `sacl-logs` export afterwards. Each result below reproduced on every run.

Tools in this directory:

| File | Purpose |
|---|---|
| `sacl-harness.sh` | `case_file`/`case_dir NAME 'U-ACE' 'OP' ['PRE']`: fresh object, SACL, remount, op, new events only |
| `alog.py` | flattens the FA XML audit log to one line per event |
| `bits.sh`, `bits-matrix.out` | 14 mask bits × 20 operations, one bit per case (280 cases) |
| `blindset.py` | setxattr of `system.nfs4_acl` with no read first (what `applyNFSv4` does) |

## 1. Storage: two SACL states per object

An object's SACL is in one of two states:

- **INHERIT**: the object has no SACL of its own. A read returns the parent's current inheritable
  `U` ACEs, applied as for a new child: `fd` → `fd` on a dir and plain on a file, `f` → `fi` on a
  dir, `n` stops at one level, and `i` on the parent does not apply to the parent itself.
  Enforcement uses the same dynamic value. A new file or dir starts in INHERIT, and so does every
  existing child when an inheritable ACE is first added to its parent.
- **EXPLICIT**: the object holds its own list, possibly empty. Parent changes no longer reach it.

Transitions:

| Event | Actor with the bypass (root, jdoe) | Actor without it (user-n1) |
|---|---|---|
| ACL read (`getxattr system.nfs4_acl`, `nfs4_getfacl`) | INHERIT → EXPLICIT with the values read | INHERIT → **EXPLICIT empty**: auditing on the object ends (3/3, `push/jr*`) |
| Blind ACL write (setxattr, no read) | EXPLICIT, set to the `U` ACEs written, **possibly none** | DACL set, SACL **left as it was** (still INHERIT, 3/3); a write that contains `U` fails EACCES |
| `nfs4_setfacl -a/-x` | a read then a write, so EXPLICIT | the read freezes to empty first |
| `stat`, data read, data write, readdir, audited access | no change | no change |
| ACL read of an **EXPLICIT** object | no change | no change (3/3, `h/xread`, actor `juser`) |
| Denied open-for-append of an EXPLICIT object | — | no change (3/3, `h/xapp`) |

**Reading the ACL changes the object**, and when a user without the bypass does the read, it
deletes the object's auditing.

Consequences:

- The ACL that comes back never has the `I` flag. An inherited ACE and an explicit one look the
  same, so a merge cannot use `I` to tell them apart.
- `nfs4_setfacl -a` of an ACE that the object already inherits makes a duplicate, because the read
  freezes the inherited copy and the add appends the same ACE. That explains the duplicates in
  `b-test`. Duplicates audit only once (`dup-aces` case).
- **The DACL is not like this.** DACL inheritance is static: an `A:fd` ACE added to a parent never
  shows up on an existing child (`push/w` case).
- **A blind DACL-only write (today's `permissionreset`) moves the object to EXPLICIT with an empty
  SACL.** That deletes an explicit SACL, as test (b) showed, and also cuts off dynamic inheritance
  from the parent for good (`blindset` on `push/y/k1`).
- The SACL stays where it is when the MD's audit policy is removed or added again (test (f)).
- The array accepts `U` ACEs on an MD with no policy and keeps them there.

## 2. Logging: when an event is written

An event is written only when **all** of these hold:

1. The MD has an audit policy attached. On `noaudit`, the same SACL and operation write nothing;
   on `data` and `toggle`, they write events.
2. The actor matches a `U` ACE in the object's effective SACL (explicit or dynamic). Matching
   works for the user SID, a group the user belongs to (`Domain Users`, `Domain Admins`),
   `EVERYONE@`, and `OWNER@` when the actor owns the object. A different user writes nothing. Root
   under AUTH_SYS matched no ACE in any test, so root's own activity was never logged.
3. The result matches the flag: `S` for success, `F` for failure. With `F` alone, a successful
   operation writes nothing.
4. The operation's access bits intersect the ACE mask. The rows are below.
5. The operation reaches the server. A cached client read writes nothing, and `stat`, `cd` and
   `ln` write nothing even with every bit set.

Errors that are not permission errors write nothing, even with `F`: `rmdir` on a non-empty dir,
and `O_EXCL` create of a file that exists.

**Reads are logged once.** A 4663 `read` is written for the first read since the object's last
attribute change. Later reads, across remounts and by any user, log only the open and close. A
chmod, utimes or ACL write arms it again. A data write disarms it: the next read after a write logs
no `read` event (3/3, `rd`/`rd2`). Waiting 60 s or 600 s does not arm it again (`rd3`). Writes are logged every time.
The 4656 open is logged every time, so count opens, not `read` records, to count reads.

The log becomes visible on the logs export about 0.1 s after the operation. Records are flushed
one at a time and can trail an operation slightly. The harness waits 3 s after a setup step so a
setup write cannot show up as part of the next operation.

### Bit → event (one bit per ACE, `bits-matrix.out`)

| Operation | Bits that log it | Event(s) |
|---|---|---|
| open for read (cat, exec) | `r` or `x` | 4656 open (AccessMask 0x21) + 4658 close; no per-READ event |
| open for write / append | `w` or `a` | 4656 open (0x6) + 4663 write (offset/length) + 4658 close |
| truncate | `w`/`a` (open+write) or `T` (4663 setattr basic) | |
| utimes | `T` → 4663 setattr basic; `w`/`a` → the open and close only | |
| chmod (file or dir) | `C` | 4670 setattr dacl |
| chgrp | `o` | 4663 setattr group |
| ACL read | `c` | 4663 getattr dacl sacl |
| ACL write | `C` (plus `c` for the read before it) | 4670 setattr dacl sacl |
| rename / unlink / rmdir (the object's own SACL) | `d` | 9999 rename / 9998 remove |
| create file in dir (the dir's SACL) | `w` or `x` | 4656 create_regular_file, named on the child |
| create subdir (the dir's SACL) | `a` or `x` | 4656 create_directory |
| remove child (the dir's SACL) | `D` or `x` | 9998 remove |
| rename child (the dir's SACL) | `w`, `x` or `D` | 9999 rename |
| readdir | `r` | 4663 readdir |
| `t`, `n`, `N`, `y` | none of the 20 operations | — |

Event IDs: 4656 open/create, 4663 access, 4658 close, 4670 permission change, 9998 remove,
9999 rename. Each event carries the actor SID, the client IP, the inode and the path.

### Failure events (actor `user-n1`, denied by the DACL; `fail.sh`, `fail.out`)

| Denied operation | Event |
|---|---|
| open for read (`cat`), including through an explicit `D` ACE | 4656 **deny** open, AccessMask 0x0, DesiredAccess 0x21 |
| open for write / append / truncate | 4656 deny open, DesiredAccess 0x6 |
| utimes | 4656 deny open (0x6) + 4663 deny setattr basic |
| chmod | 4670 deny setattr dacl |
| ACL read | 4663 deny getattr dacl sacl (`nfs4_getfacl` still exits 0) |
| ACL write | 4663 allow getattr dacl + 4670 deny setattr dacl sacl |
| create file / subdir in a dir | 4656 deny create_regular_file / create_directory |
| remove child / rename child | 9998 / 9999 deny |
| readdir (`ls` EACCES) | **nothing** |
| lookup through a dir with no `x` | **nothing** |
| exec of a file without `x` (the client refuses after ACCESS) | allow open + close only |

- With `F` alone, a denial is logged and a success is not. With `S` alone, the reverse.
- On failures the mask still gates. A denied write is logged by `w` or `a` and not by `r`. A
  denied read is logged by `r` and not by `w`. `EVERYONE@` and group (`Domain Users`) ACEs match
  on failures too.
- On an allowed open by `user-n1`, AccessMask is what was granted (0x1), not what was asked for
  (0x21). For the bypass users it is the full request.

## 3. Privilege

- `jdoe`, `user-b2`, `user-b1` and `user-b3` bypass the DACL completely over NFS, **including an
  explicit `D` deny ACE**. They can read and write `U` ACEs. `user-n1` and `user-n2` cannot: a read
  silently drops the `U` ACEs, and a `U` write fails with EACCES. The split does not follow
  Domain Admins membership, because `user-n2` is a Domain Admin.
- So no `F` (failure) event can be produced as `jdoe`; the failure rows above use `user-n1`.

## 4. What this means for permissionreset

0. **An ACL read by any user without the bypass wipes the object's audit settings**, if it was
   inheriting them. Any NFS client that runs `nfs4_getfacl`, or any backup or indexing tool that
   reads ACLs as an ordinary user, deletes auditing one object at a time with no error and no
   record. This is an array behavior, not a permissionreset one, and it is worth an FA bug report on
   its own.
1. **A read changes the object.** Mode B (`GetACL`, merge, `SetACL`), `--compare` and `--validate`
   freeze every INHERIT object they read. A tree that inherited dynamically from a few top-level
   ACEs ends up with one explicit copy per object. Later edits to the parent then stop reaching
   anything. Any read path the tool has, including a validate-only run, changes SACL semantics on
   FA.
2. **A blind write changes the object as well.** Today's apply, and Mode A without `sacl:`, sets
   every object it touches to EXPLICIT empty. RISKS #10 should say that this cuts off inheritance
   too, not only that it deletes explicit ACEs.
3. **The right Mode B for FA may be "write the SACL only where it is declared".** Put the audit
   ACEs, with `fd`, on the rule's top directory, and leave the descendants alone, or write them
   blind with their DACL and no `U`. Neither option holds up: a descendant's DACL write still
   empties its SACL (item 2). On FA, a per-object DACL repair and dynamic SACL inheritance
   **cannot both be kept** by one `setxattr` per object, unless every object is written with its
   effective audit ACEs as explicit ACEs. That is what Mode A with `sacl:` does.
4. The merge cannot depend on `I`, and it must collapse duplicates of one principal (§1).
5. The preflight read-back always succeeds on an MD with no policy, so it cannot detect a missing
   policy (test (f)). Check the MD's policy on the array, or warn about it.
6. An unprivileged blind DACL write leaves the SACL alone, so a run without the bypass is the only
   way to repair the DACL without touching the SACL. But it can repair only objects whose DACL
   lets that user write the ACL, and any read path (`--compare`, `--validate`) wipes inheriting
   SACLs (item 0).
7. Mode B and `--validate` must run as an identity with the bypass. Without it the reads come back
   empty and the writes fail with EACCES (test (d)).

## 5. Not yet determined

- One unexplained loss: `h/juser-probe` was set EXPLICIT with one `U` ACE, read by `juser` and
  given a denied append, and afterwards had no `U`. Neither step alone reproduced it (3/3 each,
  with controls). The probe had no privileged read before `juser` touched it, so the `U` write
  itself is not confirmed. Rerun with a pre-read if it matters.

- Whether the userspace transport's GETATTR of the ACL freezes the same way. It is the same
  server operation, so it is expected to.
- The cause of the bypass split (`user-n2` and `user-n1` against the others).
