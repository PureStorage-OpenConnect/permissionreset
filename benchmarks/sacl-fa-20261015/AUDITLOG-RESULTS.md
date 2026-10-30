# Audit records from a permissionreset-applied SACL — lab array A (6.10.6), 2026-10-15

Question: after `permissionreset` applies `examples/nfsv4_sacl_keep_dacl.yaml`, does activity on the
tree produce file-audit records?

Target: the medium lab tree `r20261015-144638` on `sacl-test:data`, which has audit policy
`sacl-pol` → log target `sacl-local`. Records were read from the
`sacl-logs` export with `../sacl-phase0-20261014/alog.py`. Each operation ran right after a
remount. Full event list: `auditlog-events.txt` (paths relative to the tree root).

lab array B (6.12.1) was not tested: it has no audit policy or log target, so the xlarge tree there
cannot log. Adding them is an array configuration change.

## Result — PASS

| Operation | Actor | Records |
|---|---|---|
| read `file_0000.md` | jdoe (2685) | 4656 open 0x21 + 4658 close |
| append `file_0000.md` | jdoe | 4656 open 0x6 + 4663 write (length 11) + 4658 close |
| append `file_0002.csv` | jdoe | open + write + close (jdoe bypasses the DACL, so not a denial) |
| create / read / delete `auditprobe.txt` in `bulk_data` | jdoe | 4656 create_regular_file, open, setattr, close; open + close; 9998 remove |
| create `auditprobe-deny.txt` (mode 600) at tree root | jdoe | create, open, write, close |
| ACL read of that file | jdoe | 4663 getattr dacl sacl |
| **denied** read of that file | juser (2699) | **4656 deny open, AccessMask 0x0, DesiredAccess 0x21** |
| readdir `bulk_data`, readdir tree root | jdoe | 4663 readdir (each) |
| read `file_0001.xml` | root (rid 0) | 4656 open + 4658 close |

The new files carried the inherited SACL: `auditprobe-deny.txt` read back as
`U:SF:EVERYONE@:rwadxTNcCoy` from the root's `fd` ACE.

## Things that write no record, as the phase-0 model predicts

- No 4663 `read` on the data reads: a read is logged once per attribute change; count the opens.
- juser reading `data/beta_09/bulk_data/file_0000.md` returned EACCES and logged nothing. uid 1445
  cannot search `data/`, and a denied lookup is never logged (`SACL-MODEL.md` §2).
- The first `ls bulk_data` logged nothing; the second, after a create and remove in that dir,
  logged a readdir. Readdir appears to follow the same once-per-change rule as read (an inference
  from one pair of cases, not measured the way `rd`/`rd2` were).

## Differs from the phase-0 model

- **Root was logged.** `sudo cat file_0001.xml` wrote open and close records with rid 0, and the
  medium run's own records include rid 0 getattr events. `SACL-MODEL.md` §2.2 says root matched no
  ACE in any phase-0 test. Here the ACE is `EVERYONE@`; the phase-0 cases named specific
  principals. Not yet run in isolation.
