# `permissionreset-smb inspect`: first array read (2026-11-09)

**Candidate:** `permissionreset-smb` 0.1.0 at `20bf2c3` (PR #38), unmodified, built `-c Release`
with .NET SDK 8.0.427. `permissionreset-smb.exe` SHA-256
`59B139D3896011EC49D7D4A9D4CDDE7370DEEF6FEAF51FE39595C71D944D3239` (a build with SDK 10.0.403 gave
the same hash).
**Array:** a lab FlashArray, one SMB share, a new directory created for this run and deleted after it.
**Client:** a lab Windows host, elevated, as a domain account holding `SeBackupPrivilege` and
`SeSecurityPrivilege`, with the array's audit bypass.
**Fixture:** 13 objects (directories and files) with mapped principals only, 5 of them audited, built
over SMB with the same script as the PR #35 FlashArray run. Its descriptors before the run were byte
identical to that run's on 13/13.
**Reference reader:** `GetFileSecurityW`, independent of `inspect`'s handle-based
`GetKernelObjectSecurity` read with backup intent.

What this run checks: that `inspect` reports what the array stores (read fidelity) and how it
fails. It does not check any write; the tool has none.

## Verdict

| Check | Result |
|---|---|
| `inspect` with SACL, 13 objects | **PASS 13/13** |
| `inspect --no-sacl`, 13 objects | **PASS 13/13** |
| Missing path | **PASS** on exit code and recovery; record content flagged (finding 2, 3) |
| No `SeBackupPrivilege` | **FAIL**: unhandled exception (finding 1) |

## Results

- **With SACL:** exit 0, 13 records, `sacl_read: true`. On every object the `raw` bytes equal the
  `GetFileSecurityW` bytes for owner, group, DACL and SACL. The owner, group, control word and
  control flags, and every DACL and SACL ACE (type, flags including `ID`, mask, SID), equal an
  independent decode of those bytes. The checker was confirmed to catch a tampered field.
- **`--no-sacl`:** exit 0, no `sacl` key, `sacl_read: false`. Owner, group and DACL equal the
  with-SACL read, and `raw` equals `GetFileSecurityW` without the SACL. The control word differs
  from the with-SACL read only in the SACL bits, which is what the server returns for that request
  and not a defect.
- **Missing path, mixed with a good one:** exit 1, one record per path, no crash; the good path
  still got its record.
- **No `SeBackupPrivilege`:** `inspect` and `inspect --no-sacl` both ended in an unhandled
  `Win32Exception` (1300) from the privilege check, exit `0xE0434352`, instead of exit 1 with a
  message. The token for this case had lost Administrators and both privileges but kept its High
  integrity label, so it tested a missing privilege rather than a true medium-integrity shell; the
  crash is at the privilege check either way.

## Findings and fixes

1. **A missing privilege crashed the tool.** Fixed: `inspect` now catches the failure, prints the
   privilege and the Win32 code on stderr, reads nothing and exits 1.
2. **A failed read's `error` was only the step name** (`"open"`), with no reason or code. Fixed:
   `error` now names the step and keeps the system's text (`"open: <reason>"`), and a new
   `win32_error` field carries the code.
3. **A failed read reported `sacl_read: true`.** Fixed: a record with no descriptor has no
   `sacl_read`.

The fixes are offline-tested through a fake descriptor reader (`InspectCliTests`).

## Pending

- The fixes are on a later commit than the one measured here. Read fidelity is unaffected by them
  (the decode path is unchanged), but the missing-path and missing-privilege cases must be rerun on
  the fixed build before those rows can be called a pass.
- A true medium-integrity shell is not tested.
- This is read fidelity only. Nothing here qualifies a write path.
