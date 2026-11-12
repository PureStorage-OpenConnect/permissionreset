# build-spec

`build-spec` captures the NFSv4 ACLs from exactly one directory and one file and writes a
`permissionreset`-compatible YAML spec. It never writes the templates, but it does write to the
array: before reading, it writes and removes a disposable probe under `--probe-dir` to prove the
audit bypass, and `--verify-write` also writes and reads back the captured ACLs on scratch objects
to confirm round-trip fidelity.
It refuses to overwrite an existing output file.

A desktop front end is documented in [build-spec-gui.md](build-spec-gui.md). Installing it on each
platform is covered in [INSTALL.md](../INSTALL.md#build-spec).

The identity report on stderr shows the principal strings as read from the array; stdout carries
only YAML, and only with `--output -`. "write verification: not performed" means `--verify-write`
was not passed. It does not mean nothing was written: see the probe below.

Put every flag before the two paths. Go's flag parser stops at the first positional argument, so
a flag after the paths is not parsed and the command fails (for a trailing `--output`, with
`--output is required`).

## The audit-bypass probe

Before it reads the exemplars, `build-spec` writes and removes one disposable probe in
`--probe-dir` (a scratch directory on the same mount; for the userspace transport a server path
inside the export) to prove the identity has the audit bypass. Without `--probe-dir` or
`--verify-write` it refuses and reads nothing. The probe directory and the `--verify-write` scratch
must already exist; `build-spec` does not create them. `--accept-unproven-read` skips the proof
instead; on an array where an unprivileged read empties inherited auditing, that read can change
the exemplars. See [live-read-contract.md](live-read-contract.md).

## Usage

```bash
# Linux (kernel NFSv4.1 mount)
build-spec --output project-permissions.yaml \
  --probe-dir /mnt/fb/templates/scratch \
  /mnt/fb/templates/folder /mnt/fb/templates/file.txt
```

```bash
# macOS / Windows — direct NFSv4.1 (userspace transport)
build-spec --server 192.0.2.50 --export /data \
  --auth-uid 10010 --auth-gid 10000 \
  --output project-permissions.yaml \
  --probe-dir /data/templates/scratch \
  /data/templates/folder /data/templates/file.txt
```

```powershell
# Windows PowerShell
.\build-spec.exe --server 192.0.2.50 --export /data `
  --auth-uid 10010 --auth-gid 10000 `
  --output project-permissions.yaml `
  --probe-dir /data/templates/scratch `
  /data/templates/folder /data/templates/file.txt
```

Pass `--output -` to write YAML to stdout. `--transport kernel|userspace` defaults to
`kernel` on Linux and `userspace` on macOS/Windows.

## Audit ACEs

If the exemplars carry audit (`U`) ACEs, the spec has DACL-keeping `sacl:`-only rules (an
exemplar with none gets `sacl: []`) that run with `permissionreset --sacl`; `--with-dacl` adds the
DACLs as `acl:` too. Without audit ACEs the output is a plain DACL spec with no `sacl:` key, which
runs without `--sacl`. Alarm (`L`) ACEs are dropped with a NOTE. Capture FlashArray exemplars with
the audit bypass: without it the array returns no audit ACEs. Details:
[spec-guide.md](spec-guide.md#capturing-a-sacl-spec-with-build-spec).

## `--sacl-plan`

`build-spec --sacl-plan SPEC.yaml` is a separate mode for `tools/set-saclonly/Set-SaclOnly.ps1`,
which writes SACLs over SMB. It loads a `permissionreset` spec with the same validation
`permissionreset` uses and prints JSON on stdout: each rule's label and match, its `sacl:` lines
translated to Windows audit ACEs (flags, mask, and SID and SDDL for `EVERYONE@`, `OWNER@` and
`GROUP@`), and the exclude list split into base-name and path patterns. It reads only the spec,
takes no other flag or argument, and exits non-zero for an invalid or non-`nfsv4` spec.

## Live differential test

`tools/build-spec-differential.sh` verifies that kernel and userspace transports produce
identical specs from the same exemplars, then validates both specs with `permissionreset --validate`
against a small test tree. Run on a lab host with FlashBlade mounted; exemplars and scratch
space are on the mount.

```bash
MOUNT=/mnt/fb SERVER=192.0.2.50 EXPORT=/fb-perms tools/build-spec-differential.sh \
  /mnt/fb/template_dir \
  /mnt/fb/template_file.txt
```
