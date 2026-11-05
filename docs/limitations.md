# Known Limitations (technical)

Operator-facing limitations for field deployment are in [field-preview/known-limitations.md](field-preview/known-limitations.md). This file records the technical/implementation limits of the current tree.

- SMB repair is out of scope by design — NFSv4 ACLs are authoritative for SMB clients on FlashBlade (see the [README](../README.md#multiprotocol-smb)). `protocol: smb` rejected at spec load. NFSv4-to-SMB rendering verification from a Windows client is still pending.
- Validation (`--validate`) and structural compare (`--compare`) support both `posix` and `nfsv4` protocols. `smb` is not applicable (see above).
- Directory-fix cost still scales with directory count, but is no longer a separate floor on every run — it is absorbed into the single walk. `--pfind` is the exception and keeps the two-phase cost, since an external enumerator cannot be fused with the fix.
- The filehandle cache is in-memory and is not persisted. `--resume` on the userspace transport re-resolves directory filehandles by `LOOKUP` while descending to the checkpoint frontier. The cost is proportional to depth rather than to tree size, and resume is rare, but it is a real regression against the kernel's dentry cache.
- `--pfind` keeps two-phase walk (external enumerator cannot be fused with the fix).
- `--compare`/`--validate` use structural ACL comparison with case-insensitive identity normalization; raw byte differences from idmapd domain casing no longer cause false mismatches.
- Audit ACEs (SACL) need `--sacl`, on FlashArray and on FlashBlade multiprotocol file systems. A DACL-keeping rule (`sacl:` with no `acl:`) reads each object and writes it back with its own DACL bytes and the spec's SACL. On the kernel transport the read and the write are separate calls, so a DACL change in between is lost; a conditional `VERIFY(change)` write on userspace is designed but not built (and userspace on FlashArray is implemented but has no hardware run). DACL-keeping directories cannot use the fused `ReadDirSetACL` write, and files are read in batches only on userspace. Without `--sacl`, an `acl:` spec is refused when the target root carries audit ACEs; audit ACEs below a clean root are deleted unless `--compare` is on. Full list: [spec-guide.md](spec-guide.md#limits).
- Symlink TOCTOU: trusted-tree model — target namespace assumed stable during run. A regular file can still be swapped for a symlink between the walker's `Lstat` and the apply worker's `Chmod`/`setxattr` (see [RISKS.md](../RISKS.md) item 4). Recommend a FlashBlade snapshot (instantaneous, free) before any run where concurrent filesystem modification is expected.
- `--max-ops-per-compound` on the userspace transport is accepted and validated but only partially enforced — apply uses fixed two/three-operation COMPOUNDs, validate batches 4×(PUTFH+GETATTR). The flag does not yet cap the validate batch size.
- A tuning entry is keyed by client, server, export and transport only. Mount options are outside the identity, so two differently-mounted views of one export share an entry and the last sweep wins.
- Sweeping requires a kernel NFS mount even when tuning the userspace transport, because tree generation goes through the POSIX backend.
- `make release` produces local cross-compiled binaries but there is no goreleaser or published/signed release artifact.
- `generate-tree --transport=userspace` does not validate principals. The kernel path probes every principal in the roster before fanning out — it stamps a throwaway local file with each one and refuses to start if any fails to resolve (`treegen.ValidatePrincipals`). The userspace path skips this entirely: the probe writes a local file, which a mount-free run cannot do, and there is no over-the-wire equivalent yet. A typo in `--principals` is therefore found at fan-out time rather than at startup, after the tree has begun to appear. Verify the roster against the array before a large userspace generation run.
- A mount-free `generate-tree` derives its safety ACE principal from the local account name (`--safety-principal` overrides). On a machine not bound to the NFSv4 domain that name is one the array cannot resolve, and because principals are not validated on this path (above) it is not caught at startup.
- `generate-tree --acls-only` and `--no-acls` are refused with `--transport=userspace`. Both reach only the kernel code paths whatever the transport says — a local `setxattr` of `system.nfs4_acl`, and a fan-out that copies through a mount — so on a host that has to use the userspace transport they would build the tree in the wrong place or die at the first xattr. `cmdflags.Gate` cannot express this: each flag is portable on its own, and it is the combination with a transport that is not. Re-stamping an existing tree over the userspace transport has no implementation yet.

## Identity forms in ACE principals

A spec may name a principal numerically (`A::10001:...`) or as `name@domain`
(`A::jdoe@example.com:...`). The two are reconciled for comparison, so `--validate`
and `--compare` accept either form regardless of which one the server stores. The
reconciliation needs the principal to be resolvable on the client -- through `os/user`
or `getent`, whichever answers -- plus an NFSv4 domain in `/etc/idmapd.conf`. When
either is missing the comparison falls back to matching the `who` string literally,
which is correct but stricter: a numeric spec against an idmapped export will then
report mismatches on objects whose ACLs are in fact correct. `--apply` is unaffected
either way; only the comparisons are.
