# Preflight Identity-Mapping Checklist

NFSv4 ACL principals go through three layers of identity mapping between the YAML spec and what FlashBlade stores. A misconfiguration at any layer causes EINVAL on setxattr, silent identity substitution, or `--compare`/`--validate` mismatches. Run this checklist before the first apply.

**Which half of this file applies is decided by the transport, not by the platform.** Sections 1–6
below are the `--transport=kernel` checklist: the Linux kernel NFS client is what maps names there,
so idmapd, sssd and `nsswitch.conf` matter. If you are running `--transport=userspace` — on Linux
or on macOS, where it is the only transport — skip to the userspace section at the end.

# Kernel transport (`--transport=kernel`, Linux only)

## 1. Check idmapd domain

```bash
grep -i domain /etc/idmapd.conf
```

If `Domain` is set, it must match what the FlashBlade expects. If unset, idmapd falls back to the client's DNS domain (e.g., `corp.example.com`), which may not match.

Two common configurations:

| Client | Domain | Notes |
|---|---|---|
| AD-joined | `corp.example.com` (explicit) | Matches the AD domain |
| Not joined | unset (falls back to the DNS domain) | Numeric IDs only |

## 2. Check security flavor

```bash
mount | grep <export>
# Look for sec=sys or sec=krb5
```

- `sec=sys` — principals are uid/gid numbers. Identity mapping is client-side only.
- `sec=krb5` — principals are Kerberos names. Requires a valid keytab and ticket. **Untested with permissionreset.**

## 3. Choose the right principal format in the spec

| Format | setxattr | Stored as | --compare matches |
|---|---|---|---|
| `OWNER@` / `GROUP@` / `EVERYONE@` | works | same | yes |
| numeric ID (resolvable) | works | may become `user@domain` | **no** |
| numeric ID (not resolvable) | works | same numeric | yes |
| `user@domain` | works if idmapd resolves it | `user@domain` | yes |
| `user@domain` (unresolvable) | **EINVAL** | — | — |

**Rule of thumb:** use the form the server returns. Run `nfs4_getfacl` on one file to see what the server stores, then write the spec to match exactly.

```bash
nfs4_getfacl /mnt/fb/target/somefile
```

## 4. Verify with the preflight probe

permissionreset runs a preflight probe on the target directory before the real run. It tries a single setxattr and reports immediately if it fails:

```bash
permissionreset -spec spec.yaml /mnt/fb/target
```

If the probe fails with EINVAL:

- The principal in the spec cannot be resolved by this client's idmapd
- Check that `nfs4_getfacl` can read ACLs on the target
- Check that the domain in the spec's principals matches `/etc/idmapd.conf`

## 5. Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `EINVAL` on every setxattr | Principal not resolvable by idmapd | Use the form from `nfs4_getfacl`, or fix idmapd domain |
| `--compare` never skips (Skipped: 0) | Stored form differs from spec form | Rewrite spec principals to match `nfs4_getfacl` output |
| `--validate` reports mismatches after successful apply | Same as above — identity normalization | Same fix |
| `EACCES` on setxattr | Client not authorized (root_squash or sec mismatch) | Check export policy: `no_root_squash` for root, or run as the export's allowed principal |
| Probe passes, bulk run fails | Probe uses the target directory; deeper objects may have different ownership | Check export policy covers the full tree, not just the root |

## 6. FlashArray differences (if applicable)

FlashArray normalizes ACLs differently from FlashBlade:

- Drops the `g` flag on `GROUP@`
- Resolves named principals to numeric uids in the stored ACL
- Invalidates the filehandle after a SETATTR that sets the ACL

The userspace transport refuses FlashArray by design; kernel transport is untested.

# Userspace transport (`--transport=userspace`, and everything on macOS)

Nothing above applies. The client resolves no principal names: the spec's principal strings go into
the ACL's wire bytes verbatim and the array resolves them. That is also why a name this host cannot
resolve is only a **warning** here, not a refusal — the run continues, because this host is not the
authority. Check three things instead.

**1. The array resolves every principal the spec names.** This is the only resolution that happens.
From the array:

```
pureuser@array> ls -le /<filesystem>/<a-path-with-a-known-good-acl>
```

If a principal in your spec does not appear resolvable there, the repair will write it and the
array will store something you did not intend. Fix the directory binding on the array, not on the
client.

**2. The AUTH_SYS identity is one the export accepts.** The default is the running process's uid,
gid and groups, which is right on a lab Linux client and usually wrong on a Mac. Supply it
explicitly:

```
--auth-uid 10010 --auth-gid 10000 --auth-gids 10020,10021
```

A uid of 0 draws a warning about root squash; a uid below 1000 draws a warning that it looks like a
local account. Neither blocks the run. Confirm the values against the directory's `uidNumber` and
`gidNumber` attributes for the account you intend to act as — not against the Mac's local ids.

**3. Preflight succeeded.** `permissionreset` performs a real ACL write against a probe object before
the walk begins — but **only under `--apply`**. A dry run never exercises the credential and prints
a note saying so, so do not read a clean dry run as a validated identity. If the preflight write
fails with a permission error, the credential is wrong; stop and fix it. Do not proceed on the
assumption that it will work for the rest of the tree — it will not, and you will find out after
several hours.

**Not applicable on the userspace transport:** idmapd, `nfsidmap`, `sssd`, `nsswitch.conf`, the
NFSv4 domain setting in `/etc/idmapd.conf`, and Kerberos (`sec=krb5*` is unsupported — the
userspace client implements AUTH_SYS only, so only `sec=sys` works).
