# Release acceptance

This is the procedure for accepting one release candidate. It has three parts:

1. offline checks on the exact candidate commit;
2. a lab matrix run on disposable fixtures;
3. a trial by an outside reader.

Each part produces an evidence record, and the candidate is released only when every gate below has a
recorded result. An unrun check is recorded as **not run**, never as passed. Evidence from an earlier
candidate does not carry over unless the record says why it still applies
([MAINTAINERS.md](../MAINTAINERS.md)).

Every result is tied to one candidate: a commit and the version string built from it. If the
candidate changes, rerun at least the offline checks and every lab case the change touches.

## 1. Offline checks

```bash
tools/release/acceptance-offline.sh --commit <candidate> --version <vX.Y.Z> \
  --out ~/acceptance/<vX.Y.Z> [--denylist <file>]
```

The script checks out the candidate into a fresh worktree, so uncommitted edits in your checkout
cannot affect the result. In that worktree it runs:

- `go vet` and `go test -race` (with the test cache bypassed);
- the release build, the archive packing and the archive smoke checks (`tools/release/smoke.sh`),
  which unpack every archive outside the checkout and check binaries, documents, links and example
  specs;
- the public-content scan, when you give it a denylist.

It writes `evidence.md`, `SHA256SUMS` and per-step logs. Without a denylist the scan is recorded
as not run. Do not copy a private denylist into the repository: rely on the CI `public-scan` job
instead.

The script cannot run the macOS tests, the GUI module build, CodeQL, vulncheck or lint. Read
those from the CI run for **the same commit**. A green run on a different commit does not count.

The documented commands are checked by `cmd/build_spec/doc_commands_test.go` (part of the test
run), and the guide's links by the smoke checks.

## 2. Lab acceptance matrix

Run every case on **disposable fixtures** built for the purpose, through the authorized lab process.
Never use production or user data. Cases that share a file system, export, identity configuration or
snapshot must run one at a time.

Use the binaries from the release archive whose checksum the offline record lists. Do not use a build
from a checkout. `make release` runs `make clean` first, which deletes the host binaries that
`make build` left in the checkout, so a lab script that calls them after packing fails. Run the
unpacked archive's binaries instead. Record the client OS, array model and firmware, transport, mount options, and the
credential category (for example "root, AUTH_SYS, no root squash" or "domain user without audit
bypass"). Never record the credential itself.

Correctness and operator usability are the gates here, not performance.

These are separate kinds of evidence, and a case passes only on the kinds it names:

- **NFS validation:** `permissionreset --validate` shows that stored ACEs match the spec.
- **SMB descriptor:** the raw security descriptor as Windows shows it (`Get-Acl`, `icacls`).
- **Effective access:** an ordinary user tries to open, change, list or create, and the attempt is
  allowed or refused.
- **Audit delivery:** the array logs an audited access. No case below requires it. Record it as not
  run unless it was checked.

| # | Case | Fixture | Steps | Pass when |
|---|---|---|---|---|
| L1 | Ordinary DACL reset from templates | Templates without audit entries; a tree of mixed files, dirs and existing exceptions | Follow [getting started](field-preview/getting-started.md) steps 6 to 10 | `--validate` reports 0 mismatches; allowed users get in and refused users do not (effective access) |
| L2 | Audited descendant under an unaudited root | Root with no `U` ACEs; one descendant with explicit and inherited audit ACEs | Plain reset without `--sacl` | The descendant's audit ACEs are byte-identical before and after (NFS view); its DACL is the spec's |
| L3 | No read-safety privilege | An identity without the audit bypass | `build-spec`, `--validate` and `--apply`, each in turn | Each stops before reading any existing ACL with `ErrAuditPrivilege` or `ErrAuditNotRetained`; the message names the fix; the fixture is unchanged |
| L4 | Templates carrying audit ACEs | Templates with `U` ACEs | Capture with default options, then with `--with-dacl` | Default output has `sacl:` rules and no `acl:`, and its NOTE says the spec keeps each object's own DACL and replaces only its SACL; an operator reading it per the guide does not mistake it for a DACL repair |
| L5 | Unmapped and synthetic-range identities | Objects whose ACL names `nobody`/65534, or an id >= 1e9 | `--sacl` DACL-keeping apply (with `--accept-dacl-flattening`: the flattening gate is checked first, on FlashBlade too); a spec naming a high id | Refused with the unmapped-principal, synthetic-range or high-id message (the messages are prose and do not print the Go error names); the object is left unchanged; no object is written with a substituted identity |
| L6 | SMB-written data (FlashArray) | A tree created from a Windows client | Plain reset, then the DACL-reset fidelity check | The SMB descriptor matches the spec within the limits in [RISKS.md](../RISKS.md) #11; an ordinary user's access from SMB matches the intent |
| L7 | New child after repair | The repaired L1 tree | Create a file and a directory as an ordinary user, over NFS and over SMB where used | The new objects inherit what [getting started](field-preview/getting-started.md) step 9 says: inherited ACEs (on SMB, an auto-inherited DACL with every ACE inherited); new files carry the directory rule's file-inheritable entries, so a `--validate` mismatch on them is expected when those differ from the file rule. Objects the repair wrote stay protected and explicit |
| L8 | Interrupted apply and resume | A tree large enough to stop mid-run | Kill the apply (SIGINT, then SIGKILL in a second run), then rerun with `--resume` | No summary claims completion before the resume finishes; after it, a fresh `--validate` reconciles `Checked` = `Enumerated` with 0 mismatches |
| L9 | Snapshot recovery | A disposable file system | Snapshot, verify the restore, repair, then restore | Pre-repair ACLs come back exactly; the record states that data written after the snapshot was lost too |
| L10 | Each advertised route | Every row of the guide's route table that claims support | Download, verify the checksum, run `-version` | Each route works from the archive alone, or the docs label it unsupported or unverified |

For L6, reuse the raw-descriptor comparison from the
[DACL-reset fidelity evidence](../benchmarks/dacl-reset-fidelity-20261020/README.md). Run it with
the fixture's own paths and principals, not ones copied from that record.

If a case cannot be run, for example because no identity without the bypass is available, record it
as **not run**, with the reason, and decide before release whether that limit is acceptable.

## 3. External-reader trial

One operator who did not build the tool uses **only the release archive and the
[getting-started guide](field-preview/getting-started.md)**, on a disposable fixture. A maintainer
watches and does not coach. The maintainer answers only to stop harm to anything other than the
fixture, and records that as an intervention.

The operator must:

- [ ] choose the right archive, binary and transport, and say in their own words what the repair
      will change and what it will leave alone;
- [ ] capture approved templates and say which ACL parts (DACL, SACL) the spec will change;
- [ ] apply to a canary, and find an intentionally wrong permission planted by the maintainer, using
      ordinary-user access tests (not `--validate` alone);
- [ ] interrupt a run, resume it, and recognize a run that is incomplete or failed;
- [ ] explain recovery, and restore the fixture from its snapshot.

For every intervention, record what the operator was trying to do, where they stopped, and what
they were told. Each intervention becomes a fix to the guide or the product, or an issue with a
reason it does not block the release. Unit tests do not replace this trial.

## Evidence record

Copy this into the release's evidence record. Keep raw lab data (hostnames, addresses, real
principals, paths) private, and publish only a sanitized summary that follows
[MAINTAINERS.md](../MAINTAINERS.md).

```markdown
# Release acceptance: <vX.Y.Z>

Candidate commit: <full sha>    Version string: <vX.Y.Z>
Archive checksums: <SHA256SUMS from the offline record>
CI run for this commit: <link>

## Offline
<paste evidence.md table>

## Lab
| # | Client OS | Array / firmware | Transport | Credential category | Fixture | Evidence kinds | Result | Notes |
|---|---|---|---|---|---|---|---|---|
| L1 | | | | | | NFS, access | PASS / FAIL / NOT RUN | |

## External-reader trial
Operator role (no name): <role>    Date: <date>
| Task | Completed unaided? | Interventions | Resulting fix or issue |
|---|---|---|---|

## Exclusions and remaining limits
<routes, firmware, identities and evidence kinds not covered by this candidate>
```

## Release gate

Release only when:

- the offline record passes for the candidate, and CI is green for the same commit;
- every lab case passes, or is not run with an accepted, recorded reason;
- the trial has been run and every intervention has a fix or an issue;
- the exclusions are written into COMPATIBILITY.md and the release notes.

Publishing and tagging need the release authorization of the session doing them. Having the
credentials is not that authorization.
