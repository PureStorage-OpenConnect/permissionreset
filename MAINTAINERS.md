# Maintenance covenant

This is the authoritative maintenance policy for this project. Contributors and coding agents
must follow it when developing, verifying, publishing, or releasing changes. Read it before
starting work, together with applicable repository instructions and any local instructions.

This covenant defines how authorized work is performed; it does not independently authorize
publication, releases, access changes, or mutations of external systems. Explicit user instructions
and applicable organization requirements take precedence. Surface material conflicts instead of
silently weakening the policy. Do not repeatedly ask for authorization already granted.

## 1. One authoritative product

This repository is the source of truth for product code, reusable tests, public design decisions,
user documentation, version tags, and supported release artifacts. Implement ordinary product
changes on branches of this repository and review them through pull requests.

External qualification environments consume an explicitly pinned revision or identified artifact.
They must not become independent sources of product fixes or supported binaries. Experimental
builds must be labeled as such. Bring discoveries back as focused, public-safe changes against this
repository's history. Never import unrelated private ancestry or use repeated full-tree exports as
the normal development workflow.

Embargoed security work may use a private workspace based on a known public revision, following
[SECURITY.md](SECURITY.md). Publish the reviewed fix through the coordinated disclosure process.

## 2. Public-safe before publication

Everything pushed here, including intermediate commits, must be suitable for public disclosure.
Do not publish credentials, internal infrastructure identifiers, customer data, private coordination
records, or unsanitized operational evidence. Use fictional identities and documentation addresses
in examples. Public-safe implementation plans and design decisions may live here.

Before pushing internally authored work, review outgoing commit content and author/committer
metadata, commit messages, PR text, and attachments. A clean final tree does not establish that
earlier commits are safe. Use the applicable private identifier scan and secret checks before
publication; keep private scan inputs and sensitive matches out of public logs. Public CI runs
after upload and is an additional check, not the publication boundary.

Do not assume `.gitignore` removes already tracked data or erases history. If required checks are
unavailable, finish unaffected local work and report the publication blocker; do not claim a clean
scan. Handle suspected exposures through the security process.

## 3. Explicit identity and workspace ownership

Before remote mutations, verify the intended repository, push destination, commit identity, and
effective API account. Commit attribution, Git authentication, and API authentication are separate
concerns. Do not rely on another session's globally active account or change global authentication
to route concurrent work. Never print tokens while checking identity.

Use local instructions for environment-specific routing. Keep named sessions, private paths, and
credential configuration out of tracked public instructions. Each agent owns its assigned
workspace; coordinate external work through the established handoff rather than editing another
session's checkout. Independent changes should use separate branches/worktrees with explicit file
ownership. Preserve unrelated changes.

## 4. Evidence belongs to an exact candidate

Verification records must identify the tested source revision and, for a binary, its checksum.
Also identify relevant harness revision, environment category, scenarios, and limitations. A dirty
or patched build must record its modifications and must not be described as an unmodified release.

Changes affecting ACL writes, identity mapping, traversal, recovery, or protocol behavior require
relevant hardware qualification before release. Ordinary contributors need not own hardware:
maintainers arrange qualification and record pending work explicitly. Documentation-only changes
need appropriate documentation checks, not an unnecessary hardware run.

Record passed, failed, skipped, and unverified cases separately. Offline tests do not prove hardware
behavior; historical results do not qualify a new candidate automatically. When a candidate changes,
record which evidence remains applicable and which checks must be rerun. Never call stale evidence
a test of the new revision.

Keep these claims distinct: structural ACL agreement, effective access, identity fidelity, SMB
descriptor/inheritance fidelity, traversal coverage, stored audit rules, and delivered audit events.
One passing check does not prove the others. Publish sanitized summaries; retain sensitive raw
evidence through the authorized internal process.

## 5. Review, CI, and releases

Use pull requests and the project's required CI checks. Safety-sensitive changes require an
independent review before release. Automation acting on untrusted contributions must not receive
access to privileged qualification environments. Public CI uses GitHub-hosted runners.

Build supported releases from identified commits here. Qualify the exact artifacts intended for
distribution; record their checksums. Rebuilding after qualification creates a new artifact whose
qualification must be assessed explicitly. Additional distribution packages must identify the
official artifact they contain and must not silently substitute a modified product build.

The release record must state the candidate revision, artifact checksums, relevant qualification,
remaining limitations, compatibility claims, and upgrade implications. Tagging, publishing,
merging, and external mutations follow the authorization available in the active task.

## 6. Agent completion and handoffs

At task start, read this file and applicable `CLAUDE.md` / `CLAUDE.local.md` instructions. Classify
the work as product development, qualification, or publication and identify the owning workspace.
Before a handoff, identify the exact candidate, requested scenarios, expected behavior, and scope
of authorization. A request for testing does not grant permission to modify shared infrastructure.

At completion, report what changed, checks actually run, candidate identity, unresolved failures,
and pending qualification. Local implementation may be complete while release qualification is
pending; label those states separately. Do not mark a release ready merely because code is merged,
documentation is polished, or offline tests pass.

## 7. Policy maintenance and enforcement

Keep this policy authoritative; other tracked instructions should link here rather than maintain
competing copies. Environment-specific procedures belong in local instructions. Change this
covenant deliberately through review, with an explanation of the affected boundary or workflow.

Some rules require human review or organization configuration. Do not claim branch protection,
identity checks, history scanning, or release gates are automated unless verified. Hooks and CI
should enforce what they can; a missing automated guard does not waive the policy. Report missing
enforcement separately from completed product work.
