# Security Policy

## Supported versions

Fixes go into the latest release. Older releases do not get backported fixes, so upgrade before
reporting an issue you found on an old version.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Report it privately through GitHub:
go to the repository's **Security** tab, choose **Report a vulnerability**, and describe the
problem. Only the maintainers can see the report.

Include the `permissionreset -version` output, the command you ran, the spec (with principal names
removed if they are sensitive), and what happened compared to what you expected.

## What counts

`permissionreset` writes access-control lists in bulk, so a bug that writes the wrong permissions is
a security problem, not just a correctness one. Report these privately:

- An apply that grants access the spec does not grant, or removes access the spec keeps.
- An apply that deletes or alters audit ACEs (SACL entries) it was supposed to preserve.
- A run that follows a symlink, or writes outside the target tree or past an exclude.
- A dry run, `--validate` or `--compare` run that changes anything on the array.
- Credentials, tokens or principal names leaking into logs, evidence files or support bundles.

A refusal you think is wrong, a crash or a slow run is an ordinary bug: open a normal issue.

## What happens next

The maintainers aim to acknowledge a report within five business days. They will work with you on
a fix and on when to disclose it. The fix ships in a release, with a GitHub security advisory that
credits you unless you ask not to be named.
