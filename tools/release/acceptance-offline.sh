#!/usr/bin/env bash
# Run the offline release-acceptance checks against one exact candidate commit and write an
# evidence record (docs/release-acceptance.md, "Offline checks").
#
#   tools/release/acceptance-offline.sh [--commit REV] [--version VERSION] [--out DIR]
#                                       [--denylist FILE]
#
# The checks run in a fresh git worktree of REV (default HEAD), never in the current checkout,
# so uncommitted edits cannot leak into the result. Go's test cache is bypassed (-count=1).
#
# Steps: go vet; go test -race; make release; archive checksums; make release-archive;
# tools/release/smoke.sh; tools/public-scan/scan.sh (only with --denylist or
# $PUBLIC_SCAN_DENYLIST; otherwise recorded as NOT RUN). Checks this script cannot do locally
# (macOS tests, the GUI module, CodeQL, vulncheck) are listed as CI-only, never as passed.
#
# Writes DIR/evidence.md, DIR/SHA256SUMS and DIR/logs/ (default DIR: ./acceptance-<short commit>).
# Temporary build files also go under DIR and are removed at exit.
# Exits 1 if any step that ran failed.
set -uo pipefail

commit=HEAD version="" out="" denylist=${PUBLIC_SCAN_DENYLIST:-}
while [[ $# -gt 0 ]]; do
  case $1 in
    --commit)   commit=$2; shift 2 ;;
    --version)  version=$2; shift 2 ;;
    --out)      out=$2; shift 2 ;;
    --denylist) denylist=$2; shift 2 ;;
    -h|--help)  sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "acceptance: unknown argument $1" >&2; exit 2 ;;
  esac
done

root=$(git rev-parse --show-toplevel)
sha=$(git -C "$root" rev-parse --verify "$commit^{commit}") || { echo "acceptance: no commit $commit" >&2; exit 2; }
short=${sha:0:12}
[[ -n $version ]] || version=$(git -C "$root" describe --tags --always "$sha")
out=$(mkdir -p "${out:-acceptance-$short}" && cd "${out:-acceptance-$short}" && pwd)
[[ -z $denylist ]] || denylist=$(cd "$(dirname "$denylist")" && pwd)/$(basename "$denylist")

# Build and test scratch goes under DIR, not /tmp: the race build and release cross-compiles
# need several GB, more than a small /tmp holds.
wt=$(mktemp -d "$out/.work.XXXXXX")
export TMPDIR=$wt/tmp GOTMPDIR=$wt/tmp; mkdir -p "$TMPDIR"
cleanup() { git -C "$root" worktree remove --force "$wt/src" >/dev/null 2>&1; rm -rf "$wt"; }
trap cleanup EXIT
git -C "$root" worktree add --detach -q "$wt/src" "$sha" || exit 2
cd "$wt/src"

log=$out/logs; mkdir -p "$log"
results=() fail=0
step() {  # $1 = name, rest = command
  local name=$1; shift
  echo "== $name"
  if "$@" >"$log/$name.log" 2>&1; then results+=("| $name | PASS | logs/$name.log |")
  else results+=("| $name | FAIL | logs/$name.log |"); fail=1; tail -20 "$log/$name.log"; fi
}

step vet        go vet ./...
step test-race  go test -count=1 -race -timeout 10m ./...
step release    make release VERSION="$version"
# Checksum the archives, the same files an operator downloads.
step archive    make release-archive VERSION="$version"
(cd dist && sha256sum -- *.tar.gz *.zip) >"$out/SHA256SUMS" 2>/dev/null || { results+=("| checksums | FAIL | |"); fail=1; }
step smoke      tools/release/smoke.sh dist "$version"
if [[ -n $denylist ]]; then
  step public-scan tools/public-scan/scan.sh --denylist "$denylist"
else
  results+=("| public-scan | NOT RUN (no denylist; rely on the CI public-scan job) | |")
fi

{
  echo "# Offline acceptance: $version"
  echo
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Candidate commit | \`$sha\` |"
  echo "| Version string | \`$version\` |"
  echo "| Run at (UTC) | $(date -u +%Y-%m-%dT%H:%M:%SZ) |"
  echo "| Host | $(uname -s) $(uname -m) |"
  echo "| Go | $(go version | awk '{print $3}') |"
  echo
  echo "| Check | Result | Log |"
  echo "|---|---|---|"
  printf '%s\n' "${results[@]}"
  echo "| macOS tests, GUI module, CodeQL, vulncheck, lint | CI ONLY: read the CI run for this exact commit | |"
  echo
  echo "## Archive checksums"
  echo
  echo '```'
  cat "$out/SHA256SUMS" 2>/dev/null
  echo '```'
  echo
  echo "Logs may contain local paths. Review them before publishing anything from this directory."
} >"$out/evidence.md"

echo
[[ $fail -eq 0 ]] && echo "acceptance: offline checks pass ($out/evidence.md)" || echo "acceptance: FAILED ($out/evidence.md)"
exit $fail
