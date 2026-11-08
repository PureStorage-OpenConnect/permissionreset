#!/usr/bin/env bash
# Scan tracked files (and optionally commit metadata) for internal identifiers.
#
#   tools/public-scan/scan.sh [--denylist FILE] [--commits RANGE] [--detail] [PATHSPEC...]
#
# The denylist defaults to $PUBLIC_SCAN_DENYLIST, then tools/public-scan/denylist.txt.
# Prints hits per file and per top-level directory; exits 1 when anything matches.
# --detail prints each matching line instead of the per-file counts.
# --commits RANGE also checks author/committer emails and messages in RANGE (e.g. origin/main..HEAD),
# and always rejects Committed-From trailers there, denylist or not.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
denylist=${PUBLIC_SCAN_DENYLIST:-$root/tools/public-scan/denylist.txt}
range=""
detail=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --denylist) denylist=$2; shift 2 ;;
    --commits)  range=$2; shift 2 ;;
    --detail)   detail=1; shift ;;
    -h|--help)  sed -n '2,11p' "$0"; exit 0 ;;
    --)         shift; break ;;
    *)          break ;;
  esac
done
[[ -r $denylist ]] || { echo "scan: denylist not readable: $denylist" >&2; exit 2; }

patterns=$(mktemp)
trap 'rm -f "$patterns"' EXIT
grep -vE '^[[:space:]]*(#|$)' "$denylist" > "$patterns" || true
# A pattern starting with # is a literal; the comment filter above only drops "# " style lines.
grep -E '^#[^ ]' "$denylist" >> "$patterns" || true

# The denylist itself and this scanner are expected to match.
exclude=(":!tools/public-scan/denylist.txt" ":!tools/public-scan/scan.sh")
spec=("$@")
[[ ${#spec[@]} -eq 0 ]] && spec=(.)

cd "$root"
status=0
if [[ $detail -eq 1 ]]; then
  git grep -nIiE -f "$patterns" -- "${spec[@]}" "${exclude[@]}" && status=1
else
  counts=$(git grep -cIiE -f "$patterns" -- "${spec[@]}" "${exclude[@]}" || true)
  if [[ -n $counts ]]; then
    status=1
    echo "== hits by top-level path"
    awk -F: '{split($1,p,"/"); d=(p[2]=="" ? p[1] : p[1]"/"); n[d]+=$NF; f[d]++}
             END {for (d in n) printf "%7d hits %5d files  %s\n", n[d], f[d], d}' <<<"$counts" | sort -rn
    echo
    echo "== hits by file"
    awk -F: '{printf "%7d  %s\n", $NF, $1}' <<<"$counts" | sort -rn
  fi
fi

if [[ -n $range ]]; then
  # A Committed-From trailer (hostname, OS/arch, local IP) is appended by a
  # local commit hook. It is checked here unconditionally, not through the
  # denylist, so the check needs no secret and cannot be dropped by editing one.
  trailers=$(git log --format='%h %s%n%B' "$range" | awk '/^[0-9a-f]+ /{c=$0} /^Committed-From:/{print c; print "  " $0}' || true)
  if [[ -n $trailers ]]; then
    status=1
    echo
    echo "== Committed-From trailers in $range (strip them; set core.hooksPath for this clone)"
    echo "$trailers"
  fi
  meta=$(git log --format='%h %ae %ce%n%B' "$range" | grep -iE -f "$patterns" || true)
  if [[ -n $meta ]]; then
    status=1
    echo
    echo "== commit metadata in $range"
    echo "$meta"
  fi
fi

[[ $status -eq 0 ]] && echo "scan: clean"
exit $status
