#!/usr/bin/env bash
# Check release archives the way an operator receives them: extracted into a fresh directory away
# from the checkout. Run after `make release release-archive`.
#
#   tools/release/smoke.sh [DIST_DIR] [VERSION]
#
# DIST_DIR defaults to dist; VERSION defaults to the one in the archive names. Checks that every
# expected archive exists and unpacks into one directory named after itself; that each carries its
# binaries (executable) and the documents and examples the README points to; that every relative
# link in the shipped README.md and INSTALL.md resolves inside the archive; that the native
# binaries run; that the shipped nfsv4 example specs load; and that no file in an archive is
# untracked in git. Binaries for other platforms are listed, never run. Exits 1 on any failure.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
dist=$(cd "${1:-dist}" && pwd)
version=${2:-}
if [[ -z $version ]]; then
  first=$(ls "$dist"/permissionreset_*_linux_amd64.tar.gz 2>/dev/null | head -1)
  [[ -n $first ]] || { echo "smoke: no linux_amd64 archive in $dist" >&2; exit 1; }
  version=$(basename "$first" _linux_amd64.tar.gz); version=${version#permissionreset_}
fi

fail=0
bad() { echo "FAIL: $*"; fail=1; }

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)          native=linux_amd64 ;;
  Linux/aarch64)         native=linux_arm64 ;;
  Darwin/x86_64)         native=darwin_amd64 ;;
  Darwin/arm64)          native=darwin_arm64 ;;
  *)                     native="" ;;
esac

unix_bins=(permissionreset generate-tree sweep build-spec)
docs=(README.md LICENSE THIRD-PARTY-NOTICES INSTALL.md COMPATIBILITY.md RISKS.md SECURITY.md
      docs/spec-guide.md docs/field-preview/runbook.md docs/field-preview/snapshot-runbook.md
      examples/nfsv4_basic.yaml examples/nfsv4_sacl_keep_dacl.yaml
      tools/set-saclonly/Set-SaclOnly.ps1 tools/set-saclonly/build-spec.exe)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tracked=$(cd "$root" && git ls-files)

check_links() {  # $1 = unpacked archive dir, $2 = markdown file inside it
  local base=$1 md=$2 dir link target
  dir=$(dirname "$base/$md")
  while IFS= read -r link; do
    target=${link%%#*}
    [[ -z $target ]] && continue
    [[ -e $dir/$target ]] || bad "$(basename "$base"): $md links to missing $target"
  done < <(grep -oE '\]\([^)]+\)' "$base/$md" | sed 's/^](//;s/)$//' | grep -vE '^[a-z][a-z0-9+.-]*:' || true)
}

for plat in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64; do
  name=permissionreset_${version}_${plat}
  if [[ $plat == windows_* ]]; then archive=$dist/$name.zip; else archive=$dist/$name.tar.gz; fi
  [[ -f $archive ]] || { bad "missing $(basename "$archive")"; continue; }

  out=$work/$plat
  mkdir -p "$out"
  if [[ $plat == windows_* ]]; then unzip -q "$archive" -d "$out"; else tar -xzf "$archive" -C "$out"; fi
  tops=$(ls -A "$out")
  [[ $tops == "$name" ]] || { bad "$(basename "$archive") unpacks to '$tops', want one directory $name"; continue; }
  pkg=$out/$name

  if [[ $plat == windows_* ]]; then
    [[ -f $pkg/build-spec.exe ]] || bad "$name: missing build-spec.exe"
    for b in "${unix_bins[@]}"; do [[ -e $pkg/$b || -e $pkg/$b.exe ]] && [[ $b != build-spec ]] && bad "$name: ships $b, which has no Windows port"; done
  else
    for b in "${unix_bins[@]}"; do
      [[ -x $pkg/$b ]] || bad "$name: $b missing or not executable"
    done
  fi
  for d in "${docs[@]}"; do [[ -f $pkg/$d ]] || bad "$name: missing $d"; done
  find "$pkg" -name CLAUDE.md | grep -q . && bad "$name: ships a CLAUDE.md"

  # Every shipped non-binary file must be tracked in git: nothing local or ignored leaks out.
  while IFS= read -r f; do
    rel=${f#"$pkg"/}
    case $rel in permissionreset|generate-tree|sweep|build-spec|build-spec.exe|tools/set-saclonly/build-spec.exe) continue ;; esac
    grep -qxF "$rel" <<<"$tracked" || bad "$name: $rel is not a tracked file"
  done < <(find "$pkg" -type f)

  check_links "$pkg" README.md
  check_links "$pkg" INSTALL.md

  if [[ $plat == "$native" ]]; then
    for b in "${unix_bins[@]}"; do
      v=$("$pkg/$b" --version 2>&1) || bad "$name: $b --version exited non-zero"
      grep -qF -- "$version" <<<"$v" || bad "$name: $b --version printed '$v', want $version"
      "$pkg/$b" --help >/dev/null 2>&1 || [[ $? -le 2 ]] || bad "$name: $b --help crashed"
    done
    for spec in "$pkg"/examples/nfsv4_*.yaml; do
      "$pkg/build-spec" --sacl-plan "$spec" >/dev/null 2>"$work/err" ||
        bad "$name: shipped spec $(basename "$spec") does not load: $(cat "$work/err")"
    done
    echo "ok   $name (ran natively)"
  else
    echo "ok   $name (contents only; not this platform)"
  fi
done

[[ $fail -eq 0 ]] && echo "smoke: all archives pass" || echo "smoke: FAILED"
exit $fail
