#!/usr/bin/env bash
#
# Live differential test for build-spec: compare kernel vs userspace capture.
#
# Captures the same exemplars through a Linux NFSv4.1 kernel mount and
# through userspace transport, diffs the specs, then validates both against
# a small disposable tree with permissionreset --validate.
#
# Usage:
#   build-spec-differential.sh DIR_EXEMPLAR FILE_EXEMPLAR [SCRATCH_SUBDIR]
#
# Environment:
#   MOUNT         NFS mount point (default: /mnt/fb)
#   SERVER        NFS server HOST[:PORT] for userspace (required)
#   EXPORT        Export path on server (required)
#   SCRATCH       Scratch directory under export (default: sweep)
#   AUTH_UID      Userspace auth uid (optional, defaults to running user)
#   AUTH_GID      Userspace auth gid (optional, defaults to running user's group)
#
# Example:
#   MOUNT=/mnt/data SERVER=192.0.2.50 EXPORT=/data build-spec-differential.sh /mnt/data/template_dir /mnt/data/template.txt test-scratch

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
MOUNT="${MOUNT:-/mnt/fb}"
SERVER="${SERVER:?set SERVER to the NFS server HOST[:PORT]}"
EXPORT="${EXPORT:?set EXPORT to the export path on the server}"
SCRATCH_SUBDIR="${SCRATCH:-sweep}"
AUTH_UID="${AUTH_UID:-}"
AUTH_GID="${AUTH_GID:-}"

# Required positional args
if [ $# -lt 2 ]; then
    echo "usage: build-spec-differential.sh DIR_EXEMPLAR FILE_EXEMPLAR [SCRATCH_SUBDIR]" >&2
    exit 2
fi

DIR_EXEMPLAR="$1"
FILE_EXEMPLAR="$2"
if [ $# -ge 3 ]; then
    SCRATCH_SUBDIR="$3"
fi

SCRATCH="${MOUNT}/${SCRATCH_SUBDIR}"

# Verify exemplars exist
if [ ! -d "$DIR_EXEMPLAR" ]; then
    echo "error: directory exemplar does not exist: $DIR_EXEMPLAR" >&2
    exit 1
fi
if [ ! -f "$FILE_EXEMPLAR" ]; then
    echo "error: file exemplar does not exist: $FILE_EXEMPLAR" >&2
    exit 1
fi

# Output directory
OUT=$(mktemp -d)
trap "rm -rf '$OUT'" EXIT

echo "=== build-spec differential test ==="
echo "DIR_EXEMPLAR:  $DIR_EXEMPLAR"
echo "FILE_EXEMPLAR: $FILE_EXEMPLAR"
echo "MOUNT:         $MOUNT"
echo "SERVER:        $SERVER"
echo "EXPORT:        $EXPORT"
echo "SCRATCH:       $SCRATCH"
echo "Output:        $OUT"
echo ""

# Build build-spec
echo "Building build-spec..."
cd "$REPO_ROOT"
make build-spec >/dev/null 2>&1 || {
    echo "error: failed to build build-spec" >&2
    exit 1
}

# Helper to build auth flags
build_auth_flags() {
    local flags=""
    if [ -n "$AUTH_UID" ]; then
        flags="$flags --auth-uid $AUTH_UID"
    fi
    if [ -n "$AUTH_GID" ]; then
        flags="$flags --auth-gid $AUTH_GID"
    fi
    echo "$flags"
}

AUTH_FLAGS=$(build_auth_flags)

# Verify-write scratch must be on the NFS mount (kernel) / inside the export
# (userspace). Use a subdirectory of SCRATCH for both, cleaned up in the trap.
VERIFY_SCRATCH="$SCRATCH/verify-$$"
mkdir -p "$VERIFY_SCRATCH"
trap "rm -rf '$OUT' '$VERIFY_SCRATCH'" EXIT

# Convert mount-relative paths to export-relative for userspace
DIR_EXEMPLAR_REL="${DIR_EXEMPLAR#$MOUNT}"
DIR_EXEMPLAR_REL="${DIR_EXEMPLAR_REL#/}"
FILE_EXEMPLAR_REL="${FILE_EXEMPLAR#$MOUNT}"
FILE_EXEMPLAR_REL="${FILE_EXEMPLAR_REL#/}"
VERIFY_SCRATCH_REL="${VERIFY_SCRATCH#$MOUNT}"
VERIFY_SCRATCH_REL="${VERIFY_SCRATCH_REL#/}"

# Kernel capture with --verify-write
echo "Running kernel capture with --verify-write..."
if ! "$REPO_ROOT/build-spec" \
    --transport kernel \
    --output "$OUT/kernel.yaml" \
    --verify-write "$VERIFY_SCRATCH" \
    "$DIR_EXEMPLAR" "$FILE_EXEMPLAR" 2>"$OUT/kernel.err"; then
    echo "error: kernel capture failed:" >&2
    cat "$OUT/kernel.err" >&2
    exit 1
fi

echo "Running userspace capture with --verify-write..."
if ! "$REPO_ROOT/build-spec" \
    --transport userspace \
    --server "$SERVER" \
    --export "$EXPORT" \
    $AUTH_FLAGS \
    --output "$OUT/userspace.yaml" \
    --verify-write "${EXPORT}/${VERIFY_SCRATCH_REL}" \
    "${EXPORT}/${DIR_EXEMPLAR_REL}" "${EXPORT}/${FILE_EXEMPLAR_REL}" 2>"$OUT/userspace.err"; then
    echo "error: userspace capture failed:" >&2
    cat "$OUT/userspace.err" >&2
    exit 1
fi

# Diff the specs
echo "Comparing kernel vs userspace specs..."
if ! diff -u "$OUT/kernel.yaml" "$OUT/userspace.yaml" > "$OUT/diff.txt"; then
    echo "error: kernel and userspace specs differ:" >&2
    cat "$OUT/diff.txt" >&2
    exit 1
fi
echo "✓ Specs match"
echo ""

# Create a small disposable tree in scratch
TEST_TREE="$SCRATCH/diff-test-$$"
mkdir -p "$TEST_TREE"
trap "rm -rf '$OUT' '$TEST_TREE' '$VERIFY_SCRATCH'" EXIT

echo "Creating disposable test tree at $TEST_TREE..."
mkdir -p "$TEST_TREE/subdir"
touch "$TEST_TREE/file1.txt"
touch "$TEST_TREE/subdir/file2.txt"

# Apply kernel spec to disposable tree, then validate
echo "Applying kernel spec to test tree..."
if ! "$REPO_ROOT/permissionreset" \
    --spec "$OUT/kernel.yaml" \
    --apply \
    "$TEST_TREE" 2>"$OUT/apply-kernel.err"; then
    echo "error: apply kernel spec failed:" >&2
    cat "$OUT/apply-kernel.err" >&2
    rm -rf "$TEST_TREE"
    exit 1
fi
echo "✓ Kernel spec applied"

echo "Validating kernel spec against test tree..."
if ! "$REPO_ROOT/permissionreset" \
    --spec "$OUT/kernel.yaml" \
    --validate \
    "$TEST_TREE" 2>"$OUT/validate-kernel.err"; then
    echo "error: validation of kernel spec failed:" >&2
    cat "$OUT/validate-kernel.err" >&2
    rm -rf "$TEST_TREE"
    exit 1
fi
echo "✓ Kernel spec validates"

# Apply userspace spec (identical, but proves the userspace-captured spec also works)
echo "Applying userspace spec to test tree..."
if ! "$REPO_ROOT/permissionreset" \
    --spec "$OUT/userspace.yaml" \
    --apply \
    "$TEST_TREE" 2>"$OUT/apply-userspace.err"; then
    echo "error: apply userspace spec failed:" >&2
    cat "$OUT/apply-userspace.err" >&2
    rm -rf "$TEST_TREE"
    exit 1
fi
echo "✓ Userspace spec applied"

echo "Validating userspace spec against test tree..."
if ! "$REPO_ROOT/permissionreset" \
    --spec "$OUT/userspace.yaml" \
    --validate \
    "$TEST_TREE" 2>"$OUT/validate-userspace.err"; then
    echo "error: validation of userspace spec failed:" >&2
    cat "$OUT/validate-userspace.err" >&2
    rm -rf "$TEST_TREE"
    exit 1
fi
echo "✓ Userspace spec validates"
echo ""

# Clean up tree
rm -rf "$TEST_TREE"

echo "=== PASS ==="
exit 0
