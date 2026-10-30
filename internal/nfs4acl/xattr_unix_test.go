//go:build !windows

package nfs4acl

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestGetACL_ERANGE_ResizesAndRetries simulates a getxattr whose first
// (fixed 8192-byte) attempt is too small: the kernel returns ERANGE, GetACL
// probes the required size with a nil-buffer call, allocates that size, and
// the retry succeeds.
func TestGetACL_ERANGE_ResizesAndRetries(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, 20000) // larger than the 8192 fast-path buffer
	calls := 0

	orig := getxattr
	defer func() { getxattr = orig }()
	getxattr = func(path string, attr string, dest []byte) (int, error) {
		calls++
		switch calls {
		case 1:
			// First attempt: fixed-size buffer is too small.
			if len(dest) != 8192 {
				t.Fatalf("call 1: expected 8192-byte buffer, got %d", len(dest))
			}
			return 0, unix.ERANGE
		case 2:
			// Size probe: nil/zero-length destination.
			if len(dest) != 0 {
				t.Fatalf("call 2 (size probe): expected empty dest, got %d", len(dest))
			}
			return len(want), nil
		case 3:
			if len(dest) != len(want) {
				t.Fatalf("call 3 (retry): expected %d-byte buffer, got %d", len(want), len(dest))
			}
			n := copy(dest, want)
			return n, nil
		default:
			t.Fatalf("unexpected call %d", calls)
			return 0, nil
		}
	}

	got, err := GetACL("/fake/path")
	if err != nil {
		t.Fatalf("GetACL: unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("GetACL: got %d bytes, want %d bytes matching", len(got), len(want))
	}
	if calls != 3 {
		t.Fatalf("expected 3 getxattr calls, got %d", calls)
	}
}

// TestGetACL_ERANGE_Twice_ReturnsError simulates a retry that still fails
// after resizing to the probed size: GetACL must surface the error rather
// than retry indefinitely.
func TestGetACL_ERANGE_Twice_ReturnsError(t *testing.T) {
	calls := 0

	orig := getxattr
	defer func() { getxattr = orig }()
	getxattr = func(path string, attr string, dest []byte) (int, error) {
		calls++
		switch calls {
		case 1:
			return 0, unix.ERANGE
		case 2:
			return 4096, nil // size probe succeeds
		case 3:
			return 0, unix.ERANGE // retry still fails
		default:
			t.Fatalf("unexpected call %d", calls)
			return 0, nil
		}
	}

	_, err := GetACL("/fake/path")
	if err == nil {
		t.Fatal("GetACL: expected an error after a second ERANGE, got nil")
	}
	if !errors.Is(err, unix.ERANGE) {
		t.Fatalf("GetACL: expected error to wrap ERANGE, got: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 getxattr calls, got %d", calls)
	}
}

// TestGetACL_SizeProbeFails_ReturnsError covers the case where the size
// probe itself errors (e.g. the file disappeared between calls).
func TestGetACL_SizeProbeFails_ReturnsError(t *testing.T) {
	calls := 0

	orig := getxattr
	defer func() { getxattr = orig }()
	getxattr = func(path string, attr string, dest []byte) (int, error) {
		calls++
		switch calls {
		case 1:
			return 0, unix.ERANGE
		case 2:
			return 0, unix.ENOENT
		default:
			t.Fatalf("unexpected call %d", calls)
			return 0, nil
		}
	}

	_, err := GetACL("/fake/path")
	if err == nil {
		t.Fatal("GetACL: expected an error when the size probe fails, got nil")
	}
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("GetACL: expected error to wrap ENOENT, got: %v", err)
	}
}

// TestGetACL_FastPath_NoResize confirms the common case does not touch the
// resize path at all.
func TestGetACL_FastPath_NoResize(t *testing.T) {
	want := []byte{1, 2, 3, 4}
	calls := 0

	orig := getxattr
	defer func() { getxattr = orig }()
	getxattr = func(path string, attr string, dest []byte) (int, error) {
		calls++
		n := copy(dest, want)
		return n, nil
	}

	got, err := GetACL("/fake/path")
	if err != nil {
		t.Fatalf("GetACL: unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("GetACL: got %v, want %v", got, want)
	}
	if calls != 1 {
		t.Fatalf("expected 1 getxattr call, got %d", calls)
	}
}
