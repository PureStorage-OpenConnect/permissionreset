package tuning

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

type Mount struct {
	Source, MountPoint, FSType, Server, Export string
}

// ErrNoMountForTarget reports that target is outside every NFS mount.
var ErrNoMountForTarget = errors.New("no NFS mount for target")

// ResolveMount finds the longest NFS mount containing target.
func ResolveMount(target string, mounts io.Reader) (Mount, error) {
	target, err := cleanAbsolutePath(target)
	if err != nil {
		return Mount{}, fmt.Errorf("resolve mount: %w", err)
	}

	scanner := bufio.NewScanner(mounts)
	var best Mount
	found := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || (fields[2] != "nfs" && fields[2] != "nfs4") {
			continue
		}
		source, err := unescapeMountField(fields[0])
		if err != nil {
			return Mount{}, fmt.Errorf("parse NFS mount source %q: %w", fields[0], err)
		}
		mountPoint, err := unescapeMountField(fields[1])
		if err != nil {
			return Mount{}, fmt.Errorf("parse NFS mount point %q: %w", fields[1], err)
		}
		mountPoint, err = cleanAbsolutePath(mountPoint)
		if err != nil {
			return Mount{}, fmt.Errorf("parse NFS mount point %q: %w", mountPoint, err)
		}
		if !containsPath(mountPoint, target) || found && len(mountPoint) < len(best.MountPoint) {
			continue
		}
		server, export, err := splitNFSSource(source)
		if err != nil {
			return Mount{}, err
		}
		best = Mount{
			Source:     source,
			MountPoint: mountPoint,
			FSType:     fields[2],
			Server:     server,
			Export:     filepath.Clean(export),
		}
		found = true
	}
	if err := scanner.Err(); err != nil {
		return Mount{}, fmt.Errorf("read mounts: %w", err)
	}
	if !found {
		return Mount{}, fmt.Errorf("%w: no NFS mount contains %q", ErrNoMountForTarget, target)
	}
	return best, nil
}

// ServerPath converts a path beneath mount to its path on the NFS server.
func ServerPath(localPath string, mount Mount) (string, error) {
	localPath, err := cleanAbsolutePath(localPath)
	if err != nil {
		return "", fmt.Errorf("server path: %w", err)
	}
	mountPoint, err := cleanAbsolutePath(mount.MountPoint)
	if err != nil {
		return "", fmt.Errorf("server path mount point: %w", err)
	}
	if !containsPath(mountPoint, localPath) {
		return "", fmt.Errorf("path %q is not within mount point %q", localPath, mountPoint)
	}
	if mount.Export == "" {
		return "", fmt.Errorf("server path: mount has no export")
	}

	rel, err := filepath.Rel(mountPoint, localPath)
	if err != nil {
		return "", fmt.Errorf("find path relative to mount: %w", err)
	}
	export := filepath.Clean(mount.Export)
	return filepath.Join(export, rel), nil
}

// MatchExport verifies that a mount names exactly the requested server and
// cleaned export. The default NFS port is insignificant; aliases are not.
func MatchExport(mount Mount, server, export string) error {
	if mount.Server == "" || mount.Export == "" || server == "" || export == "" {
		return fmt.Errorf("mount and requested target need nonempty server and export")
	}
	if stripDefaultNFSPort(mount.Server) != stripDefaultNFSPort(server) {
		return fmt.Errorf("mounted server %q does not match requested server %q", mount.Server, server)
	}
	if filepath.Clean(mount.Export) != filepath.Clean(export) {
		return fmt.Errorf("mounted export %q does not match requested export %q", mount.Export, export)
	}
	return nil
}

// KernelKey derives a kernel transport identity from the target's NFS mount.
func KernelKey(clients []string, target string, mounts io.Reader) (Key, error) {
	mount, err := ResolveMount(target, mounts)
	if err != nil {
		return Key{}, err
	}
	return NewKey(clients, mount.Server, mount.Export, "kernel")
}

// UserspaceKey derives a userspace transport identity without consulting local
// mounts. The server and export are explicit parts of that transport's target.
func UserspaceKey(clients []string, server, export string) (Key, error) {
	return NewKey(clients, server, export, "userspace")
}

func cleanAbsolutePath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("path %q is not absolute", path)
	}
	return filepath.Clean(path), nil
}

func containsPath(parent, child string) bool {
	if parent == string(filepath.Separator) {
		return true
	}
	return child == parent || strings.HasPrefix(child, parent+string(filepath.Separator))
}

func splitNFSSource(source string) (string, string, error) {
	separator := strings.Index(source, ":/")
	if separator <= 0 {
		return "", "", fmt.Errorf("NFS source %q lacks an absolute export", source)
	}
	server := source[:separator]
	export := source[separator+1:]
	if server == "" || export == "" {
		return "", "", fmt.Errorf("NFS source %q lacks a server or export", source)
	}
	return server, export, nil
}

func unescapeMountField(field string) (string, error) {
	var b strings.Builder
	b.Grow(len(field))
	for i := 0; i < len(field); {
		if field[i] != '\\' {
			b.WriteByte(field[i])
			i++
			continue
		}
		if i+3 >= len(field) || field[i+1] < '0' || field[i+1] > '7' || field[i+2] < '0' || field[i+2] > '7' || field[i+3] < '0' || field[i+3] > '7' {
			return "", fmt.Errorf("invalid mount escape at byte %d", i)
		}
		value, err := strconv.ParseUint(field[i+1:i+4], 8, 8)
		if err != nil {
			return "", fmt.Errorf("invalid mount escape at byte %d: %w", i, err)
		}
		b.WriteByte(byte(value))
		i += 4
	}
	return b.String(), nil
}

func stripDefaultNFSPort(server string) string {
	return strings.TrimSuffix(server, ":2049")
}
