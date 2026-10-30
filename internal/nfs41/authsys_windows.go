//go:build windows

package nfs41

import "os"

// CurrentAuthSys returns a minimal credential. On Windows os.Getuid and
// os.Getgid return -1, which casts to uint32(4294967295) — an unusable NFS
// uid. Use Config.Auth with --auth-uid / --auth-gid to supply real values.
func CurrentAuthSys() AuthSys {
	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}
	if len(host) > maxMachineName {
		host = host[:maxMachineName]
	}
	return AuthSys{Machine: host}
}

// ProcessCredentialNotes reports that process credentials are unavailable on
// Windows, so the caller knows to require --auth-uid and --auth-gid.
func ProcessCredentialNotes() []string {
	return []string{"WARNING: auxiliary group list is unavailable on Windows. The AUTH_SYS " +
		"credential carries no auxiliary gids. Give --auth-gids to say which groups the array should see."}
}
