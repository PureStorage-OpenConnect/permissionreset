//go:build !windows

package nfs41

import (
	"fmt"
	"os"
)

// CurrentAuthSys builds a credential from the running process, matching what
// the kernel client would send from the same account.
func CurrentAuthSys() AuthSys {
	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}
	if len(host) > maxMachineName {
		host = host[:maxMachineName]
	}

	// The error is deliberately dropped here and reported by
	// ProcessCredentialNotes instead: this function has no error return, and
	// giving it one would ripple through every call site for a condition that
	// is diagnostic rather than fatal. Same for the truncation on the next line.
	gids, _ := os.Getgroups()
	gids = gids[:min(len(gids), maxAuxGIDs)]
	aux := make([]uint32, len(gids))
	for i, gid := range gids {
		aux[i] = uint32(gid)
	}

	return AuthSys{
		Machine: host,
		UID:     uint32(os.Getuid()),
		GID:     uint32(os.Getgid()),
		AuxGIDs: aux,
	}
}

// ProcessCredentialNotes reports what CurrentAuthSys had to drop when it built
// a credential from this process.
//
// The 16-gid cap is RFC 5531's own and cannot be raised, so truncating is
// correct; doing it silently is not. An account in more than sixteen groups
// presents an identity missing the rest, the preflight probe passes because the
// primary identity is intact, and the objects guarded by a dropped group fail
// deep in a run that has no way to connect the two facts. One line at startup
// closes that gap.
//
// This re-reads the process rather than taking an AuthSys, because the
// truncation is only visible before it happens: a credential carrying sixteen
// gids looks identical whether the account had sixteen or sixty.
func ProcessCredentialNotes() []string {
	gids, err := os.Getgroups()
	if err != nil {
		return []string{fmt.Sprintf("WARNING: could not read this process's group list (%v), so "+
			"the AUTH_SYS credential carries no auxiliary gids at all. Give --auth-gids to say "+
			"which groups the array should see.", err)}
	}
	if len(gids) > maxAuxGIDs {
		return []string{fmt.Sprintf("WARNING: this account is in %d groups but AUTH_SYS carries "+
			"only %d, so %d were dropped from the credential. Access denials deep in the run may "+
			"be a dropped group rather than a wrong rule. Give --auth-gids to choose which %d the "+
			"array sees.", len(gids), maxAuxGIDs, len(gids)-maxAuxGIDs, maxAuxGIDs)}
	}
	return nil
}
