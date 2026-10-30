package treegen

import "fmt"

// NFSv4 access mask character strings matching the NTFS-to-NFSv4 mapping from spec.
const (
	MaskFull        = "rwaDdxtTnNcCoy"
	MaskModify      = "rwadxtTnNcoy"
	MaskReadExec    = "rxtcy"
	MaskRead        = "rtcy"
	MaskWrite       = "waTy"
	MaskAppendOnly  = "acy"
	MaskListOnly    = "rcy"
	MaskTakeOwner   = "rxtcoy"
	MaskChangePerm  = "rxtcCy"
	MaskDeleteChild = "Dcy"
)

type Scenario struct {
	Name               string
	Desc               string
	PosixRepresentable bool
	Why                string
	Owner              string // role name
	Group              string // role name
	Protected          bool
	ACEs               func(r map[string]string) []string // r maps role -> who@domain
	IsFile             bool
}

func ace(atype, flags, who, mask string) string {
	return fmt.Sprintf("%s:%s:%s:%s", atype, flags, who, mask)
}

// aceG adds the 'g' (group) flag for group principals. The NFSv4 protocol
// requires this flag so the server looks up the who field as a group, not a user.
func aceG(atype, flags, who, mask string) string {
	if flags == "" {
		flags = "g"
	} else {
		flags += "g"
	}
	return ace(atype, flags, who, mask)
}

func DirScenarios() []Scenario {
	return []Scenario{
		{
			Name:  "named_dept_full",
			Desc:  "Three distinct named principals, no well-known SIDs at all",
			Why:   "Two named groups with different masks plus a named owner is four identity classes; POSIX has three.",
			Owner: "owner_primary", Group: "group_primary",
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "fd", r["owner_primary"], MaskFull),
					aceG("A", "fd", r["group_primary"], MaskModify),
					aceG("A", "fd", r["group_readonly"], MaskReadExec),
				}
			},
		},
		{
			Name:  "deny_named_user",
			Desc:  "Explicit DENY for one named user inside an allowed group",
			Why:   "POSIX cannot deny a single user who is a member of an allowed group.",
			Owner: "owner_secondary", Group: "group_secondary",
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("D", "fd", r["user_denied"], MaskModify),
					ace("A", "fd", r["owner_secondary"], MaskFull),
					aceG("A", "fd", r["group_secondary"], MaskModify),
					ace("A", "fd", r["user_collaborator"], MaskReadExec),
				}
			},
		},
		{
			Name:  "noncanonical_order",
			Desc:  "Allow ACE placed before a deny ACE (non-canonical DACL)",
			Why:   "Exercises whether the repair tool normalizes ACE order.",
			Owner: "owner_tertiary", Group: "group_secondary",
			Protected: true,
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "fd", r["user_collaborator"], MaskModify),
					ace("D", "fd", r["user_denied"], MaskFull),
					ace("A", "fd", r["owner_tertiary"], MaskFull),
					aceG("A", "fd", r["group_readonly"], MaskReadExec),
				}
			},
		},
		{
			Name:  "inherit_only_template",
			Desc:  "Inherit-only ACEs: no effect on the dir, stamped on children",
			Why:   "IO flag has no POSIX analogue.",
			Owner: "owner_primary", Group: "group_array",
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "", r["owner_primary"], MaskFull),
					aceG("A", "fdi", r["group_array"], MaskModify),
					ace("A", "fdi", r["user_auditor"], MaskReadExec),
				}
			},
		},
		{
			Name:  "no_propagate_one_level",
			Desc:  "CI+NP ACE: applies to immediate children only",
			Why:   "NO_PROPAGATE_INHERIT means depth-1 children get the ACE and grandchildren do not.",
			Owner: "owner_secondary", Group: "group_primary",
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "fd", r["owner_secondary"], MaskFull),
					aceG("A", "dn", r["group_secondary"], MaskModify),
					aceG("A", "fd", r["group_primary"], MaskReadExec),
				}
			},
		},
		{
			Name:  "append_only_service",
			Desc:  "Service account with append-data but not write-data",
			Why:   "FILE_APPEND_DATA without FILE_WRITE_DATA is a log-drop pattern. POSIX 'w' grants both.",
			Owner: "owner_tertiary", Group: "group_primary",
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "fd", r["owner_tertiary"], MaskFull),
					ace("A", "fd", r["service_account"], MaskAppendOnly),
					aceG("A", "fd", r["group_readonly"], MaskRead),
					aceG("A", "fd", r["group_primary"], MaskModify),
				}
			},
		},
		{
			Name:  "delegated_admin_rights",
			Desc:  "Split WRITE_DAC / WRITE_OWNER across two named principals",
			Why:   "Permission-to-change-permissions and take-ownership are separate bits.",
			Owner: "owner_primary", Group: "group_array",
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "fd", r["owner_primary"], MaskFull),
					ace("A", "fd", r["user_collaborator"], MaskChangePerm),
					aceG("A", "fd", r["group_array"], MaskTakeOwner),
					aceG("A", "fd", r["group_readonly"], MaskReadExec),
				}
			},
		},
		{
			Name:  "owner_holds_no_ace",
			Desc:  "Owner has no ACE; access comes only from a named group",
			Why:   "Catches tools that assume OWNER@ always maps to an existing owner ACE.",
			Owner: "owner_secondary", Group: "group_primary",
			Protected: true,
			ACEs: func(r map[string]string) []string {
				return []string{
					aceG("A", "fd", r["group_primary"], MaskModify),
					aceG("A", "fd", r["group_secondary"], MaskReadExec),
				}
			},
		},
		{
			Name:  "protected_severed_subtree",
			Desc:  "Inheritance blocked, named principals only",
			Why:   "The classic broken subtree: someone disabled inheritance and the tree diverged.",
			Owner: "owner_tertiary", Group: "group_secondary",
			Protected: true,
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "fd", r["owner_tertiary"], MaskFull),
					ace("A", "fd", r["user_auditor"], MaskRead),
					aceG("A", "fd", r["group_readonly"], MaskListOnly),
				}
			},
		},
		{
			Name:  "six_way_split",
			Desc:  "Six distinct named principals, six distinct masks",
			Why:   "Maximum identity pressure. Anything that reduces to three classes loses principals.",
			Owner: "owner_primary", Group: "group_primary",
			Protected: true,
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "fd", r["owner_primary"], MaskFull),
					ace("A", "fd", r["owner_secondary"], MaskModify),
					ace("A", "fd", r["user_collaborator"], MaskReadExec),
					ace("A", "fd", r["user_auditor"], MaskRead),
					aceG("A", "fd", r["group_secondary"], MaskDeleteChild),
					ace("A", "fd", r["service_account"], MaskAppendOnly),
				}
			},
		},
		{
			Name:  "mixed_named_and_wellknown",
			Desc:  "Named principals alongside EVERYONE@ (control case)",
			Why:   "Confirms the tool keeps named ACEs instead of over-collapsing to EVERYONE@.",
			Owner: "owner_primary", Group: "group_primary",
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "fd", r["owner_primary"], MaskFull),
					aceG("A", "fd", r["group_primary"], MaskModify),
					ace("A", "fd", "EVERYONE@", MaskReadExec),
				}
			},
		},
	}
}

func FileScenarios() []Scenario {
	return []Scenario{
		{
			Name:  "file_denied_user",
			Desc:  "Single file denying one named user",
			Why:   "Per-user deny on one file inside an inherited subtree.",
			Owner: "owner_primary", Group: "group_primary",
			Protected: true, IsFile: true,
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("D", "", r["user_denied"], MaskFull),
					ace("A", "", r["owner_primary"], MaskFull),
					aceG("A", "", r["group_primary"], MaskModify),
				}
			},
		},
		{
			Name:  "file_append_only",
			Desc:  "Append-only file for the service account",
			Why:   "Log file the service can extend but not rewrite.",
			Owner: "owner_tertiary", Group: "group_primary",
			Protected: true, IsFile: true,
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "", r["owner_tertiary"], MaskFull),
					ace("A", "", r["service_account"], MaskAppendOnly),
					aceG("A", "", r["group_readonly"], MaskRead),
				}
			},
		},
		{
			Name:  "file_orphan_owner",
			Desc:  "File owned by a user with no ACE, readable by auditor only",
			Why:   "Owner cannot read their own file -- legal in NFSv4, impossible in POSIX.",
			Owner: "owner_secondary", Group: "group_secondary",
			Protected: true, IsFile: true,
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "", r["user_auditor"], MaskRead),
				}
			},
		},
		{
			Name:  "file_four_principal",
			Desc:  "Four named principals on one file",
			Why:   "Four identity classes on a leaf object.",
			Owner: "owner_primary", Group: "group_array",
			Protected: true, IsFile: true,
			ACEs: func(r map[string]string) []string {
				return []string{
					ace("A", "", r["owner_primary"], MaskFull),
					aceG("A", "", r["group_array"], MaskModify),
					ace("A", "", r["user_collaborator"], MaskReadExec),
					ace("A", "", r["user_auditor"], MaskRead),
				}
			},
		},
	}
}
