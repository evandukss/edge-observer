package account

import (
	"io/fs"
)

// Manifest is a bundle's bundle.json: the session it is of and every member.
type Manifest struct {
	Bundle  string   `json:"bundle"`
	Session string   `json:"session"`
	Members []Member `json:"members"`
}

// Member is one file of a bundle, by a path relative to the bundle's root.
type Member struct {
	Role     string `json:"role"`
	Path     string `json:"path"`
	Contract string `json:"contract"`
	SHA256   string `json:"sha256"`
}

// The member roles. Every one is required, and a bundle carries each once.
const (
	RoleAccount         = "account"
	RoleObservations    = "observations"
	RoleConnections     = "connections"
	RoleReconstructions = "reconstructions"
	RoleReassembly      = "reassembly"
)

// Roles is every member role, and RecordRoles the ones the seal binds.
var (
	Roles       = []string{RoleAccount, RoleObservations, RoleConnections, RoleReconstructions, RoleReassembly}
	RecordRoles = []string{RoleObservations, RoleConnections, RoleReconstructions, RoleReassembly}
)

// Outcome is where a validation ended.
type Outcome string

const (
	// Refused is a bundle that is not a conforming bundle; Findings say why.
	Refused Outcome = "refused"
	// Validated is a bundle whose core envelope validated.
	Validated Outcome = "validated"
)

// Extent is what a validation actually validated.
type Extent string

const (
	// ExtentNone is nothing vouched for: the bundle was refused.
	ExtentNone Extent = "none"
	// ExtentCoreEnvelope is the manifest, the account, the record members and
	// their binding to the session.
	ExtentCoreEnvelope Extent = "core_envelope"
)

// Reason is why a finding was made.
type Reason string

// Bundle reasons: the manifest and its members.
const (
	ManifestAbsent        Reason = "manifest_absent"
	ManifestMalformed     Reason = "manifest_malformed"
	UnknownBundleVersion  Reason = "unknown_bundle_version"
	UnknownRole           Reason = "unknown_role"
	DuplicateMember       Reason = "duplicate_member"
	MemberMissing         Reason = "member_missing"
	MemberDigestMismatch  Reason = "member_digest_mismatch"
	UnknownMemberContract Reason = "unknown_member_contract"

	// ReferenceOutsideBundle is a path that is absolute, carries a scheme, or
	// leaves the bundle's root.
	ReferenceOutsideBundle Reason = "reference_outside_bundle"
	// LinkNotPermitted is a symbolic link anywhere in the tree, which can
	// resolve outside it whatever its name says.
	LinkNotPermitted Reason = "link_not_permitted"
	// ReferenceUnresolved is a reference inside the tree that names nothing.
	ReferenceUnresolved Reason = "reference_unresolved"
)

// Account reasons: the account document.
const (
	AccountMalformed      Reason = "account_malformed"
	UnknownAccountVersion Reason = "unknown_account_version"
	// RequiredBlockAbsent is a block the contract requires that is not in
	// the document. It is never read as zeros.
	RequiredBlockAbsent Reason = "required_block_absent"
	// RequiredMemberAbsent is a member other than a block that the contract
	// requires and the document does not hold.
	RequiredMemberAbsent Reason = "required_member_absent"
	// ValueNotInContract is a member holding a value its vocabulary does not
	// name, or a count that is not a decimal string.
	ValueNotInContract Reason = "value_not_in_contract"
	// UnknownBlockState is a block whose state is not one of the four.
	UnknownBlockState Reason = "unknown_block_state"
	// BlockStateNotPermitted is a state the moment forbids: a sealed account
	// with a capture it has not reached, or a planned one carrying a seal.
	BlockStateNotPermitted Reason = "block_state_not_permitted"
	// MemberNotInContract is a member the contract does not name, wherever it
	// appears.
	MemberNotInContract Reason = "member_not_in_contract"
	// AccountNotSealed is an account in a bundle that is not sealed. A bundle
	// is of a session that ended.
	AccountNotSealed Reason = "account_not_sealed"
)

// Record reasons: the record members.
const (
	RecordMalformed      Reason = "record_malformed"
	UnknownRecordVersion Reason = "unknown_record_version"
	RecordKindMismatch   Reason = "record_kind_mismatch"
)

// Session reasons: whether the members are of one session.
const (
	// SessionMismatch is a manifest naming a different session from its
	// account.
	SessionMismatch Reason = "session_mismatch"
	// SessionBindingUnavailable is an account whose seal carries no member
	// digests, so nothing can say the records are of its session.
	SessionBindingUnavailable Reason = "session_binding_unavailable"
	// MemberNotOfSession is a record member whose digest is not the one the
	// account's seal names for that role.
	MemberNotOfSession Reason = "member_not_of_session"
	// MemberCountDisagrees is a record member holding a different number of
	// records from the one the account says was written.
	MemberCountDisagrees Reason = "member_count_disagrees"
)

// Every reason, by stage.
var (
	BundleReasons = []Reason{
		ManifestAbsent, ManifestMalformed, UnknownBundleVersion, UnknownRole, DuplicateMember, MemberMissing,
		MemberDigestMismatch, UnknownMemberContract, ReferenceOutsideBundle, LinkNotPermitted, ReferenceUnresolved,
	}
	AccountReasons = []Reason{
		AccountMalformed, UnknownAccountVersion, RequiredBlockAbsent, RequiredMemberAbsent, ValueNotInContract,
		UnknownBlockState, BlockStateNotPermitted, MemberNotInContract, AccountNotSealed,
	}
	RecordReasons  = []Reason{RecordMalformed, UnknownRecordVersion, RecordKindMismatch}
	SessionReasons = []Reason{SessionMismatch, SessionBindingUnavailable, MemberNotOfSession, MemberCountDisagrees}
)

// Finding is one refusal.
type Finding struct {
	// Member is the bundle-relative path the finding is about, or
	// ManifestName.
	Member string `json:"member"`
	// At is where inside that member: a dotted block path such as
	// "capture.ordering", a line number of a record member, or empty.
	At     string `json:"at"`
	Reason Reason `json:"reason"`
	Detail string `json:"detail"`
}

// Examined is how much a validation looked at, so a result can be told from one
// that looked at nothing.
type Examined struct {
	Members int `json:"members"`
	Records int `json:"records"`
	Blocks  int `json:"blocks"`
}

// Result is one validation's outcome. Findings is empty unless the outcome is
// Refused.
type Result struct {
	Outcome   Outcome   `json:"outcome"`
	Validated Extent    `json:"validated"`
	Session   string    `json:"session,omitempty"`
	Findings  []Finding `json:"findings"`
	Examined  Examined  `json:"examined"`
}

// Validate reads a bundle offline: the manifest, every member it names, the
// account's core blocks, the records, and whether they are of one session. It
// resolves every reference inside bundle and nowhere else, so a bundle copied to
// another path or another host validates the same.
func Validate(bundle fs.FS) Result {
	v := &validation{bundle: bundle, result: Result{Outcome: Refused, Validated: ExtentNone, Findings: []Finding{}}}
	v.run()
	return v.result
}
