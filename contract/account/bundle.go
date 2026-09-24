package account

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/contract/record"
)

// roleKind is the record kind each record role holds.
var roleKind = map[string]string{
	RoleObservations:    record.KindObservation,
	RoleConnections:     record.KindConnection,
	RoleReconstructions: record.KindReconstruction,
	RoleReassembly:      record.KindReassembly,
}

type validation struct {
	bundle   fs.FS
	options  Options
	result   Result
	manifest Manifest
	// members is each role's member, once the manifest stage found each once.
	members map[string]Member
	// content is each role's bytes.
	content map[string][]byte
	// counts is each record role's number of records.
	counts  map[string]int
	account Account
}

func (v *validation) refuse(finding Finding) {
	v.result.Findings = append(v.result.Findings, finding)
}

func (v *validation) refused() bool { return len(v.result.Findings) > 0 }

func (v *validation) run() {
	for _, stage := range []func(){v.readManifest, v.closure, v.readMembers, v.readAccount, v.readRecords, v.session, v.extensions} {
		stage()
		if v.refused() {
			v.result.Outcome, v.result.Validated = Refused, ExtentNone
			return
		}
	}
	for _, one := range v.result.Extensions {
		if one.State == ExtensionNotChecked {
			v.result.Outcome, v.result.Validated = CoreValidatedExtensionNotChecked, ExtentCoreEnvelope
			return
		}
	}
	v.result.Outcome, v.result.Validated = Validated, ExtentCoreEnvelopeAndExtensions
}

func (v *validation) readManifest() {
	content, err := fs.ReadFile(v.bundle, ManifestName)
	if err != nil {
		v.refuse(Finding{Member: ManifestName, Reason: ManifestAbsent, Detail: err.Error()})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v.manifest); err != nil {
		v.refuse(Finding{Member: ManifestName, Reason: ManifestMalformed, Detail: err.Error()})
		return
	}
	if v.manifest.Bundle != BundleVersion {
		v.refuse(Finding{Member: ManifestName, At: "bundle", Reason: UnknownBundleVersion,
			Detail: fmt.Sprintf("%q is not %s", v.manifest.Bundle, BundleVersion)})
		return
	}
	if v.manifest.Session == "" || v.manifest.Members == nil || v.manifest.Schemas == nil {
		v.refuse(Finding{Member: ManifestName, Reason: ManifestMalformed,
			Detail: "a manifest names its session, its members and its schemas, an empty list where it has none"})
	}
	v.result.Session = v.manifest.Session
	v.result.Examined.Members = len(v.manifest.Members)
}

// closure refuses any reference that leaves the bundle. A member path naming no
// file is a missing member rather than an unresolved reference, because the
// member is what is missing.
func (v *validation) closure() {
	closure := CheckClosure(v.bundle)
	for _, finding := range closure.Findings {
		if finding.Member == ManifestName && strings.HasPrefix(finding.At, "members[") &&
			finding.Reason == ReferenceUnresolved {
			finding.Reason = MemberMissing
		}
		v.refuse(finding)
	}
}

func (v *validation) readMembers() {
	v.members, v.content, v.counts = map[string]Member{}, map[string][]byte{}, map[string]int{}
	for index, member := range v.manifest.Members {
		at := fmt.Sprintf("members[%d]", index)
		switch {
		case !slices.Contains(Roles, member.Role):
			v.refuse(Finding{Member: ManifestName, At: at + ".role", Reason: UnknownRole,
				Detail: fmt.Sprintf("%q is not a member role", member.Role)})
			continue
		case v.members[member.Role].Role != "":
			v.refuse(Finding{Member: ManifestName, At: at + ".role", Reason: DuplicateMember,
				Detail: fmt.Sprintf("a bundle carries one %s member", member.Role)})
			continue
		case member.Contract != roleContract(member.Role):
			v.refuse(Finding{Member: ManifestName, At: at + ".contract", Reason: UnknownMemberContract,
				Detail: fmt.Sprintf("a %s member is written at %s, and this one names %q", member.Role,
					roleContract(member.Role), member.Contract)})
			continue
		}
		v.members[member.Role] = member
		content, err := fs.ReadFile(v.bundle, member.Path)
		if err != nil {
			v.refuse(Finding{Member: member.Path, Reason: MemberMissing, Detail: err.Error()})
			continue
		}
		if digest := digestOf(content); digest != member.SHA256 {
			v.refuse(Finding{Member: member.Path, Reason: MemberDigestMismatch,
				Detail: fmt.Sprintf("the file's digest is %s and the manifest names %q", digest, member.SHA256)})
			continue
		}
		v.content[member.Role] = content
	}
	for _, role := range Roles {
		if _, found := v.members[role]; !found {
			v.refuse(Finding{Member: ManifestName, At: "members", Reason: MemberMissing,
				Detail: fmt.Sprintf("a bundle carries a %s member, and this one does not", role)})
		}
	}
}

func (v *validation) readAccount() {
	member := v.members[RoleAccount]
	account, findings, blocks := readAccount(member.Path, v.content[RoleAccount])
	v.result.Examined.Blocks = blocks
	for _, finding := range findings {
		v.refuse(finding)
	}
	if v.refused() {
		return
	}
	if account.Moment != Sealed {
		v.refuse(Finding{Member: member.Path, At: "moment", Reason: AccountNotSealed,
			Detail: fmt.Sprintf("a bundle is of a session that ended, and this account is %s", account.Moment)})
		return
	}
	v.account = account
}

func (v *validation) readRecords() {
	for _, role := range RecordRoles {
		member := v.members[role]
		scanner := bufio.NewScanner(bytes.NewReader(v.content[role]))
		scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			at := fmt.Sprintf("line %d", line)
			var head struct {
				Record  string `json:"record"`
				Version string `json:"version"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &head); err != nil {
				v.refuse(Finding{Member: member.Path, At: at, Reason: RecordMalformed, Detail: err.Error()})
				continue
			}
			switch {
			case head.Record != roleKind[role]:
				v.refuse(Finding{Member: member.Path, At: at, Reason: RecordKindMismatch,
					Detail: fmt.Sprintf("a %s member holds %s records, and this is %q", role, roleKind[role], head.Record)})
				continue
			case head.Version != record.Version:
				v.refuse(Finding{Member: member.Path, At: at, Reason: UnknownRecordVersion,
					Detail: fmt.Sprintf("%q is not %s", head.Version, record.Version)})
				continue
			}
			if err := strictly(scanner.Bytes(), role); err != nil {
				v.refuse(Finding{Member: member.Path, At: at, Reason: RecordMalformed, Detail: err.Error()})
			}
		}
		if err := scanner.Err(); err != nil {
			v.refuse(Finding{Member: member.Path, Reason: RecordMalformed, Detail: err.Error()})
		}
		if role == RoleReassembly && line != 1 {
			v.refuse(Finding{Member: member.Path, Reason: RecordMalformed,
				Detail: fmt.Sprintf("a session has one reassembly record, and this member holds %d", line)})
		}
		v.counts[role] = line
		v.result.Examined.Records += line
	}
}

// strictly decodes one record into its record type, refusing a member the
// record contract does not name.
func strictly(line []byte, role string) error {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	switch role {
	case RoleObservations:
		return decoder.Decode(&record.Observation{})
	case RoleConnections:
		return decoder.Decode(&record.Connection{})
	case RoleReconstructions:
		return decoder.Decode(&record.Reconstruction{})
	default:
		return decoder.Decode(&record.Reassembly{})
	}
}

// session establishes that every member is of the account's session: the
// manifest names it, and every record member is the one the seal names by
// digest and by count. The manifest is whoever assembled the bundle's; the seal
// is the session's.
func (v *validation) session() {
	account := v.members[RoleAccount].Path
	if v.manifest.Session != v.account.Session {
		v.refuse(Finding{Member: ManifestName, At: "session", Reason: SessionMismatch,
			Detail: fmt.Sprintf("the manifest names session %q and its account is of session %q",
				v.manifest.Session, v.account.Session)})
	}
	if v.account.Seal.State != Carried {
		v.refuse(Finding{Member: account, At: "seal", Reason: SessionBindingUnavailable,
			Detail: fmt.Sprintf("the seal is %s (%s), so nothing names the records of this session",
				v.account.Seal.State, v.account.Seal.Why)})
		return
	}
	sealed := map[string]SealedMember{}
	for _, one := range v.account.Seal.Members {
		sealed[one.Role] = one
	}
	for _, role := range RecordRoles {
		member := v.members[role]
		one, found := sealed[role]
		switch {
		case !found:
			v.refuse(Finding{Member: account, At: "seal.members", Reason: SessionBindingUnavailable,
				Detail: fmt.Sprintf("the seal names no %s member", role)})
		case one.SHA256 != member.SHA256:
			v.refuse(Finding{Member: member.Path, Reason: MemberNotOfSession,
				Detail: fmt.Sprintf("session %q sealed %s with digest %s, and this member's is %s",
					v.account.Session, role, one.SHA256, member.SHA256)})
		case one.Records != fmt.Sprint(v.counts[role]):
			v.refuse(Finding{Member: member.Path, Reason: MemberCountDisagrees,
				Detail: fmt.Sprintf("the seal names %s records and the member holds %d", one.Records, v.counts[role])})
		}
	}
	if spool := v.account.Capture.Spool; v.account.Capture.State == Carried && spool.State == Carried {
		for _, pair := range []struct {
			role    string
			written string
			what    string
		}{
			{RoleObservations, spool.Written, "capture.spool.written"},
			{RoleConnections, spool.Connections, "capture.spool.connections"},
		} {
			if pair.written != fmt.Sprint(v.counts[pair.role]) {
				v.refuse(Finding{Member: v.members[pair.role].Path, Reason: MemberCountDisagrees,
					Detail: fmt.Sprintf("the account's %s is %s and the member holds %d records", pair.what,
						pair.written, v.counts[pair.role])})
			}
		}
	}
}

func (v *validation) extensions() {
	carried := map[string]bool{}
	for _, schema := range v.manifest.Schemas {
		carried[schema.ID] = true
	}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range v.account.Extensions {
			if !yield(name) {
				return
			}
		}
	}) {
		extension := v.account.Extensions[name]
		one := ExtensionResult{Namespace: name, Schema: extension.Schema}
		checker, executable := v.options.Extensions[extension.Schema]
		switch {
		case executable:
			if problems := checker(extension.Content); len(problems) > 0 {
				one.State = ExtensionNonconforming
				v.refuse(Finding{Member: v.members[RoleAccount].Path, At: "extensions." + name,
					Reason: ExtensionInvalid, Detail: strings.Join(problems, "; ")})
			} else {
				one.State = ExtensionConforms
			}
		case carried[extension.Schema]:
			one.State, one.Why = ExtensionNotChecked, SchemaNotExecutable
		default:
			one.State, one.Why = ExtensionNotChecked, SchemaUnavailable
		}
		v.result.Extensions = append(v.result.Extensions, one)
	}
}
