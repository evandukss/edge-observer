package account

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	observed "github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/probe"
)

// ErrUnrepresentable is what a projection fails with when its source is not an
// operational account this contract projects, or lacks a required block. An
// error rather than a default: a default is a reading the source never held.
var ErrUnrepresentable = errors.New("not representable in " + Version)

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnrepresentable}, args...)...)
}

// Records is one session's records, as the record contracts write them.
type Records struct {
	Observations    []record.Observation
	Connections     []record.Connection
	Reconstructions []record.Reconstruction
	Reassembly      record.Reassembly
}

// Paths are where Assemble writes each member, relative to the bundle root.
var Paths = map[string]string{
	RoleAccount:         "account.json",
	RoleObservations:    "records/observations.jsonl",
	RoleConnections:     "records/connections.jsonl",
	RoleReconstructions: "records/reconstructions.jsonl",
	RoleReassembly:      "records/reassembly.jsonl",
}

// Assemble writes a sealed session's bundle from its operational account and its
// records: the account projected, then Bundle.
func Assemble(source observed.Account, records Records) (map[string][]byte, error) {
	if source.Kind != observed.Sealed {
		return nil, refuse("a bundle is of a sealed session, and this account is %s", source.Kind)
	}
	account, err := Project(source, Supplied(records))
	if err != nil {
		return nil, err
	}
	return Bundle(account, records)
}

// Bundle writes a bundle of a sealed account and its records: the records, the
// account with its seal naming them by digest and count, and the manifest,
// keyed by path relative to the bundle root.
func Bundle(account Account, records Records) (map[string][]byte, error) {
	if account.Moment != Sealed {
		return nil, refuse("a bundle is of a sealed session, and this account is %s", account.Moment)
	}
	files := map[string][]byte{}
	members := map[string][]byte{}
	var err error
	if members[RoleObservations], err = lines(records.Observations); err != nil {
		return nil, err
	}
	if members[RoleConnections], err = lines(records.Connections); err != nil {
		return nil, err
	}
	if members[RoleReconstructions], err = lines(records.Reconstructions); err != nil {
		return nil, err
	}
	if members[RoleReassembly], err = lines([]record.Reassembly{records.Reassembly}); err != nil {
		return nil, err
	}
	counts := map[string]int{
		RoleObservations: len(records.Observations), RoleConnections: len(records.Connections),
		RoleReconstructions: len(records.Reconstructions), RoleReassembly: 1,
	}
	if account.Seal.State == Carried {
		account.Seal.Members = []SealedMember{}
		for _, role := range RecordRoles {
			account.Seal.Members = append(account.Seal.Members, SealedMember{Role: role,
				SHA256: digestOf(members[role]), Records: strconv.Itoa(counts[role])})
		}
	}
	encoded, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return nil, err
	}
	members[RoleAccount] = append(encoded, '\n')

	manifest := Manifest{Bundle: BundleVersion, Session: account.Session, Members: []Member{}, Schemas: []Schema{}}
	for _, role := range Roles {
		files[Paths[role]] = members[role]
		manifest.Members = append(manifest.Members, Member{Role: role, Path: Paths[role],
			Contract: roleContract(role), SHA256: digestOf(members[role])})
	}
	encoded, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	files[ManifestName] = append(encoded, '\n')
	return files, nil
}

// roleContract is the contract each role's member is written at.
func roleContract(role string) string {
	if role == RoleAccount {
		return Version
	}
	return record.Version
}

// digestOf is the lower-case hex SHA-256 of a member file.
func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func lines[T any](records []T) ([]byte, error) {
	var out bytes.Buffer
	for _, one := range records {
		encoded, err := json.Marshal(one)
		if err != nil {
			return nil, err
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// Supply is what a projection's caller says about the session's records.
// Only the caller knows whether it never sought them, sought them and failed,
// or read none; the zero Supply states nothing and is refused.
type Supply struct {
	state   BlockState
	records Records
	why     string
}

// NotSupplied is a caller that does not supply the records, such as one
// sealing a session. Reconstruction is not_carried.
func NotSupplied() Supply { return Supply{state: NotCarried} }

// Unreadable is a caller that sought the session's records and could not read
// them, and why. Reconstruction is unavailable, with that reason.
func Unreadable(why string) Supply { return Supply{state: Unavailable, why: why} }

// Supplied is a caller that read the records, however few. Reconstruction is
// carried, with zeros where they hold nothing.
func Supplied(records Records) Supply { return Supply{state: Carried, records: records} }

// Project writes an operational account in this contract, its reconstruction
// as supply says. The seal's member digests are Assemble's.
func Project(source observed.Account, supply Supply) (Account, error) {
	switch {
	case supply.state == "":
		return Account{}, errors.New("the projection was not told whether the session's records are supplied, " +
			"so its reconstruction would be a guess")
	case supply.state == Unavailable && supply.why == "":
		return Account{}, errors.New("the session's records could not be read and no reason was given, " +
			"and an unavailable reconstruction says why")
	}
	if source.Version != OperationalVersion {
		return Account{}, refuse("this projects the operational account at version %d, and this one is %d",
			OperationalVersion, source.Version)
	}
	a := Account{
		Account: Version, Session: source.Session, Moment: Moment(source.Kind), At: wall(source.At),
		Extensions: map[string]Extension{},
	}
	switch a.Moment {
	case Planned, Live, Sealed:
	default:
		return Account{}, refuse("%q is not a moment", source.Kind)
	}

	a.Provenance = Provenance{
		Block:     Block{State: Carried},
		Observer:  Observer{Block: Block{State: Carried}, Facts: factsOf(source.Build), Floor: Floor(source.Floor)},
		Contracts: []string{Version, record.Version},
		Configuration: Configuration{Block: Block{State: Carried}, References: []ConfigurationReference{{
			Document: "policy", Revision: source.Policy.Revision, Generation: strconv.Itoa(source.Policy.Generation),
		}}},
		Pipelines: Pipelines{Block: Block{State: NotCarried}},
	}

	scope, err := scopeOf(source)
	if err != nil {
		return Account{}, err
	}
	a.Scope = scope

	if a.Moment == Planned {
		a.Capture = Capture{Block: Block{State: NotReached}}
		a.Reconstruction = Reconstruction{Block: Block{State: NotReached}}
		a.Seal = Seal{Block: Block{State: NotReached}}
	} else {
		if a.Capture, err = captureOf(source); err != nil {
			return Account{}, err
		}
		a.Reconstruction = reconstructionOf(supply)
		if a.Moment == Live {
			a.Seal = Seal{Block: Block{State: NotReached}}
		} else {
			if err := sealUnitsKnown(source.Seal); err != nil {
				return Account{}, err
			}
			a.Seal = sealOf(source)
		}
	}
	a.Processing = Processing{Block: Block{State: NotCarried}}
	a.Requirements = Requirements{Block: Block{State: NotCarried}}
	return a, nil
}

func decimalOf[T ~int | ~int32 | ~int64 | ~uint64](v T) string { return fmt.Sprint(v) }

func wall(at time.Time) record.Instant {
	if at.IsZero() {
		return record.Instant{State: record.Undetermined, Domain: record.Wall, Unit: record.Nanoseconds}
	}
	return record.Instant{State: record.Determined, Domain: record.Wall, Unit: record.Nanoseconds,
		Reading: record.ObserverWallRead, Value: strconv.FormatInt(at.UnixNano(), 10)}
}

func text(value string) record.Text {
	if value == "" {
		return record.Text{State: record.Undetermined}
	}
	return record.Text{State: record.Determined, Value: value}
}

func factsOf(c probe.Capability) Facts {
	facts := Facts{
		Backend: string(c.Backend), Program: c.Program, MinimumKernel: c.MinimumKernel, Payload: c.Payload,
		Filtered: c.Filtered, Descendants: c.Descendants, Lifecycle: c.Lifecycle, Binding: c.Binding,
		SocketEvidence: c.SocketEvidence, IPv6: c.IPv6, Unobserved: nonNil(c.Unobserved), Withheld: []Withheld{},
	}
	for _, one := range c.Withheld {
		facts.Withheld = append(facts.Withheld, Withheld{Claim: string(one.Claim), Member: one.Member, Reason: one.Reason})
	}
	return facts
}

func nonNil[T any](list []T) []T {
	if list == nil {
		return []T{}
	}
	return list
}

// namespaceOf reads the operational account's "device:inode" namespace text,
// established as by names.
func namespaceOf(text, by string) (record.Namespace, error) {
	if text == "" {
		return record.Namespace{State: record.Undetermined}, nil
	}
	device, inode, found := strings.Cut(text, ":")
	if !found {
		return record.Namespace{}, refuse("%q is not a namespace", text)
	}
	return record.Namespace{State: record.Determined, Device: device, Inode: inode, EstablishedBy: by}, nil
}

func admittedNamespace(n admission.Namespace) record.Namespace {
	if !n.Known() {
		return record.Namespace{State: record.Undetermined}
	}
	return record.Namespace{State: record.Determined, Device: decimalOf(n.Device), Inode: decimalOf(n.Inode),
		EstablishedBy: record.ByResolutionRead}
}

func birthOf(start *uint64) record.Birth {
	if start == nil {
		return record.Birth{State: record.Undetermined, Domain: record.Boottime, Unit: record.ClockTicks}
	}
	return record.Birth{State: record.Determined, Domain: record.Boottime, Unit: record.ClockTicks, Value: decimalOf(*start)}
}

// instanceOf is an instance the policy's resolution read. Its pid namespace was
// read from /proc when the policy was resolved.
func instanceOf(one observed.Instance) (Instance, error) {
	return instanceEstablished(one, record.ByResolutionRead)
}

func instanceEstablished(one observed.Instance, by string) (Instance, error) {
	namespace, err := namespaceOf(one.Namespace, by)
	if err != nil {
		return Instance{}, err
	}
	return Instance{PID: one.PID, PidNamespace: namespace, NamespacePID: one.NamespacePID,
		Birth: birthOf(one.Start), Executable: text(one.Executable)}, nil
}

func instancesOf(list []observed.Instance) ([]Instance, error) {
	out := []Instance{}
	for _, one := range list {
		instance, err := instanceOf(one)
		if err != nil {
			return nil, err
		}
		out = append(out, instance)
	}
	return out, nil
}

// scopeOf is the scope, with each instance's coverage derived from the scope's
// own targets, exclusions and placement.
func scopeOf(source observed.Account) (Scope, error) {
	scope, err := scopeParts(source)
	if err != nil {
		return Scope{}, err
	}
	scope.Instances = coverageOf(scope)
	return scope, nil
}

func scopeParts(source observed.Account) (Scope, error) {
	scope := Scope{
		Block: Block{State: Carried},
		Requested: Requested{Block: Block{State: Carried}, Controls: []Control{
			{Block: Block{State: Carried}, Control: ObservationScope, Document: "policy",
				Revision: source.Policy.Revision, Member: "targets"},
			{Block: Block{State: NotCarried}, Control: TrafficScope},
			{Block: Block{State: NotCarried}, Control: RetentionAndExport},
		}},
		Targets: []Target{}, Exclusions: []Exclusion{}, Limits: nonNil(source.Limits),
		Filters: Filters{Block: Block{State: NotCarried}},
	}
	type selected struct {
		instance Instance
		targets  []string
	}
	var order []string
	selections := map[string]*selected{}
	for _, one := range source.Targets {
		target := Target{Number: one.Number, Name: one.Name, Mode: one.Mode, Descendants: Descendants(one.Answers),
			Resolution: Block{State: Carried}, Unsupported: []Unsupported{}, Cgroups: []Cgroup{}, Listeners: []Listener{}}
		if one.Unresolved != "" {
			target.Resolution = Block{State: Unavailable, Why: one.Unresolved}
		}
		var err error
		if target.Roots, err = instancesOf(one.Roots); err != nil {
			return Scope{}, err
		}
		if target.Existing, err = instancesOf(one.Descendants); err != nil {
			return Scope{}, err
		}
		if target.Denied, err = instancesOf(one.Denied); err != nil {
			return Scope{}, err
		}
		for _, unsupported := range one.Unsupported {
			instance, err := instanceOf(unsupported.Instance)
			if err != nil {
				return Scope{}, err
			}
			target.Unsupported = append(target.Unsupported, Unsupported{Instance: instance, Reason: unsupported.Reason})
		}
		if one.Cgroup != nil {
			inode := record.Text{State: record.Undetermined}
			if one.Cgroup.Inode != 0 {
				inode = record.Text{State: record.Determined, Value: decimalOf(one.Cgroup.Inode)}
			}
			target.Cgroups = append(target.Cgroups, Cgroup{Path: one.Cgroup.Path, Inode: inode, Why: one.Cgroup.Why})
		}
		for _, listener := range one.Listeners {
			target.Listeners = append(target.Listeners, Listener{Address: listener.Address, Owners: nonNil(listener.Owners)})
		}
		for _, instance := range slices.Concat(target.Roots, target.Existing) {
			key, _ := json.Marshal(instance)
			found, seen := selections[string(key)]
			if !seen {
				found = &selected{instance: instance}
				selections[string(key)] = found
				order = append(order, string(key))
			}
			if !slices.Contains(found.targets, one.Name) {
				found.targets = append(found.targets, one.Name)
			}
		}
		scope.Targets = append(scope.Targets, target)
	}
	scope.Overlap = Overlap{Block: Block{State: Carried}, Instances: []Overlapping{}}
	for _, key := range order {
		if one := selections[key]; len(one.targets) > 1 {
			scope.Overlap.Instances = append(scope.Overlap.Instances, Overlapping{Instance: one.instance, Targets: one.targets})
		}
	}
	for _, one := range source.Exclusions {
		roots, err := instancesOf(one.Roots)
		if err != nil {
			return Scope{}, err
		}
		denied, err := instancesOf(one.Denied)
		if err != nil {
			return Scope{}, err
		}
		scope.Exclusions = append(scope.Exclusions, Exclusion{Number: one.Number, Roots: roots, Denied: denied})
	}

	if source.Kind == observed.Planned {
		scope.Placement = Placement{Block: Block{State: NotReached}}
		scope.Coverage = Coverage{Block: Block{State: NotReached}}
		return scope, nil
	}
	scope.Placement = Placement{Block: Block{State: Carried}, Processes: []Placed{}}
	for _, one := range source.Processes {
		// The operational account holds neither the number inside the pid
		// namespace nor the executable for a placed process.
		placed := Placed{PID: one.PID, PidNamespace: admittedNamespace(one.Namespace), Runtime: one.Runtime,
			NamespacePID: record.Text{State: record.NotCarried}, Executable: record.Text{State: record.NotCarried},
			Mode: one.Mode.String(), Capability: factsOf(one.Capability),
			Outcome: string(one.Outcome), Reason: one.Reason, Requested: one.Requested, Confirmed: one.Confirmed,
			Partial: one.Confirmed < one.Requested, Probes: []Probe{}, Unattempted: nonNil(one.Unattempted),
			Uncatalogued: nonNil(one.Uncatalogued), Absent: nonNil(one.Absent)}
		placed.Birth = record.Birth{State: record.Undetermined, Domain: record.Boottime, Unit: record.ClockTicks}
		if one.StartTime != 0 {
			start := one.StartTime
			placed.Birth = birthOf(&start)
		}
		for _, probe := range one.Placements {
			placed.Probes = append(placed.Probes, Probe{Symbol: probe.Symbol, Path: probe.Path,
				Offset: decimalOf(probe.Offset), Confirmed: probe.Confirmed, Through: probe.Through, Refusal: probe.Refusal})
		}
		scope.Placement.Processes = append(scope.Placement.Processes, placed)
	}

	switch admissions := source.Admissions; {
	case admissions == nil:
		scope.Coverage = Coverage{Block: Block{State: NotCarried}}
	case admissions.Unavailable != "":
		scope.Coverage = Coverage{Block: Block{State: Unavailable, Why: admissions.Unavailable}}
	default:
		coverage := Coverage{Block: Block{State: Carried}, Rule: admissions.Rule, Covered: strconv.Itoa(admissions.Covered),
			ByTarget: []TargetCoverage{}, CoverageEnded: []Admission{}, GrantUnknown: []Admission{}}
		for _, one := range admissions.ByTarget {
			coverage.ByTarget = append(coverage.ByTarget, TargetCoverage{Target: one.Target,
				Covered: strconv.Itoa(one.Covered), Ended: strconv.Itoa(one.Ended), Unknown: strconv.Itoa(one.Unknown)})
		}
		for _, list := range []struct {
			from []observed.Admission
			into *[]Admission
		}{{admissions.CoverageEnded, &coverage.CoverageEnded}, {admissions.GrantUnknown, &coverage.GrantUnknown}} {
			for _, one := range list.from {
				// A descendant's admission names the pid namespace the kernel
				// reported on the event that admitted it; a target's was read
				// from /proc at resolution.
				by := record.ByResolutionRead
				if one.Inherited {
					by = record.ByAdmissionEvent
				}
				instance, err := instanceEstablished(one.Instance, by)
				if err != nil {
					return Scope{}, err
				}
				admitted := Admission{Instance: instance, Target: one.Target, Inherited: one.Inherited, Why: one.Why,
					NoLaterThan: wall(time.Time{}), ReadFrom: wall(time.Time{}), ReadTo: wall(time.Time{})}
				if one.NoLaterThan != nil {
					admitted.NoLaterThan = wall(*one.NoLaterThan)
				}
				if one.Read != nil {
					admitted.ReadFrom, admitted.ReadTo = wall(one.Read.From), wall(one.Read.To)
				}
				*list.into = append(*list.into, admitted)
			}
		}
		scope.Coverage = coverage
	}
	return scope, nil
}

func captureOf(source observed.Account) (Capture, error) {
	switch {
	case source.Capability == nil:
		return Capture{}, refuse("a %s operational account without its capability block says nothing about what "+
			"its attachment could report", source.Kind)
	case source.Seen == nil:
		return Capture{}, refuse("a %s operational account without its seen block says nothing about what came through",
			source.Kind)
	case source.Loss == nil || source.Admitted == nil || source.Refused == nil:
		return Capture{}, refuse("a %s operational account without its loss, admitted and refused blocks says nothing "+
			"about what was lost", source.Kind)
	}
	seen := source.Seen
	capture := Capture{
		Block:      Block{State: Carried},
		Capability: Capability{Block: Block{State: Carried}, Facts: factsOf(*source.Capability), Sentence: source.Capturing},
		Seen: Seen{Block: Block{State: Carried}, Transfers: decimalOf(seen.Transfers), Unmeasured: decimalOf(seen.Unmeasured),
			Empty: decimalOf(seen.Empty), Records: decimalOf(seen.Records), Connections: decimalOf(seen.Connections),
			Closed: decimalOf(seen.Closed), Early: decimalOf(seen.Early), Rejected: decimalOf(seen.Rejected),
			Unattributed: decimalOf(seen.Unattributed), EndingsUnmatched: decimalOf(seen.EndingsUnmatched),
			ConnectionsUnrecorded: decimalOf(seen.ConnectionsUnrecorded)},
		Ordering: Ordering{Block: Block{State: Carried}, Disordered: decimalOf(seen.Disordered),
			Unstamped: decimalOf(seen.Unstamped), Tolerated: decimalOf(seen.Tolerated), Lost: decimalOf(seen.Lost),
			Retired: decimalOf(seen.Interrupted), Unexplained: decimalOf(seen.Unexplained)},
	}
	if loss := source.Loss; loss.Known {
		capture.Loss = Loss{Block: Block{State: Carried}, Dropped: decimalOf(loss.Dropped),
			Unmatched: decimalOf(loss.Unmatched), Occasion: occasionOf(loss.When)}
	} else {
		capture.Loss = Loss{Block: Block{State: Unavailable, Why: loss.Why}}
	}
	if admitted := source.Admitted; admitted.Known {
		capture.Admitted = Admitted{Block: Block{State: Carried}, Descendants: decimalOf(admitted.Descendants)}
	} else {
		capture.Admitted = Admitted{Block: Block{State: Unavailable, Why: admitted.Why}}
	}
	if refused := source.Refused; refused.Known {
		reasons := map[string]string{}
		for reason, count := range refused.Reasons {
			reasons[reason] = decimalOf(count)
		}
		capture.Refused = Refusals{Block: Block{State: Carried}, Reasons: reasons}
	} else {
		capture.Refused = Refusals{Block: Block{State: Unavailable, Why: refused.Why}}
	}
	if spool := source.Spool; spool != nil {
		capture.Spool = Spool{Block: Block{State: Carried}, Written: decimalOf(spool.Written), Dropped: decimalOf(spool.Dropped),
			Refused: decimalOf(spool.Refused), Connections: decimalOf(spool.Connections),
			ConnectionsDropped: decimalOf(spool.ConnectionsDropped), ConnectionsRefused: decimalOf(spool.ConnectionsRefused),
			Bytes: decimalOf(spool.Bytes), Limit: decimalOf(spool.Limit)}
	} else {
		capture.Spool = Spool{Block: Block{State: Unavailable, Why: "the operational account carries no spool block"}}
	}
	return capture, nil
}

func occasionOf(when probe.Occasion) Occasion {
	undetermined := record.Instant{State: record.Undetermined, Domain: record.Monotonic, Unit: record.Nanoseconds}
	if !when.Seen() {
		none := record.Text{State: record.Undetermined}
		return Occasion{First: undetermined, Last: undetermined, Handle: none, PID: none, TID: none}
	}
	stamp := func(v int64) record.Instant {
		return record.Instant{State: record.Determined, Domain: record.Monotonic, Unit: record.Nanoseconds,
			Reading: record.KernelStamp, Value: decimalOf(v)}
	}
	return Occasion{First: stamp(when.First), Last: stamp(when.Last),
		Handle: record.Text{State: record.Determined, Value: decimalOf(when.Handle)},
		PID:    record.Text{State: record.Determined, Value: decimalOf(when.PID)},
		TID:    record.Text{State: record.Determined, Value: decimalOf(when.TID)}}
}

func reconstructionOf(supply Supply) Reconstruction {
	if supply.state != Carried {
		return Reconstruction{Block: Block{State: supply.state, Why: supply.why}}
	}
	records := supply.records
	exchanges, complete := 0, 0
	var unplaced uint64
	for _, one := range records.Reconstructions {
		exchanges += len(one.Exchanges)
		for _, exchange := range one.Exchanges {
			if exchange.Complete {
				complete++
			}
		}
		if value, err := strconv.ParseUint(one.Unplaced.Value, 10, 64); err == nil {
			unplaced += value
		}
	}
	return Reconstruction{Block: Block{State: Carried}, Connections: strconv.Itoa(len(records.Reconstructions)),
		Exchanges: strconv.Itoa(exchanges), Complete: strconv.Itoa(complete),
		Discards: strconv.Itoa(len(records.Reassembly.Discards)), Duplicates: strconv.Itoa(len(records.Reassembly.Duplicates)),
		Unplaced: decimalOf(unplaced)}
}

func countOf(c connection.Count, unit record.Unit) record.Count {
	if !c.Known {
		return record.Count{State: record.Undetermined, Unit: unit, Why: c.Why}
	}
	return record.Count{State: record.Determined, Unit: unit, Value: decimalOf(c.Value), Why: c.Why}
}

// counterUnits is what each seal counter counts, by its JSON name, as package
// connection declares. A counter with no unit here is refused.
var counterUnits = map[string]record.Unit{
	"ordered":              record.Places,
	"reservation_attempts": record.Events, "reservations": record.Events, "reservation_failures": record.Events,
	"submitted": record.Events, "delivered": record.Events, "undecodable": record.Events,
	"lost_after_submission": record.Events, "outstanding": record.Events,
	"still_executing": record.Calls, "unmatched_returns": record.Calls, "unmeasurable_calls": record.Calls,
	"deferred_discarded": record.Calls, "refused_in_flight": record.Calls,
	"sockets_unrecorded": record.DescriptorLifetimes, "bindings_unrecorded": record.Bindings,
	"denials_unrecorded": record.Instances,
	"transfers":          record.Calls, "unmeasured": record.Calls, "empty": record.Calls,
	"fragments": record.Fragments, "fragments_refused": record.Fragments, "persisted": record.Fragments,
	"persisted_dropped": record.Fragments, "persisted_refused": record.Fragments, "discards": record.Fragments,
	"unplaced_bytes": record.Bytes,
}

// identityUnits is the unit each conservation identity is over, in the order
// connection.Counters.Identities states them: the unit of its left side.
var identityUnits = []record.Unit{record.Places, record.Events, record.Events, record.Events, record.Calls,
	record.Fragments}

// sealUnitsKnown refuses a seal whose counters or identities have no unit
// here, so a new counter is named before it is carried.
func sealUnitsKnown(seal *connection.Seal) error {
	if seal == nil {
		return nil
	}
	for name := range countersOf(seal.Counters) {
		if _, known := counterUnits[name]; !known {
			return refuse("the seal counter %s has no unit this projection knows", name)
		}
	}
	if identities := len(seal.Counters.Identities()); identities != len(identityUnits) {
		return refuse("the seal states %d conservation identities and this projection knows the units of %d",
			identities, len(identityUnits))
	}
	return nil
}

func sealOf(source observed.Account) Seal {
	if source.Seal == nil {
		why := source.SealError
		if why == "" {
			why = "the operational account carries no seal"
		}
		return Seal{Block: Block{State: Unavailable, Why: why}}
	}
	one := source.Seal
	seal := Seal{
		Block: Block{State: Carried}, Stopped: wall(one.Stopped), Sealed: wall(one.Sealed),
		Complete: one.Complete, Because: nonNil(one.Because),
		Withdrawal: Withdrawal{At: wall(one.Withdrawal.At), Instances: strconv.Itoa(one.Withdrawal.Instances),
			Complete: one.Withdrawal.Complete, Because: one.Withdrawal.Because},
		Drain: Drain{Delivered: countOf(one.Drain.Delivered, record.Events),
			Outstanding: countOf(one.Drain.Outstanding, record.Events),
			Complete:    one.Drain.Complete, Because: one.Drain.Because},
		Interrupted: countOf(one.Interrupted, record.Calls),
		Counters:    countersOf(one.Counters),
		Conserved:   []Identity{},
		Members:     []SealedMember{},
	}
	for index, identity := range one.Counters.Identities() {
		unit := record.Unit("")
		if index < len(identityUnits) {
			unit = identityUnits[index]
		}
		holds := "not_evaluated"
		switch {
		case identity.Evaluated && identity.Holds:
			holds = "holds"
		case identity.Evaluated:
			holds = "does_not_hold"
		}
		seal.Conserved = append(seal.Conserved, Identity{Name: identity.Name, Left: countOf(identity.Left, unit),
			Right: countOf(identity.Right, unit), Holds: holds})
	}
	if complete, known := one.Counters.Complete(); known {
		seal.Recorded = Recorded{Block: Block{State: Carried}, Complete: complete}
	} else {
		seal.Recorded = Recorded{Block: Block{State: Unavailable,
			Why: "a descriptor lifetime, binding or denial count could not be read"}}
	}
	return seal
}

// countersOf is every counter by its JSON name, read off the type so a new
// counter is carried without being listed.
func countersOf(counters connection.Counters) map[string]record.Count {
	out := map[string]record.Count{}
	value := reflect.ValueOf(counters)
	for i := range value.NumField() {
		field := value.Type().Field(i)
		count, ok := value.Field(i).Interface().(connection.Count)
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		out[name] = countOf(count, counterUnits[name])
	}
	return maps.Clone(out)
}
