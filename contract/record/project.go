package record

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/jsonshape"
	"github.com/evandukss/edge-observer/reconstruct"
)

// ErrUnrepresentable is what a projection fails with when its source holds a
// value these records have no way to say. It is an error rather than a nearest
// value, because a nearest value is a fact the source never held.
var ErrUnrepresentable = errors.New("not representable in " + Version)

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnrepresentable}, args...)...)
}

func decimal(v uint64) string { return strconv.FormatUint(v, 10) }

// wallRead is an instant the observer read off its own wall clock. The zero
// time is the source's "no instant", and it is undetermined here.
func wallRead(at time.Time) Instant {
	if at.IsZero() {
		return Instant{State: Undetermined, Domain: Wall, Unit: Nanoseconds}
	}
	return Instant{State: Determined, Domain: Wall, Unit: Nanoseconds, Reading: ObserverWallRead,
		Value: strconv.FormatInt(at.UnixNano(), 10)}
}

// crossed is a kernel monotonic stamp the observer moved onto its wall clock.
func crossed(at time.Time) Instant {
	one := wallRead(at)
	if one.State == Determined {
		one.Reading = CrossedFromMonotonic
	}
	return one
}

// notCarried is a reserved instant this producer does not supply.
func notCarried(domain Domain) Instant {
	return Instant{State: NotCarried, Domain: domain, Unit: Nanoseconds}
}

// procBirth is a start identity read from /proc field 22. A fragment's process
// carries zero for one that could not be read (probe/openssl/attach, identify).
func procBirth(ticks uint64, determined bool) Birth {
	if !determined {
		return Birth{State: Undetermined, Domain: Boottime, Unit: ClockTicks}
	}
	return Birth{State: Determined, Domain: Boottime, Unit: ClockTicks, Value: decimal(ticks)}
}

func process(p fragment.Process) Process {
	return Process{PID: p.PID, Birth: procBirth(p.StartTime, p.StartTime != 0)}
}

func namespace(device, inode uint64, by string) Namespace {
	if device == 0 && inode == 0 {
		return Namespace{State: Undetermined}
	}
	return Namespace{State: Determined, Device: decimal(device), Inode: decimal(inode), EstablishedBy: by}
}

func instanceKey(k admission.Key) (InstanceKey, error) {
	if k.Generation == 0 {
		return InstanceKey{}, refuse("pid %d carries no admission generation", k.PID)
	}
	allocator := "target"
	if k.Generation.FromKernel() {
		allocator = "descent"
	}
	return InstanceKey{
		PidNamespace: namespace(k.Namespace.Device, k.Namespace.Inode, ByAdmissionEvent),
		PID:          k.PID,
		Generation:   decimal(uint64(k.Generation)),
		Allocator:    allocator,
	}, nil
}

func count(c connection.Count, unit Unit) Count {
	if !c.Known {
		return Count{State: Undetermined, Unit: unit, Why: c.Why}
	}
	return Count{State: Determined, Unit: unit, Value: strconv.FormatInt(c.Value, 10), Why: c.Why}
}

func generation(g connection.Generation) Generation {
	if !g.Known() {
		return Generation{State: Undetermined}
	}
	return Generation{State: Determined, Value: decimal(uint64(g))}
}

func descriptor(d connection.Descriptor) Descriptor {
	if !d.Known {
		return Descriptor{State: Undetermined}
	}
	n := d.Number
	return Descriptor{State: Determined, Number: &n}
}

func address(a connection.Address) Address {
	if !a.Known {
		return Address{State: Undetermined}
	}
	port := a.Port
	return Address{State: Determined, Address: a.IP.String(), Port: &port}
}

// The vocabularies. Every source value has exactly one name, and a value with
// none is refused rather than mapped to the nearest one.

func directionName(d fragment.Direction) (string, error) {
	switch d {
	case fragment.Sent:
		return "sent", nil
	case fragment.Received:
		return "received", nil
	}
	return "", refuse("direction %d", d)
}

var endings = map[connection.Ending]string{
	connection.StillOpen:            "still_open",
	connection.HandleReleasedEnding: "handle_released",
	connection.SocketClosed:         "socket_closed",
	connection.EndingUnobserved:     "unobserved",
	connection.EndingUnestablished:  "unestablished",
}

var states = map[connection.State]string{
	connection.Established: "established",
	connection.Unknown:     "unknown",
	connection.Ambiguous:   "ambiguous",
	connection.Invalidated: "invalidated",
}

var reasons = map[connection.Reason]string{
	connection.NoBindingObserved:          "no_binding_observed",
	connection.InsertionRefused:           "insertion_refused",
	connection.ObservationLost:            "observation_lost",
	connection.TransportUnsupported:       "transport_unsupported",
	connection.BindingUnobservable:        "binding_unobservable",
	connection.OperationWasNotASocket:     "operation_was_not_a_socket",
	connection.EvidenceUnreadable:         "evidence_unreadable",
	connection.OperationUnresolved:        "operation_unresolved",
	connection.RouteUnsupported:           "route_unsupported",
	connection.OperationFrameBroken:       "operation_frame_broken",
	connection.SocketEvidenceUnavailable:  "socket_evidence_unavailable",
	connection.SeveralDescriptors:         "several_descriptors",
	connection.DescriptorReplaced:         "descriptor_replaced",
	connection.TransportReplaced:          "transport_replaced",
	connection.LifetimeEvidenceEnded:      "lifetime_evidence_ended",
	connection.HandleReleased:             "handle_released",
	connection.HandleLifetimeUnobservable: "handle_lifetime_unobservable",
}

var joins = map[connection.Joinability]string{
	connection.Joins:       "joins",
	connection.DoesNotJoin: "does_not_join",
}

var joinReasons = map[connection.JoinReason]string{
	connection.NoBindingToJoin:        "no_binding_to_join",
	connection.EndpointUnreadable:     "endpoint_unreadable",
	connection.NoEndpointProducer:     "no_endpoint_producer",
	connection.NamespaceUnestablished: "namespace_unestablished",
}

var sources = map[connection.Source]string{
	connection.SetterArgument: "setter_argument",
	connection.InCallSyscall:  "in_call_syscall",
	connection.SocketLifetime: "socket_lifetime",
}

var bases = map[connection.Basis]string{
	connection.ConfirmedInCall: "confirmed_in_call",
	connection.Continuity:      "continuity",
}

var positions = map[connection.Positions]string{
	connection.PositionsEstablished:       "established",
	connection.PositionsUnknownFrom:       "unknown_from",
	connection.PositionsUnknownThroughout: "unknown_throughout",
}

// named looks a value up in a vocabulary. The zero value of every source
// vocabulary means "nobody filled this in"; where optional is true it is
// carried as an absent name, and otherwise it is refused.
func named[K comparable](table map[K]string, value K, optional bool, what string) (string, error) {
	var zero K
	if value == zero && optional {
		return "", nil
	}
	name, found := table[value]
	if !found {
		return "", refuse("%s %v has no name", what, value)
	}
	return name, nil
}

// FromFragment is one observation.
func FromFragment(r fragment.Record) (Observation, error) {
	direction, err := directionName(r.Direction)
	if err != nil {
		return Observation{}, err
	}
	return Observation{
		Record:     KindObservation,
		Version:    Version,
		Process:    process(r.Process),
		Connection: decimal(uint64(r.Connection)),
		Direction:  direction,
		Sequence:   decimal(r.Sequence),
		Offset:     decimal(r.Offset),
		Length:     r.Length,
		Payload: Payload{
			Encoding:  "base64",
			Data:      base64.StdEncoding.EncodeToString(r.Payload),
			Kept:      uint32(len(r.Payload)),
			Truncated: r.Truncated(),
		},
		Seen:     wallRead(r.At),
		Produced: notCarried(Monotonic),
	}, nil
}

// FromConnection is one connection record.
func FromConnection(r connection.Record) (Connection, error) {
	if r.Handle.Generation == 0 {
		return Connection{}, refuse("connection %d carries no handle generation", r.ID)
	}
	if !r.OpenedKnown && !r.Opened.IsZero() {
		return Connection{}, refuse("connection %d names an open time and says it is not known", r.ID)
	}
	handleKey, err := instanceKey(r.Handle.Instance)
	if err != nil {
		return Connection{}, err
	}
	key, err := instanceKey(r.Instance.Key())
	if err != nil {
		return Connection{}, err
	}
	how, err := named(endings, r.How, false, "ending")
	if err != nil {
		return Connection{}, err
	}
	executable := Text{State: Undetermined}
	if r.Instance.Executable != "" {
		executable = Text{State: Determined, Value: r.Instance.Executable}
	}

	opened := Instant{State: Undetermined, Domain: Wall, Unit: Nanoseconds}
	if r.OpenedKnown {
		opened = crossed(r.Opened)
	}

	out := Connection{
		Record:  KindConnection,
		Version: Version,
		ID:      decimal(uint64(r.ID)),
		Handle: Handle{
			Instance:   handleKey,
			Address:    decimal(r.Handle.Address),
			Generation: decimal(uint64(r.Handle.Generation)),
		},
		Instance: Instance{
			Key:        key,
			Birth:      procBirth(uint64(r.Instance.Start.Ticks), r.Instance.Start.Determined),
			Executable: executable,
		},
		Process:         process(r.Process),
		ProcessNetwork:  namespace(r.Network.Device, r.Network.Inode, ByProcessRead),
		FirstSeen:       wallRead(r.FirstSeen),
		Opened:          opened,
		Ending:          ending(how, r),
		Associations:    []Association{},
		Placements:      []Placement{},
		Fragments:       count(r.Fragments, Fragments),
		Early:           []Range{},
		EarlyUnmeasured: Count{State: Determined, Unit: Events, Value: strconv.Itoa(r.EarlyUnmeasured)},
	}

	for _, a := range r.Associations {
		one, err := association(a)
		if err != nil {
			return Connection{}, fmt.Errorf("connection %d: %w", r.ID, err)
		}
		out.Associations = append(out.Associations, one)
	}
	for _, p := range r.Placements {
		one, err := placement(p)
		if err != nil {
			return Connection{}, fmt.Errorf("connection %d: %w", r.ID, err)
		}
		out.Placements = append(out.Placements, one)
	}
	for _, e := range r.Early {
		direction, err := directionName(e.Direction)
		if err != nil {
			return Connection{}, err
		}
		out.Early = append(out.Early, Range{Direction: direction, Offset: decimal(e.Offset), Length: e.Length})
	}
	return out, nil
}

// ending keeps the instant an unobserved ending carries out of At, because
// capture stamps it with the moment the loss was detected (capture.go,
// interruptLocked) and a reader of At would take it for the end.
func ending(how string, r connection.Record) Ending {
	if r.How != connection.EndingUnobserved {
		return Ending{How: how, At: wallRead(r.Ended)}
	}
	detected := wallRead(r.Ended)
	return Ending{How: how, At: Instant{State: Undetermined, Domain: Wall, Unit: Nanoseconds}, Detected: &detected}
}

func association(a connection.Association) (Association, error) {
	direction, err := directionName(a.Direction)
	if err != nil {
		return Association{}, err
	}
	state, err := named(states, a.State, false, "association state")
	if err != nil {
		return Association{}, err
	}
	reason, err := named(reasons, a.Reason, true, "association reason")
	if err != nil {
		return Association{}, err
	}
	basis, err := named(bases, a.Basis, true, "basis")
	if err != nil {
		return Association{}, err
	}
	source, err := named(sources, a.Source, true, "source")
	if err != nil {
		return Association{}, err
	}
	join, err := named(joins, a.Join, false, "joinability")
	if err != nil {
		return Association{}, err
	}
	joinReason, err := named(joinReasons, a.JoinReason, true, "join reason")
	if err != nil {
		return Association{}, err
	}

	until := wallRead(a.Valid.Until)
	socket := Socket{State: Undetermined}
	if a.Socket.Known {
		socket = Socket{State: Determined, Inode: decimal(a.Socket.Inode)}
	}
	wire := Count{State: Undetermined, Unit: Bytes}
	if a.Wire.Known {
		wire = Count{State: Determined, Unit: Bytes, Value: strconv.FormatInt(a.Wire.Accepted, 10)}
	}
	contended := make([]Descriptor, 0, len(a.Contended))
	for _, d := range a.Contended {
		contended = append(contended, descriptor(d))
	}
	return Association{
		Direction:  direction,
		State:      state,
		Reason:     reason,
		Basis:      basis,
		Source:     source,
		Binding:    generation(a.Binding),
		Valid:      Interval{From: wallRead(a.Valid.From), Until: until, Open: a.Valid.Open},
		Descriptor: descriptor(a.Descriptor),
		Contended:  contended,
		Socket:     socket,
		Endpoints: Endpoints{
			Local:     address(a.Endpoints.Local),
			Remote:    address(a.Endpoints.Remote),
			Namespace: namespace(a.Endpoints.Netns.Device, a.Endpoints.Netns.Inode, BySocketEvidence),
		},
		Join:       join,
		JoinReason: joinReason,
		Wire:       wire,
	}, nil
}

func placement(p connection.Placement) (Placement, error) {
	direction, err := directionName(p.Direction)
	if err != nil {
		return Placement{}, err
	}
	held, err := named(positions, p.Positions, false, "positions")
	if err != nil {
		return Placement{}, err
	}
	because, err := named(reasons, p.Because, true, "placement reason")
	if err != nil {
		return Placement{}, err
	}
	out := Placement{Direction: direction, Positions: held, Because: because, Lost: count(p.Lost, Events)}
	if p.From != 0 {
		out.From = decimal(p.From)
	}
	return out, nil
}

var roles = map[reconstruct.Role]string{
	reconstruct.RoleUnknown: "unknown",
	reconstruct.Server:      "server",
	reconstruct.Client:      "client",
}

var kinds = map[http1.Kind]string{
	http1.UnknownKind: "unknown",
	http1.Request:     "request",
	http1.Response:    "response",
}

var framings = map[http1.Framing]string{
	http1.FramingNone:          "none",
	http1.FramingContentLength: "content_length",
	http1.FramingChunked:       "chunked",
	http1.FramingUntilClose:    "until_close",
	http1.FramingAmbiguous:     "ambiguous",
}

var defects = map[http1.Defect]string{
	http1.DefectNone:             "none",
	http1.DefectStreamEnded:      "stream_ended",
	http1.DefectHole:             "hole",
	http1.DefectMalformed:        "malformed",
	http1.DefectAmbiguousFraming: "ambiguous_framing",
	http1.DefectLimit:            "limit",
}

var shapeKinds = map[jsonshape.Kind]string{
	jsonshape.Invalid:       "invalid",
	jsonshape.Object:        "object",
	jsonshape.Array:         "array",
	jsonshape.Integer:       "integer",
	jsonshape.Fraction:      "fraction",
	jsonshape.Boolean:       "boolean",
	jsonshape.Null:          "null",
	jsonshape.ShortString:   "short_string",
	jsonshape.LongString:    "long_string",
	jsonshape.DecimalString: "decimal_string",
}

func lookup[K comparable](table map[K]string, value K, what string) (string, error) {
	name, found := table[value]
	if !found {
		return "", refuse("%s %v has no name", what, value)
	}
	return name, nil
}

// FromReconstruction is every connection a reconstruction holds, and the
// reassembly record for the observations it was built from. records must be
// the exact slice the reconstruction was run over, because a discard or a
// duplicate names an observation by its position in it.
func FromReconstruction(done reconstruct.Reconstruction, records []fragment.Record) ([]Reconstruction, Reassembly, error) {
	out := make([]Reconstruction, 0, len(done.Connections))
	for _, c := range done.Connections {
		one, err := fromConnection(c)
		if err != nil {
			return nil, Reassembly{}, err
		}
		out = append(out, one)
	}
	assembly := Reassembly{Record: KindReassembly, Version: Version, Discards: []Discard{}, Duplicates: []Duplicate{}}
	for _, d := range done.Discards {
		ref, err := observationRef(records, d.Index)
		if err != nil {
			return nil, Reassembly{}, err
		}
		because := ""
		if d.Err != nil {
			because = d.Err.Error()
		}
		assembly.Discards = append(assembly.Discards, Discard{Observation: ref, Because: because})
	}
	for _, d := range done.Duplicates {
		ref, err := observationRef(records, d.Index)
		if err != nil {
			return nil, Reassembly{}, err
		}
		assembly.Duplicates = append(assembly.Duplicates, Duplicate{
			Observation: ref, Offset: decimal(d.Offset), Length: decimal(d.Length), Agrees: d.Agrees,
		})
	}
	return out, assembly, nil
}

// observationRef names an observation by position. A refused observation may
// carry a direction with no name, so its direction is carried as the source
// number's decimal rather than refused - the reference must survive exactly the
// records that could not be placed.
func observationRef(records []fragment.Record, index int) (ObservationRef, error) {
	if index < 0 || index >= len(records) {
		return ObservationRef{}, refuse("observation %d is outside the %d observations given", index, len(records))
	}
	r := records[index]
	direction, err := directionName(r.Direction)
	if err != nil {
		direction = "unnamed:" + strconv.Itoa(int(r.Direction))
	}
	return ObservationRef{
		Index: index, Process: r.Process.PID, Connection: decimal(uint64(r.Connection)),
		Direction: direction, Sequence: decimal(r.Sequence),
	}, nil
}

func fromConnection(c reconstruct.Connection) (Reconstruction, error) {
	role, err := lookup(roles, c.Role, "role")
	if err != nil {
		return Reconstruction{}, err
	}
	protocol := "http/1.1"
	if c.Role == reconstruct.RoleUnknown {
		protocol = "unknown"
	}
	out := Reconstruction{
		Record:     KindReconstruction,
		Version:    Version,
		Connection: ConnectionRef{Process: process(c.Process), ID: decimal(uint64(c.ID))},
		Protocol:   protocol,
		Role:       role,
		Unplaced:   Count{State: Determined, Unit: Bytes, Value: decimal(c.Unplaced)},
		Note:       c.Note,
		Exchanges:  []Exchange{},
	}
	for i, e := range c.Exchanges {
		request, err := side(e.Request, c.Role, true)
		if err != nil {
			return Reconstruction{}, err
		}
		response, err := side(e.Response, c.Role, false)
		if err != nil {
			return Reconstruction{}, err
		}
		out.Exchanges = append(out.Exchanges, Exchange{Index: i, Request: request, Response: response, Complete: e.Complete})
	}
	return out, nil
}

// side is one half of an exchange. The direction a message crossed is derived
// from the connection's role: a server receives requests and sends responses.
func side(m *reconstruct.Message, role reconstruct.Role, request bool) (Side, error) {
	if m == nil {
		return Side{State: Absent}, nil
	}
	kind, err := lookup(kinds, m.Kind, "message kind")
	if err != nil {
		return Side{}, err
	}
	framing, err := lookup(framings, m.Framing, "framing")
	if err != nil {
		return Side{}, err
	}
	defect, err := lookup(defects, m.Defect, "defect")
	if err != nil {
		return Side{}, err
	}
	direction := "received"
	if (role == reconstruct.Server) != request {
		direction = "sent"
	}
	out := Message{
		Kind:     kind,
		Method:   m.Method,
		Target:   m.Target,
		Protocol: m.Protocol,
		Reason:   m.Reason,
		Headers:  fields(m.Headers),
		Trailers: fields(m.Trailers),
		Framing:  framing,
		Body: Body{
			Length:   decimal(m.BodyLength),
			Kept:     base64.StdEncoding.EncodeToString(m.Body),
			Holed:    decimal(m.BodyHoled),
			Elided:   decimal(m.BodyElided),
			Encoding: "base64",
		},
		Complete: m.Complete,
		Framed:   m.Framed,
		Defect:   defect,
		Detail:   m.Detail,
		Stream:   MessageRange{Direction: direction, Offset: decimal(m.Offset), End: decimal(m.End)},
	}
	if m.Kind == http1.Response {
		status := m.Status
		out.Status = &status
	}
	switch {
	case m.Shape != nil:
		shape, err := fromShape(*m.Shape)
		if err != nil {
			return Side{}, err
		}
		out.Structure = Structure{State: StructureDerived, Shape: &shape}
	case m.ShapeRefused != "":
		out.Structure = Structure{State: StructureRefused, Refused: m.ShapeRefused}
	default:
		out.Structure = Structure{State: StructureNone}
	}
	return Side{State: Present, Message: &out}, nil
}

func fields(headers []http1.Header) []Field {
	out := make([]Field, 0, len(headers))
	for _, h := range headers {
		out = append(out, Field{Name: h.Name, Value: h.Value})
	}
	return out
}

func fromShape(s jsonshape.Shape) (Shape, error) {
	kind, err := lookup(shapeKinds, s.Kind, "shape kind")
	if err != nil {
		return Shape{}, err
	}
	out := Shape{Kind: kind, Count: s.Count, Elided: s.Elided}
	for _, f := range s.Fields {
		inner, err := fromShape(f.Shape)
		if err != nil {
			return Shape{}, err
		}
		out.Fields = append(out.Fields, ShapeField{Name: f.Name, NameElided: f.NameElided, Shape: inner})
	}
	for _, e := range s.Elems {
		inner, err := fromShape(e)
		if err != nil {
			return Shape{}, err
		}
		out.Elems = append(out.Elems, inner)
	}
	return out, nil
}
