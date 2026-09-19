package record

// ConnectionRef names a connection the way an observation does: the process in
// the observer's numbering and the connection id within the session.
type ConnectionRef struct {
	Process Process `json:"process"`
	ID      string  `json:"id"`
}

// Reconstruction is what one connection's observations were read as: which
// side the process was on, the exchanges, and the offsets nothing accounted for.
type Reconstruction struct {
	Record     string        `json:"record"`
	Version    string        `json:"version"`
	Connection ConnectionRef `json:"connection"`
	// Protocol is the protocol the exchanges were read as, or "unknown" where
	// neither direction began as one.
	Protocol string `json:"protocol"`
	Role     string `json:"role"`
	// Unplaced is offsets that carried bytes and were never read as part of a
	// message, over both directions.
	Unplaced  Count      `json:"unplaced"`
	Note      string     `json:"note,omitempty"`
	Exchanges []Exchange `json:"exchanges"`
}

// Exchange is a request and its response, either of which may be absent.
type Exchange struct {
	Index    int  `json:"index"`
	Request  Side `json:"request"`
	Response Side `json:"response"`
	// Complete is both sides present and neither missing a byte.
	Complete bool `json:"complete"`
}

// Side is one half of an exchange and whether it is there at all. An absent
// response is not an empty one.
type Side struct {
	State   string   `json:"state"`
	Message *Message `json:"message,omitempty"`
}

// Presence of a side.
const (
	Present = "present"
	Absent  = "absent"
)

// Message is one message as far as it could be read.
type Message struct {
	Kind string `json:"kind"`

	Method   string `json:"method,omitempty"`
	Target   string `json:"target,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Status   *int   `json:"status,omitempty"`
	Reason   string `json:"reason,omitempty"`

	Headers  []Field `json:"headers"`
	Trailers []Field `json:"trailers"`

	Framing string `json:"framing"`
	Body    Body   `json:"body"`

	// Complete is every byte of the message present in the stream; Framed is
	// its end known.
	Complete bool   `json:"complete"`
	Framed   bool   `json:"framed"`
	Defect   string `json:"defect"`
	Detail   string `json:"detail,omitempty"`

	// Stream is where the message sits: the direction it crossed and the
	// offsets from its start line to one past its end.
	Stream MessageRange `json:"stream"`

	Structure Structure `json:"structure"`
}

// Field is a header or trailer line with its name as sent.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Body is a message body's extent and what was kept of it.
type Body struct {
	// Length is the body's extent in the stream, Kept the bytes retained,
	// Holed the bytes capture never had and Elided the bytes a bound dropped.
	Length   string `json:"length"`
	Kept     string `json:"kept"`
	Holed    string `json:"holed"`
	Elided   string `json:"elided"`
	Encoding string `json:"encoding"`
}

// MessageRange is a message's place in its stream.
type MessageRange struct {
	Direction string `json:"direction"`
	Offset    string `json:"offset"`
	End       string `json:"end"`
}

// Structure is the shape of a body: derived, refused with a reason, or none
// because there was no body.
type Structure struct {
	State   string `json:"state"`
	Refused string `json:"refused,omitempty"`
	Shape   *Shape `json:"shape,omitempty"`
}

// States of a structure.
const (
	StructureDerived = "derived"
	StructureRefused = "refused"
	StructureNone    = "none"
)

// Shape is a body's structure without its values.
type Shape struct {
	Kind   string       `json:"kind"`
	Fields []ShapeField `json:"fields,omitempty"`
	Elems  []Shape      `json:"elems,omitempty"`
	Count  int          `json:"count"`
	Elided bool         `json:"elided"`
}

// ShapeField is one member of an object shape.
type ShapeField struct {
	Name       string `json:"name"`
	NameElided bool   `json:"name_elided"`
	Shape      Shape  `json:"shape"`
}

// Reassembly is what putting a session's observations into streams refused or
// did not need. One per session.
type Reassembly struct {
	Record     string      `json:"record"`
	Version    string      `json:"version"`
	Discards   []Discard   `json:"discards"`
	Duplicates []Duplicate `json:"duplicates"`
}

// ObservationRef names an observation by its position in the session's
// observation sequence, which is the only identity a refused observation is
// guaranteed to have, and by its own fields as far as they were readable.
type ObservationRef struct {
	Index      int    `json:"index"`
	Process    int32  `json:"pid"`
	Connection string `json:"connection"`
	Direction  string `json:"direction"`
	Sequence   string `json:"sequence"`
}

// Discard is an observation reassembly refused. Its offsets are a gap.
type Discard struct {
	Observation ObservationRef `json:"observation"`
	Because     string         `json:"because"`
}

// Duplicate is an observation every offset of which was already placed.
type Duplicate struct {
	Observation ObservationRef `json:"observation"`
	Offset      string         `json:"offset"`
	Length      string         `json:"length"`
	Agrees      bool           `json:"agrees"`
}
