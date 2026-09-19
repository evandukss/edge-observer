// Package reconstruct turns the fragments of a capture into the exchanges the
// observed process had: fragments in, structure out, with no kernel and no
// privilege. It reports the process and connection, which side the process
// was on, and each exchange's request and response as HTTP framed them, with
// each body's shape. It does not interpret what any of it means.
//
// Absences stay absences:
//
//   - A connection whose traffic begins with neither a request line nor a status
//     line has an unknown side and no exchanges, not an empty server.
//   - A request nothing answered is a request and no response, not an empty
//     response.
//
// Sequence is not read: Offset orders each direction, which is all
// reconstruction needs.
package reconstruct

import (
	"fmt"
	"strings"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/jsonshape"
	"github.com/evandukss/edge-observer/stream"
)

// Role is which side of a connection the observed process was on, read off
// what each direction begins with; a fragment does not carry it.
type Role uint8

const (
	// RoleUnknown is a connection neither direction of which begins as HTTP.
	RoleUnknown Role = iota
	// Server is a process that received requests and sent responses.
	Server
	// Client is a process that sent requests and received responses.
	Client
)

func (r Role) String() string {
	switch r {
	case Server:
		return "server"
	case Client:
		return "client"
	default:
		return "unknown"
	}
}

// Message is one HTTP message with the shape of its body.
type Message struct {
	http1.Message
	// Shape is the body's structure, or nil where there is none to read.
	Shape *jsonshape.Shape
	// ShapeRefused says why a body with bytes has no shape; empty for a message
	// with no body.
	ShapeRefused string
}

// Exchange is a request and the response to it, either of which may be absent.
type Exchange struct {
	Request  *Message
	Response *Message
	// Complete reports that both sides are here and neither is missing a byte.
	Complete bool
}

// Connection is one TLS connection of one process.
type Connection struct {
	Process   fragment.Process
	ID        fragment.ConnectionID
	Role      Role
	Exchanges []Exchange
	// Unplaced is how many of the connection's offsets, over both directions,
	// were never read as part of a message.
	Unplaced uint64
	Note     string
}

// Reconstruction is every connection a set of fragments held.
type Reconstruction struct {
	Connections []Connection
	// Discards are the records the capture side should not have produced.
	Discards []stream.Discard
	// Duplicates are records whose offsets were all already placed. They change no
	// reconstruction, so they are carried: otherwise a run emitting a fragment
	// twice would look clean.
	Duplicates []stream.Duplicate
}

// Limits bounds what one capture can make this package hold.
type Limits struct {
	HTTP http1.Limits
	JSON jsonshape.Limits
}

// DefaultLimits are the bounds of the layers below.
func DefaultLimits() Limits {
	return Limits{HTTP: http1.DefaultLimits(), JSON: jsonshape.DefaultLimits()}
}

// Run reconstructs every connection the records hold.
func Run(records []fragment.Record, limits Limits) Reconstruction {
	assembled := stream.Assemble(records)
	result := Reconstruction{Discards: assembled.Discards, Duplicates: assembled.Duplicates}

	type key struct {
		process fragment.Process
		id      fragment.ConnectionID
	}

	// Assemble's stream order is fixed, so connections get a fixed order too.
	var order []key
	directions := map[key]map[fragment.Direction]stream.Stream{}
	for _, s := range assembled.Streams {
		k := key{process: s.Key.Process, id: s.Key.Connection}
		if _, seen := directions[k]; !seen {
			directions[k] = map[fragment.Direction]stream.Stream{}
			order = append(order, k)
		}
		directions[k][s.Key.Direction] = s
	}

	for _, k := range order {
		result.Connections = append(result.Connections,
			one(k.process, k.id, directions[k][fragment.Sent], directions[k][fragment.Received], limits))
	}
	return result
}

func one(process fragment.Process, id fragment.ConnectionID, sent, received stream.Stream, limits Limits) Connection {
	connection := Connection{Process: process, ID: id}

	switch connection.Role = roleOf(sent, received); connection.Role {
	case Server:
		connection.Exchanges, connection.Unplaced = pair(received, sent, limits)
	case Client:
		connection.Exchanges, connection.Unplaced = pair(sent, received, limits)
	default:
		connection.Unplaced = sent.End - sent.Start + received.End - received.Start
		connection.Note = "neither direction begins with a request line or a status line"
	}
	return connection
}

// pair reads each direction and puts the two together. HTTP/1.1 answers in
// order, so the i'th response answers the i'th request; extra messages on one
// side pair with nothing.
func pair(requestSide, responseSide stream.Stream, limits Limits) ([]Exchange, uint64) {
	requests := http1.Parse(requestSide, http1.Request, limits.HTTP)

	// A response to HEAD declares a length and carries no body, so framing the
	// responses needs to know which requests were HEAD.
	bodiless := make([]bool, len(requests.Messages))
	for i, m := range requests.Messages {
		bodiless[i] = strings.EqualFold(m.Method, "HEAD")
	}
	responses := http1.ParseResponses(responseSide, limits.HTTP, bodiless)

	var exchanges []Exchange
	for i := 0; i < max(len(requests.Messages), len(responses.Messages)); i++ {
		var exchange Exchange
		if i < len(requests.Messages) {
			exchange.Request = read(requests.Messages[i], limits.JSON)
		}
		if i < len(responses.Messages) {
			exchange.Response = read(responses.Messages[i], limits.JSON)
		}
		exchange.Complete = exchange.Request != nil && exchange.Request.Complete &&
			exchange.Response != nil && exchange.Response.Complete
		exchanges = append(exchanges, exchange)
	}

	return exchanges, requests.Unplaced + responses.Unplaced
}

// read takes the shape of a message's body, or says why it did not.
func read(m http1.Message, limits jsonshape.Limits) *Message {
	message := &Message{Message: m}

	switch {
	case m.BodyLength == 0 && len(m.Body) == 0:
		// No body at all, which is not a refused shape.
		return message
	case len(m.Body) == 0:
		message.ShapeRefused = "none of the body's bytes were captured"
	case m.BodyHoled > 0:
		message.ShapeRefused = fmt.Sprintf("%d of the body's bytes were never captured", m.BodyHoled)
	case m.BodyElided > 0:
		message.ShapeRefused = fmt.Sprintf("the body is longer than the bound by %d bytes", m.BodyElided)
	default:
		shape, err := jsonshape.Extract(m.Body, limits)
		if err != nil {
			message.ShapeRefused = err.Error()
			return message
		}
		message.Shape = &shape
	}
	return message
}

// roleOf reads which side the process was on from what each direction begins
// with. Where they do not say, it says so rather than choosing.
func roleOf(sent, received stream.Stream) Role {
	switch outbound, inbound := opening(sent), opening(received); {
	case outbound == opensResponse && inbound != opensResponse,
		outbound == opensNothing && inbound == opensRequest:
		return Server
	case outbound == opensRequest && inbound != opensRequest,
		outbound == opensNothing && inbound == opensResponse:
		return Client
	default:
		return RoleUnknown
	}
}

type opener uint8

const (
	opensNothing opener = iota
	opensRequest
	opensResponse
	opensSomethingElse
)

// opening is what a direction's first bytes start: a status line (by its
// version), a request line (a method token and a space), or neither.
func opening(s stream.Stream) opener {
	if s.End == s.Start {
		return opensNothing
	}

	head := stream.NewCursor(s).Peek(32)
	if len(head) >= 5 && string(head[:5]) == "HTTP/" {
		return opensResponse
	}
	if space := strings.IndexByte(string(head), ' '); space > 0 && isMethod(head[:space]) {
		return opensRequest
	}
	return opensSomethingElse
}

// isMethod reports whether these bytes are a token.
func isMethod(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// String renders the reconstruction for a reader: start lines, field names,
// framing, body sizes and shapes. It carries no field value and no body byte.
func (r Reconstruction) String() string {
	var b strings.Builder

	for _, connection := range r.Connections {
		fmt.Fprintf(&b, "process %d/%d connection %d %s\n",
			connection.Process.PID, connection.Process.StartTime, connection.ID, connection.Role)
		if connection.Note != "" {
			fmt.Fprintf(&b, "  %s\n", connection.Note)
		}
		for i, exchange := range connection.Exchanges {
			fmt.Fprintf(&b, "  exchange %d\n", i+1)
			write(&b, "request", exchange.Request)
			write(&b, "response", exchange.Response)
		}
		if connection.Unplaced > 0 {
			fmt.Fprintf(&b, "  %d offsets were never placed in a message\n", connection.Unplaced)
		}
	}

	for _, discard := range r.Discards {
		fmt.Fprintf(&b, "record %d was refused: %v\n", discard.Index, discard.Err)
	}
	return b.String()
}

func write(b *strings.Builder, label string, m *Message) {
	if m == nil {
		fmt.Fprintf(b, "    %s none\n", label)
		return
	}

	fmt.Fprintf(b, "    %s %s\n", label, m.StartLine())

	if len(m.Headers) > 0 {
		names := make([]string, len(m.Headers))
		for i, h := range m.Headers {
			names[i] = h.Name
		}
		fmt.Fprintf(b, "      fields %s\n", strings.Join(names, ", "))
	}
	if !m.Complete {
		fmt.Fprintf(b, "      incomplete: %s, %s\n", m.Defect, m.Detail)
	}

	switch {
	case m.Shape != nil:
		fmt.Fprintf(b, "      body %s %d bytes\n", m.Framing, m.BodyLength)
		for _, line := range strings.Split(m.Shape.String(), "\n") {
			fmt.Fprintf(b, "        %s\n", line)
		}
	case m.ShapeRefused != "":
		fmt.Fprintf(b, "      body %s %d bytes, no shape: %s\n", m.Framing, m.BodyLength, m.ShapeRefused)
	}
}
