package processing

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/jsonshape"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/reconstruct"
)

func (w *Worker) process(ctx context.Context, b *batch) error {
	if b.invalid {
		w.withhold(connection.Uncounted("invalid_input"))
		w.countProcessingFailure("")
		return nil
	}
	fragments, prefix, valid := b.placed()
	if !valid {
		w.withhold(connection.Uncounted("invalid_input"))
		w.countProcessingFailure("")
		return nil
	}
	metadata, err := record.FromConnection(*b.retirement)
	if err != nil {
		w.withhold(connection.Uncounted("invalid_input"))
		w.countProcessingFailure("")
		return nil
	}
	var source reconstruct.Connection
	var truncation *ReconstructionTruncation
	refused := connection.Counted(0)
	needsParse := false
	for _, p := range w.pipelines {
		if p.Input == "reconstruction" && !w.stopped[p.Name] {
			needsParse = true
		}
	}
	if needsParse {
		if w.options.BeforeParse != nil {
			if err := w.options.BeforeParse(ctx); err != nil {
				w.withhold(connection.Uncounted("unsettled_input"))
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			w.withhold(connection.Uncounted("unsettled_input"))
			return err
		}
		done := reconstruct.Run(fragments, w.options.Limits)
		if len(done.Connections) == 1 && len(done.Discards) == 0 && len(done.Duplicates) == 0 {
			source = done.Connections[0]
			good := 0
			for _, e := range source.Exchanges {
				if !supportedExchange(e) {
					break
				}
				good++
			}
			refused = reconstructionRefusals(source, good, prefix)
			truncation = describeTruncation(source, good, prefix)
			source.Exchanges = source.Exchanges[:good]
			// Undecidable source content and parser diagnostics never enter output.
			// Numeric Unplaced is not erased: the approved projection explicitly
			// marks it undetermined when the remaining stream is indeterminate.
			source.Note = ""
		} else if len(b.fragments) != 0 || prefix.truncated() {
			refused = connection.Uncounted("reconstruction_incomplete")
		}
		w.withhold(refused)
	}
	for _, p := range w.pipelines {
		if w.stopped[p.Name] {
			continue
		}
		artifact := Artifact{Version: ArtifactVersion, PolicyRevision: w.options.PolicyRevision, Connection: metadata, PolicyExclusions: []PolicyExclusion{}}
		switch p.Input {
		case "connection":
			// The compiler's connection-route exception rests on this separate
			// construction: a metadata pipeline never receives source messages.
		case "reconstruction":
			processed := copyConnection(source)
			run := slotRun{source: source, evidence: exclusionEvidence{fields: []PolicyExclusion{}}, bodies: map[*reconstruct.Message]string{}, shapes: w.options.Limits.JSON}
			failed := false
			for _, slot := range p.Slots {
				if !run.apply(&processed, slot) {
					w.failure(p.Name, slot.OnFailure)
					failed = true
					break
				}
			}
			if failed {
				continue
			}
			if len(processed.Exchanges) != 0 {
				projected, _, err := record.FromReconstruction(reconstruct.Reconstruction{Connections: []reconstruct.Connection{processed}}, nil)
				if err != nil {
					w.failure(p.Name, firstAction(p))
					continue
				}
				run.mark(&projected[0], processed)
				artifact.Reconstruction = &projected[0]
				artifact.ReconstructionTruncation = truncation
				artifact.PolicyExclusions = run.evidence.fields
				if truncation != nil {
					artifact.Reconstruction.Unplaced = record.Count{State: record.Undetermined, Unit: record.Bytes, Why: "reconstruction_truncated"}
				}
			}
		default:
			w.failure(p.Name, firstAction(p))
			continue
		}
		if p.Input == "connection" || artifact.Reconstruction != nil {
			for _, route := range w.routes {
				if route.Pipeline != p.Name {
					continue
				}
				artifact.Route = route
				if err := w.emit(ctx, artifact); err != nil {
					return err
				}
			}
		}
		if p.Input == "reconstruction" && (!refused.Known || refused.Value != 0) {
			// The first slot cannot accept an undecidable message. Nothing
			// later can repair that missing input; its resolved action applies.
			w.failure(p.Name, firstAction(p))
		}
	}
	return nil
}

func reconstructionRefusals(source reconstruct.Connection, good int, prefix batchPrefix) connection.Count {
	if prefix.truncated() || source.Unplaced != 0 || source.Role == reconstruct.RoleUnknown {
		return connection.Uncounted("reconstruction_incomplete")
	}
	for _, e := range source.Exchanges {
		if !e.Complete || !countableMessage(e.Request) || !countableMessage(e.Response) {
			return connection.Uncounted("reconstruction_incomplete")
		}
	}
	return connection.Counted(int64(len(source.Exchanges) - good))
}

// Cardinality needs framing and pairing, independently of whether the body
// encoding or retained body is supported by processing. Switching protocols or
// interim responses defeat the parser's one-request/one-response pairing.
func countableMessage(m *reconstruct.Message) bool {
	if m == nil || !m.Complete || !m.Framed || m.Defect != http1.DefectNone || m.BodyHoled != 0 {
		return false
	}
	if m.Protocol != "HTTP/1.0" && m.Protocol != "HTTP/1.1" {
		return false
	}
	if strings.EqualFold(m.Method, "CONNECT") || (m.Kind == http1.Response && m.Status < 200) {
		return false
	}
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, "upgrade") {
			return false
		}
	}
	return true
}

func describeTruncation(source reconstruct.Connection, good int, prefix batchPrefix) *ReconstructionTruncation {
	var retained [3]uint64
	request, response := fragment.Sent, fragment.Received
	if source.Role == reconstruct.Server {
		request, response = response, request
	}
	for _, e := range source.Exchanges[:good] {
		retained[request], retained[response] = e.Request.End, e.Response.End
	}
	var firstOmitted [3]*reconstruct.Message
	if good < len(source.Exchanges) {
		firstOmitted[request] = source.Exchanges[good].Request
		firstOmitted[response] = source.Exchanges[good].Response
	}
	var stops []TruncationStop
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		p := prefix[direction]
		if p.cut == nil && p.end <= retained[direction] {
			continue
		}
		reason, at := "unparsed_suffix", retained[direction]
		m := firstOmitted[direction]
		if m != nil {
			reason, at = messageStop(m)
		}
		// A capture cutoff causing parser end-of-input remains a capture
		// reason. An earlier parse defect remains its own reason instead.
		if p.cut != nil && (m == nil || p.cut.offset <= at) {
			reason, at = p.cut.reason, p.cut.offset
		}
		stops = append(stops, TruncationStop{Direction: direction.String(), Offset: strconv.FormatUint(retained[direction], 10), Reason: reason, EvidenceOffset: strconv.FormatUint(at, 10)})
	}
	if len(stops) == 0 {
		return nil
	}
	return &ReconstructionTruncation{State: "truncated", Suffix: "indeterminate", Stops: stops}
}

func messageStop(m *reconstruct.Message) (string, uint64) {
	switch m.Defect {
	case http1.DefectStreamEnded:
		return "incomplete_message", m.End
	case http1.DefectHole:
		return "capture_hole", m.End
	case http1.DefectMalformed:
		return "malformed_message", m.End
	case http1.DefectAmbiguousFraming:
		return "ambiguous_framing", m.End
	case http1.DefectLimit:
		return "processing_limit", m.End
	}
	if m.BodyElided != 0 {
		return "processing_limit", m.End
	}
	if !m.Complete || !m.Framed {
		return "incomplete_message", m.End
	}
	if !supportedMessage(m) {
		return "unsupported_message", m.Offset
	}
	return "unpaired_exchange", m.Offset
}

func firstAction(p config.EffectivePipeline) string {
	if len(p.Slots) == 0 {
		return config.OnFailureDropAndAccount
	}
	return p.Slots[0].OnFailure
}

func (w *Worker) failure(name, action string) {
	w.countProcessingFailure(name)
	if action == config.OnFailureStopPipeline && !w.stopped[name] {
		w.stopped[name] = true
		w.outcome.StoppedPipelines = append(w.outcome.StoppedPipelines, name)
	}
}

// A batch refusal affects all active routes; a pipeline refusal affects only
// that pipeline's routes. Count before applying its stop action, so the failure
// that stops a route counts once and later batches do not count it again.
func (w *Worker) countProcessingFailure(pipeline string) {
	for _, route := range w.routes {
		if !w.stopped[route.Pipeline] && (pipeline == "" || route.Pipeline == pipeline) {
			w.outcome.ProcessingFailures++
		}
	}
}

func (w *Worker) emit(ctx context.Context, artifact Artifact) error {
	line, err := json.Marshal(artifact)
	if err != nil {
		// Artifact is built by this binary from serializable contract types.
		// Reaching this branch means the observer's invariant is broken, not
		// bad captured input or an operator's deployment fault. Fold it into
		// the existing terminal error and seal reason, with no failure counter:
		// nothing was authorized or handed to the output writer here.
		return errors.New("internal observer defect: cannot serialize its approved artifact")
	}
	line = append(line, '\n')
	if err := ctx.Err(); err != nil {
		return err
	}
	decision := w.options.Gate.Authorize(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true})
	if !decision.Authorized {
		w.outcome.GateReason = decision.Reason
		return nil
	}
	w.outcome.Authorized++
	if err := w.options.Output.WriteApproved(ctx, Approved{line: line}); err != nil {
		w.outcome.OutputFailures++
		switch {
		case errors.Is(err, ErrOutputLimit):
			return ErrOutputLimit
		case errors.Is(err, context.Canceled):
			return context.Canceled
		case errors.Is(err, context.DeadlineExceeded):
			return context.DeadlineExceeded
		default:
			return errors.New("approved output failed")
		}
	}
	w.outcome.Written++
	return nil
}

func supportedExchange(e reconstruct.Exchange) bool {
	return e.Complete && supportedMessage(e.Request) && supportedMessage(e.Response)
}

func supportedMessage(m *reconstruct.Message) bool {
	if m == nil || !m.Complete || !m.Framed || m.Defect != http1.DefectNone || m.BodyHoled != 0 || m.BodyElided != 0 {
		return false
	}
	if m.Protocol != "HTTP/1.0" && m.Protocol != "HTTP/1.1" {
		return false
	}
	if strings.EqualFold(m.Method, "CONNECT") || (m.Kind == http1.Response && m.Status < 200) {
		return false
	}
	encodings := 0
	for _, h := range m.Headers {
		switch strings.ToLower(h.Name) {
		case "upgrade":
			return false
		case "content-encoding":
			if !strings.EqualFold(strings.TrimSpace(h.Value), "identity") {
				return false
			}
		case "transfer-encoding":
			encodings++
			if encodings > 1 || !strings.EqualFold(strings.TrimSpace(h.Value), "chunked") {
				return false
			}
		}
	}
	return true
}

func copyConnection(source reconstruct.Connection) reconstruct.Connection {
	out := source
	out.Exchanges = make([]reconstruct.Exchange, len(source.Exchanges))
	for i, e := range source.Exchanges {
		out.Exchanges[i] = reconstruct.Exchange{Request: copyMessage(e.Request), Response: copyMessage(e.Response), Complete: e.Complete}
	}
	return out
}

func copyMessage(source *reconstruct.Message) *reconstruct.Message {
	if source == nil {
		return nil
	}
	out := *source
	out.Headers, out.Trailers = slices.Clone(source.Headers), slices.Clone(source.Trailers)
	out.Body = slices.Clone(source.Body)
	out.Detail = ""
	if out.ShapeRefused != "" {
		out.ShapeRefused = "body structure unavailable"
	}
	return &out
}

type exclusionEvidence struct {
	fields []PolicyExclusion
	seen   map[PolicyExclusion]struct{}
}

// add records one removal once, however many occurrences or slots it covers.
func (e *exclusionEvidence) add(entry PolicyExclusion) {
	if e.seen == nil {
		e.seen = make(map[PolicyExclusion]struct{})
	}
	if _, exists := e.seen[entry]; exists {
		return
	}
	e.seen[entry] = struct{}{}
	e.fields = append(e.fields, entry)
}

// slotRun is one pipeline's pass over a copy of the parsed connection. Body
// operations read header facts from source, the connection as parsed, so no
// header operation earlier in the route changes what they admit.
type slotRun struct {
	source   reconstruct.Connection
	evidence exclusionEvidence
	// bodies holds what policy did to a processed message's body: removed, or
	// values_removed. A message absent from it kept its body.
	bodies map[*reconstruct.Message]string
	shapes jsonshape.Limits
}

func (r *slotRun) apply(c *reconstruct.Connection, slot config.EffectiveSlot) bool {
	a := slot.Arguments
	if a == nil {
		return false
	}
	switch slot.Implementation {
	case config.RemoveHeaders, config.ReplaceHeaderValues, config.TruncateHeaderValues,
		config.RemoveBody, config.ReduceBodyToStructure, config.RemoveQuery,
		config.RemoveJSONFields, config.ReplaceJSONValues, config.RemoveFormFields, config.RemoveQueryParameters,
		config.RequestBodyFields:
	default:
		return false
	}
	for index, e := range c.Exchanges {
		for side, m := range []*reconstruct.Message{e.Request, e.Response} {
			message := config.MessageRequest
			if side == 1 {
				message = config.MessageResponse
			}
			where := PolicyExclusion{Exchange: index, Message: message, Disposition: DispositionRemoved}
			switch slot.Implementation {
			case config.RemoveHeaders, config.ReplaceHeaderValues, config.TruncateHeaderValues:
				where.Section = "headers"
				m.Headers = r.transformFields(m.Headers, slot, where)
				where.Section = "trailers"
				m.Trailers = r.transformFields(m.Trailers, slot, where)
			case config.RemoveBody:
				if slices.Contains(a.Messages, message) && (len(m.Body) > 0 || r.bodies[m] == DispositionValuesRemoved) {
					r.removeBody(m, where, DispositionRemoved)
				}
			case config.ReduceBodyToStructure:
				if slices.Contains(a.Messages, message) && len(m.Body) > 0 {
					if m.Shape == nil {
						r.removeBody(m, where, DispositionRemoved)
						break
					}
					m.Body = nil
					r.bodies[m] = DispositionValuesRemoved
					where.Field, where.Disposition = config.BodyValuesField, DispositionValuesRemoved
					r.evidence.add(where)
				}
			case config.RemoveJSONFields, config.ReplaceJSONValues:
				if slices.Contains(a.Messages, message) && len(m.Body) > 0 {
					r.editBody(m, slot, where)
				}
			case config.RemoveFormFields:
				if side == 0 && len(m.Body) > 0 {
					if !admittedForm(r.source.Exchanges[index].Request) {
						r.removeBody(m, where, DispositionRemovedUndecidable)
						break
					}
					body, matched, undecidable := removeParameters(string(m.Body), a.Names)
					if undecidable {
						r.removeBody(m, where, DispositionRemovedUndecidable)
						break
					}
					r.spliced(m, []byte(body), matched, config.FormFieldPrefix, where)
				}
			case config.RequestBodyFields:
				if side == 0 && len(m.Body) > 0 {
					r.requestBody(m, r.source.Exchanges[index].Request, a, where)
				}
			case config.RemoveQuery:
				if side == 0 {
					if cut := strings.IndexByte(m.Target, '?'); cut >= 0 {
						m.Target = m.Target[:cut]
						where.Field = config.TargetQueryField
						r.evidence.add(where)
					}
				}
			case config.RemoveQueryParameters:
				if side == 0 {
					if path, query, has := strings.Cut(m.Target, "?"); has {
						kept, matched, undecidable := removeParameters(query, a.Names)
						if undecidable {
							m.Target = path
							where.Field, where.Disposition = config.TargetQueryField, DispositionRemovedUndecidable
							r.evidence.add(where)
							break
						}
						m.Target = path + "?" + kept
						for _, name := range matched {
							where.Field = config.QueryFieldPrefix + name
							r.evidence.add(where)
						}
					}
				}
			}
		}
	}
	return true
}

func (r *slotRun) transformFields(fields []http1.Header, slot config.EffectiveSlot, where PolicyExclusion) []http1.Header {
	out := fields[:0]
	for _, h := range fields {
		name := strings.ToLower(h.Name)
		if slices.Contains(slot.Arguments.Headers, name) {
			switch slot.Implementation {
			case config.RemoveHeaders:
				where.Field = config.HeaderFieldPrefix + name
				r.evidence.add(where)
				continue
			case config.ReplaceHeaderValues:
				h.Value = slot.Arguments.Value
			case config.TruncateHeaderValues:
				h.Value = h.Value[:min(len(h.Value), slot.Arguments.Length)]
			}
		}
		out = append(out, h)
	}
	return out
}

// removeBody drops a body's bytes and structure; its length and framing stay.
func (r *slotRun) removeBody(m *reconstruct.Message, where PolicyExclusion, disposition string) {
	m.Body, m.Shape, m.ShapeRefused = nil, nil, ""
	r.bodies[m] = DispositionRemoved
	where.Field, where.Disposition = config.BodyField, disposition
	r.evidence.add(where)
}

func (r *slotRun) editBody(m *reconstruct.Message, slot config.EffectiveSlot, where PolicyExclusion) {
	var replacement []byte
	if slot.Implementation == config.ReplaceJSONValues {
		replacement = jsonString(slot.Arguments.Value)
	}
	body, hits, err := editJSON(m.Body, slot.Arguments.Pointers, replacement)
	if err != nil {
		r.removeBody(m, where, DispositionRemovedUndecidable)
		return
	}
	var matched []string
	for i, hit := range hits {
		if hit {
			matched = append(matched, slot.Arguments.Pointers[i])
		}
	}
	if replacement != nil {
		// A replaced value is not a removal and records no entry.
		r.spliced(m, body, nil, config.JSONFieldPrefix, where)
		return
	}
	r.spliced(m, body, matched, config.JSONFieldPrefix, where)
}

// spliced keeps a body whose other bytes are unchanged, records a removal for
// each selector that matched, and derives the structure again from what is
// kept, so it never describes a removed member.
func (r *slotRun) spliced(m *reconstruct.Message, body []byte, matched []string, prefix string, where PolicyExclusion) {
	for _, selector := range matched {
		where.Field = prefix + selector
		r.evidence.add(where)
	}
	if string(body) == string(m.Body) {
		return
	}
	m.Body = body
	m.Shape, m.ShapeRefused = nil, ""
	if shape, err := jsonshape.Extract(body, r.shapes); err == nil {
		m.Shape = &shape
	} else {
		m.ShapeRefused = "body structure unavailable"
	}
}

// mark writes into the projection what policy did to each body: a removed
// body keeps its length and framing, has no kept bytes and has structure
// state removed; a body whose values went keeps its derived structure.
func (r *slotRun) mark(projected *record.Reconstruction, processed reconstruct.Connection) {
	for i, e := range processed.Exchanges {
		for _, pair := range []struct {
			source *reconstruct.Message
			side   record.Side
		}{{e.Request, projected.Exchanges[i].Request}, {e.Response, projected.Exchanges[i].Response}} {
			if pair.side.Message == nil {
				continue
			}
			switch r.bodies[pair.source] {
			case DispositionRemoved:
				pair.side.Message.Body.Kept = ""
				pair.side.Message.Structure = record.Structure{State: record.StructureRemoved}
			case DispositionValuesRemoved:
				pair.side.Message.Body.Kept = ""
			}
		}
	}
}
