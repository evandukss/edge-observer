package processing

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
)

// Error text is structural and never includes a value taken from the file.
func validateArtifact(a Artifact) error {
	if a.Version != ArtifactVersion && a.Version != ArtifactVersion1 {
		return errors.New("unsupported artifact version")
	}
	if a.PolicyRevision == "" || a.Route.Pipeline == "" || a.Route.Sink == "" || a.Route.Kind == "" {
		return errors.New("missing policy revision or route")
	}
	if a.Connection.Record != record.KindConnection || a.Connection.Version != record.Version || a.Connection.ID == "" {
		return errors.New("invalid connection identity or version")
	}
	r := a.Reconstruction
	if r == nil {
		if a.ReconstructionTruncation != nil || len(a.PolicyExclusions) != 0 {
			return errors.New("reconstruction evidence without reconstruction")
		}
		return nil
	}
	if r.Record != record.KindReconstruction || r.Version != record.Version ||
		r.Connection.ID != a.Connection.ID || r.Connection.Process != a.Connection.Process || len(r.Exchanges) == 0 {
		return errors.New("invalid reconstruction identity, version or population")
	}
	exchanges := make(map[int]record.Exchange, len(r.Exchanges))
	for _, e := range r.Exchanges {
		if _, exists := exchanges[e.Index]; exists || e.Index < 0 || !e.Complete {
			return errors.New("invalid retained exchange")
		}
		exchanges[e.Index] = e
		if !readableSide(e.Request, "request") || !readableSide(e.Response, "response") {
			return errors.New("invalid retained message or body encoding")
		}
	}
	if err := validateTruncation(a); err != nil {
		return err
	}
	seen := make(map[PolicyExclusion]bool, len(a.PolicyExclusions))
	bodyEntry := map[*record.Message]bool{}
	for _, exclusion := range a.PolicyExclusions {
		e, exists := exchanges[exclusion.Exchange]
		if !exists || seen[exclusion] {
			return errors.New("invalid policy exclusion identity")
		}
		seen[exclusion] = true
		var m *record.Message
		switch exclusion.Message {
		case "request":
			m = e.Request.Message
		case "response":
			m = e.Response.Message
		default:
			return errors.New("invalid policy exclusion message")
		}
		if a.Version == ArtifactVersion1 {
			if exclusion.Field != "" || exclusion.Disposition != "" || !lowerFieldName(exclusion.Name) {
				return errors.New("invalid policy exclusion identity")
			}
			if err := absentHeader(m, exclusion.Section, exclusion.Name); err != nil {
				return err
			}
			continue
		}
		body, err := versionTwoExclusion(exclusion, m)
		if err != nil {
			return err
		}
		bodyEntry[m] = bodyEntry[m] || body
	}
	for _, e := range r.Exchanges {
		for _, m := range []*record.Message{e.Request.Message, e.Response.Message} {
			if m.Structure.State == record.StructureRemoved && (a.Version == ArtifactVersion1 || !bodyEntry[m]) {
				return errors.New("removed body structure without removal evidence")
			}
		}
	}
	return nil
}

// absentHeader is that a removed header is not also present in its section.
func absentHeader(m *record.Message, section, name string) error {
	var fields []record.Field
	switch section {
	case "headers":
		fields = m.Headers
	case "trailers":
		fields = m.Trailers
	default:
		return errors.New("invalid policy exclusion section")
	}
	for _, field := range fields {
		if strings.EqualFold(field.Name, name) {
			return errors.New("excluded field also present in retained message")
		}
	}
	return nil
}

// versionTwoExclusion checks one entry against the message it names, and
// reports whether it is a whole-body removal.
func versionTwoExclusion(exclusion PolicyExclusion, m *record.Message) (bool, error) {
	field, err := config.ParseExclusionField(exclusion.Field)
	if err != nil || exclusion.Name != "" {
		return false, errors.New("invalid policy exclusion field")
	}
	if (field.Kind == config.HeaderFieldPrefix) != (exclusion.Section != "") {
		return false, errors.New("invalid policy exclusion section")
	}
	want := DispositionRemoved
	switch field.Kind {
	case config.BodyField:
		if exclusion.Disposition == DispositionRemovedUndecidable {
			want = DispositionRemovedUndecidable
		}
		if m.Body.Kept != "" || m.Structure.State != record.StructureRemoved {
			return false, errors.New("removed body evidence contradicts the retained body")
		}
	case config.BodyValuesField:
		want = DispositionValuesRemoved
		if m.Body.Kept != "" || (m.Structure.State != record.StructureDerived && m.Structure.State != record.StructureRemoved) {
			return false, errors.New("removed values evidence contradicts the retained body")
		}
	case config.TargetQueryField, config.QueryFieldPrefix, config.FormFieldPrefix:
		if m.Kind != "request" || (field.Kind == config.TargetQueryField && strings.Contains(m.Target, "?")) {
			return false, errors.New("query or form evidence contradicts its message")
		}
		// A parameter operation that cannot decide a query removes all of it.
		if field.Kind == config.TargetQueryField && exclusion.Disposition == DispositionRemovedUndecidable {
			want = DispositionRemovedUndecidable
		}
	case config.HeaderFieldPrefix:
		if err := absentHeader(m, exclusion.Section, field.Header); err != nil {
			return false, err
		}
	}
	if exclusion.Disposition != want {
		return false, errors.New("invalid policy exclusion disposition")
	}
	return field.Kind == config.BodyField, nil
}

func readableSide(side record.Side, kind string) bool {
	m := side.Message
	if side.State != record.Present || m == nil || m.Kind != kind || !m.Complete || !m.Framed || m.Defect != "none" || m.Body.Encoding != "base64" {
		return false
	}
	if m.Stream.Direction != "sent" && m.Stream.Direction != "received" {
		return false
	}
	start, okStart := decimalOffset(m.Stream.Offset)
	end, okEnd := decimalOffset(m.Stream.End)
	if !okStart || !okEnd || end < start {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(m.Body.Kept)
	return err == nil
}

func validateTruncation(a Artifact) error {
	t := a.ReconstructionTruncation
	if t == nil {
		if a.Reconstruction.Unplaced.Why == "reconstruction_truncated" {
			return errors.New("missing reconstruction truncation evidence")
		}
		return nil
	}
	u := a.Reconstruction.Unplaced
	if t.State != "truncated" || t.Suffix != "indeterminate" || len(t.Stops) == 0 || len(t.Stops) > 2 ||
		u.State != record.Undetermined || u.Unit != record.Bytes || u.Value != "" || u.Why != "reconstruction_truncated" {
		return errors.New("invalid reconstruction truncation state")
	}
	previous := 0
	for _, stop := range t.Stops {
		direction := 0
		switch stop.Direction {
		case "sent":
			direction = 1
		case "received":
			direction = 2
		}
		if direction <= previous {
			return errors.New("invalid reconstruction truncation direction order")
		}
		previous = direction
		offset, okOffset := decimalOffset(stop.Offset)
		evidence, okEvidence := decimalOffset(stop.EvidenceOffset)
		if !okOffset || !okEvidence || evidence < offset {
			return errors.New("invalid reconstruction truncation offsets")
		}
		switch stop.Reason {
		case "capture_hole", "positions_unknown", "incomplete_message", "malformed_message", "ambiguous_framing", "processing_limit", "unsupported_message", "unpaired_exchange", "unparsed_suffix":
		default:
			return errors.New("invalid reconstruction truncation reason")
		}
	}
	return nil
}

func decimalOffset(value string) (uint64, bool) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return n, err == nil
}

func lowerFieldName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}
