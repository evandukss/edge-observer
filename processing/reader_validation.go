package processing

import (
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/extension"
)

// Error text is structural and never includes a value taken from the file.
func validateArtifact(a Artifact) error {
	if a.Version != ArtifactVersion && a.Version != ArtifactVersion2 && a.Version != ArtifactVersion1 {
		return errors.New("unsupported artifact version")
	}
	if a.PolicyRevision == "" || a.Route.Pipeline == "" || a.Route.Sink == "" || a.Route.Kind == "" {
		return errors.New("missing policy revision or route")
	}
	if a.Connection.Record != record.KindConnection || a.Connection.Version != record.Version || a.Connection.ID == "" {
		return errors.New("invalid connection identity or version")
	}
	if a.Version == ArtifactVersion2 {
		if err := validateIDs(a); err != nil {
			return err
		}
		if a.ExtensionOutcomes == nil || a.ReplacementExclusions == nil {
			return errors.New("missing extension outcomes or replacement exclusions")
		}
	}
	if a.Version == ArtifactVersion3 {
		if a.Session == "" || a.ExchangeIDs != nil || a.PolicyExclusions == nil || a.ExtensionOutcomes == nil || a.ReplacementExclusions == nil {
			return errors.New("invalid exchange-line envelope")
		}
		switch a.Record {
		case ArtifactExchange:
			if _, ok := positiveDecimal(a.ExchangeID); !ok || a.Index == nil || *a.Index < 0 || a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 || a.Reconstruction.Exchanges[0].Index != *a.Index || a.ReconstructionTruncation != nil {
				return errors.New("invalid exchange-line identity or population")
			}
		case ArtifactConnection:
			if a.ExchangeID != "" || a.Index != nil || a.Reconstruction != nil {
				return errors.New("exchange content on retirement line")
			}
			if a.ReconstructionTruncation != nil {
				if err := validateRetirementTruncation(a.ReconstructionTruncation); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid approved record kind")
		}
	}
	r := a.Reconstruction
	if r == nil {
		if (a.ReconstructionTruncation != nil && a.Version != ArtifactVersion3) || len(a.PolicyExclusions) != 0 || len(a.ExtensionOutcomes) != 0 ||
			len(a.ReplacementExclusions) != 0 {
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
	if a.Version == ArtifactVersion2 {
		if err := validateCount(a, r); err != nil {
			return err
		}
	}
	owners, err := validateOutcomes(a, exchanges)
	if err != nil {
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
		m, err := excludedMessage(e, exclusion.Message)
		if err != nil {
			return err
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
		// An entry describes the captured content, and is checked against the
		// written content only where no extension's change replaced it.
		body, err := versionTwoExclusion(exclusion, m, owners[ownedBy(exclusion)] == "")
		if err != nil {
			return err
		}
		bodyEntry[m] = bodyEntry[m] || body
	}
	replaced := make(map[ReplacementExclusion]bool, len(a.ReplacementExclusions))
	for _, exclusion := range a.ReplacementExclusions {
		e, exists := exchanges[exclusion.Exchange]
		if !exists || replaced[exclusion] || !changedBy(a, exclusion.Exchange, exclusion.Extension) {
			return errors.New("invalid replacement exclusion identity")
		}
		replaced[exclusion] = true
		m, err := excludedMessage(e, exclusion.Message)
		if err != nil {
			return err
		}
		body, err := versionTwoExclusion(exclusion.PolicyExclusion, m,
			owners[ownedBy(exclusion.PolicyExclusion)] == exclusion.Extension)
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

func excludedMessage(e record.Exchange, message string) (*record.Message, error) {
	switch message {
	case "request":
		return e.Request.Message, nil
	case "response":
		return e.Response.Message, nil
	}
	return nil, errors.New("invalid policy exclusion message")
}

// component is one replaceable part of one exchange.
type component struct {
	exchange int
	field    string
}

func ownedBy(e PolicyExclusion) component {
	return component{exchange: e.Exchange, field: fieldOfRemoval(e)}
}

// validateIDs is a version 2 line's id range: decimal strings, the count the
// range holds, and no first or last where nothing was issued.
func validateIDs(a Artifact) error {
	ids := a.ExchangeIDs
	if ids == nil {
		return errors.New("missing exchange id range")
	}
	count, ok := decimalOffset(ids.Count)
	if !ok {
		return errors.New("invalid exchange id range")
	}
	if count == 0 {
		if ids.First != "" || ids.Last != "" {
			return errors.New("invalid exchange id range")
		}
		return nil
	}
	first, ok1 := positiveDecimal(ids.First)
	last, ok2 := positiveDecimal(ids.Last)
	if !ok1 || !ok2 || last < first || last-first+1 != count {
		return errors.New("invalid exchange id range")
	}
	return nil
}

// validateCount is every retained exchange's index within the line's range.
func validateCount(a Artifact, r *record.Reconstruction) error {
	count, _ := decimalOffset(a.ExchangeIDs.Count)
	for _, e := range r.Exchanges {
		if uint64(e.Index) >= count {
			return errors.New("retained exchange outside the exchange id range")
		}
	}
	return nil
}

func positiveDecimal(value string) (uint64, bool) {
	n, ok := decimalOffset(value)
	return n, ok && n > 0 && value[0] != '0'
}

// The fields an extension's change can replace.
var replaceable = []string{config.FieldRequestLine, config.FieldRequestHeaders, config.FieldRequestBody,
	config.FieldResponseLine, config.FieldResponseHeaders, config.FieldResponseBody}

// validateOutcomes checks every extension outcome and returns which extension
// owns each component's written content: the one whose change of it no later
// extension overwrote. A component no extension owns is the captured content.
func validateOutcomes(a Artifact, exchanges map[int]record.Exchange) (map[component]string, error) {
	owners := map[component]string{}
	type ran struct {
		exchange  int
		extension string
	}
	once := map[ran]bool{}
	for _, o := range a.ExtensionOutcomes {
		key := ran{exchange: o.Exchange, extension: o.Extension}
		if _, exists := exchanges[o.Exchange]; !exists || once[key] || !config.ExtensionName.MatchString(o.Extension) {
			return nil, errors.New("invalid extension outcome identity")
		}
		once[key] = true
		switch o.Outcome {
		case extension.Unchanged:
			if o.Changed != nil || o.Overwritten != nil || o.Reason != "" {
				return nil, errors.New("invalid unchanged extension outcome")
			}
		case extension.Failed:
			if o.Changed != nil || o.Overwritten != nil || !slices.Contains(failureReasons, o.Reason) {
				return nil, errors.New("invalid failed extension outcome")
			}
		case extension.Changed:
			if o.Changed == nil || o.Overwritten == nil || len(o.Changed) == 0 || o.Reason != "" {
				return nil, errors.New("invalid changed extension outcome")
			}
			for _, field := range o.Changed {
				if !slices.Contains(replaceable, field) || repeated(o.Changed, field) {
					return nil, errors.New("invalid changed extension outcome")
				}
				if !slices.Contains(o.Overwritten, field) {
					owners[component{exchange: o.Exchange, field: field}] = o.Extension
				}
			}
			for _, field := range o.Overwritten {
				if !slices.Contains(o.Changed, field) || repeated(o.Overwritten, field) {
					return nil, errors.New("invalid changed extension outcome")
				}
			}
		default:
			return nil, errors.New("invalid extension outcome")
		}
	}
	return owners, nil
}

func repeated(fields []string, field string) bool {
	n := 0
	for _, f := range fields {
		if f == field {
			n++
		}
	}
	return n > 1
}

// failureReasons is every reason a failed outcome can name.
var failureReasons = []string{extension.Timeout, extension.Crash, extension.ProtocolError, extension.OversizedFrame,
	extension.UnknownID, extension.Flood, extension.Malformed, extension.NotGiven, extension.ReadOnly,
	extension.RemovedContent, extension.Excluded, extension.Declined, extension.Unavailable, extension.Busy,
	extension.TooLarge}

// changedBy is whether name's outcome for exchange is changed.
func changedBy(a Artifact, exchange int, name string) bool {
	return slices.ContainsFunc(a.ExtensionOutcomes, func(o ExtensionOutcome) bool {
		return o.Exchange == exchange && o.Extension == name && o.Outcome == extension.Changed
	})
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

// versionTwoExclusion checks one entry's form and, where written is set,
// that the message it names agrees with it, and reports whether it is a
// whole-body removal of the written content.
func versionTwoExclusion(exclusion PolicyExclusion, m *record.Message, written bool) (bool, error) {
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
		if written && (m.Body.Kept != "" || m.Structure.State != record.StructureRemoved) {
			return false, errors.New("removed body evidence contradicts the retained body")
		}
	case config.BodyValuesField:
		want = DispositionValuesRemoved
		if written && (m.Body.Kept != "" || (m.Structure.State != record.StructureDerived && m.Structure.State != record.StructureRemoved)) {
			return false, errors.New("removed values evidence contradicts the retained body")
		}
	case config.TargetQueryField, config.QueryFieldPrefix, config.FormFieldPrefix:
		if m.Kind != "request" || (written && field.Kind == config.TargetQueryField && strings.Contains(m.Target, "?")) {
			return false, errors.New("query or form evidence contradicts its message")
		}
		// A parameter operation that cannot decide a query removes all of it.
		if field.Kind == config.TargetQueryField && exclusion.Disposition == DispositionRemovedUndecidable {
			want = DispositionRemovedUndecidable
		}
	case config.HeaderFieldPrefix:
		if exclusion.Section != "headers" && exclusion.Section != "trailers" {
			return false, errors.New("invalid policy exclusion section")
		}
		if written {
			if err := absentHeader(m, exclusion.Section, field.Header); err != nil {
				return false, err
			}
		}
	}
	if exclusion.Disposition != want {
		return false, errors.New("invalid policy exclusion disposition")
	}
	return written && field.Kind == config.BodyField, nil
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
		case "capture_hole", "positions_unknown", "incomplete_message", "malformed_message", "ambiguous_framing", "processing_limit", "unsupported_message", "unpaired_exchange", "unparsed_suffix", TruncationConnectionCut:
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

func validateRetirementTruncation(t *ReconstructionTruncation) error {
	a := Artifact{Reconstruction: &record.Reconstruction{Unplaced: record.Count{State: record.Undetermined, Unit: record.Bytes, Why: "reconstruction_truncated"}}, ReconstructionTruncation: t}
	return validateTruncation(a)
}
