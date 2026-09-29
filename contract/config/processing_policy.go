package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/contract/policy"
)

const supportedFields = "message.headers.<lowercase exact HTTP name>, message.body, message.body.values, message.target.query, message.query.<name>, message.form.<name> or message.body.json<pointer>"

func compileExclusions(plan *ProcessingPlan) []Finding {
	var failures []Finding
	for di, loaded := range plan.resolved.Policy {
		f := &processingFindings{document: fmt.Sprintf("policy:%d", di)}
		d := loaded.Document
		if len(d.Claims) > 0 || len(d.Approvals) > 0 {
			f.add("policy", UnsupportedForm, "trusted component claims and approvals are not supported by the processing runtime")
		}
		for ri, r := range d.Requirements {
			subject := r.ID
			if subject == "" {
				subject = fmt.Sprintf("requirement:%d.%d", di, ri)
			}
			if r.Operation != "transform_field" {
				f.add(subject, UnsupportedForm, "only mandatory field removal is supported by the processing runtime")
				continue
			}
			if r.Target.Kind != "sink" {
				f.add(subject, UnsupportedTransform, "exclusions require a sink target")
				continue
			}
			transform, _ := r.Parameters["transformation"].(string)
			field, _ := r.Parameters["field"].(string)
			parsed, err := ParseExclusionField(field)
			if transform != "remove" || err != nil {
				detail := "supported form is remove on " + supportedFields
				if err != nil {
					detail += ": " + err.Error()
				}
				f.add(subject, UnsupportedTransform, "%s", detail)
				continue
			}
			parametersOK := true
			for name := range r.Parameters {
				if name != "field" && name != "transformation" && name != "arguments" {
					f.add(subject, InvalidTransformParameters, "parameter %q is not defined for field removal", name)
					parametersOK = false
				}
			}
			if raw, present := r.Parameters["arguments"]; present {
				args, isObject := raw.(map[string]any)
				if !isObject || len(args) != 0 {
					f.add(subject, InvalidTransformParameters, "remove takes no arguments; omit arguments or provide an empty object")
					parametersOK = false
				}
			}
			if !parametersOK {
				continue
			}
			// This field projection is defined by the runtime's field grammar,
			// not a field or capability invented by a pack.
			if !slices.Contains(plan.resolved.Inventory.RecordFields, field) {
				plan.resolved.Inventory.RecordFields = append(plan.resolved.Inventory.RecordFields, field)
			}
			plan.exclusions = append(plan.exclusions, Exclusion{Declaration: r.ID, Field: field, Header: parsed.Header, FailureAction: r.FailureAction})
		}
		failures = append(failures, f.list...)
	}
	if len(failures) > 0 {
		return failures
	}
	decided := policy.Decide(plan.resolved.Policy, plan.resolved.Inventory)
	for _, finding := range decided.Findings {
		if finding.Disposition != policy.Accept {
			failures = append(failures, Finding{Document: "policy", Subject: finding.Declaration, Reason: Reason("policy_" + string(finding.Reason)), Detail: "policy vocabulary refused the declaration: " + string(finding.Reason)})
		}
	}
	if len(failures) > 0 {
		return failures
	}
	for _, route := range plan.routes {
		p := plan.resolved.Pipelines[slices.IndexFunc(plan.resolved.Pipelines, func(p EffectivePipeline) bool { return p.Name == route.Pipeline })]
		if p.Input != "reconstruction" {
			continue
		}
		subject := "route:" + route.Pipeline + "->" + route.Sink
		for _, exclusion := range plan.exclusions {
			// Validated above, so this parse cannot fail.
			field, _ := ParseExclusionField(exclusion.Field)
			covered := map[string]bool{}
			for _, slot := range p.Slots {
				messages := covers(slot, field)
				if len(messages) == 0 {
					continue
				}
				for _, m := range messages {
					covered[m] = true
				}
				// Every slot counted towards the removal must honour the
				// requirement: an earlier drop cannot silently replace a
				// required pipeline stop.
				if slot.OnFailure != exclusion.FailureAction {
					failures = append(failures, Finding{
						Document: p.DeclaredBy, Subject: subject,
						Reason: ExclusionFailureActionMismatch,
						Detail: fmt.Sprintf("requirement %s requires %s on removal failure; slot %s selects %s", exclusion.Declaration, exclusion.FailureAction, slot.Name, slot.OnFailure),
					})
				}
			}
			var uncovered []string
			for _, m := range fieldMessages(field) {
				if !covered[m] {
					uncovered = append(uncovered, m)
				}
			}
			if len(uncovered) == 0 {
				continue
			}
			detail := fmt.Sprintf("requirement %s requires removal of header %s on every durable reconstruction route", exclusion.Declaration, exclusion.Header)
			if field.Kind != HeaderFieldPrefix {
				detail = fmt.Sprintf("requirement %s requires removal of %s on every durable reconstruction route; nothing on this route removes it from the %s", exclusion.Declaration, exclusion.Field, strings.Join(uncovered, " or the "))
			}
			failures = append(failures, Finding{Document: p.DeclaredBy, Subject: subject, Reason: ExclusionNotEnforced, Detail: detail})
		}
	}
	return failures
}

// fieldMessages is the messages an exclusion field reaches. A header field is
// removed from both messages by one remove-headers slot, so its coverage is
// counted once, as the request.
func fieldMessages(field ExclusionField) []string {
	switch field.Kind {
	case HeaderFieldPrefix, TargetQueryField, QueryFieldPrefix, FormFieldPrefix:
		return []string{MessageRequest}
	}
	return []string{MessageRequest, MessageResponse}
}

// covers is the messages for which one slot satisfies an exclusion field.
// Replacement and truncation satisfy nothing.
func covers(slot EffectiveSlot, field ExclusionField) []string {
	a := slot.Arguments
	if a == nil {
		return nil
	}
	switch field.Kind {
	case HeaderFieldPrefix:
		if slot.Implementation == RemoveHeaders && slices.Contains(a.Headers, field.Header) {
			return []string{MessageRequest}
		}
	case BodyField:
		if slot.Implementation == RemoveBody {
			return a.Messages
		}
	case BodyValuesField:
		if slot.Implementation == RemoveBody || slot.Implementation == ReduceBodyToStructure {
			return a.Messages
		}
	case FormFieldPrefix:
		// Not reduce-body-to-structure: it keeps member names, and a JSON
		// member name can carry a form parameter, as in {"&card_number=4111":1}.
		if (slot.Implementation == RemoveBody && slices.Contains(a.Messages, MessageRequest)) ||
			(slot.Implementation == RemoveFormFields && slices.Contains(a.Names, field.Name)) {
			return []string{MessageRequest}
		}
	case TargetQueryField:
		if slot.Implementation == RemoveQuery {
			return []string{MessageRequest}
		}
	case QueryFieldPrefix:
		if slot.Implementation == RemoveQuery || (slot.Implementation == RemoveQueryParameters && slices.Contains(a.Names, field.Name)) {
			return []string{MessageRequest}
		}
	case JSONFieldPrefix:
		if slot.Implementation == RemoveBody || slot.Implementation == ReduceBodyToStructure {
			return a.Messages
		}
		if slot.Implementation == RemoveJSONFields {
			want := PointerTokens(field.Pointer)
			for _, pointer := range a.Pointers {
				if tokens := PointerTokens(pointer); len(tokens) <= len(want) && slices.Equal(tokens, want[:len(tokens)]) {
					return a.Messages
				}
			}
		}
	}
	return nil
}
