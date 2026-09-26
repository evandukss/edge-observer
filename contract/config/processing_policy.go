package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/contract/policy"
)

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
				f.add(subject, UnsupportedForm, "only mandatory header removal is supported by the processing runtime")
				continue
			}
			if r.Target.Kind != "sink" {
				f.add(subject, UnsupportedTransform, "header exclusions require a sink target")
				continue
			}
			transform, _ := r.Parameters["transformation"].(string)
			field, _ := r.Parameters["field"].(string)
			header, ok := strings.CutPrefix(field, "message.headers.")
			if transform != "remove" || !ok || !headerName(header) || strings.ToLower(header) != header {
				f.add(subject, UnsupportedTransform, "supported form is remove on message.headers.<lowercase exact HTTP name>")
				continue
			}
			parametersOK := true
			for name := range r.Parameters {
				if name != "field" && name != "transformation" && name != "arguments" {
					f.add(subject, InvalidTransformParameters, "parameter %q is not defined for header removal", name)
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
			// This field projection is defined by the runtime's exact-name grammar,
			// not a field or capability invented by a pack.
			if !slices.Contains(plan.resolved.Inventory.RecordFields, field) {
				plan.resolved.Inventory.RecordFields = append(plan.resolved.Inventory.RecordFields, field)
			}
			plan.exclusions = append(plan.exclusions, Exclusion{Declaration: r.ID, Field: field, Header: header, FailureAction: r.FailureAction})
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
		for _, exclusion := range plan.exclusions {
			enforced := false
			for _, slot := range p.Slots {
				if slot.Implementation != RemoveHeaders || slot.Arguments == nil || !slices.Contains(slot.Arguments.Headers, exclusion.Header) {
					continue
				}
				enforced = true
				// Every removal of this field must honour the requirement: an
				// earlier drop cannot silently replace a required pipeline stop.
				if slot.OnFailure != exclusion.FailureAction {
					failures = append(failures, Finding{
						Document: p.DeclaredBy, Subject: "route:" + route.Pipeline + "->" + route.Sink,
						Reason: ExclusionFailureActionMismatch,
						Detail: fmt.Sprintf("requirement %s requires %s on removal failure; slot %s selects %s", exclusion.Declaration, exclusion.FailureAction, slot.Name, slot.OnFailure),
					})
				}
			}
			if !enforced {
				failures = append(failures, Finding{Document: p.DeclaredBy, Subject: "route:" + route.Pipeline + "->" + route.Sink, Reason: ExclusionNotEnforced, Detail: fmt.Sprintf("requirement %s requires removal of header %s on every durable reconstruction route", exclusion.Declaration, exclusion.Header)})
			}
		}
	}
	return failures
}
