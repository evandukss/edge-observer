package account

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/evandukss/edge-observer/contract/record"
)

// coverageOf is every instance a scope names, with its coverage read off the
// scope's own targets, exclusions and placement.
//
// An instance is joined to a placement by pid and pid namespace, the members
// both carry at operational account version 1. Where no placement matches, or
// more than one does, the coverage is undetermined: no placement is not a
// placement saying the instance was not attached.
func coverageOf(scope Scope) Instances {
	type entry struct {
		covered InstanceCoverage
		// selection and exclusion are the references naming the instance in
		// the targets and in the exclusions.
		selection, exclusion, unsupported []string
		reason                            string
	}
	var order []string
	entries := map[string]*entry{}
	at := func(instance Instance) *entry {
		key, _ := json.Marshal(instance)
		found, seen := entries[string(key)]
		if !seen {
			found = &entry{covered: InstanceCoverage{Instance: instance, SelectedBy: []string{}, ExcludedBy: []string{},
				Evidence: []string{}}}
			entries[string(key)] = found
			order = append(order, string(key))
		}
		return found
	}
	addOnce := func(list []string, value string) []string {
		if slices.Contains(list, value) {
			return list
		}
		return append(list, value)
	}

	for t, target := range scope.Targets {
		for _, list := range []struct {
			name      string
			instances []Instance
		}{{"roots", target.Roots}, {"existing_descendants", target.Existing}} {
			for i, instance := range list.instances {
				one := at(instance)
				one.covered.SelectedBy = addOnce(one.covered.SelectedBy, target.Name)
				one.selection = append(one.selection, fmt.Sprintf("account:scope.targets[%d].%s[%d]", t, list.name, i))
			}
		}
		for i, instance := range target.Denied {
			one := at(instance)
			one.covered.ExcludedBy = addOnce(one.covered.ExcludedBy, "target:"+target.Name)
			one.exclusion = append(one.exclusion, fmt.Sprintf("account:scope.targets[%d].denied[%d]", t, i))
		}
		for i, unsupported := range target.Unsupported {
			one := at(unsupported.Instance)
			one.covered.SelectedBy = addOnce(one.covered.SelectedBy, target.Name)
			one.unsupported = append(one.unsupported, fmt.Sprintf("account:scope.targets[%d].unsupported[%d]", t, i))
			one.reason = unsupported.Reason
		}
	}
	for e, exclusion := range scope.Exclusions {
		for _, list := range []struct {
			name      string
			instances []Instance
		}{{"roots", exclusion.Roots}, {"denied", exclusion.Denied}} {
			for i, instance := range list.instances {
				one := at(instance)
				one.covered.ExcludedBy = addOnce(one.covered.ExcludedBy, fmt.Sprintf("exclusion:%d", exclusion.Number))
				one.exclusion = append(one.exclusion, fmt.Sprintf("account:scope.exclusions[%d].%s[%d]", e, list.name, i))
			}
		}
	}

	out := Instances{Block: Block{State: Carried}, Instances: []InstanceCoverage{}}
	for _, key := range order {
		one := entries[key]
		covered := one.covered
		covered.MultiplySelected = len(covered.SelectedBy) > 1
		switch {
		case len(one.exclusion) > 0:
			covered.Coverage = Excluded
			covered.Evidence = one.exclusion
		case len(one.unsupported) > 0:
			covered.Coverage = NotCovered
			covered.Why = "no adapter can observe it: " + one.reason
			covered.Evidence = one.unsupported
		case scope.Placement.State != Carried:
			covered.Coverage = CoverageUndetermined
			covered.Why = fmt.Sprintf("placement is %s, so nothing says whether it was attached", scope.Placement.State)
		default:
			covered = placed(covered, one.selection, scope.Placement.Processes)
		}
		out.Instances = append(out.Instances, covered)
	}
	return out
}

// placed is a selected instance's coverage, from the one placement that names
// it.
func placed(covered InstanceCoverage, selection []string, processes []Placed) InstanceCoverage {
	var matches []int
	for index, process := range processes {
		if process.PID == covered.Instance.PID && samePidNamespace(process.PidNamespace, covered.Instance) {
			matches = append(matches, index)
		}
	}
	switch len(matches) {
	case 0:
		covered.Coverage = CoverageUndetermined
		covered.Why = "no placement names this instance"
		return covered
	case 1:
	default:
		covered.Coverage = CoverageUndetermined
		covered.Why = fmt.Sprintf("%d placements could be this instance", len(matches))
		return covered
	}
	process := processes[matches[0]]
	covered.Evidence = append(slices.Clone(selection), fmt.Sprintf("account:scope.placement.processes[%d]", matches[0]))
	switch {
	case process.Outcome != "attached":
		covered.Coverage = NotCovered
		covered.Why = fmt.Sprintf("its attachment is %s: %s", process.Outcome, process.Reason)
	case process.Confirmed < process.Requested:
		covered.Coverage = PartiallyCovered
		covered.Why = fmt.Sprintf("%d of the %d probes it was asked for are placed", process.Confirmed, process.Requested)
	default:
		covered.Coverage = Covered
	}
	return covered
}

// samePidNamespace is two determined pid namespaces naming one nsfs entry. An
// undetermined one matches nothing, so an instance whose namespace was not read
// is never joined to a placement by its pid alone.
func samePidNamespace(namespace record.Namespace, instance Instance) bool {
	other := instance.PidNamespace
	return namespace.State == record.Determined && other.State == record.Determined &&
		namespace.Device == other.Device && namespace.Inode == other.Inode
}
