package account

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	observed "github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/connection"
)

// represented is every fact the operational account holds, by JSON path, and
// where the account carries it ([] for array positions, * for map keys): a
// contract path or the reason it is not carried.
var represented = map[string]string{
	".version": "account", ".kind": "moment", ".session": "session", ".at": "at.value",
	".policy.revision":   "provenance.configuration.references[].revision",
	".policy.generation": "provenance.configuration.references[].generation",

	".floor.published": "provenance.observer.floor.published", ".floor.proved": "provenance.observer.floor.proved",
	".floor.established":     "provenance.observer.floor.established",
	".floor.would_establish": "provenance.observer.floor.would_establish",

	".targets[].number": "scope.targets[].number", ".targets[].name": "scope.targets[].name",
	".targets[].mode":                 "scope.targets[].mode",
	".targets[].answers.existing":     "scope.targets[].descendants.existing",
	".targets[].answers.future":       "scope.targets[].descendants.future",
	".targets[].answers.boundary":     "scope.targets[].descendants.boundary",
	".targets[].answers.root_exit":    "scope.targets[].descendants.root_exit",
	".targets[].answers.replacement":  "scope.targets[].descendants.replacement",
	".targets[].unresolved":           "scope.targets[].resolution.why",
	".targets[].cgroup.path":          "scope.targets[].cgroups[].path",
	".targets[].cgroup.inode":         "scope.targets[].cgroups[].inode.value",
	".targets[].cgroup.why":           "scope.targets[].cgroups[].why",
	".targets[].listeners[].address":  "scope.targets[].listeners[].address",
	".targets[].listeners[].owners[]": "scope.targets[].listeners[].owners[]",
	".targets[].unsupported[].reason": "scope.targets[].unsupported[].reason",
	".exclusions[].number":            "scope.exclusions[].number",
	".limits[]":                       "scope.limits[]",

	".processes[].PID":                    "scope.placement.processes[].pid",
	".processes[].StartTime":              "scope.placement.processes[].birth.value",
	".processes[].Runtime":                "scope.placement.processes[].runtime",
	".processes[].Requested":              "scope.placement.processes[].requested",
	".processes[].Confirmed":              "scope.placement.processes[].confirmed",
	".processes[].Placements[].symbol":    "scope.placement.processes[].probes[].symbol",
	".processes[].Placements[].path":      "scope.placement.processes[].probes[].path",
	".processes[].Placements[].offset":    "scope.placement.processes[].probes[].offset",
	".processes[].Placements[].confirmed": "scope.placement.processes[].probes[].confirmed",
	".processes[].Placements[].through":   "scope.placement.processes[].probes[].through",
	".processes[].Placements[].refusal":   "scope.placement.processes[].probes[].refusal",
	".processes[].Unattempted[]":          "scope.placement.processes[].unattempted[]",
	".processes[].Uncatalogued[]":         "scope.placement.processes[].uncatalogued[]",
	".processes[].Absent[]":               "scope.placement.processes[].absent[]",
	".processes[].Outcome":                "scope.placement.processes[].outcome",
	".processes[].Reason":                 "scope.placement.processes[].reason",
	".processes[].Namespace.Device":       "scope.placement.processes[].pid_namespace.device",
	".processes[].Namespace.Inode":        "scope.placement.processes[].pid_namespace.inode",
	".processes[].Mode":                   "scope.placement.processes[].mode",

	".capturing": "capture.capability.sentence",

	".seen.transfers": "capture.seen.transfers", ".seen.unmeasured": "capture.seen.unmeasured",
	".seen.empty": "capture.seen.empty", ".seen.records": "capture.seen.records",
	".seen.connections": "capture.seen.connections", ".seen.closed": "capture.seen.closed",
	".seen.early": "capture.seen.early", ".seen.rejected": "capture.seen.rejected",
	".seen.unattributed": "capture.seen.unattributed", ".seen.endings_unmatched": "capture.seen.endings_unmatched",
	".seen.connections_unrecorded": "capture.seen.connections_unrecorded",
	".seen.disordered":             "capture.ordering.disordered", ".seen.unstamped": "capture.ordering.unstamped",
	".seen.tolerated": "capture.ordering.tolerated", ".seen.lost": "capture.ordering.lost",
	".seen.interrupted": "capture.ordering.retired", ".seen.unexplained": "capture.ordering.unexplained",

	".loss.known": "capture.loss.state", ".loss.why": "capture.loss.why",
	".loss.dropped": "capture.loss.dropped", ".loss.unmatched": "capture.loss.unmatched",
	".loss.when.first": "capture.loss.occasion.first.value", ".loss.when.last": "capture.loss.occasion.last.value",
	".loss.when.handle": "capture.loss.occasion.handle.value", ".loss.when.pid": "capture.loss.occasion.pid.value",
	".loss.when.tid":  "capture.loss.occasion.tid.value",
	".admitted.known": "capture.admitted.state", ".admitted.why": "capture.admitted.why",
	".admitted.descendants": "capture.admitted.descendants",

	".admissions.rule": "scope.coverage.rule", ".admissions.covered": "scope.coverage.covered",
	".admissions.by_target[].target":  "scope.coverage.by_target[].target",
	".admissions.by_target[].covered": "scope.coverage.by_target[].covered",
	".admissions.by_target[].ended":   "scope.coverage.by_target[].ended",
	".admissions.by_target[].unknown": "scope.coverage.by_target[].unknown",
	".admissions.unavailable":         "scope.coverage.why",

	".refused.known": "capture.refused.state", ".refused.why": "capture.refused.why",
	".refused.reasons.*": "capture.refused.reasons.*",

	".spool.written": "capture.spool.written", ".spool.dropped": "capture.spool.dropped",
	".spool.refused": "capture.spool.refused", ".spool.connections": "capture.spool.connections",
	".spool.connections_dropped": "capture.spool.connections_dropped",
	".spool.connections_refused": "capture.spool.connections_refused",
	".spool.bytes":               "capture.spool.bytes", ".spool.limit": "capture.spool.limit",

	".seal.stopped": "seal.stopped.value", ".seal.sealed": "seal.sealed.value",
	".seal.withdrawal.at": "seal.withdrawal.at.value", ".seal.withdrawal.instances": "seal.withdrawal.instances",
	".seal.withdrawal.complete": "seal.withdrawal.complete", ".seal.withdrawal.because": "seal.withdrawal.because",
	".seal.drain.delivered.value": "seal.drain.delivered.value", ".seal.drain.delivered.known": "seal.drain.delivered.state",
	".seal.drain.delivered.why":     "seal.drain.delivered.why",
	".seal.drain.outstanding.value": "seal.drain.outstanding.value",
	".seal.drain.outstanding.known": "seal.drain.outstanding.state",
	".seal.drain.outstanding.why":   "seal.drain.outstanding.why",
	".seal.drain.complete":          "seal.drain.complete", ".seal.drain.because": "seal.drain.because",
	".seal.counters.*.value": "seal.counters.*.value", ".seal.counters.*.known": "seal.counters.*.state",
	".seal.counters.*.why":    "seal.counters.*.why",
	".seal.interrupted.value": "seal.interrupted.value", ".seal.interrupted.known": "seal.interrupted.state",
	".seal.interrupted.why": "seal.interrupted.why",
	".seal.complete":        "seal.complete", ".seal.because[]": "seal.because[]",
	".seal_error": "seal.why",
}

// Facts that recur at several places in the operational account, written once:
// every instance, and every capability.
func init() {
	instances := map[string]string{
		".targets[].roots[]":                    "scope.targets[].roots[]",
		".targets[].descendants[]":              "scope.targets[].existing_descendants[]",
		".targets[].denied[]":                   "scope.targets[].denied[]",
		".targets[].unsupported[].instance":     "scope.targets[].unsupported[].instance",
		".exclusions[].roots[]":                 "scope.exclusions[].roots[]",
		".exclusions[].denied[]":                "scope.exclusions[].denied[]",
		".admissions.coverage_ended[].instance": "scope.coverage.coverage_ended[].instance",
		".admissions.grant_unknown[].instance":  "scope.coverage.grant_unknown[].instance",
	}
	for from, into := range instances {
		represented[from+".pid"] = into + ".pid"
		represented[from+".namespace"] = into + ".pid_namespace.inode"
		represented[from+".namespace_pid"] = into + ".namespace_pid"
		represented[from+".start"] = into + ".birth.value"
		represented[from+".executable"] = into + ".executable.value"
	}
	for _, list := range []string{"coverage_ended", "grant_unknown"} {
		from, into := ".admissions."+list+"[]", "scope.coverage."+list+"[]"
		represented[from+".target"] = into + ".target"
		represented[from+".inherited"] = into + ".inherited"
		represented[from+".no_later_than"] = into + ".no_later_than.value"
		represented[from+".read.from"] = into + ".read_from.value"
		represented[from+".read.to"] = into + ".read_to.value"
		represented[from+".why"] = into + ".why"
	}
	capabilities := map[string]string{
		".build":                  "provenance.observer",
		".capability":             "capture.capability",
		".processes[].Capability": "scope.placement.processes[].capability",
	}
	for from, into := range capabilities {
		for _, name := range []string{"backend", "program", "minimum_kernel", "payload", "filtered", "descendants",
			"lifecycle", "binding", "socket_evidence", "ipv6"} {
			represented[from+"."+name] = into + "." + name
		}
		represented[from+".unobserved[]"] = into + ".unobserved[]"
		represented[from+".withheld[].claim"] = into + ".withheld[].claim"
		represented[from+".withheld[].member"] = into + ".withheld[].member"
		represented[from+".withheld[].reason"] = into + ".withheld[].reason"
	}
}

// fill sets every exported field of v to a non-zero value, booleans to truth,
// from the type, so a new field is covered automatically.
func fill(v reflect.Value, truth bool) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem(), truth)
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[time.Time]() {
			v.Set(reflect.ValueOf(time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)))
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i), truth)
			}
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fill(v.Index(0), truth)
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		element := reflect.New(v.Type().Elem()).Elem()
		fill(element, truth)
		key := reflect.New(v.Type().Key()).Elem()
		fill(key, truth)
		v.SetMapIndex(key, element)
	case reflect.Bool:
		v.SetBool(truth)
	case reflect.String:
		v.SetString("7")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v.SetUint(7)
	}
}

// filled is a sealed operational account holding every fact. With truth false,
// every fallible reading has failed and carries its reason.
func filled(t *testing.T, truth bool) observed.Account {
	t.Helper()
	var a observed.Account
	fill(reflect.ValueOf(&a).Elem(), truth)
	a.Version, a.Kind = observed.Version, observed.Sealed
	for _, target := range a.Targets {
		for _, list := range [][]observed.Instance{target.Roots, target.Descendants, target.Denied} {
			for i := range list {
				list[i].Namespace = "7:7"
			}
		}
		for i := range target.Unsupported {
			target.Unsupported[i].Instance.Namespace = "7:7"
		}
	}
	for _, one := range a.Exclusions {
		for _, list := range [][]observed.Instance{one.Roots, one.Denied} {
			for i := range list {
				list[i].Namespace = "7:7"
			}
		}
	}
	for _, list := range [][]observed.Admission{a.Admissions.CoverageEnded, a.Admissions.GrantUnknown} {
		for i := range list {
			list[i].Instance.Namespace = "7:7"
		}
	}
	if truth {
		a.Admissions.Unavailable, a.SealError = "", ""
		a.Targets[0].Unresolved = ""
	} else {
		a.Seal = nil
	}
	return a
}

// leaves is every path in a JSON document that holds a value, with array
// positions written [] and the members of the two open maps written *.
func leaves(t *testing.T, document any, open ...string) map[string]bool {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	var walk func(value any, at string)
	walk = func(value any, at string) {
		switch typed := value.(type) {
		case map[string]any:
			if slices.Contains(open, at) {
				for _, member := range typed {
					walk(member, at+".*")
				}
				return
			}
			for key, member := range typed {
				walk(member, at+"."+key)
			}
		case []any:
			for _, element := range typed {
				walk(element, at+"[]")
			}
		case nil:
		case string:
			if typed != "" {
				found[at] = true
			}
		default:
			found[at] = true
		}
	}
	walk(decoded, "")
	return found
}

func TestEveryFactTheOperationalAccountHoldsIsCarried(t *testing.T) {
	source := map[string]bool{}
	carried := map[string]bool{}
	for _, truth := range []bool{true, false} {
		account := filled(t, truth)
		for leaf := range leaves(t, account, ".refused.reasons", ".seal.counters") {
			source[leaf] = true
		}
		projected, err := Project(account, Supplied(Records{}))
		if err != nil {
			t.Fatalf("projecting the filled account (truth %v): %v", truth, err)
		}
		for leaf := range leaves(t, projected, ".capture.refused.reasons", ".seal.counters") {
			carried[strings.TrimPrefix(leaf, ".")] = true
		}
	}

	// Presence first: a short listing would pass having compared nothing.
	if len(source) < 150 {
		t.Fatalf("wiring, not the property: the filled operational account holds %d facts, too few to be the "+
			"account, so nothing below measured anything", len(source))
	}

	for _, leaf := range slices.Sorted(func(yield func(string) bool) {
		for leaf := range source {
			if !yield(leaf) {
				return
			}
		}
	}) {
		into, listed := represented[leaf]
		switch {
		case !listed:
			t.Errorf("the operational account holds %s and nothing says where the account carries it", leaf)
		case !carried[into]:
			t.Errorf("the operational account holds %s, said to be carried at %s, and the projection holds nothing there",
				leaf, into)
		}
	}
	for leaf := range represented {
		if !source[leaf] {
			t.Errorf("%s is listed and the operational account holds no such fact", leaf)
		}
	}
}

// Counters are carried by name, each checked individually rather than through
// a wildcard.
func TestEverySealCounterIsCarriedByName(t *testing.T) {
	var counters connection.Counters
	fill(reflect.ValueOf(&counters).Elem(), true)
	encoded, err := json.Marshal(counters)
	if err != nil {
		t.Fatal(err)
	}
	var names map[string]any
	if err := json.Unmarshal(encoded, &names); err != nil {
		t.Fatal(err)
	}
	carried := countersOf(counters)
	if len(names) < 20 {
		t.Fatalf("wiring, not the property: the seal's counters encode %d names, too few to be the type", len(names))
	}
	for name := range names {
		if count, found := carried[name]; !found || count.State != "determined" || count.Value != "7" {
			t.Errorf("the seal counter %s is carried as %+v (found %v)", name, count, found)
		}
	}
	if len(carried) != len(names) {
		t.Errorf("the seal holds %d counters and %d are carried", len(names), len(carried))
	}
}

// An unreadable seal count is carried as undetermined with its reason, never
// as zero.
func TestAnUnreadSealCountIsUndeterminedAndNotZero(t *testing.T) {
	count := countOf(connection.Uncounted("the counter map could not be read"), "calls")
	if count.State != "undetermined" || count.Value != "" || count.Why == "" {
		t.Fatalf("an unread count projected as %+v", count)
	}
}
