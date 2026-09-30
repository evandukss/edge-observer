package account

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
)

// The files a conformance tree holds beside its bundle. The acceptance
// documents are read from ConformanceAcceptance inside the tree, by the names in
// AcceptanceDocuments.
const (
	ConformanceBundle        = "bundle"
	ConformanceConfiguration = "configuration.json"
	ConformanceAcceptance    = "acceptance"
)

// AcceptanceDocuments are the acceptance specification's documents whose
// evidence references the agreement check resolves.
var AcceptanceDocuments = []string{"ACCEPTANCE.md", "ROWS.md", "QUESTIONS.md"}

// Agreement reasons: a conformance tree whose contracts do not line up.
const (
	// BundleNotValidated is a conformance bundle that did not validate.
	BundleNotValidated Reason = "bundle_not_validated"
	// ConfigurationNotReferenced is an account that does not reference the
	// configuration beside it by that configuration's digest.
	ConfigurationNotReferenced Reason = "configuration_not_referenced"
	// VersionDisagrees is a contract version one document names that another
	// does not use.
	VersionDisagrees Reason = "version_disagrees"
	// RecordReferenceUnresolved is a record naming a connection the bundle holds
	// no record of.
	RecordReferenceUnresolved Reason = "record_reference_unresolved"
	// ConfigurationRefused is a configuration the configuration reader
	// (contract/config) refuses.
	ConfigurationRefused Reason = "configuration_refused"
	// AcceptanceReferenceUnresolved is an evidence reference the acceptance
	// specification documents that does not resolve against the conformance
	// bundle, or is not in a reference form at all.
	AcceptanceReferenceUnresolved Reason = "acceptance_reference_unresolved"
)

// AgreementOutcome is where an agreement check ended. A check that cannot run
// on its input reports a finding against it, so Agree never stands over
// something unchecked.
type AgreementOutcome string

const (
	// Agree is every check run and every one agreeing.
	Agree AgreementOutcome = "agree"
	// Disagree is a check that found contracts not lining up.
	Disagree AgreementOutcome = "disagree"
)

// Agreement is one agreement check's outcome: what it checked, what disagreed,
// and how many evidence references each acceptance document yielded.
type Agreement struct {
	Outcome    AgreementOutcome `json:"outcome"`
	Checked    []string         `json:"checked"`
	Findings   []Finding        `json:"findings"`
	References map[string]int   `json:"references"`
}

// CheckAgreement reads a conformance tree - a bundle, the configuration its
// session ran under, and the acceptance specification's documents - and checks
// that the record, account, configuration and acceptance contracts line up
// across it (ACCOUNT.md, Agreement across the contracts).
func CheckAgreement(tree fs.FS, options Options) Agreement {
	a := &agreement{tree: tree, result: Agreement{Outcome: Disagree, Checked: []string{}, Findings: []Finding{},
		References: map[string]int{}}}
	a.run(options)
	if len(a.result.Findings) == 0 {
		a.result.Outcome = Agree
	}
	return a.result
}

type agreement struct {
	tree          fs.FS
	result        Agreement
	account       Account
	configuration []byte
}

func (a *agreement) find(member, at string, reason Reason, format string, args ...any) {
	a.result.Findings = append(a.result.Findings, Finding{Member: member, At: at, Reason: reason,
		Detail: fmt.Sprintf(format, args...)})
}

func (a *agreement) run(options Options) {
	bundle, err := fs.Sub(a.tree, ConformanceBundle)
	if err != nil {
		a.find(ConformanceBundle, "", BundleNotValidated, "%v", err)
		return
	}
	validated := Validate(bundle, options)
	a.result.Checked = append(a.result.Checked, "bundle")
	if validated.Outcome == Refused {
		for _, finding := range validated.Findings {
			a.find(ConformanceBundle+"/"+finding.Member, finding.At, BundleNotValidated, "%s: %s", finding.Reason,
				finding.Detail)
		}
		return
	}
	content, _ := fs.ReadFile(bundle, Paths[RoleAccount])
	if err := json.Unmarshal(content, &a.account); err != nil {
		a.find(ConformanceBundle+"/"+Paths[RoleAccount], "", BundleNotValidated, "%v", err)
		return
	}
	if a.configuration, err = fs.ReadFile(a.tree, ConformanceConfiguration); err != nil {
		a.find(ConformanceConfiguration, "", ConfigurationNotReferenced, "%v", err)
		return
	}

	a.references()
	a.versions()
	a.configurationCheck()
	a.records(bundle)
	a.acceptance(bundle)
}

// configurationCheck reads the tree's configuration with the configuration
// reader, as the observer reads it. A configuration that enables packs is
// refused here, since the tree holds none of them.
func (a *agreement) configurationCheck() {
	a.result.Checked = append(a.result.Checked, "configuration")
	_, findings := config.Compile(a.configuration, nil)
	for _, finding := range findings {
		a.find(ConformanceConfiguration, finding.Subject, ConfigurationRefused, "%s %s: %s", finding.Document,
			finding.Reason, finding.Detail)
	}
}

func (a *agreement) references() {
	a.result.Checked = append(a.result.Checked, "configuration_reference")
	want := "sha256:" + digestOf(a.configuration)
	if a.account.Provenance.Configuration.State == Carried {
		for _, reference := range a.account.Provenance.Configuration.References {
			if reference.Document == "configuration" && reference.Revision == want {
				return
			}
		}
	}
	a.find(Paths[RoleAccount], "provenance.configuration", ConfigurationNotReferenced,
		"the account names no configuration at revision %s, which is the configuration beside it", want)
}

func (a *agreement) versions() {
	a.result.Checked = append(a.result.Checked, "versions")
	known := []string{Version, record.Version, config.FileVersion}
	for index, contract := range a.account.Provenance.Contracts {
		if !slices.Contains(known, contract) {
			a.find(Paths[RoleAccount], fmt.Sprintf("provenance.contracts[%d]", index), VersionDisagrees,
				"%q is not a contract version in use: %v", contract, known)
		}
	}
	for _, needed := range []string{Version, record.Version} {
		if !slices.Contains(a.account.Provenance.Contracts, needed) {
			a.find(Paths[RoleAccount], "provenance.contracts", VersionDisagrees,
				"the account's bundle is written at %s and the account does not name it", needed)
		}
	}
	var head struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(a.configuration, &head); err != nil || head.Version != config.FileVersion {
		a.find(ConformanceConfiguration, "version", VersionDisagrees, "%q is not %s", head.Version,
			config.FileVersion)
	}
}

// records checks that every connection an observation or a reconstruction
// names is a connection record in the bundle.
func (a *agreement) records(bundle fs.FS) {
	a.result.Checked = append(a.result.Checked, "record_references")
	type key struct {
		pid int32
		id  string
	}
	connections := map[key]bool{}
	a.each(bundle, Paths[RoleConnections], func(line []byte) {
		var one struct {
			ID      string `json:"id"`
			Process struct {
				PID int32 `json:"pid"`
			} `json:"process"`
		}
		if json.Unmarshal(line, &one) == nil {
			connections[key{one.Process.PID, one.ID}] = true
		}
	})
	if len(connections) == 0 {
		a.find(Paths[RoleConnections], "", RecordReferenceUnresolved, "the bundle holds no connection record to resolve against")
		return
	}
	number := 0
	a.each(bundle, Paths[RoleObservations], func(line []byte) {
		number++
		var one struct {
			Connection string `json:"connection"`
			Process    struct {
				PID int32 `json:"pid"`
			} `json:"process"`
		}
		if json.Unmarshal(line, &one) == nil && !connections[key{one.Process.PID, one.Connection}] {
			a.find(Paths[RoleObservations], fmt.Sprintf("line %d", number), RecordReferenceUnresolved,
				"the observation names connection %s of pid %d, which the bundle holds no record of", one.Connection, one.Process.PID)
		}
	})
	number = 0
	a.each(bundle, Paths[RoleReconstructions], func(line []byte) {
		number++
		var one struct {
			Connection struct {
				ID      string `json:"id"`
				Process struct {
					PID int32 `json:"pid"`
				} `json:"process"`
			} `json:"connection"`
		}
		if json.Unmarshal(line, &one) == nil && !connections[key{one.Connection.Process.PID, one.Connection.ID}] {
			a.find(Paths[RoleReconstructions], fmt.Sprintf("line %d", number), RecordReferenceUnresolved,
				"the reconstruction names connection %s of pid %d, which the bundle holds no record of",
				one.Connection.ID, one.Connection.Process.PID)
		}
	})
}

// each visits every line of a record member. A member it cannot read, or read to
// the end, is a finding against that member: otherwise a failure to read would
// look like a member holding no references, and the check would agree over it.
func (a *agreement) each(tree fs.FS, name string, visit func([]byte)) {
	content, err := fs.ReadFile(tree, name)
	if err != nil {
		a.find(ConformanceBundle+"/"+name, "", RecordReferenceUnresolved,
			"the record member cannot be read, so the references in it are not checked: %v", err)
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
	for scanner.Scan() {
		visit(scanner.Bytes())
	}
	if err := scanner.Err(); err != nil {
		a.find(ConformanceBundle+"/"+name, "", RecordReferenceUnresolved,
			"the record member cannot be read to its end, so the references after that point are not checked: %v", err)
	}
}

var (
	codeSpan    = regexp.MustCompile("`([^`\n]+)`")
	placeholder = regexp.MustCompile(`<[^<>]+>`)
)

// acceptance resolves every evidence reference the acceptance documents write
// against the conformance bundle. An account reference must resolve; a record
// reference names ids only a real run assigns, so here it must only be well
// formed. The guard against reading nothing covers the three documents
// together.
func (a *agreement) acceptance(bundle fs.FS) {
	a.result.Checked = append(a.result.Checked, "acceptance_references")
	total, read := 0, 0
	for _, name := range AcceptanceDocuments {
		member := ConformanceAcceptance + "/" + name
		content, err := fs.ReadFile(a.tree, member)
		if err != nil {
			a.find(member, "", AcceptanceReferenceUnresolved, "the acceptance document cannot be read: %v", err)
			continue
		}
		read++
		count := 0
		for _, match := range codeSpan.FindAllSubmatch(content, -1) {
			span := string(match[1])
			scheme, _, _ := strings.Cut(span, ":")
			switch scheme {
			case ReferenceAccount, ReferenceConnections, ReferenceReconstructions, ReferenceObservations:
			default:
				continue
			}
			count++
			resolution := Resolve(bundle, placeholder.ReplaceAllString(span, "0"))
			switch {
			case scheme == ReferenceAccount && resolution.Outcome != Resolved:
				a.find(member, span, AcceptanceReferenceUnresolved, "the reference is %s against the conformance account: %s",
					resolution.Outcome, resolution.Why)
			case resolution.Outcome == NotAReference:
				a.find(member, span, AcceptanceReferenceUnresolved, "the reference is not in a reference form: %s", resolution.Why)
			}
		}
		a.result.References[member] = count
		total += count
	}
	if read > 0 && total == 0 {
		a.find(ConformanceAcceptance, "", AcceptanceReferenceUnresolved,
			"the acceptance documents yield no evidence reference, so nothing was resolved")
	}
}
