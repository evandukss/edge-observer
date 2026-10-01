package policy

import "github.com/evandukss/edge-observer/contract/config"

// ProcessingRefused covers a configuration the reader or the compiler refused.
// Each Finding names the document and the key it refuses; there is no
// executable plan on refusal.
const ProcessingRefused config.Outcome = "processing_refused"

// CompileProcessing is the activation configuration entry point. It reads the
// configuration with the contract's reader, compiles it to the plan, and
// assembles the observation approval, without attaching or opening a session.
// directory is the absolute directory holding the configuration file, against
// which an extension's relative command is resolved. Activation callers
// consume its Policy; workers consume Processing. Revision names the
// configuration's bytes. Input slices need not outlive this call.
func CompileProcessing(content []byte, directory string) (Policy, error) {
	compiled, findings := config.Compile(content, directory)
	if len(findings) > 0 {
		return Policy{}, &Refused{Outcome: ProcessingRefused, Findings: findings}
	}
	result, findings := assemble(content, compiled.File, compiled.Plan.Observer())
	if len(findings) > 0 {
		return Policy{}, &Refused{Outcome: ProcessingRefused, Findings: findings}
	}
	result.Processing = compiled.Plan
	result.ProcessingRevision = compiled.ProcessingRevision
	return result, nil
}
