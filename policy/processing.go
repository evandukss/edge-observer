package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/evandukss/edge-observer/contract/config"
)

// ProcessingRefused covers a configuration the reader or the compiler refused.
// Each Finding names the document and the key it refuses; there is no
// executable plan on refusal.
const ProcessingRefused config.Outcome = "processing_refused"

// CompileProcessing is the activation configuration entry point. It reads the
// configuration and the packs it enables with the contract's reader, compiles
// them to the plan, and assembles the observation approval, without attaching
// or opening a session. Activation callers consume its Policy; workers consume
// Processing. Revision names the configuration's bytes and, with packs, every
// pack's name and bytes in the order supplied. Input slices need not outlive
// this call.
func CompileProcessing(content []byte, packs []config.Supplied) (Policy, error) {
	compiled, findings := config.Compile(content, packs)
	if len(findings) > 0 {
		return Policy{}, &Refused{Outcome: ProcessingRefused, Findings: findings}
	}
	result, findings := assemble(content, compiled.File, compiled.Plan.Observer())
	if len(findings) > 0 {
		return Policy{}, &Refused{Outcome: ProcessingRefused, Findings: findings}
	}
	result.Processing = compiled.Plan
	result.ProcessingRevision = compiled.ProcessingRevision
	if len(packs) > 0 {
		result.Revision = processingDigest("observer.processing.bundle/v1", content, packs)
	}
	return result, nil
}

func processingDigest(domain string, content []byte, manifests []config.Supplied) string {
	digest := sha256.New()
	digest.Write([]byte(domain))
	add := func(raw []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(raw)))
		digest.Write(size[:])
		digest.Write(raw)
	}
	add(content)
	for _, manifest := range manifests {
		add([]byte(manifest.Name))
		add(manifest.Content)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}
