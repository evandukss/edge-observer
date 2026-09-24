package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/evandukss/edge-observer/contract/config"
)

// ProcessingRefused covers a configuration refused by the bounded processing
// profile. Each Finding identifies the structural, composition or runtime rule
// that actually decided it; there is no executable plan on refusal.
const ProcessingRefused config.Outcome = "processing_refused"

// CompileProcessing is the activation configuration entry point. It validates
// both processing and observation approval without attaching or opening a
// session. Activation callers consume its Policy; workers consume Processing.
// Revision identifies the configuration plus every supplied manifest, including
// disabled manifests, in supplied order. Input slices need not outlive this call.
func CompileProcessing(content []byte, manifests []config.Supplied) (Policy, error) {
	plan, findings := config.CompileProcessing(content, manifests)
	if len(findings) > 0 {
		return Policy{}, &Refused{Outcome: ProcessingRefused, Findings: findings}
	}
	// The compiler has already read this document with the same reader. This
	// supplies observation approval to the existing assembler, never a second
	// interpretation of processing slots or policy requirements.
	written, _ := config.ReadConfiguration(content)
	result, err := assemble(content, written, plan.Observer())
	if err != nil {
		return Policy{}, &Refused{Outcome: ProcessingRefused, Findings: []config.Finding{{Document: "configuration", Subject: "observation_scope", Reason: "invalid_observation_approval", Detail: err.Error()}}}
	}
	result.Processing = plan
	// Bind the whole accepted declaration, except the two scopes whose reload
	// rules are checked separately. An inclusion list would silently omit a new
	// processing field when the configuration type grows.
	written.Observer = config.Observer{}
	written.ObservationScope = config.ObservationScope{}
	declaration, err := json.Marshal(written)
	if err != nil {
		return Policy{}, fmt.Errorf("encode the compiled processing generation: %w", err)
	}
	result.ProcessingRevision = processingDigest("observer.processing.generation/v1", declaration, manifests)
	// Keep the no-pack revision compatible with the ordinary configuration
	// loader; a supplied bundle also binds names and content boundaries.
	if len(manifests) > 0 {
		result.Revision = processingDigest("observer.processing.bundle/v1", content, manifests)
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
