package processing

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/evandukss/edge-observer/contract/record"
)

// ErrReaderUnavailable was returned by the interface-only publication.
// Deprecated: the implemented reader no longer returns this error.
var ErrReaderUnavailable = errors.New("approved artifact reader is not implemented")

// ErrNoArtifacts means approved.jsonl exists but contains no records. It does
// not establish that nothing crossed, or that no values were excluded.
var ErrNoArtifacts = errors.New("approved artifact contains no records")

// ReadArtifacts visits the complete LF-terminated records in ArtifactName in
// file order. It reads only that file through session; it never opens a raw
// spool, configuration, socket or running process. PolicyRevision and
// Route are capture-time facts, not instructions to execute local policy.
//
// A missing file preserves errors.Is(err, fs.ErrNotExist). An empty file returns
// ErrNoArtifacts. Invalid JSON, an unsupported version, an invalid artifact or
// an unterminated final line returns an error naming the record number without
// quoting its content. Earlier complete records may already have been visited;
// callers must preserve the final error rather than claim a complete reading.
// A visit error stops reading and is returned unchanged. Each visited Artifact
// owns its decoded data. A nil visitor is refused.
//
// Validation requires the published versions, a named policy revision and
// route, connection identity, and (when present) a reconstruction of that same
// connection with complete, present request/response pairs and base64 bodies.
// Truncation and exclusion evidence must refer to that retained population;
// the detailed structural rules are in docs/approved-inspection.md.
func ReadArtifacts(files fs.FS, visit func(Artifact) error) error {
	return ReadArtifactFiles(files, []string{ArtifactName}, "", visit)
}
func readArtifactFile(files fs.FS, name, session string, visit func(Artifact) error) (count int, result error) {
	f, err := files.Open(name)
	if err != nil {
		return 0, fmt.Errorf("open approved artifact: %w", err)
	}
	defer func() {
		if err := f.Close(); result == nil && err != nil {
			result = errors.New("close approved artifact failed")
		}
	}()
	r := bufio.NewReader(f)
	for number := 1; ; number++ {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return count, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return count, fmt.Errorf("approved artifact record %d: unterminated final line (malformed)", number)
			}
			return count, fmt.Errorf("approved artifact record %d: read failed", number)
		}
		var a Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			return count, fmt.Errorf("approved artifact record %d: invalid JSON (malformed)", number)
		}
		if err := validateArtifact(a); err != nil {
			return count, fmt.Errorf("approved artifact record %d: %w (malformed)", number, err)
		}
		if session != "" && a.Session != session {
			continue
		}
		count++
		if err := visit(a); err != nil {
			return count, err
		}
	}
}

// RenderArtifact writes one artifact as text with its persisted version, policy
// revision, route, connection metadata and reconstruction provenance. Permitted
// headers and trailers retain their values; base64 bodies are decoded and
// quoted so control bytes cannot act as terminal instructions. Message stream
// directions and offsets, the actual connection ending, Unplaced and every
// ReconstructionTruncation stop remain visible. No local policy is consulted.
// PolicyExclusions is rendered as unavailable for nil (absent or null on the
// wire), none excluded for an empty array, or one line per entry for a
// populated array: the field and disposition in version 2, the section and
// header name in version 1. These claims concern retained messages only, never
// an unknown suffix. Each retained body line names its structure state, so a
// body removed by policy does not read as an empty one.
// It propagates output errors and applies the same validation as ReadArtifacts.
//
// The text includes the persisted record as indented JSON, followed by decoded
// body values and a human-readable exclusion disposition. JSON escapes field
// values; decoded bodies use Go string quoting, including non-text bytes.
func RenderArtifact(out io.Writer, artifact Artifact) error {
	if out == nil {
		return errors.New("approved artifact renderer requires an output")
	}
	if err := validateArtifact(artifact); err != nil {
		return err
	}
	w := &artifactText{out: out}
	w.printf("approved artifact  version=%q policy_revision=%q pipeline=%q sink=%q kind=%q\n",
		artifact.Version, artifact.PolicyRevision, artifact.Route.Pipeline, artifact.Route.Sink, artifact.Route.Kind)
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return errors.New("encode approved artifact for inspection failed")
	}
	w.printf("%s\n", encoded)
	switch {
	case artifact.PolicyExclusions == nil:
		w.printf("policy exclusions  unavailable: this artifact does not establish which fields were excluded\n")
	case len(artifact.PolicyExclusions) == 0:
		w.printf("policy exclusions  none excluded in retained messages; no claim about an indeterminate suffix\n")
	default:
		for _, e := range artifact.PolicyExclusions {
			switch {
			case artifact.Version == ArtifactVersion1:
				w.printf("policy excluded  exchange=%d message=%q section=%q name=%q (value not retained)\n",
					e.Exchange, e.Message, e.Section, e.Name)
			case e.Section != "":
				w.printf("policy excluded  exchange=%d message=%q field=%q section=%q disposition=%q (value not retained)\n",
					e.Exchange, e.Message, e.Field, e.Section, e.Disposition)
			default:
				w.printf("policy excluded  exchange=%d message=%q field=%q disposition=%q (value not retained)\n",
					e.Exchange, e.Message, e.Field, e.Disposition)
			}
		}
	}
	if artifact.Reconstruction != nil {
		for _, e := range artifact.Reconstruction.Exchanges {
			for _, side := range []record.Side{e.Request, e.Response} {
				m := side.Message
				// Validation established the encoding before any output.
				body, _ := base64.StdEncoding.DecodeString(m.Body.Kept)
				w.printf("retained body  exchange=%d message=%q direction=%q offset=%q end=%q structure=%q bytes=%q\n",
					e.Index, m.Kind, m.Stream.Direction, m.Stream.Offset, m.Stream.End, m.Structure.State, body)
			}
		}
	}
	return w.err
}

// Preserve the first write failure, including a short write without an error.
// fmt.Fprintf itself does not turn that broken Writer contract into an error.
type artifactText struct {
	out io.Writer
	err error
}

func (w *artifactText) printf(format string, args ...any) {
	if w.err != nil {
		return
	}
	text := fmt.Sprintf(format, args...)
	var n int
	n, w.err = io.WriteString(w.out, text)
	if w.err == nil && n != len(text) {
		w.err = io.ErrShortWrite
	}
}
