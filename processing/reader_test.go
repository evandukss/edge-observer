package processing_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/evandukss/edge-observer/processing"
)

// These checks cover useful output and reader failures, not the independently
// owned condition-2 exclusion/absence and undecidable-suffix guarantee.
func readableArtifact(t *testing.T) ([]byte, processing.Artifact) {
	t.Helper()
	var out outputLog
	w, store := worker(t, workerPlan(t, pipeline("exchanges")), &out)
	enqueue(t, store, batch(t, 1, "GET /public HTTP/1.1\r\nX-Public: useful\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\npublic-body"))
	if result := drain(t, w); result.Written != 1 || len(out.lines) != 1 {
		t.Fatalf("producer did not write the useful control: %+v", result)
	}
	return out.lines[0], out.artifacts[0]
}

func artifactFS(data []byte) fstest.MapFS {
	return fstest.MapFS{processing.ArtifactName: &fstest.MapFile{Data: data}}
}

func requireUsefulRead(t *testing.T, data []byte) {
	t.Helper()
	var out bytes.Buffer
	visits := 0
	err := processing.ReadArtifacts(artifactFS(data), func(a processing.Artifact) error {
		visits++
		return processing.RenderArtifact(&out, a)
	})
	if err != nil || visits != 1 {
		t.Fatalf("decidable control: visits=%d err=%v", visits, err)
	}
	for _, value := range []string{"useful", "public-body", "fixture-policy", "exchanges", "account", `"direction": "sent"`, `"offset": "0"`, `"ending"`} {
		if !strings.Contains(out.String(), value) {
			t.Fatalf("successful read omitted %q: %s", value, &out)
		}
	}
}

func TestApprovedReaderRequiresUsefulRecordsAndNamesReachedFailures(t *testing.T) {
	line, artifact := readableArtifact(t)
	unsupported := artifact
	unsupported.Version = "future-version"
	badVersion, err := json.Marshal(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "contains no records"},
		{"malformed", []byte("{\"payload\":broken-sensitive-text}\n"), "record 1: invalid JSON"},
		{"version", append(badVersion, '\n'), "record 1: unsupported artifact version"},
		{"incomplete-final-line", bytes.TrimSuffix(line, []byte{'\n'}), "record 1: unterminated final line"},
		{"zero-artifact", []byte("{}\n"), "record 1: unsupported artifact version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireUsefulRead(t, line)
			visits := 0
			err := processing.ReadArtifacts(artifactFS(tc.data), func(processing.Artifact) error { visits++; return nil })
			if err == nil || !strings.Contains(err.Error(), tc.want) || visits != 0 {
				t.Fatalf("fault branch not reached: visits=%d err=%v want=%q", visits, err, tc.want)
			}
			if strings.Contains(err.Error(), "sensitive-text") {
				t.Fatal("parse diagnostic echoed source content")
			}
			t.Logf("reached %s after useful control", tc.want)
		})
	}
}

func TestApprovedReaderMissingFileAndNilVisitor(t *testing.T) {
	line, _ := readableArtifact(t)
	requireUsefulRead(t, line)
	if err := processing.ReadArtifacts(fstest.MapFS{}, func(processing.Artifact) error { t.Fatal("missing file visited"); return nil }); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file identity lost: %v", err)
	}
	if err := processing.ReadArtifacts(artifactFS(line), nil); err == nil || !strings.Contains(err.Error(), "visitor") {
		t.Fatalf("nil visitor was not refused: %v", err)
	}
}

func TestApprovedReaderKeepsEarlierRecordsButReturnsFinalFailure(t *testing.T) {
	line, _ := readableArtifact(t)
	requireUsefulRead(t, line)
	for _, tail := range []string{"{\n", "{partial"} {
		data := append(append([]byte{}, line...), tail...)
		var out bytes.Buffer
		err := processing.ReadArtifacts(artifactFS(data), func(a processing.Artifact) error { return processing.RenderArtifact(&out, a) })
		if err == nil || !strings.Contains(err.Error(), "record 2") || !strings.Contains(out.String(), "public-body") {
			t.Fatalf("partial read concealed output or final failure: %v\n%s", err, &out)
		}
	}
}

type failedArtifactOutput struct {
	calls int
	err   error
}

func (w *failedArtifactOutput) Write([]byte) (int, error) {
	w.calls++
	return 0, w.err
}

func TestApprovedReaderPropagatesVisitorAndOutputFailures(t *testing.T) {
	line, artifact := readableArtifact(t)
	requireUsefulRead(t, line)
	sentinel := errors.New("consumer stopped")
	visits := 0
	err := processing.ReadArtifacts(artifactFS(append(append([]byte{}, line...), line...)), func(processing.Artifact) error {
		visits++
		return sentinel
	})
	if err != sentinel || visits != 1 {
		t.Fatalf("visitor stop lost: visits=%d err=%v", visits, err)
	}
	for _, failure := range []error{sentinel, nil} {
		out := &failedArtifactOutput{err: failure}
		want := failure
		if want == nil {
			want = io.ErrShortWrite
		}
		if err := processing.RenderArtifact(out, artifact); err != want || out.calls != 1 {
			t.Fatalf("output fault: calls=%d err=%v want=%v", out.calls, err, want)
		}
	}
}
