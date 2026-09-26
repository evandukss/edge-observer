//go:build attach

package attach_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// t18InspectedHeaders is the request headers of the exchange for target, as
// `observer inspect <session> --text` prints the approved record holding it:
// the record's JSON follows its "approved artifact" line and ends at the first
// line that closes it. Nothing of the repository reads it.
func t18InspectedHeaders(t *testing.T, text, target string) []byte {
	t.Helper()
	lines := strings.Split(text, "\n")
	found := 0
	var headers []byte
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "approved artifact  ") {
			continue
		}
		end := i + 1
		for end < len(lines) && lines[end] != "}" {
			end++
		}
		if end == len(lines) {
			t.Fatalf("an approved record printed by inspect never closes:\n%s", text)
		}
		var one t18Artifact
		if err := json.Unmarshal([]byte(strings.Join(lines[i+1:end+1], "\n")), &one); err != nil {
			t.Fatalf("an approved record printed by inspect is not JSON: %v", err)
		}
		if one.Reconstruction != nil {
			for _, exchange := range one.Reconstruction.Exchanges {
				if exchange.Request.Message != nil && exchange.Request.Message.Target == target {
					var compact bytes.Buffer
					if err := json.Compact(&compact, exchange.Request.Message.Headers); err != nil {
						t.Fatalf("the printed headers are not JSON: %v", err)
					}
					headers = compact.Bytes()
					found++
				}
			}
		}
		i = end
	}
	if found != 1 {
		t.Fatalf("wiring, not the property: inspect printed %d exchanges for %s, want one:\n%s", found, target, text)
	}
	return headers
}

// Row 6, the equivalence half, read through the public command alone. The
// demonstration pack reverses the operator's two slots. The same order written
// straight into the operator's configuration, with no pack enabled and no pack
// directory beside it, must give the same bytes for the same request; the
// operator's own order must not, or the comparison could not tell the orders
// apart. Each session is stopped and then read only by `observer inspect
// <session directory> --text`.
func TestT18TheEffectiveOrderWrittenAsConfigurationGivesThePacksBytes(t *testing.T) {
	binary := built(t)
	port := serving(t)
	const marker = "t18-equivalence"
	printed := map[string][]byte{}
	for _, how := range []string{"the pack", "its order written directly", "the operator's order"} {
		t.Run(how, func(t *testing.T) {
			client := speaking(t, port)
			c := configuring(t, target("client", client.process))
			switch how {
			case "the pack":
				demonstrating(t, c, []string{demonstrationPack}, target("client", client.process))
			case "its order written directly":
				demonstrating(t, c, []string{}, target("client", client.process))
				t18Edit(t, c, func(document map[string]any) {
					pipeline := document["pipelines"].([]any)[0].(map[string]any)
					pipeline["slots"] = []any{
						t18Slot("mark", "truncate-header-values", `{"headers":["authorization"],"length":8}`),
						t18Slot("limit", "replace-header-values", `{"headers":["authorization"],"value":"`+byThePack+`"}`),
					}
				})
				if err := os.RemoveAll(filepath.Join(filepath.Dir(c.path), "packs")); err != nil {
					t.Fatalf("remove the pack directory: %v", err)
				}
			case "the operator's order":
				demonstrating(t, c, []string{}, target("client", client.process))
			}
			observer := started(t, binary, c)
			sendCredential(t, client, marker)
			ended(t, observer, c)
			stdout, stderr, err := t18Command(t, 30*time.Second, binary, "inspect", observer.directory(c), "--text")
			if err != nil {
				t.Fatalf("inspect the session: %v\n%s", err, stderr)
			}
			printed[how] = t18InspectedHeaders(t, stdout, "/?asked="+marker)
			t.Logf("%s: %s", how, printed[how])
		})
	}
	pack, direct, operator := printed["the pack"], printed["its order written directly"], printed["the operator's order"]
	if pack == nil || direct == nil || operator == nil {
		t.Fatal("wiring, not the property: a session printed nothing to compare")
	}
	if !bytes.Contains(pack, []byte(`"`+byThePack)) || bytes.Contains(pack, []byte(credential)) {
		t.Fatalf("wiring, not the property: the pack's session printed %s, not the pack's value", pack)
	}
	if bytes.Equal(pack, operator) {
		t.Fatalf("wiring, not the property: the operator's order printed the same bytes as the pack's, so equality measures nothing: %s", pack)
	}
	if !bytes.Equal(pack, direct) {
		t.Errorf("the effective order written directly printed %s, and the pack %s", direct, pack)
	}
}
