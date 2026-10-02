//go:build attach

package attach_test

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// largestNames is n JSON strings, prefix and index.
func largestNames(prefix string, n int) []string {
	var names []string
	for i := range n {
		names = append(names, fmt.Sprintf("%s%d", prefix, i))
	}
	return names
}

// largestValues is n members, prefix and index, each with the value value(i).
func largestValues(prefix string, n int, value func(i int) any) map[string]any {
	values := map[string]any{}
	for i := range n {
		values[fmt.Sprintf("%s%d", prefix, i)] = value(i)
	}
	return values
}

// largestRules is every rule key at its limit and every limit at its largest
// value. With form rules, the form and the request JSON rules are
// one operation; without them, every key is operations of its own.
func largestRules(form bool) map[string]any {
	remove := map[string]any{
		"headers": largestNames("x-r", config.MaxRemovedHeaders), "query": largestNames("q", config.MaxRuleNames),
		"query_string": true, "bodies": []string{"request", "response"},
		"body_values": []string{"request", "response"},
		"json": map[string]any{"request": largestNames("/r", config.MaxRulePointers),
			"response": largestNames("/r", config.MaxRulePointers)},
	}
	if form {
		remove["form"] = largestNames("f", config.MaxRuleNames)
	}
	value := func(i int) any { return fmt.Sprintf("v%d", i) }
	return map[string]any{
		"remove": remove,
		"mask": map[string]any{"headers": largestValues("x-m", config.MaxMaskedHeaders, value),
			"json": map[string]any{"request": largestValues("/m", config.MaxRulePointers, value),
				"response": largestValues("/m", config.MaxRulePointers, value)}},
		"truncate": map[string]any{"headers": largestValues("x-t", config.MaxTruncatedHeaders,
			func(i int) any { return i + 1 })},
		"limits": map[string]any{"events": config.MaxEvents,
			"state_every_seconds": config.MaxStateEverySeconds, "workers": config.MaxWorkers},
	}
}

// The largest configuration a user can write starts, and an exchange goes
// through every operation to the approved output: a removed header is absent,
// a masked one carries its value and a truncated one its first byte.
func TestTheLargestConfigurationStartsAndWrites(t *testing.T) {
	binary := built(t)
	port := serving(t)
	for _, form := range []bool{true, false} {
		t.Run(map[bool]string{true: "every rule key at its limit", false: "the most operations"}[form], func(t *testing.T) {
			client := speaking(t, port)
			c := configuring(t, target("largest", client.process))
			content, err := os.ReadFile(c.path)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(content, &document); err != nil {
				t.Fatal(err)
			}
			for key, value := range largestRules(form) {
				document[key] = value
			}
			written, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if len(written) > config.MaxProcessingBytes {
				t.Fatalf("wiring, not the property: the configuration is %d bytes, over the budget", len(written))
			}
			if err := os.WriteFile(c.path, written, 0o600); err != nil {
				t.Fatal(err)
			}

			observer := started(t, binary, c)
			// The test server serves files, so the path is its root; the query is
			// removed whole, and the exchange is found by its X-Keep value.
			keep := "t27-largest-" + strconv.FormatBool(form)
			request := "GET /?q0=removed HTTP/1.1\r\nHost: localhost\r\nX-Keep: " + keep + "\r\n" +
				"X-R0: removed-value\r\nX-M0: masked-value\r\nX-T0: truncated-value\r\n\r\n"
			if _, err := io.WriteString(client.send, request); err != nil {
				t.Fatalf("wiring, not the property: the client could not send: %v", err)
			}
			status, err := client.receive.ReadString('\n')
			if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200") {
				t.Fatalf("wiring, not the property: the request was answered %q (%v)", status, err)
			}
			length := -1
			for {
				header, err := client.receive.ReadString('\n')
				if err != nil {
					t.Fatalf("wiring, not the property: the response ended inside its headers: %v", err)
				}
				if header == "\r\n" {
					break
				}
				if name, value, found := strings.Cut(header, ":"); found && strings.EqualFold(name, "content-length") {
					length, _ = strconv.Atoi(strings.TrimSpace(value))
				}
			}
			if _, err := io.ReadFull(client.receive, make([]byte, length)); length < 0 || err != nil {
				t.Fatalf("wiring, not the property: the response body of %d bytes was not read: %v", length, err)
			}
			ended(t, observer, c)

			found := 0
			err = processing.ReadArtifacts(os.DirFS(c.directory), func(a processing.Artifact) error {
				if a.Reconstruction == nil || a.Connection.Process.PID != client.process.PID {
					return nil
				}
				for _, exchange := range a.Reconstruction.Exchanges {
					message := exchange.Request.Message
					if message == nil {
						continue
					}
					headers := map[string]string{}
					for _, field := range message.Headers {
						headers[strings.ToLower(field.Name)] = field.Value
					}
					if headers["x-keep"] != keep {
						continue
					}
					found++
					if _, present := headers["x-r0"]; present || headers["x-m0"] != "v0" || headers["x-t0"] != "t" ||
						message.Target != "/" {
						t.Errorf("PROPERTY: the exchange's request is %q with headers %v, want the query removed, "+
							"x-r0 removed, x-m0 v0 and x-t0 t", message.Target, headers)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("read the approved output: %v", err)
			}
			if found != 1 {
				t.Fatalf("PROPERTY: the approved output holds %d exchanges marked %s from pid %d, want one", found,
					keep, client.process.PID)
			}
		})
	}
}
