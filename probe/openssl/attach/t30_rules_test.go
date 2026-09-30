//go:build attach

package attach_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// t30Set is one group of rules and the exchanges that show each of them. The
// groups are kept apart where one rule would hide another: a whole body
// removed hides what a field rule did to it.
type t30Set struct {
	name     string
	rules    map[string]any
	requests []string
	check    func(t *testing.T, records []t30Artifact)
}

func t30Sets() []t30Set {
	P, K := t30Protected, t30Permitted
	return []t30Set{
		{
			name: "fields",
			rules: map[string]any{
				"remove": map[string]any{
					"headers": []string{"authorization"}, "query": []string{"token"}, "form": []string{"card_number"},
					"json": map[string]any{"request": []string{"/card/number"}, "response": []string{"/card/number", "/items/*/pan"}},
				},
				"mask":     map[string]any{"headers": map[string]any{"x-api-key": "withheld"}, "json": map[string]any{"response": map[string]any{"/email": "withheld"}}},
				"truncate": map[string]any{"headers": map[string]any{"x-trace-id": 8}},
			},
			requests: []string{
				t30Get("/resp/card?token="+P+"&keep="+K, "Authorization: Bearer "+P, "X-Api-Key: "+P, "X-Trace-Id: "+P, "X-Public: "+K),
				t30Post("/form", []string{"application/x-www-form-urlencoded"}, "card_number="+P+"&keep="+K),
				t30Post("/json", []string{"application/json"}, `{"card":{"number":"`+P+`","brand":"`+K+`"}}`),
			},
			check: func(t *testing.T, records []t30Artifact) {
				card := t30Find(t, records, "/resp/card?")
				if strings.Contains(card.Request.Target, "token=") || !strings.Contains(card.Request.Target, "keep="+K) {
					t.Errorf("remove.query: the target is %q", card.Request.Target)
				}
				if len(card.Request.header("authorization")) != 0 || !card.excluded("request", "message.headers.authorization", "removed") {
					t.Errorf("remove.headers: authorization %q, exclusions %v", card.Request.header("authorization"), card.Exclusions)
				}
				if got := card.Request.header("x-api-key"); len(got) != 1 || got[0] != "withheld" {
					t.Errorf("mask.headers: x-api-key is %q", got)
				}
				if got := card.Request.header("x-trace-id"); len(got) != 1 || got[0] != P[:8] {
					t.Errorf("truncate.headers: x-trace-id is %q", got)
				}
				var response struct {
					Card  map[string]any   `json:"card"`
					Email any              `json:"email"`
					Items []map[string]any `json:"items"`
				}
				if err := json.Unmarshal([]byte(card.Response.kept(t)), &response); err != nil {
					t.Fatalf("wiring, not the property: the response body kept is not JSON: %v", err)
				}
				if _, present := response.Card["number"]; present || response.Card["brand"] != K {
					t.Errorf("remove.json response /card/number: the card kept is %v", response.Card)
				}
				if response.Email != "withheld" {
					t.Errorf("mask.json response /email: email is %v", response.Email)
				}
				if len(response.Items) != 1 || response.Items[0]["label"] != K {
					t.Fatalf("wiring, not the property: the items kept are %v", response.Items)
				}
				if _, present := response.Items[0]["pan"]; present {
					t.Errorf("remove.json response /items/*/pan: the item kept is %v", response.Items[0])
				}
				form := t30Find(t, records, "/form")
				if kept := form.Request.kept(t); strings.Contains(kept, "card_number") || !strings.Contains(kept, "keep="+K) ||
					!form.excluded("request", "message.form.card_number", "removed") {
					t.Errorf("remove.form: kept %q, exclusions %v", kept, form.Exclusions)
				}
				body := t30Find(t, records, "/json")
				var request struct {
					Card map[string]any `json:"card"`
				}
				if err := json.Unmarshal([]byte(body.Request.kept(t)), &request); err != nil {
					t.Fatalf("wiring, not the property: the request body kept is not JSON: %v", err)
				}
				if _, present := request.Card["number"]; present || request.Card["brand"] != K ||
					!body.excluded("request", "message.body.json/card/number", "removed") {
					t.Errorf("remove.json request /card/number: kept %v, exclusions %v", request.Card, body.Exclusions)
				}
			},
		},
		{
			name:     "query string",
			rules:    map[string]any{"remove": map[string]any{"query_string": true}},
			requests: []string{t30Get("/" + K + "?x=" + P)},
			check: func(t *testing.T, records []t30Artifact) {
				one := t30Find(t, records, "/"+K)
				if one.Request.Target != "/"+K || !one.excluded("request", "message.target.query", "removed") {
					t.Errorf("remove.query_string: target %q, exclusions %v", one.Request.Target, one.Exclusions)
				}
			},
		},
		{
			name:     "bodies",
			rules:    map[string]any{"remove": map[string]any{"bodies": []string{"request", "response"}}},
			requests: []string{t30Post("/resp/text", []string{"text/plain"}, P, "X-Public: "+K)},
			check: func(t *testing.T, records []t30Artifact) {
				one := t30Find(t, records, "/resp/text")
				for message, m := range map[string]*t30Message{"request": one.Request, "response": one.Response} {
					if m.kept(t) != "" || m.Body.Length == "0" || m.Structure.State != "removed" ||
						!one.excluded(message, "message.body", "removed") {
						t.Errorf("remove.bodies %s: kept %q of %s, structure %q, exclusions %v",
							message, m.kept(t), m.Body.Length, m.Structure.State, one.Exclusions)
					}
				}
			},
		},
		{
			name:     "body values",
			rules:    map[string]any{"remove": map[string]any{"body_values": []string{"request", "response"}}},
			requests: []string{t30Post("/resp/names", []string{"application/json"}, `{"`+K+`":"`+P+`"}`)},
			check: func(t *testing.T, records []t30Artifact) {
				one := t30Find(t, records, "/resp/names")
				for message, m := range map[string]*t30Message{"request": one.Request, "response": one.Response} {
					if m.kept(t) != "" || m.Structure.Shape.at(K) == nil || !one.excluded(message, "message.body.values", "values_removed") {
						t.Errorf("remove.body_values %s: kept %q, structure %+v, exclusions %v",
							message, m.kept(t), m.Structure, one.Exclusions)
					}
				}
			},
		},
	}
}

// Case 1 and row 18. Each group of rules, written once in the operator's file
// with no pack and once in a pack the file enables, changes what the session
// writes, and at the write boundary no protected marker crosses a write in any
// form - plainly or inside the base64 of a kept body - while the permitted
// marker beside it does. The control writes every one of these exchanges with
// no rules at all: there each field is written, and the protected marker
// crosses, which is what makes its absence above mean something.
func TestT30EveryRuleChangesWhatIsWrittenAndNoProtectedValueCrossesAWrite(t *testing.T) {
	binary := built(t)
	port := t30Serving(t)
	for _, source := range []string{"the operator's file", "a pack"} {
		for _, set := range t30Sets() {
			t.Run(source+"/"+set.name, func(t *testing.T) {
				client := speaking(t, port)
				c := configuring(t, target("client", client.process))
				watch := []map[string]any{t30Watch("client", client.process)}
				var packs []config.Supplied
				keys := set.rules
				if source == "a pack" {
					packs = append(packs, t30PackBytes(t, c, "t30-rules", set.rules))
					keys = map[string]any{"packs": []string{"t30-rules"}}
				}
				content := t30Written(t, c, t30Encoded(t, t30Document(c, watch, keys)))
				t30Accepted(t, content, packs...)
				w := t30Started(t, binary, c)
				for _, request := range set.requests {
					t30Send(t, client, request)
				}
				records := t30Finished(t, binary, c, w, client, 2)
				set.check(t, records)
				if n := t30Crossed(w, t30Protected); n != 0 {
					t.Errorf("the protected marker crossed a write %d times, plainly or base64-encoded", n)
				}
				t25Clean(t, w)
			})
		}
	}
	t.Run("the control, with no rules", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		content := t30Written(t, c, t30Encoded(t, t30Document(c, []map[string]any{t30Watch("client", client.process)}, nil)))
		t30Accepted(t, content)
		w := t30Started(t, binary, c)
		for _, set := range t30Sets() {
			for _, request := range set.requests {
				t30Send(t, client, request)
			}
		}
		records := t30Finished(t, binary, c, w, client, 2)
		card := t30Find(t, records, "/resp/card?")
		if !strings.Contains(card.Request.Target, "token="+t30Protected) || !t30Has(card.Request.header("authorization"), "Bearer "+t30Protected) ||
			!t30Has(card.Request.header("x-api-key"), t30Protected) || !t30Has(card.Request.header("x-trace-id"), t30Protected) ||
			!strings.Contains(card.Response.kept(t), t30Protected) {
			t.Errorf("without rules the fields are not written as sent: %+v", card.Request)
		}
		for _, prefix := range []string{"/form", "/json", "/resp/text", "/resp/names"} {
			if one := t30Find(t, records, prefix); !strings.Contains(one.Request.kept(t), t30Protected) {
				t.Errorf("without rules %s's request body is not written as sent: %q", prefix, one.Request.kept(t))
			}
		}
		if one := t30Find(t, records, "/"+t30Permitted); !strings.Contains(one.Request.Target, "?x="+t30Protected) {
			t.Errorf("without rules the query string is not written: %q", one.Request.Target)
		}
		if n := t30Crossed(w, t30Protected); n == 0 {
			t.Errorf("wiring, not the property: without rules the protected marker crossed no write, so its absence " +
				"under the rules measures nothing")
		}
	})
}

// Case 1, write_content false: plaintext is read and processed and never
// written. With no rules at all, neither marker - each rides a header, a query
// or a body - crosses a write, and no exchanges route line is written. The
// control is the no-rules run above, which writes the exchanges.
func TestT30WriteContentFalseWritesNoPlaintext(t *testing.T) {
	binary := built(t)
	client := speaking(t, t30Serving(t))
	c := configuring(t, target("client", client.process))
	content := t30Written(t, c, t30Encoded(t, t30Document(c, []map[string]any{t30Watch("client", client.process)},
		map[string]any{"write_content": false})))
	t30Accepted(t, content)
	w := t30Started(t, binary, c)
	before := t30Live(t, binary, c).Seen.Records
	for _, set := range t30Sets() {
		for _, request := range set.requests {
			t30Send(t, client, request)
		}
	}
	if after := t30Live(t, binary, c).Seen.Records; after < before+6 {
		t.Fatalf("wiring, not the property: the exchanges reached capture as %d records", after-before)
	}
	records := t30Finished(t, binary, c, w, client, 1)
	connections := 0
	for _, record := range records {
		if record.Route.Pipeline == config.ExchangesPipeline || record.Reconstruction != nil {
			t.Errorf("an exchanges line was written with write_content false: %+v", record.Route)
		}
		if record.Route.Pipeline == config.ConnectionsPipeline {
			connections++
		}
	}
	if connections == 0 {
		t.Fatal("wiring, not the property: not even the connection record was written")
	}
	for _, marker := range []string{t30Protected, t30Permitted} {
		if n := t30Crossed(w, marker); n != 0 {
			t.Errorf("plaintext crossed a write with write_content false: %s %d times", marker, n)
		}
	}
}
