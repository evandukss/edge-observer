//go:build attach

package attach_test

import (
	"testing"
)

// The published order - remove, then mask, then truncate, then body_values - is
// the one executed, shown by two pairs the order decides.
//
//	remove before body_values   request remove.json /card/number with request
//	                            body_values: the kept structure lacks number, and
//	                            the evidence carries removed and values_removed.
//	                            Reversed, the values go first, the JSON removal
//	                            finds no body, and the name stays
//	mask before body_values     response mask.json /card/number as "withheld" with
//	                            response body_values: the kept kind is the mask's,
//	                            short_string. Reversed, it is the original's,
//	                            decimal_string
//
// The control is body_values alone: there the name is in the structure and the
// kind is decimal_string, so the pair's result is the order's doing and not
// the fixture's.
func TestThePublishedOrderIsTheOneExecuted(t *testing.T) {
	binary := built(t)
	port := rulesServing(t)
	request := rulesPost("/resp/decimal", []string{"application/json"}, `{"card":{"number":"`+rulesProtected+`","brand":"visa"}}`)
	for _, paired := range []bool{true, false} {
		name := map[bool]string{true: "each pair", false: "body_values alone"}[paired]
		t.Run(name, func(t *testing.T) {
			client := speaking(t, port)
			c := configuring(t, target("client", client.process))
			remove := map[string]any{"body_values": []string{"request", "response"}}
			keys := map[string]any{"remove": remove}
			if paired {
				remove["json"] = map[string]any{"request": []string{"/card/number"}}
				keys["mask"] = map[string]any{"json": map[string]any{"response": map[string]any{"/card/number": "withheld"}}}
			}
			content := rulesWritten(t, c, rulesEncoded(t, rulesDocument(c, []map[string]any{rulesWatch("client", client.process)}, keys)))
			rulesAccepted(t, content)
			w := rulesStarted(t, binary, c)
			rulesSend(t, client, request)
			one := rulesFind(t, rulesFinished(t, binary, c, w, client, 2), "/resp/decimal")
			requestCard := one.Request.Structure.Shape.at("card")
			responseNumber := one.Response.Structure.Shape.at("card", "number")
			if requestCard == nil || responseNumber == nil || requestCard.at("brand") == nil {
				t.Fatalf("wiring, not the property: no derived structure to read the order from: request %+v, response %+v",
					one.Request.Structure, one.Response.Structure)
			}
			t.Logf("request card fields %+v; response number kind %q; exclusions %v", requestCard.Fields, responseNumber.Kind, one.Exclusions)
			if !paired {
				if requestCard.at("number") == nil || responseNumber.Kind != "decimal_string" {
					t.Fatalf("wiring, not the property: without the paired rule the name is absent or the kind is %q",
						responseNumber.Kind)
				}
				return
			}
			if requestCard.at("number") != nil {
				t.Errorf("remove before body_values: the kept structure still holds number")
			}
			if !one.excluded("request", "message.body.json/card/number", "removed") ||
				!one.excluded("request", "message.body.values", "values_removed") {
				t.Errorf("remove before body_values: the evidence lacks removed or values_removed: %v", one.Exclusions)
			}
			if responseNumber.Kind != "short_string" {
				t.Errorf("mask before body_values: the kept kind is %q, not the mask's short_string", responseNumber.Kind)
			}
			if n := rulesCrossed(w, rulesProtected); n != 0 {
				t.Errorf("the protected marker crossed a write %d times", n)
			}
		})
	}
}
