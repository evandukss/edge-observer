# Independent condition-2 checks and predeclared mutations

Base: `6b496724c69cf6cff8cfb285c6447a722cbb3728`. Author: Solo 218,
second engagement on todo 171, following comment 1980 before todo 170.
The implementation is complete. These tests are expected to pass; there is no
interface-stub red claim. No implementation or implementer test was changed.

Author-owned file: `cmd/observer/p3t9b_condition2_test.go`.
Run selection: `go test -race -count=1 -v ./cmd/observer -run
'^TestP3T9BCondition2PublicInspection$'`. The public binary built by this test
must use the same mounted source as the test process. Static and full unit
gates remain the orchestrator's; inherited example/attach failures are separate.

## Cases and scope

Each child producer sends two measured transfers through production capture,
intake, worker and writer; checks transfer acceptance and one sealed artifact;
and exits. Parent copies only account/artifact, deletes source, installs a
different accepted local policy, and runs the public binary. All eight cases
require actual permitted header, decoded body, capture policy and stream
provenance. A dead/no-output path fails USEFUL_OUTPUT.

* `removed`: duplicate mixed-case Authorization in both headers and trailers,
  in both message sides. Public output must contain four unique lowercase
  location tuples and no protected value or protected field. No value is stored
  in a tuple. `never_present` runs the same removal policy with the field absent,
  and requires known empty evidence. Thus configured removal is not evidence
  that any field was encountered.
* `legacy_absent` and `legacy_null`: useful producer artifact with only the
  evidence member removed. Null is produced by decoding/re-encoding that absent
  record using the public Artifact type. Wire form is checked before inspection;
  both require unavailable evidence, beside the `never_present` empty-array
  control. Four wire forms, three meanings; output slice nilness is checked.
* `suffix_withheld`: still-open connection with a complete first exchange and a
  second request whose header never finishes. Its marker was supplied to and
  accepted by capture. Output must omit it while displaying the first exchange,
  the exact sent exclusion/evidence offsets and incomplete-message reason,
  and undetermined Unplaced. `suffix_complete` completes that same second
  request and supplies its response; the public command must display its marker
  and both exchanges, without truncation. Neither member gets a transport close.
* `replaced` and `truncated`: supplied protected input changes to a permitted
  value while the diagnostic field stays present and the exclusion list stays
  empty. These must not be represented as removals.

These are synthetic-event public-command tests. They do not establish live
attachment, all durable write routes, all encodings of arbitrary secrets, or
entire-stream completeness from a complete exchange. Marker absence scans the
whole command output in literal and standard-base64 forms. Parsed assertions
decode the JSON printed by the public command, not the input artifact as a
substitute for inspection. Input decoding serves only wire-form/identity setup.

## Mutation plan declared before execution

Solo 188 builds one mutant at a time, mounts it over the indicated source,
reads its hash in the container, and runs the unchanged selection. Do not edit
the author's tree. Record exact mutation, mounted hash, failing child/assertion,
surviving children, and unexpected earlier failures. A build/setup/reader refusal
is not a targeted assertion kill. Report every survivor; do not silently change
tests or mutations after results.

All mutations target `processing/reader.go`. Insertions below are inside
`RenderArtifact`, after its successful `validateArtifact` check and before
`w := &artifactText{out: out}`, unless specified otherwise. This placement
models bad rendering of accepted input without the structural validator
preventing the tested assertion from running. Each is independent.

| ID | Exact mutation | Expected assertion and children |
| --- | --- | --- |
| M1 | Change `case artifact.PolicyExclusions == nil:` to `case len(artifact.PolicyExclusions) == 0:` | NONE_EXCLUDED: never_present, suffix_withheld, suffix_complete, replaced, truncated. Populated and both legacy children survive. |
| M2 | Change that nil case to `case false:` | LEGACY_UNAVAILABLE: legacy_absent and legacy_null only. All six others survive. |
| M3 | In the human `policy excluded` format arguments, replace `e.Section` with the literal `"headers"`. | EXCLUSION_TUPLES: removed only (trailers have wrong location, duplicate header lines). Others survive. |
| M4 | Insert `if len(artifact.PolicyExclusions) > 0 { artifact.Reconstruction.Exchanges[0].Request.Message.Headers = append(artifact.Reconstruction.Exchanges[0].Request.Message.Headers, record.Field{Name: "Authorization", Value: ""}) }`. | REMOVED_FIELD: removed only. Empty value avoids triggering the protected-marker assertion first. Others survive. |
| M5 | Just after `w := &artifactText{out: out}`, insert `if len(artifact.PolicyExclusions) > 0 { w.printf("diagnostic %s\n", "T9B_PROTECTED_6d2e9a") }`. | PROTECTED_ABSENCE: removed only. Others survive. Explicit synthetic emission calibrates the whole-output oracle, not a claim that production retains this value. |
| M6 | At the same location insert `if artifact.ReconstructionTruncation != nil { w.printf("diagnostic %s\n", "T9B_SUFFIX_4c8b1f") }`. | SUFFIX_ABSENCE: suffix_withheld only. Others survive. Same synthetic-emission limitation as M5. |
| M7 | Insert `if artifact.ReconstructionTruncation != nil { artifact.ReconstructionTruncation.Stops[0].Offset = "0" }`. | SUFFIX_EVIDENCE: suffix_withheld only, exact boundary assertion. Others survive. |
| M8 | In the final retained-body `w.printf` arguments replace `body` with `[]byte{}`; preserve the decode line's use with `_ = body` if needed. | USEFUL_OUTPUT: all eight children, decoded body marker absent despite retained base64 JSON. There is no surviving child; the unmutated run is the useful control. |
| M9 | Insert a loop through `artifact.Reconstruction.Exchanges[0].Request.Message.Headers` replacing any value exactly `"T9B_REPLACED_5a1d"` with `"wrong"` (guard Reconstruction != nil). | TRANSFORM_PRESENT: replaced only. Others survive. |
| M10 | Same loop, replace a value exactly `"KEEP"` with `"wrong"`. | TRANSFORM_PRESENT: truncated only. Others survive. |
| M11 | Insert `if artifact.Reconstruction != nil && len(artifact.Reconstruction.Exchanges) == 2 { artifact.Reconstruction.Exchanges = artifact.Reconstruction.Exchanges[:1] }`. | SUFFIX_CONTROL: suffix_complete only. First exchange still gives useful output; others survive. |

M1/M2 calibrate the mutually exclusive disposition assertions. M3 calibrates
tuple provenance; M4 field absence independently of value absence; M5/M6 the
two absence assertions; M7 the reached suffix boundary; M8 useful output;
M9/M10 transformed-field presence; M11 the completed-neighbor success check.
Harness preconditions (process exit, copied-file population, accepted input,
wire construction and policy change) are not claimed as separately mutated
product guarantees. No mutation has been executed by the independent author.
