package account

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	observed "github.com/evandukss/edge-observer/account"
)

// The kernel a session ran on is projected as the block its reading allows: a
// recorded release carried, an unread one unavailable with its reason, an
// account without the record not carried, and a dry run not reached. Each
// projection is read back against the contract's own shape.
func TestTheSessionsKernelIsProjectedAsTheBlockItsReadingAllows(t *testing.T) {
	const release, why = "6.8.0-recorded", "open /proc/sys/kernel/osrelease: permission denied"
	for name, one := range map[string]struct {
		kind   observed.Kind
		kernel *observed.Kernel
		want   Kernel
	}{
		"sealed, recorded":        {observed.Sealed, &observed.Kernel{Release: release}, Kernel{Block: Block{State: Carried}, Release: release}},
		"live, recorded":          {observed.Live, &observed.Kernel{Release: release}, Kernel{Block: Block{State: Carried}, Release: release}},
		"sealed, unread":          {observed.Sealed, &observed.Kernel{Why: why}, Kernel{Block: Block{State: Unavailable, Why: why}}},
		"sealed, without record":  {observed.Sealed, nil, Kernel{Block: Block{State: NotCarried}}},
		"live, without record":    {observed.Live, nil, Kernel{Block: Block{State: NotCarried}}},
		"planned, without record": {observed.Planned, nil, Kernel{Block: Block{State: NotReached}}},
	} {
		t.Run(name, func(t *testing.T) {
			source := filled(t, true)
			source.Kind, source.Kernel = one.kind, one.kernel
			projected, err := Project(source, NotSupplied())
			if err != nil {
				t.Fatalf("project the account: %v", err)
			}
			if projected.Provenance.State != Carried {
				t.Fatalf("wiring, not the property: the provenance block is %s, so nothing inside it is read",
					projected.Provenance.State)
			}
			switch got := projected.Provenance.Kernel; {
			case got == nil:
				t.Errorf("the projection carries no kernel block, want %+v", one.want)
			case *got != one.want:
				t.Errorf("the kernel block is %+v, want %+v", *got, one.want)
			}

			content, err := json.Marshal(projected)
			if err != nil {
				t.Fatalf("encode the projection: %v", err)
			}
			_, findings, blocks := readAccount("account", content)
			if blocks == 0 {
				t.Fatal("wiring, not the property: the shape read no blocks, so its silence measures nothing")
			}
			for _, finding := range findings {
				if strings.HasPrefix(finding.At, "provenance") {
					t.Errorf("the contract refuses the provenance it was given: %+v", finding)
				}
			}
		})
	}
}

// exampleWithKernel is the example account with its provenance's kernel member
// set to kernel, or left out where kernel is nil.
func exampleWithKernel(t *testing.T, kernel map[string]any) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(up, "examples", "bundle", "account.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	provenance, found := document["provenance"].(map[string]any)
	if !found {
		t.Fatal("wiring, not the property: the example account has no provenance object")
	}
	delete(provenance, "kernel")
	if kernel != nil {
		provenance["kernel"] = kernel
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// An account written before sessions recorded their kernel has no kernel
// member and still reads. One that has the member is read against the
// contract: a carried block names its release.
func TestAnAccountWithoutTheKernelReadsAndACarriedKernelNamesItsRelease(t *testing.T) {
	for name, one := range map[string]struct {
		kernel map[string]any
		at     string
		reason Reason
	}{
		"without the member":       {nil, "", ""},
		"carried with its release": {map[string]any{"state": "carried", "release": "6.8.0-recorded"}, "", ""},
		"not carried":              {map[string]any{"state": "not_carried"}, "", ""},
		"carried with no release":  {map[string]any{"state": "carried"}, "provenance.kernel.release", RequiredMemberAbsent},
		"unavailable with no why":  {map[string]any{"state": "unavailable"}, "provenance.kernel.why", RequiredMemberAbsent},
	} {
		t.Run(name, func(t *testing.T) {
			_, findings, blocks := readAccount("account.json", exampleWithKernel(t, one.kernel))
			if blocks == 0 {
				t.Fatal("wiring, not the property: the shape read no blocks, so its silence measures nothing")
			}
			if one.reason == "" {
				if len(findings) != 0 {
					t.Errorf("the account is refused: %+v", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].At != one.at || findings[0].Reason != one.reason {
				t.Errorf("the account is refused with %+v, want one %s at %s", findings, one.reason, one.at)
			}
		})
	}
}
