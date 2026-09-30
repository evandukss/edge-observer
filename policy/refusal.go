package policy

import (
	"fmt"
	"strings"

	"github.com/evandukss/edge-observer/contract/config"
)

// Refused is a configuration the contract's reader or compiler refused, with
// their findings unchanged.
type Refused struct {
	Outcome  config.Outcome
	Findings []config.Finding
}

func (r *Refused) Error() string {
	lines := make([]string, 0, len(r.Findings))
	for _, finding := range r.Findings {
		// A key is named with its document where the document is not the
		// configuration itself, so a pack's key is never read as the operator's.
		where := strings.TrimSpace(finding.Subject)
		switch {
		case where == "":
			where = finding.Document
		case finding.Document != "" && finding.Document != "configuration":
			where = finding.Document + " " + where
		}
		lines = append(lines, fmt.Sprintf("%s: %s: %s", where, finding.Reason, finding.Detail))
	}
	return fmt.Sprintf("%s: %s", r.Outcome, strings.Join(lines, "; "))
}
