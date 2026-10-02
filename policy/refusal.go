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
		where := strings.TrimSpace(finding.Subject)
		if where == "" {
			where = finding.Document
		}
		lines = append(lines, fmt.Sprintf("%s: %s: %s", where, finding.Reason, finding.Detail))
	}
	return fmt.Sprintf("%s: %s", r.Outcome, strings.Join(lines, "; "))
}
