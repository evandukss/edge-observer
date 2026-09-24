package process

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// LoadApproval reads an approval file. The file is JSON in the shape of Rule
// and Approval, and a rule names one selector, never both:
//
//	{"rules": [{"executable": "/usr/bin/interpreter", "arguments": ["/srv/one/main"]}]}
//	{"rules": [{"cgroup": "/system.slice/one.service"}]}
//
// Arguments are what a process listing shows now, without trailing padding
// (Rule). Every failure is refused rather than defaulted, including an unknown
// field: each would otherwise yield an approval observing nothing that looks
// like a correct run on a quiet host.
func LoadApproval(path string) (Approval, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Approval{}, fmt.Errorf("read the approval: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	var approval Approval
	if err := decoder.Decode(&approval); err != nil {
		return Approval{}, fmt.Errorf("read the approval %s: %w", path, err)
	}
	if len(approval.Rules) == 0 {
		return Approval{}, fmt.Errorf("read the approval %s: it approves no process", path)
	}
	for i, rule := range approval.Rules {
		if err := rule.Validate(); err != nil {
			return Approval{}, fmt.Errorf("read the approval %s: rule %d: %w", path, i+1, err)
		}
	}
	for i, library := range approval.Libraries {
		if err := library.Validate(); err != nil {
			return Approval{}, fmt.Errorf("read the approval %s: library %d: %w", path, i+1, err)
		}
	}
	return approval, nil
}

// ErrNoApproval is returned when no approval was named at all, separate from a
// rejected file.
var ErrNoApproval = errors.New("no approval was named, and nothing is observed without one")
