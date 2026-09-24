package policy

import (
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/contract/config"
)

// LocalAccount is the one sink kind this program has: the session's spool and
// the account sealed beside it, on this host.
const LocalAccount = "local_account"

// The record types the core produces into pipelines.
const (
	Observation    = "observation"
	Connection     = "connection"
	Reconstruction = "reconstruction"
)

// Inventory is what this program has, as the contract's check sees it: no
// built-in component, one sink kind that keeps plaintext on the host, and the
// descendant answers admission gives. It is never read from a file.
func Inventory() config.Available {
	emits := []string{Observation, Connection, Reconstruction}
	return config.Available{
		Types: []config.RecordType{
			{Name: Observation, Fields: []string{"observation.id", "connection.id", "direction", "bytes"}},
			{Name: Connection, Fields: []string{"connection.id", "process.instance", "local.port", "remote.port"}},
			{Name: Reconstruction, Fields: []string{"connection.id", "message.start_line", "message.headers", "message.body"}},
		},
		CoreEmits:   emits,
		SinkKinds:   []config.SinkKind{{Name: LocalAccount, Accepts: emits, LeavesHost: false, RetainsPlaintext: true}},
		Descendants: fixedAnswers(admission.ModeFollow.Answers()),
	}
}

// fixedAnswers spells admission's three fixed answers in the contract's words.
// An answer with no word here is spelled empty, which no configuration can
// state, so it is refused rather than matched by accident.
func fixedAnswers(answers admission.Answers) config.FixedAnswers {
	var fixed config.FixedAnswers
	if answers.Boundary == admission.ExecEndsTheGrant {
		fixed.Boundary = "exec_ends_the_grant"
	}
	if answers.RootExit == admission.SurvivorsKeepTheirGrants {
		fixed.RootExit = "survivors_keep_their_grants"
	}
	if answers.Replacement == admission.ReplacementNeedsRestart {
		fixed.Replacement = "needs_restart"
	}
	return fixed
}
