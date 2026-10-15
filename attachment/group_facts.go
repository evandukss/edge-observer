package attachment

import (
	"errors"
	"fmt"
	"strings"

	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
)

// ForProcess retains the owner's optional interfaces: an unattested owner must
// remain unconfirmed, even though the aggregate can route attestation calls.
func (g *Group) ForProcess(pid int32) (probe.Attachment, error) {
	at, err := g.forPID(pid)
	if err != nil {
		return nil, err
	}
	return at.live, nil
}

// facts reads every owner and keeps successful answers beside named errors.
// A missing optional interface is unknown, never an empty successful answer.
func facts[T any](g *Group, what string, read func(probe.Attachment) (T, error)) ([]T, error) {
	out := make([]T, 0, len(g.owners))
	var failures []error
	for _, at := range g.owners {
		one, err := read(at.live)
		if err != nil {
			failures = append(failures, fmt.Errorf("adapter %s %s: %w", at.name, what, err))
			continue
		}
		out = append(out, one)
	}
	return out, errors.Join(failures...)
}

func (g *Group) Grants() ([]probe.Grant, error) {
	all, err := facts(g, "grants", func(live probe.Attachment) ([]probe.Grant, error) {
		if one, ok := live.(probe.Granting); ok {
			return one.Grants()
		}
		return nil, errors.New("cannot report grants")
	})
	var out []probe.Grant
	for _, one := range all {
		out = append(out, one...)
	}
	return out, err
}
func (g *Group) Withdrawals() ([]probe.Withdrawal, error) {
	all, err := facts(g, "withdrawals", func(live probe.Attachment) ([]probe.Withdrawal, error) {
		if one, ok := live.(probe.Accounting); ok {
			return one.Withdrawals()
		}
		return nil, errors.New("cannot report withdrawals")
	})
	var out []probe.Withdrawal
	for _, one := range all {
		out = append(out, one...)
	}
	return out, err
}
func (g *Group) EndedCounts() ([]probe.EndedCount, error) {
	all, err := facts(g, "ended counts", func(live probe.Attachment) ([]probe.EndedCount, error) {
		if one, ok := live.(probe.Ending); ok {
			return one.EndedCounts()
		}
		return nil, errors.New("cannot report ended counts")
	})
	type target struct {
		name   string
		number int
	}
	positions := make(map[target]int)
	var out []probe.EndedCount
	for _, counts := range all {
		for _, one := range counts {
			key := target{one.Target, one.Number}
			if i, found := positions[key]; found {
				out[i].Count += one.Count
			} else {
				positions[key] = len(out)
				out = append(out, one)
			}
		}
	}
	return out, err
}
func (g *Group) Retained() ([]held.Occupancy, error) {
	all, err := facts(g, "retained stores", func(live probe.Attachment) ([]held.Occupancy, error) {
		if one, ok := live.(held.Reader); ok {
			return one.Retained()
		}
		return nil, errors.New("cannot report retained stores")
	})
	g.mutex.Lock()
	retired := 0
	for pending := range g.pending {
		retired += len(pending.ended)
	}
	out := []held.Occupancy{{Store: "attachment.owners", Held: len(g.owners)}, {Store: "attachment.routes", Held: len(g.routes), Rebuilds: g.routesChurn.Rebuilds()}, {Store: "attachment.pending", Held: len(g.pending)}, {Store: "attachment.pending_ends", Held: retired}}
	g.mutex.Unlock()
	positions := make(map[string]int)
	for _, stores := range all {
		for _, one := range stores {
			if i, found := positions[one.Store]; found {
				out[i].Held += one.Held
				out[i].Bound += one.Bound
				out[i].Rebuilds += one.Rebuilds
			} else {
				positions[one.Store] = len(out)
				out = append(out, one)
			}
		}
	}
	return out, err
}
func (g *Group) Refusals() (map[string]int64, error) {
	all, err := facts(g, "refusals", func(live probe.Attachment) (map[string]int64, error) {
		if one, ok := live.(probe.Refusing); ok {
			return one.Refusals()
		}
		return nil, errors.New("cannot report refusals")
	})
	out := make(map[string]int64)
	for _, counts := range all {
		for reason, count := range counts {
			out[reason] += count
		}
	}
	return out, err
}
func (g *Group) Losses() (probe.Losses, error) {
	all, err := facts(g, "losses", func(live probe.Attachment) (probe.Losses, error) {
		if one, ok := live.(probe.Counting); ok {
			return one.Losses()
		}
		return probe.Losses{}, errors.New("cannot report losses")
	})
	out := probe.Losses{UnderWay: probe.UnderWay{Known: true}}
	for _, one := range all {
		out.Dropped += one.Dropped
		out.Unmatched += one.Unmatched
		out.Descendants += one.Descendants
		out.UnderWay.Threads += one.UnderWay.Threads
		out.UnderWay.Undetermined += one.UnderWay.Undetermined
		if out.UnderWay.First == nil && one.UnderWay.First != nil {
			first := *one.UnderWay.First
			out.UnderWay.First = &first
		}
		if !one.UnderWay.Known {
			out.UnderWay.Known = false
			out.UnderWay.Why = strings.TrimPrefix(out.UnderWay.Why+"; "+one.UnderWay.Why, "; ")
		}
		if one.When.Seen() {
			last := max(out.When.Last, one.When.Last)
			if !out.When.Seen() || one.When.First < out.When.First {
				out.When = one.When
			}
			out.When.Last = last
		}
	}
	if err != nil {
		out.UnderWay.Known = false
		out.UnderWay.Why = err.Error()
	}
	return out, err
}
