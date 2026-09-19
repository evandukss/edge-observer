package connection

import "fmt"

// Count is a quantity that may not be knowable. An unread counter and a zero
// one are the same int64 and opposite answers. Nothing is invented to balance
// an identity: one with an unknown term cannot be evaluated.
type Count struct {
	Value int64  `json:"value"`
	Known bool   `json:"known"`
	Why   string `json:"why,omitempty"`
}

// Counted is a quantity that was measured.
func Counted(value int64) Count { return Count{Value: value, Known: true} }

// Uncounted is a quantity nobody could read, with the reason. It is the zero
// value when the reason is empty, so an unfilled field reads as unknown.
func Uncounted(why string) Count { return Count{Why: why} }

func (c Count) String() string {
	if !c.Known {
		if c.Why == "" {
			return "not known"
		}
		return "not known: " + c.Why
	}
	return fmt.Sprintf("%d", c.Value)
}

// Add sums two counts; an unknown term makes the sum unknown.
func (c Count) Add(other Count) Count {
	if !c.Known {
		return c
	}
	if !other.Known {
		return other
	}
	return Counted(c.Value + other.Value)
}
