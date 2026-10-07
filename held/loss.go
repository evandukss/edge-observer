package held

import "sync"

// Loss is bounded control state shared by one occupancy's capture and retained
// input. It needs no payload queue slot. A cut and an enqueue are ordered under
// one lock; already enqueued output is unaffected. No operation clears a cut.
type Loss struct {
	mutex  sync.Mutex
	reason string
}

func (l *Loss) Stop(reason string) {
	if l == nil {
		return
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.reason == "" {
		l.reason = reason
	}
}

func (l *Loss) Reason() string {
	if l == nil {
		return ""
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.reason
}

// Authorize runs only a short, nonblocking enqueue. It must not call Loss.
func (l *Loss) Authorize(enqueue func()) bool {
	if l == nil {
		enqueue()
		return true
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.reason != "" {
		return false
	}
	enqueue()
	return true
}
