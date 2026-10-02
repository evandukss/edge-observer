package main

import "github.com/evandukss/edge-observer/held"

// Retained is what this session holds now, store by store: the processes and
// targets the activation account names, and everything capture, the intake,
// processing, the attachment and the sink queue behind the output hold. A
// part this session does not have is not listed; one that cannot be read
// fails the reading.
func (d *daemon) Retained() ([]held.Occupancy, error) {
	d.planMutex.Lock()
	out := []held.Occupancy{
		{Store: "observer.plan_processes", Held: len(d.plan.Processes)},
		{Store: "observer.plan_targets", Held: len(d.plan.Targets)},
	}
	d.planMutex.Unlock()
	var parts []held.Reader
	if d.capture != nil {
		parts = append(parts, d.capture)
	}
	if d.intake != nil {
		parts = append(parts, d.intake)
	}
	if d.processing != nil && d.processing.run != nil {
		parts = append(parts, d.processing.run)
	}
	if reader, can := d.attached.(held.Reader); can {
		parts = append(parts, reader)
	}
	if d.output != nil {
		parts = append(parts, d.output)
	}
	for _, part := range parts {
		stores, err := part.Retained()
		if err != nil {
			return nil, err
		}
		out = append(out, stores...)
	}
	return out, nil
}
