//go:build attach

package ebpf

// IndependentRemoveReturn closes a real kernel link after measurability was
// established. It deliberately leaves the function's measurability unchanged.
func IndependentRemoveReturn(s *Session, symbol string) (int, error) {
	n := 0
	for i := range s.placed {
		p := &s.placed[i]
		if p.point.Symbol == symbol && p.back != nil {
			if err := p.back.Close(); err != nil {
				return n, err
			}
			p.back = nil
			n++
		}
	}
	return n, nil
}

// IndependentPlace installs the data probes after a pre-live workload.
func IndependentPlace(s *Session, points []Point) error {
	if err := s.place(points); err != nil {
		return err
	}
	return s.measurable()
}
