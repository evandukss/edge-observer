package capture

// StreamsOf is the session's map of followed streams, for a test measuring what
// the map allocates.
func StreamsOf(s *Session) any { return s.streams }
