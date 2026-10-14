package brotli

// The context maps and modes of every compressed metablock are cut from
// storage the Reader keeps, not allocated for each metablock: made once at the
// largest size the format allows, 256 block types of 64 literal contexts, 4
// distance contexts and one mode, and zeroed for each use as a new allocation
// would be. A Reader decodes one stream at a time, so nothing is shared between
// streams; Reset after an error rebuilds the Reader without it. A read that
// stops within a map resumes past this point, so the entries it has decoded
// are kept.

const (
	maxLiteralContextMap  = maxNumberOfBlockTypes << literalContextBits
	maxDistanceContextMap = maxNumberOfBlockTypes << distanceContextBits
)

// zeroedFrom returns n zeroed bytes cut from *storage, making it most bytes
// long when it is shorter than n.
func zeroedFrom(storage *[]byte, n, most uint) []byte {
	if uint(cap(*storage)) < n {
		*storage = make([]byte, max(n, most))
	}
	b := (*storage)[:n]
	clear(b)
	return b
}

// contextMapStorage is the storage of the map decodeContextMap is about to
// read, size entries long.
func contextMapStorage(s *Reader, context_map_arg *[]byte, size uint32) []byte {
	if context_map_arg == &s.dist_context_map {
		return zeroedFrom(&s.dist_context_map_storage, uint(size), maxDistanceContextMap)
	}
	return zeroedFrom(&s.context_map_storage, uint(size), maxLiteralContextMap)
}
