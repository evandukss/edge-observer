package processing

// BatchesOf is the worker's map of connections whose input it holds, for a test
// measuring what the map allocates.
func BatchesOf(w *Worker) any { return w.batches }
