package main

// consumeStorageExhaustion runs only in the serial controller. Each source's
// closure is sticky; the controller records its observation once before seal.
// Gate decisions can observe closure first, but cannot increment this witness.
func (d *daemon) consumeStorageExhaustion() {
	if d.storageExhausted == nil || d.gate == nil || d.storageExhaustionConsumptions != 0 {
		return
	}
	select {
	case <-d.storageExhausted:
		d.gate.ConsumeStorageExhaustion()
		d.storageExhaustionConsumptions++
	default:
	}
}
