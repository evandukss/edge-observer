package probe

import (
	"strconv"
	"strings"

	"github.com/evandukss/edge-observer/fragment"
)

// Function is one entry point a TLS library moves plaintext through. The set
// is a fact about the runtime and its version, kept here rather than in an
// adapter. A library exporting an uncatalogued family member is reported:
// otherwise traffic is silently missed.
type Function struct {
	Symbol string `json:"symbol"`

	// Since is the runtime release that first exported this function, separating
	// an old library from a broken one.
	Since string `json:"since"`

	Direction fragment.Direction `json:"-"`

	// Probed is whether the observer attaches to it; if not, Note says why.
	Probed bool   `json:"probed"`
	Note   string `json:"note,omitempty"`

	// Count says where the function reports how many bytes it moved.
	Count Count `json:"count"`

	// CountArg is the one-based argument index of the count out-parameter for a
	// CountOutParameter function, taken from the signature: SSL_write_ex2 has a
	// flags word at four and the count at five, unlike the rest of the _ex family.
	// Zero for a count in a register or no bytes.
	CountArg uint8 `json:"count_arg,omitempty"`

	// Early marks the functions carrying TLS 1.3 early data: ordinary stream
	// bytes, but replayable and not forward-secret, so worth recording.
	Early bool `json:"early,omitempty"`
}

// Count is where a function reports its byte count, which decides whether a
// register-only probe can measure it.
type Count int

const (
	// CountNone is a function that moves no bytes: a connection ending.
	CountNone Count = iota

	// CountReturned is a function returning the byte count: a register.
	CountReturned

	// CountOutParameter is a function returning a status and writing the count
	// through a pointer: a memory read, so a register-only probe sees only that
	// the call happened.
	CountOutParameter
)

// Runtime is one TLS implementation as the catalogue describes it.
type Runtime struct {
	Name string

	// Prefixes is what a member of this runtime's plaintext family looks like, so
	// uncatalogued exports can be found.
	Prefixes []string

	Functions []Function

	// Lifecycle is what the runtime calls when a connection ends. Without it a
	// reused endpoint continues the previous connection's stream, invisibly.
	Lifecycle []Function
}

// OpenSSL is the plaintext-moving family of OpenSSL's libssl, read off real
// libraries: libssl.so.3 of OpenSSL 3.5.6 exports all nine, 3.3.2 all but the
// two peeks. Since is the release that introduced the function, not the
// symbol's version node (OPENSSL_3.0.0 for all but SSL_write_ex2).
var OpenSSL = Runtime{
	Name:     "openssl",
	Prefixes: []string{"SSL_read", "SSL_write", "SSL_peek"},
	Functions: []Function{
		{Symbol: "SSL_read", Since: "0.9.8", Direction: fragment.Received, Probed: true, Count: CountReturned},
		{Symbol: "SSL_write", Since: "0.9.8", Direction: fragment.Sent, Probed: true, Count: CountReturned},
		{Symbol: "SSL_read_ex", Since: "1.1.1", Direction: fragment.Received, Probed: true, Count: CountOutParameter, CountArg: 4},
		{Symbol: "SSL_write_ex", Since: "1.1.1", Direction: fragment.Sent, Probed: true, Count: CountOutParameter, CountArg: 4},
		// TLS 1.3 early data: application bytes sent before the handshake finishes.
		{Symbol: "SSL_read_early_data", Since: "1.1.1", Direction: fragment.Received, Probed: true, Count: CountOutParameter, CountArg: 4, Early: true},
		{Symbol: "SSL_write_early_data", Since: "1.1.1", Direction: fragment.Sent, Probed: true, Count: CountOutParameter, CountArg: 4, Early: true},
		{Symbol: "SSL_write_ex2", Since: "3.3.0", Direction: fragment.Sent, Probed: true, Count: CountOutParameter, CountArg: 5},
		// A peek's bytes are returned again by the next read, so they are taken there.
		{
			Symbol: "SSL_peek", Since: "0.9.8", Direction: fragment.Received, Count: CountReturned,
			Note: "a peek returns bytes a later read returns again, and the read is where they are taken",
		},
		{
			Symbol: "SSL_peek_ex", Since: "1.1.1", Direction: fragment.Received, Count: CountOutParameter,
			Note: "a peek returns bytes a later read returns again, and the read is where they are taken",
		},
	},
	Lifecycle: []Function{
		// The SSL object identifies a connection, and its address is reused.
		{Symbol: "SSL_free", Since: "0.9.8", Probed: true},
	},
}

// Probed is the functions the observer attaches to.
func (r Runtime) Probed() []Function {
	probed := make([]Function, 0, len(r.Functions))
	for _, function := range r.Functions {
		if function.Probed {
			probed = append(probed, function)
		}
	}
	return probed
}

// Symbols is every function name the catalogue names for this runtime, probed
// or not.
func (r Runtime) Symbols() []string {
	symbols := make([]string, 0, len(r.Functions))
	for _, function := range r.Functions {
		symbols = append(symbols, function.Symbol)
	}
	return symbols
}

// Lookup finds a catalogued function by symbol, in the plaintext family and
// the lifecycle: both are attached, and dropping lifecycle probes would let
// reused addresses continue old streams.
func (r Runtime) Lookup(symbol string) (Function, bool) {
	for _, function := range append(r.Functions, r.Lifecycle...) {
		if function.Symbol == symbol {
			return function, true
		}
	}
	return Function{}, false
}

// Family reports whether a symbol looks like a member of this runtime's
// plaintext family.
func (r Runtime) Family(symbol string) bool {
	for _, prefix := range r.Prefixes {
		if strings.HasPrefix(symbol, prefix) {
			return true
		}
	}
	return false
}

// ExpectedIn is the catalogued functions a library of this version should
// export. An unknown version expects nothing.
func (r Runtime) ExpectedIn(version string) []Function {
	if version == "" {
		return nil
	}

	var expected []Function
	for _, function := range r.Functions {
		if compare(function.Since, version) <= 0 {
			expected = append(expected, function)
		}
	}
	return expected
}

// compare orders two dotted release numbers; a non-numeric component compares
// as 0.
func compare(left, right string) int {
	leftParts, rightParts := strings.Split(left, "."), strings.Split(right, ".")
	for i := 0; i < len(leftParts) || i < len(rightParts); i++ {
		if difference := number(leftParts, i) - number(rightParts, i); difference != 0 {
			return difference
		}
	}
	return 0
}

func number(parts []string, at int) int {
	if at >= len(parts) {
		return 0
	}
	// A release like 1.1.1a carries a letter; only the number counts.
	digits := parts[at]
	for i, c := range digits {
		if c < '0' || c > '9' {
			digits = digits[:i]
			break
		}
	}
	value, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return value
}
