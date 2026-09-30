package config

// The two documents a user writes, each with a version of its own, so a pack
// given as a configuration, or the reverse, is refused by its version and a
// later format cannot silently reinterpret an older file.
const (
	FileVersion = "observer.config/1"
	PackVersion = "observer.pack/1"
)

// Which descendants of a watched process are watched too.
const (
	// ChildrenAll is the ones running when the watch is resolved and every one
	// created afterwards. The default.
	ChildrenAll = "all"
	// ChildrenExisting is the ones running when the watch is resolved.
	ChildrenExisting = "existing"
	ChildrenNone     = "none"
)

// LogStdout is the log value that sends the log to standard output alone. It is
// the default.
const LogStdout = "stdout"

// The route every approved line names: a published constant, not something the
// user names.
const (
	ExchangesPipeline   = "exchanges"
	ConnectionsPipeline = "connections"
	AccountSink         = "account"
	LocalAccountKind    = "local_account"
)

// The inputs of the two fixed pipelines.
const (
	ReconstructionInput = "reconstruction"
	ConnectionInput     = "connection"
)

// What a user can reach, per rule key, counted over the configuration and its
// packs together: distinct names or pointers. One operation takes at most
// MaxFieldSelectors of them, so the merged rules never compile to one the
// internal layer would refuse.
const (
	MaxRemovedHeaders   = MaxHeaderNames
	MaxMaskedHeaders    = MaxHeaderNames
	MaxTruncatedHeaders = MaxHeaderNames
	MaxRuleNames        = MaxFieldSelectors
	MaxRulePointers     = MaxFieldSelectors
)

// The largest values of limits, so a limit a user can write never overflows
// what it is multiplied into: output_mib into bytes, events into the intake's
// byte allowance at the decoder's per-event payload ceiling, and
// state_every_seconds into a duration.
const (
	MaxOutputMiB         int64 = (1<<63 - 1) >> 20
	MaxEventPayloadBytes int64 = 4096
	MaxEvents            int64 = (1<<63 - 1) / MaxEventPayloadBytes
	MaxStateEverySeconds int64 = (1<<63 - 1) / 1_000_000_000
)

// Refusal reasons of the reader and the compiler, in the user's terms. Every
// one names the document and the key it is about.
const (
	UnknownKey      Reason = "unknown_key"
	DuplicateKey    Reason = "duplicate_key"
	WrongType       Reason = "wrong_type"
	TrailingContent Reason = "trailing_content"
	MissingKey      Reason = "missing_key"
	InvalidValue    Reason = "invalid_value"
	LimitExceeded   Reason = "limit_exceeded"
	// RuleConflict is two rules that would keep different values for one field.
	// Removal is never one of them: it wins over every other rule.
	RuleConflict Reason = "rule_conflict"
	// InternalDefect is a refusal from the layer below the reader, or a plan that
	// does not enforce what the documents ask. It is the observer's defect,
	// never the user's error, and it fails closed.
	InternalDefect Reason = "internal_defect"
)

// File is the configuration a user writes, as read.
type File struct {
	Output string
	Log    string

	Watch     []Watch
	Ignore    []Match
	Libraries []Library

	// WriteContent false writes connection records only. Plaintext is still
	// read into memory and processed; it is never written.
	WriteContent bool

	Rules  Rules
	Limits Limits

	// Packs are the packs enabled, by name, in the order written.
	Packs []string
}

// Watch is one program to watch: a name, the conditions that select it, and
// which of its descendants are watched too.
type Watch struct {
	Name     string
	Match    Match
	Children string
}

// Limits are the three observer settings, with every absent one resolved to
// its default.
type Limits struct {
	OutputMiB         int64
	Events            int64
	StateEverySeconds int64
}

// Pack is a pack as read: rules it adds to the configuration's. It cannot
// weaken them.
type Pack struct {
	Name  string
	Rules Rules
}

// Rules are what one document asks to be removed, masked and truncated, in the
// order written. Header names are kept as written; they compare ignoring case.
type Rules struct {
	Remove   Remove
	Mask     Mask
	Truncate Truncate
}

// Remove is every removal. Each entry is a guarantee: it is recorded as a
// mandatory exclusion, and the observer refuses to start when it cannot
// enforce one.
type Remove struct {
	Headers     []string
	Query       []string
	QueryString bool
	Form        []string
	JSON        MessagePointers
	Bodies      []string
	BodyValues  []string
}

// MessagePointers are JSON pointers keyed by the message they apply to.
type MessagePointers struct {
	Request  []string
	Response []string
}

// Mask replaces a value and keeps the field. It never counts as removal.
type Mask struct {
	Headers []NamedValue
	JSON    MessageValues
}

// MessageValues are JSON pointers with the value each is masked with, keyed by
// message.
type MessageValues struct {
	Request  []NamedValue
	Response []NamedValue
}

// NamedValue is one header name or JSON pointer and the value written in its
// place.
type NamedValue struct {
	Name  string
	Value string
}

// Truncate keeps at most Length bytes of each named header's value.
type Truncate struct {
	Headers []NamedLength
}

// NamedLength is one header name and the length its value is truncated to.
type NamedLength struct {
	Name   string
	Length int
}
