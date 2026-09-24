// Package account is the Go form of the published account contract - what a
// session says about its scope, coverage, provenance, losses, what it could not
// establish and what processing did - and of the offline bundle carrying a
// sealed account with the records it describes. ACCOUNT.md beside this file is
// the contract; where the two disagree, the document is corrected first.
//
// Every block says whether it is carried, and a reader that cannot find a
// required block refuses rather than reading zeros.
package account

import (
	"encoding/json"

	"github.com/evandukss/edge-observer/contract/record"
)

// The versions this draft names. No machine-readable schema is published;
// example JSON files show the shapes, and the Go validators enforce the contracts.
const (
	Version       = "observer.account/1-draft"
	BundleVersion = "observer.bundle/1-draft"
)

// OperationalVersion is the version of the operational account (package
// account at the module root) that this account is projected from.
const OperationalVersion = 1

// ManifestName is the file at the root of a bundle that names its members.
const ManifestName = "bundle.json"

// Moment is which of the three moments an account describes.
type Moment string

const (
	Planned Moment = "planned"
	Live    Moment = "live"
	Sealed  Moment = "sealed"
)

// BlockState is whether a block is carried, and if not, which absence it is.
// No absence is zero, and a block missing from the document is refused.
type BlockState string

const (
	// Carried is a block whose members are present and read.
	Carried BlockState = "carried"
	// Unavailable is a block the producer tried to read and could not; Why
	// says what failed.
	Unavailable BlockState = "unavailable"
	// NotReached is a block the moment precedes: a planned account has no
	// capture, and only a sealed one has a seal.
	NotReached BlockState = "not_reached"
	// NotCarried is a block this contract names and this producer does not
	// supply at all. It is never a reading of the session.
	NotCarried BlockState = "not_carried"
)

// RequiredBlocks is the dotted path of every required block: required wherever
// its parent is Carried, and refused if absent.
var RequiredBlocks = []string{
	"provenance", "provenance.observer", "provenance.configuration", "provenance.pipelines",
	"scope", "scope.requested", "scope.instances", "scope.overlap", "scope.placement", "scope.coverage",
	"scope.filters",
	"capture", "capture.capability", "capture.seen", "capture.loss", "capture.admitted", "capture.ordering",
	"capture.refused", "capture.spool",
	"reconstruction", "processing", "requirements", "seal", "seal.recorded",
}

// Block is the state every block carries.
type Block struct {
	State BlockState `json:"state"`
	Why   string     `json:"why,omitempty"`
}

// Account is one session's account.
type Account struct {
	Account        string         `json:"account"`
	Session        string         `json:"session"`
	Moment         Moment         `json:"moment"`
	At             record.Instant `json:"at"`
	Provenance     Provenance     `json:"provenance"`
	Scope          Scope          `json:"scope"`
	Capture        Capture        `json:"capture"`
	Reconstruction Reconstruction `json:"reconstruction"`
	Processing     Processing     `json:"processing"`
	Requirements   Requirements   `json:"requirements"`
	Seal           Seal           `json:"seal"`

	// Extensions is namespaced pack material, under its own member so nothing in
	// it can stand where a core block stands.
	Extensions map[string]Extension `json:"extensions"`
}

// Extension is one namespace's material and the schema it declares.
type Extension struct {
	Schema  string          `json:"schema"`
	Content json.RawMessage `json:"content"`
}

// Provenance is what produced the account and against what configuration.
type Provenance struct {
	Block
	Observer      Observer      `json:"observer"`
	Contracts     []string      `json:"contracts"`
	Configuration Configuration `json:"configuration"`
	Pipelines     Pipelines     `json:"pipelines"`
}

// Observer is what the build that wrote the account can do, and the kernel
// floor it publishes: claims about the build, not the session.
type Observer struct {
	Block
	Facts
	Floor Floor `json:"floor"`
}

// Facts is what an attachment mechanism can report, decided at build or
// attach.
type Facts struct {
	Backend        string     `json:"backend"`
	Program        string     `json:"program"`
	MinimumKernel  string     `json:"minimum_kernel"`
	Payload        bool       `json:"payload"`
	Filtered       bool       `json:"filtered"`
	Descendants    bool       `json:"descendants"`
	Lifecycle      bool       `json:"lifecycle"`
	Binding        bool       `json:"binding"`
	SocketEvidence bool       `json:"socket_evidence"`
	IPv6           bool       `json:"ipv6"`
	Unobserved     []string   `json:"unobserved"`
	Withheld       []Withheld `json:"withheld"`
}

// Withheld is a member of a capability the mechanism does not report, and why.
type Withheld struct {
	Claim  string `json:"claim"`
	Member string `json:"member"`
	Reason string `json:"reason,omitempty" account:"optional"`
}

// Floor is the oldest kernel the build publishes and whether that is proved.
type Floor struct {
	Published      string `json:"published"`
	Proved         bool   `json:"proved"`
	Established    string `json:"established"`
	WouldEstablish string `json:"would_establish"`
}

// Configuration is the configuration the session ran under, by reference:
// name, content revision and activated generation. Never its content.
type Configuration struct {
	Block
	References []ConfigurationReference `json:"references"`
}

// ConfigurationReference is one configuration document by reference.
type ConfigurationReference struct {
	Document   string `json:"document"`
	Revision   string `json:"revision"`
	Generation string `json:"generation,omitempty" account:"count"`
}

// Pipelines is the effective pipelines and every component's version.
type Pipelines struct {
	Block
	Pipelines []Pipeline `json:"pipelines"`
}

// Pipeline is one effective pipeline as the configuration check resolved it.
type Pipeline struct {
	Name       string         `json:"name"`
	Input      string         `json:"input"`
	DeclaredBy string         `json:"declared_by"`
	Slots      []PipelineSlot `json:"slots"`
	Sinks      []string       `json:"sinks"`
}

// PipelineSlot is one slot, what fills it, at which version, and who selected it.
type PipelineSlot struct {
	Slot           string `json:"slot"`
	Implementation string `json:"implementation"`
	Version        string `json:"version"`
	SelectedBy     string `json:"selected_by"`
}

// Scope is what was asked for, what it resolved to, and what the session's
// coverage turned out to be.
type Scope struct {
	Block
	Requested  Requested   `json:"requested"`
	Targets    []Target    `json:"targets"`
	Exclusions []Exclusion `json:"exclusions"`
	Overlap    Overlap     `json:"overlap"`
	Placement  Placement   `json:"placement"`
	Coverage   Coverage    `json:"coverage"`

	// Instances is every instance the scope named, each with its coverage stated.
	Instances Instances `json:"instances"`
	Filters   Filters   `json:"filters"`
	Limits    []string  `json:"limits"`
}

// The three controls, as separate references.
const (
	ObservationScope   = "observation_scope"
	TrafficScope       = "traffic_scope"
	RetentionAndExport = "retention_and_export"
)

// Requested is the three controls as the configuration stated them, by
// reference.
type Requested struct {
	Block
	Controls []Control `json:"controls"`
}

// Control is one control by reference. One this producer does not read is
// NotCarried, not empty.
type Control struct {
	Block
	Control  string `json:"control" account:"identity"`
	Document string `json:"document,omitempty"`
	Revision string `json:"revision,omitempty"`
	Member   string `json:"member,omitempty"`
}

// Instance is one process as the scope names it. Never its arguments.
type Instance struct {
	PID          int32            `json:"pid"`
	PidNamespace record.Namespace `json:"pid_namespace"`
	NamespacePID int32            `json:"namespace_pid"`
	Birth        record.Birth     `json:"birth"`
	Executable   record.Text      `json:"executable"`
}

// Descendants is the five answers a target's descendant policy gives.
type Descendants struct {
	Existing    bool   `json:"existing"`
	Future      bool   `json:"future"`
	Boundary    string `json:"boundary"`
	RootExit    string `json:"root_exit"`
	Replacement string `json:"replacement"`
}

// Target is one selection rule and what it resolved to.
type Target struct {
	Number      int           `json:"number"`
	Name        string        `json:"name"`
	Mode        string        `json:"mode"`
	Descendants Descendants   `json:"descendants"`
	Resolution  Block         `json:"resolution"`
	Roots       []Instance    `json:"roots"`
	Existing    []Instance    `json:"existing_descendants"`
	Denied      []Instance    `json:"denied"`
	Unsupported []Unsupported `json:"unsupported"`

	// Cgroups is the cgroup a cgroup target named, as resolved; Listeners the
	// sockets a port target resolved to.
	Cgroups   []Cgroup   `json:"cgroups"`
	Listeners []Listener `json:"listeners"`
}

// Cgroup is the object a cgroup target's path named when it was resolved.
type Cgroup struct {
	Path  string      `json:"path"`
	Inode record.Text `json:"inode"`
	Why   string      `json:"why,omitempty" account:"optional"`
}

// Listener is one listening socket a port target resolved to, and the pids
// (observer's namespace) holding it.
type Listener struct {
	Address string  `json:"address"`
	Owners  []int32 `json:"owners"`
}

// Unsupported is a selected process no adapter can observe: eligible and
// uncovered, not absent.
type Unsupported struct {
	Instance Instance `json:"instance"`
	Reason   string   `json:"reason"`
}

// Exclusion is one exclusion and what it denied.
type Exclusion struct {
	Number int        `json:"number"`
	Roots  []Instance `json:"roots"`
	Denied []Instance `json:"denied"`
}

// Overlap is every instance more than one target selected.
type Overlap struct {
	Block
	Instances []Overlapping `json:"instances"`
}

// Overlapping is one instance and the targets that selected it.
type Overlapping struct {
	Instance Instance `json:"instance"`
	Targets  []string `json:"targets"`
}

// Placement is what was attached per process, and where fewer probes were
// placed than asked.
type Placement struct {
	Block
	Processes []Placed `json:"processes"`
}

// Placed is one process's attachment. Its identity is not unique under pid
// reuse while the birth is undetermined; the birth reaching the event removes
// that.
type Placed struct {
	PID          int32            `json:"pid"`
	Birth        record.Birth     `json:"birth"`
	PidNamespace record.Namespace `json:"pid_namespace"`
	NamespacePID record.Text      `json:"namespace_pid"`
	Executable   record.Text      `json:"executable"`
	Runtime      string           `json:"runtime"`
	Mode         string           `json:"mode"`
	Capability   Facts            `json:"capability"`
	Outcome      string           `json:"outcome"`
	Reason       string           `json:"reason,omitempty" account:"optional"`
	Requested    int              `json:"requested"`
	Confirmed    int              `json:"confirmed"`
	Partial      bool             `json:"partial"`
	Probes       []Probe          `json:"probes"`
	Unattempted  []string         `json:"unattempted"`
	Uncatalogued []string         `json:"uncatalogued"`
	Absent       []string         `json:"absent"`
}

// Probe is one entry point a probe was asked for, and what the kernel said.
type Probe struct {
	Symbol    string `json:"symbol"`
	Path      string `json:"path"`
	Offset    string `json:"offset" account:"count"`
	Confirmed bool   `json:"confirmed"`
	Through   string `json:"through,omitempty" account:"optional"`
	Refusal   string `json:"refusal,omitempty" account:"optional"`
}

// Instances is per-instance coverage over every instance the scope named.
type Instances struct {
	Block
	Instances []InstanceCoverage `json:"instances"`
}

// The coverage one instance can have, mutually exclusive. Multiple selection
// is its own member.
const (
	// Covered is an instance attached with every probe it was asked for.
	Covered = "covered"
	// PartiallyCovered is an instance attached with fewer probes than asked.
	PartiallyCovered = "partially_covered"
	// NotCovered is an instance selected and not attached, or unobservable; Why
	// says which.
	NotCovered = "not_covered"
	// Excluded is an instance an exclusion removed.
	Excluded = "excluded"
	// CoverageUndetermined is an instance whose coverage nothing establishes. Never
	// read as not covered.
	CoverageUndetermined = "undetermined"
)

// InstanceCoverage is one instance and its coverage.
type InstanceCoverage struct {
	Instance Instance `json:"instance"`

	// SelectedBy is every target that selected the instance.
	SelectedBy       []string `json:"selected_by"`
	MultiplySelected bool     `json:"multiply_selected"`

	// ExcludedBy is what removed it: "target:<name>" or "exclusion:<number>".
	ExcludedBy []string `json:"excluded_by"`

	Coverage string `json:"coverage"`
	Why      string `json:"why,omitempty" account:"optional"`

	// Evidence is the references establishing the coverage (ACCOUNT.md, Evidence
	// references); empty where undetermined.
	Evidence []string `json:"evidence"`
}

// Coverage is coverage over every admission the session recorded.
type Coverage struct {
	Block
	Rule          string           `json:"rule"`
	Covered       string           `json:"covered,omitempty" account:"count"`
	ByTarget      []TargetCoverage `json:"by_target"`
	CoverageEnded []Admission      `json:"coverage_ended"`
	GrantUnknown  []Admission      `json:"grant_unknown"`
}

// TargetCoverage is one target's share of the admissions.
type TargetCoverage struct {
	Target  string `json:"target"`
	Covered string `json:"covered,omitempty" account:"count"`
	Ended   string `json:"ended,omitempty" account:"count"`
	Unknown string `json:"unknown,omitempty" account:"count"`
}

// Admission is one admission whose coverage ended or whose grant was not read.
// NoLaterThan and Read are undetermined where there is none.
type Admission struct {
	Instance    Instance       `json:"instance"`
	Target      string         `json:"target"`
	Inherited   bool           `json:"inherited"`
	NoLaterThan record.Instant `json:"no_later_than"`
	ReadFrom    record.Instant `json:"read_from"`
	ReadTo      record.Instant `json:"read_to"`
	Why         string         `json:"why,omitempty" account:"optional"`
}

// The stages a traffic filter acts at. A filter needing reconstruction acts
// after plaintext was copied, never evidence about what was read.
const (
	PreCapture  = "pre_capture"
	PostCapture = "post_capture"
)

// Filters is every traffic filter and the stage it acts at.
type Filters struct {
	Block
	Filters []Filter `json:"filters"`
}

// Filter is one traffic filter.
type Filter struct {
	Name  string `json:"name"`
	Stage string `json:"stage"`
}

// Capture is what the attachment could report, what came through and what was
// lost, each its own block.
type Capture struct {
	Block
	Capability Capability `json:"capability"`
	Seen       Seen       `json:"seen"`
	Loss       Loss       `json:"loss"`
	Admitted   Admitted   `json:"admitted"`
	Ordering   Ordering   `json:"ordering"`
	Refused    Refusals   `json:"refused"`
	Spool      Spool      `json:"spool"`
}

// Capability is what the attachment can report, and the observer's sentence
// saying so.
type Capability struct {
	Block
	Facts
	Sentence string `json:"sentence"`
}

// Seen is what capture saw and placed. Counts are decimal strings.
type Seen struct {
	Block
	Transfers   string `json:"transfers,omitempty" account:"count"`
	Unmeasured  string `json:"unmeasured,omitempty" account:"count"`
	Empty       string `json:"empty,omitempty" account:"count"`
	Records     string `json:"records,omitempty" account:"count"`
	Connections string `json:"connections,omitempty" account:"count"`
	Closed      string `json:"closed,omitempty" account:"count"`
	Early       string `json:"early,omitempty" account:"count"`

	// Rejected, Unattributed and EndingsUnmatched are what capture could not
	// place.
	Rejected         string `json:"rejected,omitempty" account:"count"`
	Unattributed     string `json:"unattributed,omitempty" account:"count"`
	EndingsUnmatched string `json:"endings_unmatched,omitempty" account:"count"`

	// ConnectionsUnrecorded is connections capture placed and could not record.
	ConnectionsUnrecorded string `json:"connections_unrecorded,omitempty" account:"count"`
}

// Loss is what the kernel side discarded. Losses only.
type Loss struct {
	Block
	Dropped   string   `json:"dropped,omitempty" account:"count"`
	Unmatched string   `json:"unmatched,omitempty" account:"count"`
	Occasion  Occasion `json:"occasion"`
}

// Occasion is when unmatched returns were seen (the host's monotonic clock),
// and the first one's handle, process and thread.
type Occasion struct {
	First  record.Instant `json:"first"`
	Last   record.Instant `json:"last"`
	Handle record.Text    `json:"handle"`
	PID    record.Text    `json:"pid"`
	TID    record.Text    `json:"tid"`
}

// Admitted is what the kernel admitted on its own account. It is not a loss.
type Admitted struct {
	Block
	Descendants string `json:"descendants,omitempty" account:"count"`
}

// Ordering is whether observations could be placed in production order, and
// what a break cost. Never folded into Loss.
type Ordering struct {
	Block
	Disordered  string `json:"disordered,omitempty" account:"count"`
	Unstamped   string `json:"unstamped,omitempty" account:"count"`
	Tolerated   string `json:"tolerated,omitempty" account:"count"`
	Lost        string `json:"lost,omitempty" account:"count"`
	Retired     string `json:"retired,omitempty" account:"count"`
	Unexplained string `json:"unexplained,omitempty" account:"count"`
}

// Refusals is what the kernel program refused, by reason.
type Refusals struct {
	Block
	Reasons map[string]string `json:"reasons"`
}

// Spool is what the spool kept, dropped and refused.
type Spool struct {
	Block
	Written            string `json:"written,omitempty" account:"count"`
	Dropped            string `json:"dropped,omitempty" account:"count"`
	Refused            string `json:"refused,omitempty" account:"count"`
	Connections        string `json:"connections,omitempty" account:"count"`
	ConnectionsDropped string `json:"connections_dropped,omitempty" account:"count"`
	ConnectionsRefused string `json:"connections_refused,omitempty" account:"count"`
	Bytes              string `json:"bytes,omitempty" account:"count"`
	Limit              string `json:"limit,omitempty" account:"count"`
}

// Reconstruction is the session's reconstruction in totals; per-connection
// status is in the bundle's reconstruction records.
type Reconstruction struct {
	Block
	Connections string `json:"connections,omitempty" account:"count"`
	Exchanges   string `json:"exchanges,omitempty" account:"count"`
	Complete    string `json:"complete,omitempty" account:"count"`
	Discards    string `json:"discards,omitempty" account:"count"`
	Duplicates  string `json:"duplicates,omitempty" account:"count"`
	Unplaced    string `json:"unplaced,omitempty" account:"count"`
}

// Processing is what the configured pipelines did with what capture delivered.
type Processing struct {
	Block
	Pipelines []Processed `json:"pipelines"`
}

// Processed is one pipeline's dispositions.
type Processed struct {
	Pipeline   string    `json:"pipeline"`
	Activation string    `json:"activation"`
	Received   string    `json:"received,omitempty" account:"count"`
	Suppressed []Counted `json:"suppressed"`
	Failed     []Counted `json:"failed"`
	Outputs    []Output  `json:"outputs"`
}

// Counted is a count attributed to what produced it and why.
type Counted struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
	Count  string `json:"count,omitempty" account:"count"`
}

// Output is what one sink was handed and what became of it.
type Output struct {
	Sink        string `json:"sink"`
	Disposition string `json:"disposition"`
	Count       string `json:"count,omitempty" account:"count"`
}

// Requirements is every declaration's disposition: what the core enforces,
// apart from what an extension declares.
type Requirements struct {
	Block
	CoreEnforced      []Enforced `json:"core_enforced"`
	ExtensionDeclared []Declared `json:"extension_declared"`
	Refused           []Declared `json:"refused"`
}

// Enforced is a requirement the core accepted and enforces, with its scope:
// enforcement point, what it covers and does not, and the sink where relevant.
type Enforced struct {
	Declaration      string        `json:"declaration"`
	Operation        string        `json:"operation"`
	EnforcementPoint string        `json:"enforcement_point"`
	Covers           string        `json:"covers"`
	DoesNotCover     string        `json:"does_not_cover"`
	Sink             *EnforcedSink `json:"sink,omitempty" account:"optional"`
	Pipelines        []string      `json:"pipelines"`
}

// EnforcedSink is the sink an acceptance targets, as the runtime inventory
// knows it, including whether it leaves the host or keeps plaintext.
type EnforcedSink struct {
	Kind             string `json:"kind"`
	LeavesHost       bool   `json:"leaves_host"`
	RetainsPlaintext bool   `json:"retains_plaintext"`
}

// Declared is a declaration the core does not enforce: an allowed trusted claim
// with its limitation, or a refused declaration.
type Declared struct {
	Declaration string   `json:"declaration"`
	DeclaredBy  string   `json:"declared_by"`
	Disposition string   `json:"disposition"`
	Reason      string   `json:"reason"`
	Limitation  string   `json:"limitation,omitempty" account:"optional"`
	Pipelines   []string `json:"pipelines"`
}

// Seal is how the session ended and the members it sealed, with record counts.
type Seal struct {
	Block
	Stopped     record.Instant `json:"stopped"`
	Sealed      record.Instant `json:"sealed"`
	Complete    bool           `json:"complete"`
	Because     []string       `json:"because"`
	Withdrawal  Withdrawal     `json:"withdrawal"`
	Drain       Drain          `json:"drain"`
	Interrupted record.Count   `json:"interrupted"`

	// Counters is every counter the seal holds, by the observer's own name.
	Counters  map[string]record.Count `json:"counters"`
	Conserved []Identity              `json:"conserved"`
	Recorded  Recorded                `json:"recorded"`
	Members   []SealedMember          `json:"members"`
}

// Withdrawal is capture authority being withdrawn.
type Withdrawal struct {
	At        record.Instant `json:"at"`
	Instances string         `json:"instances" account:"count"`
	Complete  bool           `json:"complete"`
	Because   string         `json:"because,omitempty" account:"optional"`
}

// Drain is what was delivered after authority was withdrawn, and what was not.
type Drain struct {
	Delivered   record.Count `json:"delivered"`
	Outstanding record.Count `json:"outstanding"`
	Complete    bool         `json:"complete"`
	Because     string       `json:"because,omitempty" account:"optional"`
}

// Identity is one conservation identity over the seal's counters, as the
// observer evaluated it.
type Identity struct {
	Name  string       `json:"name"`
	Left  record.Count `json:"left"`
	Right record.Count `json:"right"`
	// Holds is "holds", "does_not_hold", or "not_evaluated".
	Holds string `json:"holds"`
}

// Recorded is whether every descriptor lifetime, binding and denial seen could
// be recorded; Unavailable where any count could not be read.
type Recorded struct {
	Block
	Complete bool `json:"complete"`
}

// SealedMember is one record member as the seal names it: role, digest and
// record count. It binds a bundle's records to this session.
type SealedMember struct {
	Role    string `json:"role"`
	SHA256  string `json:"sha256"`
	Records string `json:"records,omitempty" account:"count"`
}
