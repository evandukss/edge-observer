package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

// additive decides whether a candidate policy only adds to the one in force,
// naming the targets it adds, or says what it takes away. Reload adds; restart
// takes away. Removing a target, changing an exclusion, where the observer
// writes, which libraries may be probed, or a kept target's conditions or mode
// is refused with the reason, and one forbidden change refuses the whole
// candidate. A target needing a library nothing has attached is decided where
// libraries are known (set.Admit).
func additive(current, candidate policy.Policy) ([]process.Rule, string) {
	if current.Settings != candidate.Settings {
		return nil, "the candidate changes where the observer writes or how often it restates its state, " +
			"which a restart applies"
	}
	if !sameLibraries(current.Approval.Libraries, candidate.Approval.Libraries) {
		return nil, "the candidate changes which library builds a probe may be placed on, which a restart applies"
	}

	for i, exclusion := range candidate.Approval.Exclusions {
		if !slices.ContainsFunc(current.Approval.Exclusions, func(held process.Rule) bool { return sameRule(held, exclusion) }) {
			return nil, fmt.Sprintf("the candidate adds an exclusion (exclusion %d): a denial of something "+
				"already observed is a withdrawal, and a restart is how anything is taken away", i+1)
		}
	}
	for i, exclusion := range current.Approval.Exclusions {
		if !slices.ContainsFunc(candidate.Approval.Exclusions, func(offered process.Rule) bool { return sameRule(exclusion, offered) }) {
			return nil, fmt.Sprintf("the candidate removes an exclusion (exclusion %d), which a restart applies", i+1)
		}
	}

	for _, held := range current.Approval.Rules {
		index := slices.IndexFunc(candidate.Approval.Rules, func(offered process.Rule) bool { return offered.Name == held.Name })
		if index < 0 {
			return nil, fmt.Sprintf("the candidate removes target %s, and a restart is how anything is taken away", held.Name)
		}
		if !sameRule(held, candidate.Approval.Rules[index]) {
			return nil, fmt.Sprintf("the candidate changes target %s, which removes the target it was; a "+
				"restart applies it", held.Name)
		}
	}

	var added []process.Rule
	for _, offered := range candidate.Approval.Rules {
		if !slices.ContainsFunc(current.Approval.Rules, func(held process.Rule) bool { return held.Name == offered.Name }) {
			added = append(added, offered)
		}
	}
	return added, ""
}

// sameRule compares every condition a rule names and its mode, telling a
// written argument list from an absent one.
func sameRule(one, other process.Rule) bool {
	guard := func(rule process.Rule) process.PIDGuard {
		if rule.PID == nil {
			return process.PIDGuard{}
		}
		return *rule.PID
	}
	return one.Name == other.Name && one.Executable == other.Executable &&
		(one.Arguments == nil) == (other.Arguments == nil) && slices.Equal(one.Arguments, other.Arguments) &&
		one.Cgroup == other.Cgroup && (one.PID == nil) == (other.PID == nil) && guard(one) == guard(other) &&
		one.Port == other.Port && one.Interface == other.Interface && one.Mode == other.Mode
}

func sameLibraries(one, other []process.LibraryApproval) bool {
	encode := func(libraries []process.LibraryApproval) string {
		content, _ := json.Marshal(libraries)
		return string(content)
	}
	return encode(one) == encode(other)
}

// reloadRecord is what a reload answers and logs: the outcome, the generation
// in force afterwards, and why where refused.
type reloadRecord struct {
	Record     string    `json:"record"`
	Version    int       `json:"version"`
	Session    string    `json:"session"`
	At         time.Time `json:"at"`
	Outcome    string    `json:"outcome"`
	Generation int       `json:"generation"`
	Revision   string    `json:"revision"`
	Reason     string    `json:"reason,omitempty"`
	Added      []string  `json:"added,omitempty"`
	Admitted   int       `json:"admitted"`
	Skipped    []string  `json:"skipped,omitempty"`
	Retracted  []string  `json:"retracted,omitempty"`
	Bound      string    `json:"bound,omitempty"`
}

// reloadBound is stated in every reload record: the one window reload does not
// close.
const reloadBound = "the window between the reload command's reading and this session's write is closed " +
	"against pid reuse and open against exec: a process that execs inside it keeps its pid and its start, " +
	"and the kernel's exec hook finds no grant yet to revoke. This session re-reads each process's name and " +
	"command line before its write and after it, which narrows the window and does not close it - the name " +
	"is fifteen bytes the process chooses and the command line is memory the process may rewrite"

// reloadRequest is what the reload command read, with its privileges, for a
// session that dropped them: the candidate's resolution, the selected
// processes, their files, and why any could not be read.
type reloadRequest struct {
	Revision   string                  `json:"revision"`
	Resolution process.Resolution      `json:"resolution"`
	Processes  []process.Process       `json:"processes"`
	Read       map[int32]probe.Reading `json:"read"`
	Unread     map[int32]string        `json:"unread,omitempty"`
}

// unchanged says whether p still runs what the reload command read, from what
// a capability-less session can still read, naming any change.
//
// The session re-checks and the command resolves: after privilege.Drop the
// session cannot read /proc/<pid>/exe, maps, root or namespace links of other
// users' processes, so resolving here would admit nothing. It takes the support
// verdict, file ids, namespaces, executable and arguments from the command
// (a root command writing a root-owned control directory) and re-checks:
//
//	the start        a reused pid starts at another tick, so reuse is refused
//	name, cmdline    an ordinary exec changes them
//
// The second row is advisory: the name is 15 bytes the process chooses and the
// command line is memory it may rewrite. An exec keeping both is not seen here;
// see reloadBound.
func unchanged(root string, p process.Process, read probe.Reading) (string, bool) {
	now, err := process.ReadExec(root, p.PID)
	switch {
	case os.IsNotExist(err):
		return "it exited after the reload command read it", false
	case err != nil:
		return fmt.Sprintf("it could not be read again, so whether it still runs what the reload command read "+
			"is not known: %v", err), false
	case now.StartTime != p.StartTime || now.StartTime != read.Exec.StartTime:
		return fmt.Sprintf("the pid is held by a process that started at tick %d, and the reload command read "+
			"the one that started at tick %d", now.StartTime, read.Exec.StartTime), false
	case now.Comm != read.Exec.Comm || now.Cmdline != read.Exec.Cmdline:
		return fmt.Sprintf("it execed after the reload command read it: it ran %q and runs %q",
			read.Exec.Comm, now.Comm), false
	}
	return "", true
}

// reload puts in force what the session's configuration now adds, from what
// the reload command read, or refuses and leaves the policy unchanged. A newly
// admitted process gets a fresh generation and coverage from this reload's
// time; nothing already in force is touched.
func (d *daemon) reload(at time.Time, body []byte) reloadRecord {
	record := reloadRecord{
		Record: "reload", Version: recordVersion, Session: d.session, At: at,
		Generation: d.plan.Policy.Generation, Revision: d.plan.Policy.Revision, Bound: reloadBound,
	}
	refuse := func(why string) reloadRecord {
		record.Outcome, record.Reason = "refused", why
		return record
	}

	var request reloadRequest
	if err := json.Unmarshal(body, &request); err != nil {
		return refuse(fmt.Sprintf("the request carries no reading this session can use (%v): the reload "+
			"command reads the candidate for a session that cannot read it itself after attaching", err))
	}
	candidate, err := policy.Load(d.path)
	if err != nil {
		return refuse(err.Error())
	}
	if request.Revision != candidate.Revision {
		return refuse(fmt.Sprintf("the configuration changed between the reload command's reading (%s) and "+
			"this session's (%s), so what was read is not what would be put in force; reload again",
			request.Revision, candidate.Revision))
	}
	added, why := additive(d.policy, candidate)
	if why != "" {
		return refuse(why)
	}
	if len(added) == 0 {
		record.Outcome = "unchanged"
		return record
	}
	admitting, can := d.attached.(probe.Admitting)
	if !can {
		return refuse("this attachment admits nothing after attaching, so a restart applies the candidate")
	}

	names := make(map[string]bool, len(added))
	for _, rule := range added {
		names[rule.Name] = true
		record.Added = append(record.Added, rule.Name)
	}
	// What an added target did not admit is named per target and process, so a
	// reload that admitted nothing is never read as one that admitted everything.
	for _, target := range request.Resolution.Targets {
		if names[target.Name] && target.Unresolved != "" {
			record.Skipped = append(record.Skipped, fmt.Sprintf("target %s: %s", target.Name, target.Unresolved))
		}
	}
	skip := func(pid int32, why string) {
		record.Skipped = append(record.Skipped, fmt.Sprintf("pid %d: %s", pid, why))
	}

	processes := make(map[int32]process.Process, len(request.Processes))
	for _, p := range request.Processes {
		processes[p.PID] = p
	}
	admit := probe.Request{Deny: request.Resolution.Denials, Read: make(map[int32]probe.Reading)}
	attempts := make(map[int32]attachment.Attempt)
	for _, one := range request.Resolution.Selections {
		if !slices.ContainsFunc(one.NamedBy(), func(reason admission.Provenance) bool { return names[reason.Target] }) {
			continue
		}
		p, found := processes[one.ObserverPID]
		read, readFor := request.Read[one.ObserverPID]
		switch {
		case !found || !readFor:
			why := request.Unread[one.ObserverPID]
			if why == "" {
				why = "the reload command sent no reading of it, and this session cannot read it after attaching"
			}
			skip(one.ObserverPID, why)
			continue
		case !read.Report.Supported:
			skip(p.PID, read.Report.Reason())
			continue
		}
		// Before the write (unchanged says what this can and cannot see).
		if why, same := unchanged(procfs, p, read); !same {
			skip(p.PID, why)
			continue
		}
		admit.Processes = append(admit.Processes, p)
		admit.Admit = append(admit.Admit, one)
		admit.Read[p.PID] = read
		attempts[p.PID] = attachment.Attempt{Process: p, Admitted: one, Alive: true, Support: read.Report,
			Catalogued: catalogued()}
	}

	if len(admit.Processes) > 0 {
		admitted, err := admitting.Admit(admit)
		for _, skipped := range admitted.Skipped {
			skip(skipped.Selection.ObserverPID, skipped.Why)
		}
		if err != nil {
			return refuse(err.Error())
		}
		// After the write: an exec between the check and the write left no grant for
		// the kernel's exec hook to revoke, and this finds it. An exec after the write
		// is revoked by the hook.
		var kept, taken []admission.Selection
		for _, one := range admitted.Selections {
			if why, same := unchanged(procfs, processes[one.ObserverPID], admit.Read[one.ObserverPID]); !same {
				taken = append(taken, one)
				record.Retracted = append(record.Retracted, fmt.Sprintf("pid %d: %s", one.ObserverPID, why))
				continue
			}
			kept = append(kept, one)
		}
		if len(taken) > 0 {
			admitting.Retract(taken)
		}
		record.Admitted = len(kept)
		for _, one := range kept {
			attempt := attempts[one.ObserverPID]
			attempt.Admitted = one
			if attested, canAttest := d.attached.(probe.Attested); canAttest {
				attempt.Attested = true
				attempt.Placements, attempt.Err = attested.Placements(one.ObserverPID)
			}
			if covering, can := d.attached.(probe.Covering); can {
				if capability, err := covering.Capable(one.ObserverPID); err == nil {
					attempt.Capability = capability
				}
			}
			d.plan.Processes = append(d.plan.Processes, attachment.Describe(attempt))
		}
	}

	// The candidate is the policy in force from here, at the next generation.
	generation := d.plan.Policy.Generation + 1
	inspected := func(p process.Process) probe.Report {
		if read, found := request.Read[p.PID]; found {
			return read.Report
		}
		return probe.Report{Process: p.Identity()}
	}
	resolved := account.Plan(at, account.Policy{Revision: candidate.Revision, Generation: generation},
		request.Resolution, attach.Built(), inspected)
	d.policy = candidate
	d.plan.Policy = resolved.Policy
	d.plan.Limits = resolved.Limits
	for _, target := range resolved.Targets {
		if names[target.Name] {
			d.plan.Targets = append(d.plan.Targets, target)
		}
	}
	record.Outcome, record.Generation, record.Revision = "activated", generation, candidate.Revision
	return record
}

// readForReload is the reload command reading the candidate for the running
// session, with the privileges that session dropped.
func readForReload(candidate policy.Policy) (reloadRequest, error) {
	resolution, table, err := resolve(candidate.Approval)
	if err != nil {
		return reloadRequest{}, err
	}
	adapter := attach.NeweBPF(candidate.Approval)
	catalog, err := probe.NewCatalog(adapter)
	if err != nil {
		return reloadRequest{}, err
	}
	request := reloadRequest{Revision: candidate.Revision, Resolution: resolution,
		Read: make(map[int32]probe.Reading), Unread: make(map[int32]string)}
	for _, one := range resolution.Selections {
		p, found := table.Lookup(one.ObserverPID)
		if !found {
			continue
		}
		request.Processes = append(request.Processes, p)
		// Re-checked fields are read first and the executable again last, so an exec
		// between resolution and this reading is caught here.
		exec, err := process.ReadExec(procfs, p.PID)
		if err != nil || exec.StartTime != p.StartTime {
			request.Unread[p.PID] = "it exited or its pid was reused while the reload command read it"
			continue
		}
		reading := probe.Reading{Report: catalog.Inspect(p), Exec: exec}
		if reading.Report.Supported {
			library, libc, err := adapter.Identify(p, reading.Report)
			if err != nil {
				request.Unread[p.PID] = "the reload command could not name the libraries it runs: " + err.Error()
				continue
			}
			reading.Library, reading.Libc = library, libc
		}
		if device, inode, err := process.Network(procfs, p.PID); err == nil {
			reading.Network = probe.Netns{Device: device, Inode: inode}
		}
		again, err := os.Readlink(filepath.Join(procfs, strconv.Itoa(int(p.PID)), "exe"))
		if err != nil || again != p.Executable {
			request.Unread[p.PID] = "it execed while the reload command read it"
			continue
		}
		request.Read[p.PID] = reading
	}
	return request, nil
}

// reloadCommand reads the running session's configuration with this command's
// privileges and asks the session to put in force what it adds.
func reloadCommand(path string, stdout io.Writer) error {
	read, err := policy.Load(path)
	if err != nil {
		return err
	}
	if _, _, err := holder(read.Settings.Directory); err != nil {
		return err
	}
	request, err := readForReload(read)
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode what was read for the session: %w", err)
	}
	answer, err := ask(read.Settings.Directory, "reload", body, askWithin)
	if err != nil {
		return err
	}
	var record reloadRecord
	if err := json.Unmarshal(answer, &record); err != nil {
		return fmt.Errorf("read the session's answer: %w", err)
	}
	var refused struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(answer, &refused) == nil && refused.Error != "" {
		return fmt.Errorf("the running session could not answer: %s", refused.Error)
	}
	_, _ = stdout.Write(append(answer, '\n'))
	if record.Outcome == "refused" {
		return fmt.Errorf("the reload was refused and generation %d is still in force: %s",
			record.Generation, strings.TrimSpace(record.Reason))
	}
	return nil
}
