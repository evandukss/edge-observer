// Command observer attaches to the processes a configuration selects and
// reports what crossed their TLS boundary.
//
// It runs in the foreground, logs to the configured file (and to standard
// output in the foreground), and seals one account per session beside that
// session's spool. It listens on nothing: a command to a running session is a
// request file in its directory plus a signal to the pid its pid file names.
// It drops every capability once the probes are placed. Nothing leaves the
// host.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/internal/published"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/privilege"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/spool"
)

const name = "observer"

// procfs is where the kernel publishes what this program reads about processes.
const procfs = "/proc"

// askWithin is how long a command waits for a running session to answer. An
// answer takes milliseconds; this is margin, short enough that a session that
// will never answer is reported.
const askWithin = 10 * time.Second

// stopWithin is how long stop waits for a session to seal and release its pid
// file: the drain's bound, one file written, and a margin.
const stopWithin = drainWithin + 25*time.Second

func usage() string {
	return name + `: usage:
  ` + name + ` preflight <configuration> [--text]
      whether a capture of this configuration can run on this host, asked
      before anything attaches: READY, or NOT READY naming what is missing, or
      INDETERMINATE naming what could not be read. It exits 0 only on READY
  ` + name + ` start <configuration> [--daemonize]
      resolve the policy, attach, and record activation in the log. It runs in
      the foreground, and a supervisor supervises it as it is. --daemonize
      returns once the observer has activated and leaves it running detached,
      or exits non-zero with the reason where it could not activate
  ` + name + ` restart <configuration>
      end the running session, sealing it, and start a new one detached. Its
      activation record says which session it follows and how long nothing was
      observed in between
  ` + name + ` stop <configuration>
      end the running session, sealing its account beside its spool
  ` + name + ` reload <configuration>
      put in force what the configuration the session was started with now ADDS:
      a target needing no probe beyond what is attached. Anything it takes away,
      and a library nothing has attached, is refused and waits for a restart
  ` + name + ` dry-run <configuration> [--text [--local]]
      what the policy WOULD select, printed before anything attaches
  ` + name + ` inspect <configuration | session directory> [--text]
      the running session's account, as it stands; or, given a session's
      directory, the account that session sealed when it ended, read from that
      directory alone on any machine. There --text adds each exchange
      reconstructed from the spool beside the account: start lines, header
      names and body shapes, and no header value or body byte

The configuration is one JSON file, the operator configuration of
contract/config/CONFIG.md: where the log and the spools go, what to
attach to, what never to attach to, and which library builds a probe may be
placed on. A section this program does not implement is refused by name. The
account is JSON unless --text asks for the one a
person reads; --local adds each target's conditions, arguments included, for a
view that stays on this host.`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, name+": "+err.Error())
		os.Exit(1)
	}
}

func run(arguments []string, stdout io.Writer) error {
	if len(arguments) < 2 {
		return fmt.Errorf("a command and a configuration are named, and this names %d arguments\n%s",
			len(arguments), usage())
	}
	command, configuration, options := arguments[0], arguments[1], arguments[2:]

	allowed := map[string][]string{
		"preflight": {"--text"},
		"start":     {"--daemonize"},
		"restart":   nil,
		"stop":      nil,
		"reload":    nil,
		"dry-run":   {"--text", "--local"},
		"inspect":   {"--text"},
	}
	accepts, known := allowed[command]
	if !known {
		return fmt.Errorf("unknown command %q\n%s", command, usage())
	}
	for _, option := range options {
		if !slices.Contains(accepts, option) {
			return fmt.Errorf("%s does not take %q\n%s", command, option, usage())
		}
	}
	text, local := slices.Contains(options, "--text"), slices.Contains(options, "--local")

	switch command {
	case "preflight":
		return ready(configuration, text, stdout)
	case "start":
		if slices.Contains(options, "--daemonize") {
			return daemonize(configuration, stdout)
		}
		return start(configuration, stdout)
	case "restart":
		return restart(configuration, stdout)
	case "stop":
		return stop(configuration, stdout)
	case "reload":
		return reloadCommand(configuration, stdout)
	case "dry-run":
		return dryRun(configuration, text, local, stdout)
	default:
		return inspect(configuration, text, stdout)
	}
}

// ready says whether a capture of this configuration can run on this host,
// before anything attaches. It judges exactly the processes start would attach
// to, exclusions and refusals applied.
func ready(path string, text bool, stdout io.Writer) error {
	read, err := policy.Load(path)
	if err != nil {
		return err
	}
	resolution, table, err := resolve(read.Approval)
	if err != nil {
		return err
	}
	selected := make([]process.Process, 0, len(resolution.Selections))
	for _, one := range resolution.Selections {
		if p, found := table.Lookup(one.ObserverPID); found {
			selected = append(selected, p)
		}
	}
	catalog, err := probe.NewCatalog(attach.NeweBPF(read.Approval))
	if err != nil {
		return err
	}
	host := preflight.Running()
	host.Loads = attach.Loads
	readiness := preflight.Assess(host, selected, catalog)

	if text {
		_, _ = fmt.Fprintf(stdout, "verdict        %s\n", readiness.Verdict)
		for _, r := range readiness.Requirements {
			subject := r.Name
			if r.PID != 0 {
				subject += fmt.Sprintf(", pid %d", r.PID)
			}
			_, _ = fmt.Fprintf(stdout, "%-14s %s: %s\n", strings.ToUpper(string(r.Status)), subject, r.Found)
		}
	} else {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(readiness); err != nil {
			return err
		}
	}
	if readiness.Verdict == preflight.Ready {
		return nil
	}
	var named []string
	for _, r := range readiness.Requirements {
		if r.Status != preflight.Met {
			named = append(named, r.Name+" "+string(r.Status))
		}
	}
	return fmt.Errorf("%s: %s", readiness.Verdict, strings.Join(named, ", "))
}

// dryRun prints what the policy would select, attaching nothing. Its coverage
// is planned: nothing is placed yet.
func dryRun(path string, text, local bool, stdout io.Writer) error {
	read, err := policy.Load(path)
	if err != nil {
		return err
	}
	resolution, _, err := resolve(read.Approval)
	if err != nil {
		return err
	}
	catalog, err := probe.NewCatalog(attach.NeweBPF(read.Approval))
	if err != nil {
		return err
	}
	plan := account.Plan(time.Now(), account.Policy{Revision: read.Revision}, resolution, attach.Built(), catalog.Inspect)
	return emit(stdout, plan, text, local)
}

// inspect prints a session's account: a running session's as it stands, asked
// through its configuration, or a finished session's as sealed, read from its
// directory alone - with, as text, the exchanges reconstructed from its spool.
// The second works on a copy on any machine.
func inspect(path string, text bool, stdout io.Writer) error {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return inspectFinished(os.DirFS(path), text, stdout)
	}
	read, err := policy.Load(path)
	if err != nil {
		return err
	}
	answer, err := ask(read.Settings.Directory, "inspect", nil, askWithin)
	if err != nil {
		return err
	}
	var refused struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(answer, &refused) == nil && refused.Error != "" {
		return fmt.Errorf("the running session could not answer: %s", refused.Error)
	}
	if !text {
		_, err := stdout.Write(append(answer, '\n'))
		return err
	}
	var live account.Account
	if err := json.Unmarshal(answer, &live); err != nil {
		return fmt.Errorf("read the running session's account: %w", err)
	}
	account.Render(stdout, live, false)
	return nil
}

// inspectFinished prints the account a session sealed, reading only through
// its directory. JSON is the sealed file as written; text is rendered as for a
// running session, then the reconstructed exchanges. A session that never
// sealed is refused: its spool is a capture nothing accounts for.
func inspectFinished(session fs.FS, text bool, stdout io.Writer) error {
	content, err := fs.ReadFile(session, sealedName)
	if errors.Is(err, fs.ErrNotExist) {
		for _, name := range []string{spool.Name, spool.ConnectionsName} {
			if _, statErr := fs.Stat(session, name); statErr == nil {
				return errNeverSealed
			}
		}
		return errNotASession
	}
	if err != nil {
		return fmt.Errorf("read the sealed account: %w", err)
	}
	var sealed account.Account
	if err := json.Unmarshal(content, &sealed); err != nil {
		return fmt.Errorf("read the sealed account: %w", err)
	}
	switch {
	case sealed.Version != account.Version:
		return fmt.Errorf("the sealed account is version %d and this observer reads version %d",
			sealed.Version, account.Version)
	case sealed.Kind != account.Sealed:
		return fmt.Errorf("%s holds a %s account, and a finished session's is %s", sealedName, sealed.Kind, account.Sealed)
	}
	if text {
		account.Render(stdout, sealed, false)
		return renderExchanges(session, stdout)
	}
	_, err = stdout.Write(content)
	return err
}

// renderExchanges prints the reconstruction of a finished session's spool.
// Reconstruction happens only when a capture is read back, never while it
// runs. It prints start lines, header names, framing, body extents and shapes,
// and no header value or body byte. An account without its spool says so; an
// unreadable spool is an error after the account.
func renderExchanges(session fs.FS, stdout io.Writer) error {
	done, err := published.Reconstruct(session)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		_, err = fmt.Fprintf(stdout, "exchanges  NOT RECONSTRUCTED: no %s is beside the account, so nothing "+
			"here says what crossed\n", spool.Name)
		return err
	case err != nil:
		return fmt.Errorf("the account is printed, and the spool beside it could not be reconstructed: %w", err)
	}
	exchanges := 0
	for _, one := range done.Connections {
		exchanges += len(one.Exchanges)
	}
	if _, err := fmt.Fprintf(stdout, "exchanges  %d connections and %d exchanges reconstructed from %s: start "+
		"lines, header names and body shapes, no header value and no body byte\n",
		len(done.Connections), exchanges, spool.Name); err != nil {
		return err
	}
	_, err = io.WriteString(stdout, done.String())
	return err
}

func emit(to io.Writer, a account.Account, text, local bool) error {
	if text {
		account.Render(to, a, local)
		return nil
	}
	encoder := json.NewEncoder(to)
	encoder.SetIndent("", "  ")
	return encoder.Encode(a)
}

// sealedSession is the most recent session to seal, so the next can report how
// long nothing was observed in between.
type sealedSession struct {
	Session  string    `json:"session"`
	Sealed   time.Time `json:"sealed"`
	Account  string    `json:"account"`
	Complete bool      `json:"complete"`
}

func lastSealed(directory string) (sealedSession, error) {
	content, err := os.ReadFile(filepath.Join(directory, lastName))
	if err != nil {
		return sealedSession{}, err
	}
	var last sealedSession
	if err := json.Unmarshal(content, &last); err != nil {
		return sealedSession{}, fmt.Errorf("read %s: %w", lastName, err)
	}
	return last, nil
}

// stop ends the running session and waits for it to seal.
func stop(path string, stdout io.Writer) error {
	read, err := policy.Load(path)
	if err != nil {
		return err
	}
	directory := read.Settings.Directory
	pid, session, err := holder(directory)
	if err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	for deadline := time.Now().Add(stopWithin); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, _, err := holder(directory); !errors.Is(err, errNotRunning) {
			continue
		}
		last, err := lastSealed(directory)
		if err != nil || last.Session != session {
			return fmt.Errorf("session %s ended and no account says it sealed: %v", session, err)
		}
		how := "complete"
		if !last.Complete {
			how = "INCOMPLETE, and the account says why"
		}
		_, _ = fmt.Fprintf(stdout, "stopped    session %s, sealed %s, account %s\n", session, how, last.Account)
		return nil
	}
	return fmt.Errorf("pid %d did not end within %s", pid, stopWithin)
}

// start runs one session until it is stopped: in the foreground, or as the
// detached child daemonize started.
func start(path string, stdout io.Writer) (err error) {
	reporting := detachedReport()
	defer func() {
		if err != nil {
			report(reporting, "failed %v", err)
		}
	}()
	read, err := policy.Load(path)
	if err != nil {
		return err
	}
	held, err := acquire(read.Settings.Directory)
	if err != nil {
		return err
	}
	defer held.release()
	log, err := openLog(read.Settings, reporting == nil, stdout)
	if err != nil {
		return err
	}
	defer func() { _ = log.close() }()

	// Signals are taken first: a stop can arrive any time after this process
	// exists, and the default action would end the run unsealed.
	stopping := make(chan os.Signal, 1)
	signal.Notify(stopping, os.Interrupt, syscall.SIGTERM)
	asking := make(chan os.Signal, 1)
	signal.Notify(asking, syscall.SIGUSR1)

	session := newIdentity()
	running, err := begin(read, session)
	if err != nil {
		_ = log.write(startFailed(session, time.Now(), err))
		return err
	}
	running.path = path
	if err := held.record(os.Getpid(), session); err != nil {
		running.abandon()
		_ = log.write(startFailed(session, time.Now(), err))
		return fmt.Errorf("record the running session: %w", err)
	}

	activatedAt := time.Now()
	current := running.snapshot(account.Live, activatedAt)
	record := activated(session, os.Getpid(), activatedAt, current)
	record.Follows = running.follows(activatedAt)
	if err := log.write(record); err != nil {
		// An activation nobody can read is not an activation: readiness is learned
		// from this record alone.
		running.abandon()
		return fmt.Errorf("write the activation record: %w", err)
	}
	notify("READY=1\nSTATUS=activated session " + session)
	// The parent returns on this record; nothing later is the parent's to report.
	report(reporting, "activated %s", session)
	reporting = nil

	control := &controller{directory: read.Settings.Directory, answer: func(kind string, body []byte) ([]byte, error) {
		switch kind {
		case "inspect":
			return json.MarshalIndent(running.snapshot(account.Live, time.Now()), "", "  ")
		case "reload":
			record := running.reload(time.Now(), body)
			if err := log.write(record); err != nil {
				running.logFailures++
			}
			return json.Marshal(record)
		default:
			return nil, fmt.Errorf("a running session answers inspect and reload, and %q is not something it answers", kind)
		}
	}}

	ticker := time.NewTicker(read.Settings.StateEvery)
	defer ticker.Stop()
	previous := current
	for {
		select {
		case <-stopping:
			return running.finish(log)
		case <-asking:
			control.serve()
		case at := <-ticker.C:
			now := running.snapshot(account.Live, at)
			if err := log.write(stated(session, at, now, previous)); err != nil {
				// An unwritable log does not stop observation; failures are counted and the
				// final record reports them.
				running.logFailures++
			}
			previous = now
		}
	}
}

// daemon is one output session between its activation and its seal.
type daemon struct {
	policy  policy.Policy
	session string

	// path is the configuration this session started with, which reload reads
	// again.
	path string

	// directory is this session's own: its spool and its sealed account.
	directory string

	written  *spool.Spool
	capture  *capture.Session
	attached probe.Attachment

	// plan is the account at activation - resolved policy and what the kernel
	// confirmed attached - which every later account starts from.
	plan account.Account

	logFailures int
}

// begin resolves the policy, opens the spool, attaches, drops every capability
// and reads its own posture back. A failure anywhere leaves nothing behind.
func begin(read policy.Policy, session string) (*daemon, error) {
	resolution, table, err := resolve(read.Approval)
	if err != nil {
		return nil, err
	}
	catalog, err := probe.NewCatalog(attach.NeweBPF(read.Approval))
	if err != nil {
		return nil, err
	}
	plan := account.Plan(time.Now(), account.Policy{Revision: read.Revision, Generation: 1}, resolution,
		attach.Built(), catalog.Inspect)
	if err := selectedAnything(resolution); err != nil {
		return nil, err
	}

	directory := filepath.Join(read.Settings.Directory, sessionsName, session)
	written, err := spool.Open(directory, read.Settings.BoundMiB<<20)
	if err != nil {
		return nil, err
	}
	leaveNothing := func() {
		_ = written.Close()
		_ = os.RemoveAll(directory)
	}
	recording := capture.Recording(written, written)
	attached, observed, err := observe(catalog, resolution, table, recording)
	if err != nil {
		leaveNothing()
		return nil, err
	}
	// What the kernel confirms, handed to capture before any connection record is
	// written: it decides what an absence in a record means.
	recording.Observing(attached.Capability())

	if err := privilege.Drop(); err != nil {
		_ = attached.Close()
		leaveNothing()
		return nil, err
	}
	if err := posture(); err != nil {
		_ = attached.Close()
		leaveNothing()
		return nil, err
	}
	plan.Attached(account.Live, session, observed, attached.Capability())
	return &daemon{
		policy: read, session: session, directory: directory,
		written: written, capture: recording, attached: attached, plan: plan,
	}, nil
}

// abandon undoes a session that attached and could not be activated.
func (d *daemon) abandon() {
	_ = d.attached.Close()
	_ = d.written.Close()
	_ = os.RemoveAll(d.directory)
}

// resolve reads the host and resolves the policy. Listening sockets are read
// only for a port target and the boot id only for a pid target; an unreadable
// boot refuses those pid targets by name.
func resolve(approval process.Approval) (process.Resolution, process.Table, error) {
	table, err := process.Read(procfs)
	if err != nil {
		return process.Resolution{}, process.Table{}, err
	}
	names := func(has func(process.Rule) bool) bool {
		return slices.ContainsFunc(approval.Rules, has) || slices.ContainsFunc(approval.Exclusions, has)
	}
	if names(func(rule process.Rule) bool { return rule.Port != 0 }) {
		listeners, err := process.ReadListeners(procfs)
		if err != nil {
			return process.Resolution{}, process.Table{}, fmt.Errorf("read the listening sockets a port "+
				"resolves against: %w", err)
		}
		table = table.WithListeners(listeners)
	}
	host := process.Host{Table: table}
	if names(func(rule process.Rule) bool { return rule.PID != nil }) {
		if boot, err := process.ReadBoot(procfs); err == nil {
			host.Boot = boot
		}
	}
	return approval.Resolve(host), table, nil
}

// selectedAnything refuses a policy none of whose targets selected a process.
// A target selecting nothing beside others that did is reported, not refused.
func selectedAnything(resolution process.Resolution) error {
	var barren []string
	for _, target := range resolution.Targets {
		if len(target.Roots) > 0 {
			return nil
		}
		barren = append(barren, fmt.Sprintf("target %d (%s) selected nothing: %s",
			target.Number, target.Name, target.Unresolved))
	}
	return fmt.Errorf("no process on this host matches the configuration: %s", strings.Join(barren, "; "))
}

// posture reads back from the kernel what this process holds and exposes.
func posture() error {
	self := filepath.Join(procfs, "self")
	held, err := privilege.Effective(self)
	if err != nil {
		return err
	}
	if held != 0 {
		return fmt.Errorf("this process still holds %#x after dropping its capabilities", held)
	}
	listening, err := privilege.Listening(self)
	if err != nil {
		return err
	}
	if len(listening) > 0 {
		return fmt.Errorf("this process is listening on %v, and it takes nothing in", listening)
	}
	return nil
}

// snapshot is the session's account as it stands at one moment.
func (d *daemon) snapshot(kind account.Kind, at time.Time) account.Account {
	a := d.plan
	a.Kind = kind
	run := account.Run{Seen: d.capture.Stats()}
	run.Losses, run.LossesErr = losses(d.attached)
	run.Refusals, run.RefusalsErr = refused(d.attached)
	if granting, can := d.attached.(probe.Granting); can {
		run.Grants, run.GrantsErr = granting.Grants()
		if run.GrantsErr == nil && run.Grants == nil {
			run.Grants = []probe.Grant{}
		}
	} else {
		run.GrantsErr = errors.New("this attachment does not record what it admitted")
	}
	stats := d.written.Stats()
	run.Spool = &stats
	a.Ran(at, run)
	return a
}

// follows is the session this one follows, from the last seal, and the gap in
// between.
func (d *daemon) follows(activatedAt time.Time) *follows {
	last, err := lastSealed(d.policy.Settings.Directory)
	if err != nil || last.Session == "" {
		return nil
	}
	return &follows{
		Session: last.Session, Sealed: last.Sealed,
		Gap: fmt.Sprintf("nothing was observed from %s, when session %s sealed, to %s, when this one activated",
			last.Sealed.UTC().Format(time.RFC3339Nano), last.Session, activatedAt.UTC().Format(time.RFC3339Nano)),
	}
}

// finish is the finalisation in its one order - stop production, drain what
// was in flight, read the counters, seal - then writes the account once beside
// the spool.
func (d *daemon) finish(log *logger) error {
	sealer := &connection.Sealer{Producer: producing(d.attached), Within: drainWithin}
	seal, sealErr := sealer.Stop()
	// The run's inventory has three sources, none able to answer for another: the
	// program (produced), capture (placed) and the spool (kept).
	seal.Counters = seal.Counters.Join(d.capture.Counted())
	seal.Counters = seal.Counters.Join(d.written.Counted())
	// The backend's production count makes a trailing loss visible.
	d.capture.Finish(seal.Sealed, seal.Counters.ReservationAttempts)

	// Read while the program's maps are open; closing the attachment closes them.
	final := d.snapshot(account.Sealed, time.Now())
	final.Closed(seal, sealErr)
	if err := d.attached.Close(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, name+": "+err.Error())
	}
	_ = d.written.Close()

	record := stopped{
		Record: "stopped", Version: recordVersion, Session: d.session, At: time.Now(),
		Sealed: sealErr == nil, Complete: sealErr == nil && seal.Complete, LogFailures: d.logFailures,
	}
	path := filepath.Join(d.directory, sealedName)
	content, err := json.MarshalIndent(final, "", "  ")
	if err == nil {
		err = place(path, append(content, '\n'))
	}
	if err != nil {
		record.Error = err.Error()
		_ = log.write(record)
		return fmt.Errorf("write the sealed account: %w", err)
	}
	record.Account = path

	// The same session in the account contract, projected from the operational
	// account. A failed projection leaves the operational account sealed and says
	// so.
	contractPath := filepath.Join(d.directory, published.Name)
	contractAccount, err := published.Account(final)
	if err == nil {
		content, err = json.MarshalIndent(contractAccount, "", "  ")
	}
	if err == nil {
		err = place(contractPath, append(content, '\n'))
	}
	if err != nil {
		record.ContractError = err.Error()
	} else {
		record.Contract = contractPath
	}

	sealedAt := record.At
	if final.Seal != nil {
		sealedAt = final.Seal.Sealed
	}
	last, _ := json.Marshal(sealedSession{Session: d.session, Sealed: sealedAt, Account: path, Complete: record.Complete})
	if err := place(filepath.Join(d.policy.Settings.Directory, lastName), last); err != nil {
		record.Error = err.Error()
	}
	return log.write(record)
}

// notify tells a supervisor that named a notify socket that the session is up.
// It is never the only readiness signal - the activation record in the log is -
// and a write failure changes nothing.
func notify(state string) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return
	}
	defer func() { _ = connection.Close() }()
	_, _ = connection.Write([]byte(state))
}

// drainWithin is how long finalisation waits for what production left in
// flight: the reader declares the ring empty after 50ms idle, so this is ample,
// and short enough that a stop does not seem to hang.
const drainWithin = 5 * time.Second

// producing is the attachment as the finalisation can drive it, or a producer
// that reports it cannot be stopped. The seal then says the run was still
// producing when sealed.
func producing(attached probe.Attachment) connection.Producer {
	if canStop, ok := attached.(connection.Producer); ok {
		return canStop
	}
	return unstoppable{backend: string(attached.Capability().Backend)}
}

// unstoppable is what the boundary drives when the attachment cannot be stopped.
type unstoppable struct{ backend string }

func (u unstoppable) StopProducing() (connection.Withdrawal, error) {
	return connection.Withdrawal{At: time.Now()}, fmt.Errorf(
		"the %s attachment cannot withdraw its own capture authority, so it is still producing",
		u.backend)
}

func (u unstoppable) Drain(time.Duration) (connection.Drained, error) {
	return connection.Drained{
		Delivered:   connection.Uncounted("this attachment does not drain"),
		Outstanding: connection.Uncounted("this attachment does not say what it had in flight"),
	}, nil
}

func (u unstoppable) Account() (connection.Counters, error) {
	return connection.Counters{}, fmt.Errorf("the %s attachment counts nothing", u.backend)
}

// observe attaches to the selected processes an adapter supports and
// describes what the kernel says about each. The whole set goes to the adapter
// at once: a probe is placed on a file and fires for every process running it,
// so per-process placement would report each call once per placement.
func observe(catalog probe.Catalog, resolution process.Resolution, table process.Table,
	sink probe.Sink) (probe.Attachment, []attachment.Observed, error) {
	adapter, canAttach := catalog.Adapters()[0].(probe.Adapter)

	attempts := make([]attachment.Attempt, 0, len(resolution.Selections))
	request := probe.Request{Deny: resolution.Denials}
	for _, one := range resolution.Selections {
		p, found := table.Lookup(one.ObserverPID)
		if !found {
			continue
		}
		attempt := attachment.Attempt{
			Process:    p,
			Admitted:   one,
			Alive:      alive(p),
			Support:    catalog.Inspect(p),
			Catalogued: catalogued(),
		}
		if attempt.Support.Supported && attempt.Alive {
			request.Processes = append(request.Processes, p)
			request.Admit = append(request.Admit, one)
		}
		attempts = append(attempts, attempt)
	}

	var live probe.Attachment
	var attachErr error
	switch {
	case !canAttach:
		attachErr = fmt.Errorf("the %s adapter cannot attach", catalog.Adapters()[0].Name())
	case len(request.Processes) > 0:
		live, attachErr = adapter.Attach(request, sink)
	}

	observed := make([]attachment.Observed, 0, len(attempts))
	var reasons []string
	for _, attempt := range attempts {
		switch {
		case !attempt.Support.Supported || !attempt.Alive:
		case attachErr != nil:
			attempt.Err = attachErr
		default:
			attested, canAttest := live.(probe.Attested)
			attempt.Attested = canAttest
			if canAttest {
				attempt.Placements, attempt.Err = attested.Placements(attempt.Process.PID)
			}
			// What the attachment covering this process can do, which may be less than
			// the whole attachment.
			if covering, can := live.(probe.Covering); can {
				capability, err := covering.Capable(attempt.Process.PID)
				if err == nil {
					attempt.Capability = capability
				}
			}
		}
		described := attachment.Describe(attempt)
		if described.Reason != "" {
			reasons = append(reasons, fmt.Sprintf("pid %d: %s", described.PID, described.Reason))
		}
		observed = append(observed, described)
	}

	switch {
	case attachErr != nil:
		return nil, observed, attachErr
	case live == nil:
		return nil, observed, fmt.Errorf("%w: %s", attachment.ErrNothingAttached, strings.Join(reasons, "; "))
	}
	return live, observed, nil
}

// alive reports whether the process is still in the table: one that matched
// and then exited is a reason of its own.
func alive(p process.Process) bool {
	_, err := process.Identify(procfs, p.PID)
	return err == nil
}

// catalogued is every function the catalogue attaches to, against which an
// entry point nothing tried to place is measured.
func catalogued() []string {
	functions := append(probe.OpenSSL.Probed(), probe.OpenSSL.Lifecycle...)
	symbols := make([]string, 0, len(functions))
	for _, function := range functions {
		symbols = append(symbols, function.Symbol)
	}
	return symbols
}

// losses is what the attachment discarded on the kernel side, or why that is
// unknown. A backend that does not count, or whose counters are unreadable, is
// not one that lost nothing.
func losses(attached probe.Attachment) (probe.Losses, error) {
	counted, canCount := attached.(probe.Counting)
	if !canCount {
		return probe.Losses{}, fmt.Errorf("this attachment does not count what it lost")
	}
	return counted.Losses()
}

// refused is what the attachment's program refused, by reason, or why that is
// unknown.
func refused(attached probe.Attachment) (map[string]int64, error) {
	refusing, can := attached.(probe.Refusing)
	if !can {
		return nil, fmt.Errorf("this attachment does not say what it refused")
	}
	return refusing.Refusals()
}
