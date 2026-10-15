// Command observer attaches to the processes a configuration selects and
// reports what crossed their TLS boundary.
//
// It runs in the foreground, logs to the configured file (and to standard
// output in the foreground), and seals one account per session beside that
// session's approved output. It listens on nothing: a command to a running
// session is a request file in its directory plus a signal to its pid.
// It drops every capability once the probes are placed. Nothing leaves the
// host.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/evandukss/edge-observer/account"
	protected "github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/privilege"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
	"github.com/evandukss/edge-observer/spool"
	"golang.org/x/sys/unix"
)

const name = "observer"

// procfs is where the kernel publishes what this program reads about processes.
const procfs = "/proc"

// askWithin is how long a command waits for a running session to answer. An
// answer takes milliseconds; this is margin, short enough that a session that
// will never answer is reported.
const askWithin = 10 * time.Second

func usage() string {
	return name + `: usage:
  ` + name + ` preflight <configuration> [--text]
      whether a capture of this configuration can run on this host, asked
      before anything attaches: READY, or NOT READY naming what is missing, or
      INDETERMINATE naming what could not be read. It exits 0 only on READY
  ` + name + ` start <configuration> [--daemonize | --stdout]
      resolve the policy, attach, and record activation in the log. It runs in
      the foreground, and a supervisor supervises it as it is. --daemonize
      returns once the observer has activated and leaves it running detached,
      or exits non-zero with the reason where it could not activate. --stdout
      mirrors approved JSONL in the foreground and sends operational logs to
      stderr; it cannot be combined with --daemonize or log configured as stdout
  ` + name + ` restart <configuration>
      end the running session, sealing it, and start a new one detached. Its
      activation record names the last validated seal and leaves coverage
      between that seal and activation not established. A configuration a detached session would refuse is
      refused before anything is stopped, and the new session runs the
      configuration as it was checked, whatever the file holds by then
  ` + name + ` stop <configuration>
      end the running session, sealing its account under sessions/<session>
  ` + name + ` reload <configuration>
      put in force what the configuration the session was started with now ADDS:
      a target needing no probe beyond what is attached. Anything it takes away,
      and a library nothing has attached, is refused and waits for a restart
  ` + name + ` reopen <configuration>
      reopen approved, derived and log files after rotation, acknowledging only
      after each old write has finished and the replacement file is open
  ` + name + ` dry-run <configuration> [--text [--local]]
      what the policy WOULD select, printed before anything attaches
  ` + name + ` inspect <configuration | session directory> [--text [--file <path> ...] [--session <id>]]
      the running session's account, as it stands; or, given a session's
      directory, the account that session sealed when it ended. --text adds
      approved records from the stable approved.jsonl, filtered to that session;
      --file selects explicit files, including rotated files, and --session
      selects another session. Historical session-local output is also readable;
      missing or empty approved output is an error

The configuration is one JSON file, observer.config/1 of
contract/config/CONFIG.md: where approved output and the log go, what to
watch, what to ignore, which library builds a probe may be placed on, and what
to remove, mask and truncate, and the extensions to run. A key it does not
define is refused by name. An extension's command written as a relative path is
resolved against the configuration's directory, and every command must be an
executable file before anything attaches; stop, and inspect of a running
session, read only where the session is and never a command. The account is
JSON unless --text asks for the one a person reads; --local adds each target's
conditions, arguments included, for a view that stays on this host.`
}

func main() {
	exitOnError(run(os.Args[1:], os.Stdout))
}

func exitOnError(err error) {
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, name+": "+err.Error())
		os.Exit(probe.CaptureFailureExitStatus)
	}
}

func run(arguments []string, stdout io.Writer) error {
	return runWith(arguments, stdout, commandDependencies{})
}

func runWith(arguments []string, stdout io.Writer, deps commandDependencies) error {
	if len(arguments) < 2 {
		return fmt.Errorf("a command and a configuration are named, and this names %d arguments\n%s",
			len(arguments), usage())
	}
	command, configuration, options := arguments[0], arguments[1], arguments[2:]
	// Made absolute once, here: an extension's relative command is resolved
	// against the configuration's directory, and a detached session and a
	// reload read it again from elsewhere.
	configuration, err := filepath.Abs(configuration)
	if err != nil {
		return fmt.Errorf("resolve the configuration's path: %w", err)
	}

	allowed := map[string][]string{
		"preflight": {"--text"},
		"start":     {"--daemonize", "--stdout"},
		"restart":   nil,
		"stop":      nil,
		"reload":    nil,
		"reopen":    nil,
		"dry-run":   {"--text", "--local"},
		"inspect":   {"--text"},
	}
	accepts, known := allowed[command]
	if !known {
		return fmt.Errorf("unknown command %q\n%s", command, usage())
	}
	var files []string
	sessionFilter := ""
	if command == "inspect" {
		var flags []string
		for i := 0; i < len(options); i++ {
			option := options[i]
			if option == "--file" || option == "--session" {
				if i+1 == len(options) {
					return fmt.Errorf("%s requires a value", option)
				}
				i++
				if option == "--file" {
					files = append(files, options[i])
				} else {
					sessionFilter = options[i]
				}
			} else {
				flags = append(flags, option)
			}
		}
		options = flags
		if (len(files) > 0 || sessionFilter != "") && !slices.Contains(options, "--text") {
			return errors.New("--file and --session require --text")
		}
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
		mirror := slices.Contains(options, "--stdout")
		if mirror && slices.Contains(options, "--daemonize") {
			return errors.New("--stdout requires foreground operation and cannot be combined with --daemonize")
		}
		if slices.Contains(options, "--daemonize") {
			return daemonize(configuration, stdout)
		}
		return startWith(configuration, stdout, mirror, deps)
	case "restart":
		return restart(configuration, stdout)
	case "stop":
		return stop(configuration, stdout)
	case "reopen":
		return reopenCommand(configuration, stdout)
	case "reload":
		return reloadCommand(configuration, stdout)
	case "dry-run":
		return dryRun(configuration, text, local, stdout)
	default:
		return inspectFiles(configuration, text, stdout, files, sessionFilter)
	}
}

// ready says whether a capture of this configuration can run on this host,
// before anything attaches. It judges exactly the processes start would attach
// to, exclusions and refusals applied, and the envelope it runs in with start's
// own check: run the same way start will be, it answers for start.
func ready(path string, text bool, stdout io.Writer) error {
	read, err := loadProcessing(path)
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
	// A failure leaves the process dumpable, and the envelope's core_dumps
	// judgment says so, as it would refuse start.
	_ = undumpable()
	host := preflight.Running()
	host.Loads = attach.Loads
	host.Envelope = envelopeJudged
	readiness := preflight.Assess(host, selected, catalog)
	judged := slices.Concat(readiness.Requirements, readiness.Envelope)

	subject := func(r preflight.Requirement) string {
		named := r.Name
		if r.Check != "" {
			named += " " + r.Check
		}
		if r.PID != 0 {
			named += fmt.Sprintf(", pid %d", r.PID)
		}
		return named
	}
	// The extensions start would run, each labelled: not a requirement, and
	// never part of the verdict.
	extensions := account.ExtensionsOf(read.Processing.Extensions())
	if text {
		_, _ = fmt.Fprintf(stdout, "verdict        %s\n", readiness.Verdict)
		for _, r := range judged {
			_, _ = fmt.Fprintf(stdout, "%-14s %s: %s\n", strings.ToUpper(string(r.Status)), subject(r), r.Found)
		}
		for _, one := range extensions {
			_, _ = fmt.Fprintf(stdout, "%-14s %s: %s; timeout %d ms; extension-declared, not observer-enforced\n",
				"EXTENSION", one.Name, strings.Join(one.Fields, ", "), one.TimeoutMS)
		}
	} else {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(struct {
			preflight.Readiness
			Extensions []account.Extension `json:"extensions"`
		}{readiness, extensions}); err != nil {
			return err
		}
	}
	if readiness.Verdict == preflight.Ready {
		return nil
	}
	var named []string
	for _, r := range judged {
		if r.Status == preflight.Met {
			continue
		}
		if r.Check == "" {
			named = append(named, r.Name+" "+string(r.Status))
		} else {
			named = append(named, subject(r)+" "+string(r.Status))
		}
	}
	return fmt.Errorf("%s: %s", readiness.Verdict, strings.Join(named, ", "))
}

// dryRun prints what the policy would select, attaching nothing. Its coverage
// is planned: nothing is placed yet.
func dryRun(path string, text, local bool, stdout io.Writer) error {
	read, err := loadProcessing(path)
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
	plan.Extensions = account.ExtensionsOf(read.Processing.Extensions())
	return emit(stdout, plan, text, local)
}

// inspect prints a session's account: a running session's as it stands, asked
// through its configuration, or a finished session's as sealed, read from its
// directory alone - with, as text, its persisted approved records.
// The second works on a copy on any machine.
func inspect(path string, text bool, stdout io.Writer) error {
	return inspectFiles(path, text, stdout, nil, "")
}
func inspectFiles(path string, text bool, stdout io.Writer, files []string, sessionFilter string) error {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		if !text {
			return inspectFinished(os.DirFS(path), false, stdout)
		}
		content, err := os.ReadFile(filepath.Join(path, sealedName))
		if err != nil {
			return inspectFinished(os.DirFS(path), true, stdout)
		}
		var sealed account.Account
		if err := json.Unmarshal(content, &sealed); err != nil {
			return err
		}
		if sessionFilter == "" && len(files) == 0 {
			if _, err := os.Stat(filepath.Join(path, processing.ArtifactName)); err == nil {
				return inspectFinished(os.DirFS(path), true, stdout)
			}
		}
		if sessionFilter == "" {
			sessionFilter = sealed.Session
		}
		if len(files) == 0 {
			local := filepath.Join(path, processing.ArtifactName)
			if _, err := os.Stat(local); err == nil {
				files = []string{local}
			} else {
				files = []string{filepath.Join(filepath.Dir(filepath.Dir(path)), processing.ArtifactName)}
			}
		}
		return inspectSelected(os.DirFS(path), stdout, files, sessionFilter)
	}
	directory, err := sessionDirectory(path)
	if err != nil {
		return err
	}
	answer, err := ask(directory, "inspect", nil, askWithin)
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
	if len(files) == 0 && sessionFilter == "" {
		return nil
	}
	if len(files) == 0 {
		files = []string{filepath.Join(directory, processing.ArtifactName)}
	}
	if sessionFilter == "" {
		sessionFilter = live.Session
	}
	names := make([]string, 0, len(files))
	for _, path := range files {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		names = append(names, strings.TrimPrefix(absolute, "/"))
	}
	return processing.ReadArtifactFiles(os.DirFS("/"), names, sessionFilter, func(a processing.Artifact) error { return processing.RenderArtifact(stdout, a) })
}

// inspectFinished prints the account a session sealed, reading only through
// its directory. JSON is the sealed file as written; text is rendered as for a
// running session, then the approved records. A session that never sealed
// is refused: its output is a capture nothing accounts for.
func inspectSelected(session fs.FS, stdout io.Writer, files []string, sessionFilter string) error {
	var encoded bytes.Buffer
	if err := inspectFinished(session, false, &encoded); err != nil {
		return err
	}
	var sealed account.Account
	if err := json.Unmarshal(encoded.Bytes(), &sealed); err != nil {
		return err
	}
	var rendered bytes.Buffer
	account.Render(&rendered, sealed, false)
	if _, err := rendered.WriteTo(stdout); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for _, path := range files {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		names = append(names, strings.TrimPrefix(absolute, "/"))
	}
	return processing.ReadArtifactFiles(os.DirFS("/"), names, sessionFilter, func(a processing.Artifact) error { return processing.RenderArtifact(stdout, a) })
}

func inspectFinished(session fs.FS, text bool, stdout io.Writer) error {
	sealed, content, err := readSessionSeal(session)
	if errors.Is(err, fs.ErrNotExist) {
		if state, statErr := fs.Stat(session, controlName); statErr == nil {
			if state.IsDir() {
				return errNeverSealed
			}
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return fmt.Errorf("read session control state: %w", statErr)
		}
		for _, name := range []string{processing.ArtifactName, spool.Name, spool.ConnectionsName} {
			if _, statErr := fs.Stat(session, name); statErr == nil {
				return errNeverSealed
			}
		}
		return errNotASession
	}
	if err != nil {
		return fmt.Errorf("read the sealed account: %w", err)
	}
	if text {
		var rendered bytes.Buffer
		account.Render(&rendered, sealed, false)
		if _, err := rendered.WriteTo(stdout); err != nil {
			return err
		}
		return processing.ReadArtifacts(session, func(a processing.Artifact) error {
			return processing.RenderArtifact(stdout, a)
		})
	}
	_, err = stdout.Write(content)
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

// sealedSession discovers the last validated seal. It establishes no coverage
// between that seal and a later activation. Lost is the account's losses as one
// clause (account.Account.Lost) and Reason the gate's reason for refusing
// release, for stop to print beside how it sealed.
type sealedSession struct {
	Session  string           `json:"session"`
	Sealed   time.Time        `json:"sealed"`
	Account  string           `json:"account"`
	Complete bool             `json:"complete"`
	Lost     string           `json:"lost,omitempty"`
	Reason   probe.GateReason `json:"reason,omitempty"`
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
	a, _, err := readSessionSeal(os.DirFS(filepath.Dir(last.Account)))
	if err != nil {
		return sealedSession{}, err
	}
	if a.Session != last.Session || !a.Seal.Sealed.Equal(last.Sealed) {
		return sealedSession{}, errors.New("last-seal pointer does not identify its account")
	}
	last.Complete, last.Lost = a.Seal.Complete, a.Lost()
	if a.Processing != nil {
		last.Reason = a.Processing.GateReason
	}
	return last, nil
}

// stop ends the running session and waits for it to seal.
func stop(path string, stdout io.Writer) error {
	directory, err := sessionDirectory(path)
	if err != nil {
		return err
	}
	return stopIn(directory, stdout)
}

// stopIn ends the session running over directory and waits for it to seal.
func stopIn(directory string, stdout io.Writer) error {
	return stopInUsing(directory, stdout, holder)
}

func stopInUsing(directory string, stdout io.Writer, observe func(string) (int, string, error)) error {
	pid, session, err := holder(directory)
	if err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	for deadline := time.Now().Add(stopWithin); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		currentPID, currentSession, holderErr := observe(directory)
		if holderErr == nil && currentPID == pid && currentSession == session {
			continue
		}
		if holderErr != nil && !errors.Is(holderErr, errNotRunning) {
			// Release can leave a held but empty pid file. An unknown observation
			// does not establish that our session ended; keep the original deadline.
			continue
		}
		return stoppedSession(directory, session, stdout)
	}
	return fmt.Errorf("pid %d did not end within %s", pid, stopWithin)
}

// startWith runs one session until it is stopped: in the foreground, or as
// the detached child daemonize started.
func startWith(path string, stdout io.Writer, mirror bool, deps commandDependencies) (err error) {
	boundary := newShutdownBoundary(os.Exit)
	// Registered first, so the exit backstop remains armed through every cleanup.
	defer boundary.disarm()
	reporting := detachedReport()
	defer func() {
		if err != nil {
			report(reporting, "failed %v", err)
		}
	}()
	if mirror && reporting != nil {
		return errors.New("--stdout requires foreground operation")
	}
	read, err := configurationFor(path, handedOver())
	if err != nil {
		return err
	}
	if mirror && read.Settings.Log == policy.Stdout {
		return errors.New("--stdout cannot be combined with log configured as stdout")
	}
	held, err := acquire(read.Settings.Directory)
	if err != nil {
		return err
	}
	defer held.release()
	console, consoleName := stdout, "stdout"
	if mirror {
		console, consoleName = deps.stderr, "stderr"
		if console == nil {
			console = os.Stderr
		}
	}
	log, err := openLogTo(read.Settings, reporting == nil, consoleName, console)
	if err != nil {
		return err
	}
	defer func() { _ = log.close() }()

	// Signals are taken first: a stop can arrive any time after this process
	// exists, and the default action would end the run unsealed.
	stopping, asking, stopSignals := deps.signals()
	defer stopSignals()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-stopping:
			boundary.trigger()
		case <-watchDone:
		}
	}()

	options := processing.WriterOptions{Directory: read.Settings.Directory}
	if mirror {
		options.Stdout, err = sink.NewStream(stdout)
		if err != nil {
			return fmt.Errorf("open stdout delivery: %w", err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = options.Stdout.Close(ctx)
		}()
	}
	session := newIdentity()
	var running *daemon
	switch {
	case deps.begin != nil:
		running, err = deps.begin(read, session, options)
	case mirror:
		running, err = beginWithWriter(read, session, options)
	default:
		running, err = begin(read, session)
	}
	if err != nil {
		_ = log.write(startFailed(session, time.Now(), err))
		return err
	}
	running.shutdown = boundary
	running.path = path
	running.log = log
	running.prepareShutdown()
	// Ends of executions reach the session from here on, with its log in place.
	running.ends.serve(running)
	if err := held.record(os.Getpid(), session); err != nil {
		running.abandon()
		_ = log.write(startFailed(session, time.Now(), err))
		return fmt.Errorf("record the running session: %w", err)
	}

	activatedAt := time.Now()
	current := running.snapshot(account.Live, activatedAt)
	record := activated(session, os.Getpid(), activatedAt, current, running.payloadPosture)
	record.MemoryAssurance = "Current payload-holder membership and limits verified. Memory containment is conditional on entering the isolated bounded no-swap cgroup before exec and keeping membership and limits fixed through capture. These readings do not establish that no allocation predates entry."
	record.Follows = running.follows(activatedAt)
	if err := log.write(record); err != nil {
		running.logFailures.Add(1)
	}

	notify("READY=1\nSTATUS=activated session " + session)
	// The parent returns on this record; nothing later is the parent's to report.
	report(reporting, "activated %s", session)
	reporting = nil

	control := &controller{directory: running.directory, answer: func(kind string, body []byte) ([]byte, error) {
		switch kind {
		case "inspect":
			return json.MarshalIndent(running.snapshot(account.Live, time.Now()), "", "  ")
		case "reopen":
			ctx, cancel := context.WithTimeout(context.Background(), askWithin/2)
			defer cancel()
			if err := errors.Join(running.output.Reopen(ctx), log.reopen(ctx)); err != nil {
				return nil, fmt.Errorf("reopen: %w", err)
			}
			return json.Marshal(map[string]string{"session": session, "status": "reopened"})
		case "reload":
			record := running.reload(time.Now(), body)
			if err := log.write(record); err != nil {
				running.logFailures.Add(1)
			}
			return json.Marshal(record)
		default:
			return nil, fmt.Errorf("a running session answers inspect, reload and reopen, and %q is not something it answers", kind)
		}
	}}

	ticker := time.NewTicker(read.Settings.StateEvery)
	defer ticker.Stop()
	running.serveUntilStop(stopping, asking, ticker.C, control, log, current)
	return running.finish(log)
}

// serveUntilStop is the production controller loop. Intake exhaustion can
// withdraw idle capture; output failures are counted independently.
func (d *daemon) serveUntilStop(stopping, asking <-chan os.Signal, ticks <-chan time.Time, control *controller, log *logger, previous account.Account) {
	s := d.prepareShutdown()
	// Receipt of a shutdown trigger is never dependent on control.serve returning.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-stopping:
			s.trigger()
		case <-d.gate.Withdrawal():
			s.trigger()
		case <-watchDone:
		}
	}()
	failed := d.startProcessing()
	go func() {
		select {
		case <-failed:
			s.trigger()
		case <-watchDone:
		}
	}()
	for {
		select {
		case <-s.started:
			return
		case <-asking:
			if !d.controllerStep(s, func() { control.serve() }) {
				return
			}
		case at := <-ticks:
			if !d.controllerStep(s, func() {
				now := d.snapshot(account.Live, at)
				if err := log.write(stated(d.session, at, now, previous)); err != nil {
					d.logFailures.Add(1)
				}
				previous = now
			}) {
				return
			}
		}
	}
}

// daemon is one output session between its activation and its seal.
type daemon struct {
	shutdownInit       sync.Once
	shutdown           *shutdownBoundary
	shutdownPlan       account.Account
	shutdownHooks      *shutdownHooks
	shutdownEarlyHooks *shutdownHooks
	controllerFailure  atomic.Pointer[shutdownFailure]
	finishOnce         sync.Once
	finishErr          error
	withdrawalOnce     sync.Once
	withdrawalResult   chan withdrawalResult
	processingStart    sync.Once
	processingMutex    sync.Mutex
	processingClosed   bool

	policy  policy.Policy
	session string

	// path is the configuration this session started with, which reload reads
	// again.
	path string

	// directory holds this session's accounts. Output uses stable parent paths.
	directory string

	output             *processing.Writer
	processing         *processingRun
	capture            *capture.Session
	attached           probe.Attachment
	intake             *intake.Store
	gate               *probe.DeliveryGate
	payloadPosture     protected.Posture
	verifyParticipants func(*probe.DeliveryGate, []process.Process) (protected.Posture, error)
	// processingTaken is processing.Options.Taken for this session's workers;
	// nil outside tests.
	processingTaken func(worker int, process fragment.Process, connection fragment.ConnectionID)

	// plan is the account at activation - resolved policy and what the kernel
	// confirmed attached - which every later account starts from. planMutex
	// guards its processes, which an attachment's goroutine drops as their
	// executions end (ended).
	plan      account.Account
	planMutex sync.Mutex

	// log is the session's log, which extensions' standard error is copied
	// into; extensionLogFailures counts the lines of it that could not be
	// written, from the extensions' own goroutines.
	log                  *logger
	extensionLogFailures atomic.Int64

	// endedLogFailures counts the ends of executions that could not be written
	// to the log, from the attachment's goroutines (ended), and ends is where
	// the attachment tells of them.
	endedLogFailures atomic.Int64
	ends             *endings

	logFailures atomic.Int64
}

// begin establishes dumpability in the payload holder and verifies the entire
// protected setup before attach. Plaintext does not exist here before attach;
// moving any plaintext earlier would invalidate this ordering argument.
func begin(read policy.Policy, session string) (*daemon, error) {
	return beginWithWriter(read, session, processing.WriterOptions{Directory: read.Settings.Directory})
}

func beginWithWriter(read policy.Policy, session string, options processing.WriterOptions) (*daemon, error) {
	if read.Processing == nil || read.ProcessingRevision == "" {
		return nil, &protected.Refusal{Check: protected.ProcessingPlan, PID: os.Getpid(), Detail: "a compiler-produced processing plan and revision are required"}
	}
	if err := undumpable(); err != nil {
		return nil, err
	}
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
	plan.Extensions = account.ExtensionsOf(read.Processing.Extensions())
	plan.Kernel = kernelOf(procfs)
	if err := selectedAnything(resolution); err != nil {
		return nil, err
	}
	participants := make([]process.Process, 0, len(resolution.Selections))
	for _, selection := range resolution.Selections {
		participant, found := table.Lookup(selection.ObserverPID)
		if !found {
			return nil, &protected.Refusal{Check: protected.ParticipantOutsideEnvelope, PID: os.Getpid(), Detail: fmt.Sprintf("selected participant pid %d has no identity reading", selection.ObserverPID)}
		}
		participants = append(participants, participant)
	}
	directory := filepath.Join(read.Settings.Directory, sessionsName, session)
	// Leave control state before capture starts, including when no command
	// ever asks this session for an account before it dies.
	if err := os.MkdirAll(filepath.Join(directory, controlName), 0700); err != nil {
		return nil, err
	}
	output, err := processing.OpenWriter(options)
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	removeOutput := func() { _ = output.Close(); _ = os.RemoveAll(directory) }

	prepared, err := protected.Prepare(read, participants, uint64(read.Settings.AdmittedEventLimit))
	if err != nil {
		removeOutput()
		return nil, err
	}

	leaveNothing := func() {
		_ = prepared.Intake.Close()
		_ = output.Close()
		_ = os.RemoveAll(directory)
	}
	recording := prepared.Recording
	ends := &endings{}
	attached, observed, err := observe(catalog, resolution, table, recording, prepared.Gate, ends.told)
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
		capture: recording, attached: attached, plan: plan,
		output: output,
		intake: prepared.Intake, gate: prepared.Gate, payloadPosture: prepared.Posture,
		verifyParticipants: protected.VerifyActive, ends: ends,
	}, nil
}

// abandon undoes a session that attached and could not be activated.
func (d *daemon) abandon() {
	_ = d.attached.Close()
	_ = d.output.Close()
	_ = d.intake.Close()
	_ = os.RemoveAll(d.directory)
}

// resolve reads the host and resolves the policy. Listening sockets are read
// only for a port target and the boot id only for a pid target; an unreadable
// boot refuses those pid targets by name.
func resolve(approval process.Approval) (process.Resolution, process.Table, error) {
	return resolveFrom(procfs, approval)
}

// kernelOf is the release of the kernel under root, as the session's account
// records it. It is read at activation and carried, because inspection may run
// on another host, whose kernel says nothing about this session's.
func kernelOf(root string) *account.Kernel {
	path := filepath.Join(root, "sys/kernel/osrelease")
	content, err := os.ReadFile(path)
	release := strings.TrimSpace(string(content))
	switch {
	case err != nil:
		return &account.Kernel{Why: err.Error()}
	case release == "":
		return &account.Kernel{Why: path + " is empty"}
	}
	return &account.Kernel{Release: release}
}

func resolveFrom(root string, approval process.Approval) (process.Resolution, process.Table, error) {
	return approval.ResolveFrom(root)
}

// undumpable makes this process non-dumpable, as the payload holder must be
// before anything attaches. start does it before its envelope is checked, and
// preflight before it judges the envelope, so both judge the same process.
func undumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return &protected.Refusal{Check: protected.CoreDumps, PID: os.Getpid(), Detail: fmt.Sprintf("set payload-holder dumpability before attach: %v", err)}
	}
	return nil
}

// envelopeJudged is start's envelope check (activation.Envelope) on this
// process and the selected ones, in the words preflight reports.
func envelopeJudged(selected []process.Process) []preflight.EnvelopeJudgment {
	var judged []preflight.EnvelopeJudgment
	for _, one := range protected.Envelope(selected) {
		judged = append(judged, preflight.EnvelopeJudgment{Check: string(one.Check), Met: one.Met,
			Unreadable: one.Unreadable, PID: one.PID, Detail: one.Detail})
	}
	return judged
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
	run := account.Run{Seen: d.capture.Stats()}
	run.Losses, run.LossesErr = losses(d.attached)
	run.Refusals, run.RefusalsErr = refused(d.attached)
	if granting, can := d.attached.(probe.Granting); can {
		run.Grants, run.GrantsErr = granting.Grants()
		if run.GrantsErr == nil && run.Grants == nil {
			run.Grants = []probe.Grant{}
		}
		// Read after the grants: reading them lets go of the admissions it finds
		// ended, which are counted here.
		if ending, can := d.attached.(probe.Ending); can && run.GrantsErr == nil {
			run.Ended, run.GrantsErr = ending.EndedCounts()
		}
	} else {
		run.GrantsErr = errors.New("this attachment does not record what it admitted")
	}
	run.Processing = d.processingSnapshot()
	// The plan is read after the grants, whose reading drops the processes it
	// finds ended.
	d.planMutex.Lock()
	a := d.plan
	a.Processes = slices.Clone(d.plan.Processes)
	d.planMutex.Unlock()
	a.Kind = kind
	a.Ran(at, run)
	if d.log != nil && d.log.queue != nil {
		stats := d.log.queue.Stats()
		a.LogDelivery = &stats
		a.LogDestinations = d.log.destinationStats()
	}
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
		Gap: fmt.Sprintf("last validated seal: %s, session %s; this session activated at %s; coverage in between is not established",
			last.Sealed.UTC().Format(time.RFC3339Nano), last.Session, activatedAt.UTC().Format(time.RFC3339Nano)),
	}
}

// notify tells a supervisor that named a notify socket that the session is up.
// Readiness follows successful activation independently of log delivery.
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

// observe groups selected processes by their catalogue-selected adapter and
// describes what the kernel says about each. Each adapter gets its complete
// group at once: per-process placement on a shared file would duplicate calls.
func observe(catalog probe.Catalog, resolution process.Resolution, table process.Table,
	sink probe.Sink, gate *probe.DeliveryGate, ended func(probe.Ended)) (probe.Attachment, []attachment.Observed, error) {
	state := gate.Snapshot()
	if state.MaxEvents == 0 || state.Charged != 0 || state.Reason != "" {
		return nil, nil, &protected.Refusal{Check: protected.DeliveryGate, PID: os.Getpid(), Detail: "attach requires the verified fresh delivery gate"}
	}
	reports := make(map[int32]probe.Report)

	attempts := make([]attachment.Attempt, 0, len(resolution.Selections))
	request := probe.Request{Deny: resolution.Denials, DeliveryGate: gate, Ended: ended}
	for _, one := range resolution.Selections {
		p, found := table.Lookup(one.ObserverPID)
		if !found {
			continue
		}
		attempt := attachment.Attempt{
			Process:  p,
			Admitted: one,
			Alive:    alive(p),
			Support:  catalog.Inspect(p),
		}
		attempt.Catalogued = cataloguedFor(attempt.Support)
		reports[p.PID] = attempt.Support
		if attempt.Support.Supported && attempt.Alive {
			request.Processes = append(request.Processes, p)
			request.Admit = append(request.Admit, one)
		}
		attempts = append(attempts, attempt)
	}

	var live probe.Attachment
	var attachErr error
	if len(request.Processes) > 0 {
		group, err := attachment.Attach(catalog, request, reports, sink)
		attachErr = err
		if group != nil {
			live = group
		}
	}

	observed := make([]attachment.Observed, 0, len(attempts))
	var reasons []string
	for _, attempt := range attempts {
		switch {
		case !attempt.Support.Supported || !attempt.Alive:
		case attachErr != nil:
			attempt.Err = attachErr
		default:
			owner := live
			if grouped, ok := live.(*attachment.Group); ok {
				owner, attempt.Err = grouped.ForProcess(attempt.Process.PID)
			}
			attested, canAttest := owner.(probe.Attested)
			attempt.Attested = canAttest
			if canAttest {
				attempt.Placements, attempt.Err = attested.Placements(attempt.Process.PID)
			}
			if owner != nil {
				attempt.Capability = owner.Capability()
			}
			// What the attachment covering this process can do, which may be less than
			// the whole attachment.
			if covering, can := owner.(probe.Covering); can {
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

// cataloguedFor names the selected runtime's expected placements.
func cataloguedFor(report probe.Report) []string {
	if report.Adapter == probe.OpenSSL.Name {
		return catalogued()
	}
	for _, support := range report.Support {
		if support.Adapter == report.Adapter {
			var symbols []string
			for _, point := range support.Probes {
				symbols = append(symbols, point.Symbol)
			}
			return symbols
		}
	}
	return nil
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
