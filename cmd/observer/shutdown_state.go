package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/evandukss/edge-observer/account"
)

// The trigger watcher owns these deadlines independently of the controller and
// finalization owners. Production's exit callback is os.Exit: no deferred close
// or blocked filesystem operation can postpone the backstop.
type shutdownBoundary struct {
	once          sync.Once
	started       chan struct{}
	work          context.Context
	publish       context.Context
	cancelWork    context.CancelFunc
	cancelPublish context.CancelFunc
	exit          func(int)
	hard          *time.Timer
	hardMutex     sync.Mutex
	disarmed      bool
}

func newShutdownBoundary(exit func(int)) *shutdownBoundary {
	return &shutdownBoundary{started: make(chan struct{}), exit: exit}
}

func (s *shutdownBoundary) trigger() {
	s.once.Do(func() {
		at := time.Now()
		s.work, s.cancelWork = context.WithDeadline(context.Background(), at.Add(shutdownWorkWithin))
		s.publish, s.cancelPublish = context.WithDeadline(context.Background(), at.Add(shutdownExitWithin))
		s.hardMutex.Lock()
		if s.exit != nil && !s.disarmed {
			s.hard = time.AfterFunc(time.Until(at.Add(shutdownExitWithin)), func() { s.exit(1) })
		}
		s.hardMutex.Unlock()
		close(s.started)
	})
}

func (s *shutdownBoundary) finished() {
	s.cancelWork()
	s.cancelPublish()
	// start disarms the independent exit timer only after its deferred cleanup.
}

// disarm runs last when start returns. A completed command invocation must not
// retain a timer that can terminate a later invocation in the same process.
func (s *shutdownBoundary) disarm() {
	s.hardMutex.Lock()
	defer s.hardMutex.Unlock()
	s.disarmed = true
	if s.hard != nil {
		s.hard.Stop()
	}
}

type shutdownFailure struct {
	Stage shutdownStage
	Err   error
}

func (e *shutdownFailure) Error() string { return fmt.Sprintf("%s: %v", e.Stage, e.Err) }
func (e *shutdownFailure) Unwrap() error { return e.Err }

// A timed-out owner can finish its private call, but it cannot hand a later
// result back into the account. The channel owns that result and has no reader
// once the deadline wins.
func shutdownStep[T any](ctx context.Context, hooks *shutdownHooks, stage shutdownStage, fn func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, &shutdownFailure{stage, fmt.Errorf("not reached: %w", err)}
	}
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		if hooks != nil && hooks.Before != nil {
			if err := hooks.Before(ctx, stage); err != nil {
				done <- result{err: err}
				return
			}
		}
		if err := ctx.Err(); err != nil {
			done <- result{err: err}
			return
		}
		value, err := fn()
		done <- result{value, err}
	}()
	select {
	case got := <-done:
		if err := ctx.Err(); err != nil {
			return zero, &shutdownFailure{stage, err}
		}
		if got.err != nil {
			return got.value, &shutdownFailure{stage, got.err}
		}
		return got.value, nil
	case <-ctx.Done():
		return zero, &shutdownFailure{stage, ctx.Err()}
	}
}

func shutdownCall(ctx context.Context, hooks *shutdownHooks, stage shutdownStage, fn func() error) error {
	_, err := shutdownStep(ctx, hooks, stage, func() (struct{}, error) { return struct{}{}, fn() })
	return err
}

// readSessionSeal is shared by stop, inspection and discovery. The pointer and
// command receipt never participate in validating a session's own proof.
func readSessionSeal(session fs.FS) (account.Account, []byte, error) {
	content, err := fs.ReadFile(session, sealedName)
	if err != nil {
		return account.Account{}, nil, err
	}
	var a account.Account
	if err = json.Unmarshal(content, &a); err != nil {
		return a, nil, fmt.Errorf("read the sealed account: %w", err)
	}
	if err = validateSessionSeal(a); err != nil {
		return a, nil, err
	}
	return a, content, nil
}

func validateSessionSeal(a account.Account) error {
	switch {
	case a.Version != account.Version:
		return fmt.Errorf("the sealed account is version %d and this observer reads version %d", a.Version, account.Version)
	case a.Kind != account.Sealed:
		return fmt.Errorf("%s holds a %s account, and a finished session's is %s", sealedName, a.Kind, account.Sealed)
	case a.Session == "" || a.Seal == nil || a.Seal.Sealed.IsZero() || a.SealError != "":
		return fmt.Errorf("%w: account has no valid final seal", errNeverSealed)
	}
	return nil
}

// terminalName is command control state, not seal evidence. It is written only
// after publication attempts. Its absence cannot turn a valid seal into an
// unsealed session, but stop cannot claim command success without it.
const terminalName = "stop-result.json"

type shutdownReceipt struct {
	Session string          `json:"session"`
	Sealed  time.Time       `json:"sealed"`
	Outcome shutdownOutcome `json:"outcome"`
	Error   string          `json:"error,omitempty"`
}

func (d *daemon) placeFinal(ctx context.Context, stage shutdownStage, path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return &shutdownFailure{stage, err}
	}
	return shutdownCall(ctx, d.shutdownHooks, stage, func() error {
		return placeBefore(ctx, path, append(content, '\n'))
	})
}

// Temporary writes are not publication. Recheck permission after every possibly
// blocking preparation step and immediately before the atomic rename. A syscall
// already handed to the OS is not recalled; production's hard exit ends its owner.
func placeBefore(ctx context.Context, path string, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".seal-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, writeErr := f.Write(content)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func stoppedSession(directory, session string, stdout io.Writer) error {
	path := filepath.Join(directory, sessionsName, session)
	a, _, err := readSessionSeal(os.DirFS(path))
	if err != nil {
		return fmt.Errorf("session %s ended UNSEALED: %w", session, err)
	}
	if a.Session != session {
		return fmt.Errorf("session %s ended UNSEALED: account belongs to %s", session, a.Session)
	}
	how := "complete"
	if !a.Seal.Complete {
		how = "INCOMPLETE: " + strings.Join(a.Seal.Because, "; ")
	}
	if lost := a.Lost(); lost != "" {
		how += " (LOST " + lost + ")"
	}
	if a.Processing != nil && a.Processing.GateReason != "" {
		how += ", release refused: " + string(a.Processing.GateReason)
	}
	if _, err := fmt.Fprintf(stdout, "stopped    session %s, sealed %s, account %s\n", session, how, filepath.Join(path, sealedName)); err != nil {
		return err
	}
	content, err := os.ReadFile(filepath.Join(path, controlName, terminalName))
	if err != nil {
		return fmt.Errorf("session %s is sealed; command publication outcome unavailable: %w", session, err)
	}
	var receipt shutdownReceipt
	if err := json.Unmarshal(content, &receipt); err != nil {
		return fmt.Errorf("session %s is sealed; invalid command outcome: %w", session, err)
	}
	if receipt.Session != session || !receipt.Sealed.Equal(a.Seal.Sealed) {
		return fmt.Errorf("session %s is sealed; command outcome does not match this seal", session)
	}
	if !a.Seal.Complete {
		return fmt.Errorf("session %s sealed INCOMPLETE: %s", session, strings.Join(a.Seal.Because, "; "))
	}
	if a.Processing != nil && a.Processing.GateReason.InvalidatesCapture() {
		return fmt.Errorf("capture ended: %s", a.Processing.GateReason)
	}
	if receipt.Outcome != shutdownComplete || receipt.Error != "" {
		return fmt.Errorf("session %s sealed; %s: %s", session, receipt.Outcome, receipt.Error)
	}
	return nil
}

// controllerStep keeps one controller operation at a time. Once shutdown starts,
// the caller waits only until the original work deadline; a held operation may
// finish privately but cannot hold up the controller's return to finalization.
func (d *daemon) controllerStep(s *shutdownBoundary, fn func()) bool {
	done := make(chan error, 1)
	go func() {
		if err := d.beforeShutdown(context.Background(), shutdownController); err != nil {
			done <- err
			return
		}
		select {
		case <-s.started:
			if err := s.work.Err(); err != nil {
				done <- err
				return
			}
		default:
		}
		fn()
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			d.controllerFailure.Store(&shutdownFailure{shutdownController, err})
			s.trigger()
			return false
		}
		return true
	case <-s.started:
		select {
		case <-done:
		case <-s.work.Done():
		}
		return false
	}
}
