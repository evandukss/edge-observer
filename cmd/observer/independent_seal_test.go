package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/internal/published"
)

func it4Account(t *testing.T, directory string) account.Account {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, sealedName))
	if err != nil {
		t.Fatal(err)
	}
	var a account.Account
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestIndependentP4PublicationFailures(t *testing.T) {
	for _, stage := range []shutdownStage{shutdownAccount, shutdownProjection, shutdownPointer} {
		t.Run(string(stage), func(t *testing.T) {
			f := processingController(t)
			f.liveControl(t)
			f.halt(t)
			calls := 0
			var accountAtBoundary []byte
			fault := errors.New("independent publication failure")
			f.d.shutdownHooks = &shutdownHooks{Before: func(_ context.Context, at shutdownStage) error {
				if at != stage {
					return nil
				}
				calls++
				accountAtBoundary, _ = os.ReadFile(filepath.Join(f.d.directory, sealedName))
				return fault
			}}
			var logs bytes.Buffer
			log := &logger{out: &logs}
			err := f.finish(log)
			_ = log.close()
			if calls == 0 {
				t.Fatal("wiring: publication boundary was never reached")
			}
			if stage != shutdownAccount && len(accountAtBoundary) == 0 {
				t.Fatal("wiring: failure did not follow successful account publication")
			}
			if err == nil {
				t.Error("publication failure returned success")
			}
			var read bytes.Buffer
			inspectErr := inspect(f.d.directory, false, &read)
			if stage == shutdownAccount {
				if inspectErr == nil || !errors.Is(inspectErr, errNeverSealed) {
					t.Errorf("failed account publication must be unsealed: %v", inspectErr)
				}
				if _, err := os.Stat(filepath.Join(f.d.policy.Settings.Directory, lastName)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("failed account publication installed a discovery pointer: %v", err)
				}
			} else {
				if inspectErr != nil {
					t.Errorf("later publication failure undid the session seal: %v", inspectErr)
				}
				if !bytes.Equal(read.Bytes(), accountAtBoundary) {
					t.Error("account changed after its authoritative publication")
				}
				_, projectionErr := os.Stat(filepath.Join(f.d.directory, published.Name))
				if stage == shutdownProjection && !errors.Is(projectionErr, os.ErrNotExist) {
					t.Errorf("failed projection unexpectedly exists: %v", projectionErr)
				}
				if stage == shutdownPointer && projectionErr != nil {
					t.Errorf("pointer failure removed the earlier projection: %v", projectionErr)
				}
			}
			lines := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte{'\n'})
			if len(lines) != 1 {
				t.Fatalf("terminal outcome record count=%d want 1", len(lines))
			}
			var terminal stopped
			if err := json.Unmarshal(lines[0], &terminal); err != nil {
				t.Fatal(err)
			}
			if terminal.Record != "stopped" || terminal.Sealed != (stage != shutdownAccount) {
				t.Errorf("stopped record misstates actual seal: %+v", terminal)
			}
			if stage == shutdownProjection && !strings.Contains(terminal.ContractError, fault.Error()) {
				t.Errorf("projection failure not reported in stopped record: %+v", terminal)
			}
		})
	}
}

func TestIndependentP4AccountPublishedOnceWithFinalFacts(t *testing.T) {
	f := processingController(t)
	f.liveControl(t)
	f.halt(t)
	var logs bytes.Buffer
	log := &logger{out: &logs}
	f.d.log = log
	if err := log.write(map[string]string{"record": "before-seal"}); err != nil {
		t.Fatal(err)
	}
	var first []byte
	accountCalls, projectionCalls := 0, 0
	f.d.shutdownHooks = &shutdownHooks{Before: func(_ context.Context, stage shutdownStage) error {
		switch stage {
		case shutdownAccount:
			accountCalls++
		case shutdownProjection:
			projectionCalls++
			if first == nil {
				first, _ = os.ReadFile(filepath.Join(f.d.directory, sealedName))
			}
		}
		return nil
	}}
	if err := f.finish(log); err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("wiring: no account observed before projection")
	}
	if accountCalls != 1 || projectionCalls != 1 {
		t.Errorf("publication counts: account=%d projection=%d; each must be published once", accountCalls, projectionCalls)
	}
	final, err := os.ReadFile(filepath.Join(f.d.directory, sealedName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, final) {
		t.Error("published account was rewritten")
	}
	var initial account.Account
	if err := json.Unmarshal(first, &initial); err != nil {
		t.Fatal(err)
	}
	if initial.LogDelivery == nil || initial.LogDelivery.Authorized != 1 || initial.LogDelivery.Written != 1 || initial.LogDelivery.Pending != 0 {
		t.Errorf("first publication omitted final pre-seal log accounting: %+v", initial.LogDelivery)
	}
}

func TestIndependentP4SealsEndureAndGapStaysUnknown(t *testing.T) {
	root := t.TempDir()
	seal := func(name string, fail bool) *processingControllerFixture {
		f := processingController(t)
		f.liveControl(t)
		f.halt(t)
		f.d.policy.Settings.Directory = root
		f.d.session, f.d.plan.Session = name, name
		if fail {
			f.d.shutdownHooks = &shutdownHooks{Before: func(_ context.Context, at shutdownStage) error {
				if at == shutdownAccount {
					return errors.New("account unavailable")
				}
				return nil
			}}
		}
		err := f.finish(&logger{})
		if (err != nil) != fail {
			t.Fatalf("wiring: finalization fail=%t returned %v", fail, err)
		}
		return f
	}
	a := seal("session-a", false)
	activated := time.Now().Add(time.Second)
	assertGap := func(d *daemon) {
		t.Helper()
		got := d.follows(activated)
		sealed := it4Account(t, a.d.directory)
		if sealed.Seal == nil || got == nil || got.Session != "session-a" || !got.Sealed.Equal(sealed.Seal.Sealed) {
			t.Fatalf("gap lost the last validated seal: %+v", got)
		}
		if strings.Contains(got.Gap, "nothing was observed") || !strings.Contains(got.Gap, "not established") {
			t.Errorf("gap claims knowledge of intervening observation: %q", got.Gap)
		}
		if !strings.Contains(got.Gap, activated.UTC().Format(time.RFC3339Nano)) || !strings.Contains(got.Gap, sealed.Seal.Sealed.UTC().Format(time.RFC3339Nano)) {
			t.Errorf("gap does not retain seal and activation times: %q", got.Gap)
		}
	}
	assertGap(a.d)
	unsealed := seal("observing-unsealed", true)
	assertGap(unsealed.d)
	b := seal("session-b", false)
	copied := filepath.Join(t.TempDir(), "copied-a")
	if err := os.CopyFS(copied, os.DirFS(a.d.directory)); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{a.d.directory, b.d.directory, copied} {
		var out bytes.Buffer
		if err := inspect(dir, false, &out); err != nil {
			t.Errorf("seal did not survive a later seal/directory copy at %s: %v", dir, err)
		}
	}
	var out bytes.Buffer
	if err := inspect(unsealed.d.directory, false, &out); !errors.Is(err, errNeverSealed) {
		t.Errorf("unpublished account became sealed after B: %v", err)
	}
}

func TestIndependentP4FirstTriggerKeepsDeadlines(t *testing.T) {
	boundary := newShutdownBoundary(nil)
	boundary.trigger()
	defer boundary.finished()
	work, workOK := boundary.work.Deadline()
	publication, publicationOK := boundary.publish.Deadline()
	if !workOK || !publicationOK || publication.Sub(work) != 5*time.Second {
		t.Fatalf("first trigger lacks shared 20s/25s deadlines: %v %v", work, publication)
	}
	boundary.trigger()
	laterWork, _ := boundary.work.Deadline()
	laterPublication, _ := boundary.publish.Deadline()
	if !work.Equal(laterWork) || !publication.Equal(laterPublication) {
		t.Errorf("later trigger reset first deadlines: work %v -> %v; publication %v -> %v", work, laterWork, publication, laterPublication)
	}
}
