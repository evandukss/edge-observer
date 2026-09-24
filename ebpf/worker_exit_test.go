//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
)

func independentRetiringWorkerSource() string {
	return "#define _GNU_SOURCE\n" + independentTransferSource + `
#include <sys/syscall.h>

static int retire_commands[2], survivor_commands[2], identities[2], answers[2];
struct worker_identity { int kind; pid_t tid; };

static void *retiring_worker(void *unused) {
    struct worker_identity who = {1, (pid_t)syscall(SYS_gettid)};
    if (write(identities[1], &who, sizeof(who)) != sizeof(who)) _exit(30);
    char command;
    if (read(retire_commands[0], &command, 1) != 1) _exit(31);
    return NULL;
}

static void *surviving_worker(void *unused) {
    struct worker_identity who = {2, (pid_t)syscall(SYS_gettid)};
    if (write(identities[1], &who, sizeof(who)) != sizeof(who)) _exit(32);
    char command;
    while (read(survivor_commands[0], &command, 1) == 1) {
        int result = transfer("/independent-after-worker-exit");
        if (write(answers[1], &result, sizeof(result)) != sizeof(result)) _exit(33);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    port = atoi(argv[1]);
    context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    printf("ready\n"); fflush(stdout);
    pthread_t retiring, surviving;
    pid_t retired_tid = 0, survivor_tid = 0;
    char command[8];
    while (fgets(command, sizeof(command), stdin)) {
        if (command[0] == 'T') {
            if (pipe(retire_commands) || pipe(survivor_commands) || pipe(identities) || pipe(answers)) return 34;
            if (pthread_create(&retiring, NULL, retiring_worker, NULL) ||
                pthread_create(&surviving, NULL, surviving_worker, NULL)) return 35;
            for (int i = 0; i < 2; i++) {
                struct worker_identity who;
                if (read(identities[0], &who, sizeof(who)) != sizeof(who)) return 36;
                if (who.kind == 1) retired_tid = who.tid;
                else if (who.kind == 2) survivor_tid = who.tid;
                else return 37;
            }
            printf("workers %d %d\n", retired_tid, survivor_tid);
        } else if (command[0] == 'P') {
            printf("parent %d\n", transfer("/independent-parent"));
        } else if (command[0] == 'R') {
            if (write(retire_commands[1], "R", 1) != 1) return 38;
            if (pthread_join(retiring, NULL)) return 39;
            printf("retired %d\n", retired_tid);
        } else if (command[0] == 'G') {
            if (write(survivor_commands[1], "G", 1) != 1) return 40;
            int result;
            if (read(answers[0], &result, sizeof(result)) != sizeof(result)) return 41;
            printf("worker %d\n", result);
        }
        fflush(stdout);
    }
    return 0;
}
`
}

func independentLiveTask(t *testing.T, pid, tid int32) {
	t.Helper()
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/stat", pid, tid))
	if err != nil {
		t.Fatalf("required live task %d of process %d is absent: %v", tid, pid, err)
	}
	_, suffix, found := strings.Cut(string(stat), ") ")
	if !found || len(suffix) == 0 || suffix[0] == 'Z' || suffix[0] == 'X' || suffix[0] == 'x' {
		t.Fatalf("task %d of process %d is not live: %q", tid, pid, stat)
	}
}

func independentRetiredTask(t *testing.T, pid, tid int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := os.Stat(fmt.Sprintf("/proc/%d/task/%d", pid, tid))
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			t.Fatalf("cannot establish whether worker %d retired: %v", tid, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("joined worker %d has not left process %d", tid, pid)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkerExitPreservesTheLeaderAndAnotherWorkersCapture(t *testing.T) {
	for _, beforeAttach := range []bool{true, false} {
		t.Run(fmt.Sprintf("workers-before-attach=%t", beforeAttach), func(t *testing.T) {
			port, received := independentPeer(t)
			actor := independentActor(t, independentRetiringWorkerSource(), port)
			parent := loaded(t, int32(actor.command.Process.Pid))
			var retired, survivor int32
			startWorkers := func() {
				if _, err := io.WriteString(actor.input, "T\n"); err != nil {
					t.Fatal(err)
				}
				line, err := actor.output.ReadString('\n')
				if _, scanErr := fmt.Sscanf(line, "workers %d %d", &retired, &survivor); err != nil || scanErr != nil || retired <= 0 || survivor <= 0 || retired == survivor || retired == parent.PID || survivor == parent.PID {
					t.Fatalf("two distinct non-leader workers were not established: %q: %v, %v", line, err, scanErr)
				}
				independentLiveTask(t, parent.PID, retired)
				independentLiveTask(t, parent.PID, survivor)
			}
			if beforeAttach {
				startWorkers()
			}
			session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: authorise(parent)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = session.Close() }()
			if !beforeAttach {
				// A count seeded at attach must not hide the ordinary case where
				// the process creates and retires workers after capture starts.
				startWorkers()
			}
			if _, err := io.WriteString(actor.input, "P\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "parent 0\n")
			peerReceived(t, received, "/independent-parent")
			control := attribution(drain(session, 100*time.Millisecond), "/independent-parent")
			if control == nil || control.Generation == 0 || control.PID != parent.PID {
				t.Fatalf("pre-exit peer-confirmed capture control was not established: %+v", control)
			}
			if _, err := io.WriteString(actor.input, "R\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, fmt.Sprintf("retired %d\n", retired))
			independentRetiredTask(t, parent.PID, retired)
			independentLiveTask(t, parent.PID, parent.PID)
			independentLiveTask(t, parent.PID, survivor)
			check := func(path string, tid int32, generation admission.Generation) {
				count := 0
				for _, event := range drain(session, 100*time.Millisecond).events {
					if event.Kind != ebpf.Transfer || event.Direction != fragment.Sent || !strings.Contains(string(event.Payload), path) {
						continue
					}
					count++
					if event.PID != parent.PID || event.TID != tid || event.Namespace != parent.Namespace || event.NamespacePID != parent.NamespacePID || event.Generation != generation {
						t.Errorf("worker retirement changed the surviving execution's grant or attribution: %+v", event)
					}
				}
				if count != 1 {
					t.Errorf("peer-confirmed transfer by surviving task %d appeared %d times after non-leader exit, want 1", tid, count)
				}
			}
			if _, err := io.WriteString(actor.input, "G\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "worker 0\n")
			peerReceived(t, received, "/independent-after-worker-exit")
			check("/independent-after-worker-exit", survivor, control.Generation)
			if _, err := io.WriteString(actor.input, "P\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "parent 0\n")
			peerReceived(t, received, "/independent-parent")
			check("/independent-parent", parent.PID, control.Generation)
			independentLiveTask(t, parent.PID, parent.PID)
			independentLiveTask(t, parent.PID, survivor)
		})
	}
}
