//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

// The parent is the tracer and deliberately does not wait for the worker
// until commanded. Its child is the admitted TLS actor. No observer result
// decides when the two terminal tasks have been established.
const executionZombieSource = independentTransferSource + `
#include <sys/ptrace.h>
#include <sys/syscall.h>
static int commands[2], reports[2];
static void report_int(int value) {
    if (write(reports[1], &value, sizeof(value)) != sizeof(value)) _exit(31);
}
static int take_int(void) {
    int value;
    if (read(reports[0], &value, sizeof(value)) != sizeof(value)) exit(32);
    return value;
}
static char take_command(void) {
    char command;
    if (read(commands[0], &command, 1) != 1) _exit(33);
    return command;
}
static void *remaining_worker(void *unused) {
    report_int((int)syscall(SYS_gettid));
    while (take_command() == 'G') report_int(transfer("/execution-worker"));
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 2 || pipe(commands) || pipe(reports)) return 34;
    port = atoi(argv[1]);
    pid_t child = fork();
    if (child < 0) return 35;
    if (!child) {
        close(commands[1]); close(reports[0]);
        context = SSL_CTX_new(TLS_client_method());
        if (!context) return 36;
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
        report_int(0);
        if (take_command() != 'P') return 37;
        report_int(transfer("/execution-leader"));
        take_command();
        pthread_t worker;
        if (pthread_create(&worker, NULL, remaining_worker, NULL)) return 38;
        pthread_exit(NULL);
    }
    close(commands[0]); close(reports[1]);
    if (take_int()) return 39;
    printf("ready\nactor %d\n", child); fflush(stdout);
    char line[16]; pid_t tid = 0;
    while (fgets(line, sizeof(line), stdin)) {
        char command = line[0];
        if (command == 'P' || command == 'G') {
            if (write(commands[1], &command, 1) != 1) return 40;
            printf("transfer %d\n", take_int());
        } else if (command == 'L' || command == 'U') {
            if (write(commands[1], &command, 1) != 1) return 41;
            tid = take_int();
            if (command == 'L' && ptrace(PTRACE_SEIZE, tid, 0, 0)) {perror("seize");return 42;}
            printf("worker %d\n", tid);
        } else if (command == 'X') {
            if (write(commands[1], &command, 1) != 1) return 43;
            printf("exiting\n");
        } else if (command == 'R') {
            int status;
            if (waitpid(tid, &status, __WALL) != tid || !WIFEXITED(status)) return 44;
            printf("reaped\n");
        } else break;
        fflush(stdout);
    }
    kill(child, SIGKILL);
    while (waitpid(-1, NULL, __WALL) > 0) {}
    return 0;
}
`

func executionActorNumber(t *testing.T, actor *armingProcess, label string) int32 {
	t.Helper()
	line, err := actor.output.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var gotLabel string
	var pid int32
	if _, err := fmt.Sscanf(line, "%s %d", &gotLabel, &pid); err != nil || gotLabel != label || pid <= 0 {
		t.Fatalf("fixture: expected %s identity, got %q", label, line)
	}
	return pid
}

func executionTaskState(t *testing.T, pid, tid int32, want byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/stat", pid, tid))
		if err != nil {
			t.Fatal(err)
		}
		end := strings.LastIndex(string(stat), ")")
		if end < 0 {
			t.Fatal("fixture: real stat has no comm boundary")
		}
		fields := strings.Fields(string(stat)[end+1:])
		if len(fields) > 0 && fields[0] == string(want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("fixture: task %d never reached %c: %s", tid, want, stat)
		}
		time.Sleep(time.Millisecond)
	}
}

func executionThreadCount(t *testing.T, pid int32, want string) {
	t.Helper()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Threads:") {
			if strings.TrimSpace(strings.TrimPrefix(line, "Threads:")) != want {
				t.Fatalf("fixture: thread count is %q, want %s", line, want)
			}
			return
		}
	}
	t.Fatal("fixture: Threads is absent")
}

func TestExecutionRetainedTerminalGroupHasAnActualNonrunningResult(t *testing.T) {
	for _, traced := range []bool{false, true} {
		t.Run(fmt.Sprintf("traced=%t", traced), func(t *testing.T) {
			port, received := independentPeer(t)
			actor := independentActor(t, executionZombieSource, port)
			pid := executionActorNumber(t, actor, "actor")
			parent := loaded(t, pid)
			session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: authorise(parent)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = session.Close() }()
			admitted := independentAdmittedIdentity(t, session, parent)
			if _, err := io.WriteString(actor.input, "P\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "transfer 0\n")
			peerReceived(t, received, "/execution-leader")
			if attribution(drain(session, 100*time.Millisecond), "/execution-leader") == nil {
				t.Fatal("fixture: selected leader's transfer did not reach observer")
			}
			command := "U\n"
			if traced {
				command = "L\n"
			}
			if _, err := io.WriteString(actor.input, command); err != nil {
				t.Fatal(err)
			}
			tid := executionActorNumber(t, actor, "worker")
			executionTaskState(t, pid, pid, 'Z')
			executionTaskState(t, pid, tid, 'S')
			executionThreadCount(t, pid, "2")
			if _, err := io.WriteString(actor.input, "G\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "transfer 0\n")
			peerReceived(t, received, "/execution-worker")
			_ = drain(session, 100*time.Millisecond)
			independentWithdrawal(t, session, admitted, ebpf.GrantEndedWhileRunning)
			live, err := session.Withdrawn()
			if err != nil || len(live) != 1 {
				t.Fatalf("live group result: %v %+v", err, live)
			}
			retained := live[0].Reading
			if retained.Witness.TID != tid || retained.Witness.State != 'S' {
				t.Fatalf("live witness does not name the peer-confirmed worker: %+v", retained)
			}
			if _, err := io.WriteString(actor.input, "X\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "exiting\n")
			executionTaskState(t, pid, pid, 'Z')
			if traced {
				executionTaskState(t, pid, tid, 'Z')
				executionThreadCount(t, pid, "2")
			} else {
				deadline := time.Now().Add(5 * time.Second)
				for {
					_, err := os.Stat(fmt.Sprintf("/proc/%d/task/%d", pid, tid))
					if os.IsNotExist(err) {
						break
					}
					if err != nil || time.Now().After(deadline) {
						t.Fatalf("fixture: final worker has not exited: %v", err)
					}
					time.Sleep(time.Millisecond)
				}
				executionThreadCount(t, pid, "1")
			}
			if held, err := ebpf.IndependentKernelGrantPresent(session, admitted); err != nil || held {
				t.Fatalf("fixture: absent grant not established: %t %v", held, err)
			}
			known := 0
			for _, one := range session.Inventory() {
				if one.Instance.Key() == admitted.Key() {
					known++
				}
			}
			if known != 1 {
				t.Fatalf("retained admission count %d, want one", known)
			}
			got, err := session.Withdrawn()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Selection.Instance.Key() != admitted.Key() {
				t.Fatalf("terminal retained admission needs exactly one matching result: %+v", got)
			}
			if got[0].State != ebpf.ExecutionEnded && got[0].State != ebpf.ExecutionIndeterminate {
				t.Errorf("terminal group reported running: %+v", got[0])
			}
			if !reflect.DeepEqual(live[0].Reading, retained) || live[0].Reading.Witness.TID != tid || live[0].Reading.Observed.From.IsZero() {
				t.Error("past observation was lost after witness exit")
			}
			if traced {
				if _, err := io.WriteString(actor.input, "R\n"); err != nil {
					t.Fatal(err)
				}
				actorLine(t, actor, "reaped\n")
			}
		})
	}
}
