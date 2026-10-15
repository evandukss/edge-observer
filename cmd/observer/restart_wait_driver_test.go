package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// This test executable runs the real command. Only its first post-signal
// holder observation waits for the attach test's pipe handshake. The result
// comes from holder, and is returned unchanged after the fixture unlocks.
func init() {
	if os.Getenv("OBSERVER_RESTART_WAIT_DRIVER") != "1" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "restart" {
		restarting.stop = func(c checked, stdout io.Writer) error {
			events := os.NewFile(3, "restart wait events")
			commands := os.NewFile(4, "restart wait commands")
			defer func() {
				_ = events.Close()
				_ = commands.Close()
			}()
			encoder, decoder := json.NewEncoder(events), json.NewDecoder(commands)
			emit := func(event map[string]any) {
				event["at"] = time.Now().UnixNano()
				exitOnError(encoder.Encode(event))
			}
			await := func(want string) {
				var command string
				exitOnError(decoder.Decode(&command))
				if command != want {
					exitOnError(fmt.Errorf("wiring: restart wait command %q, want %q", command, want))
				}
			}
			calls := 0
			return stopInUsing(c.read.Settings.Directory, stdout, func(directory string) (int, string, error) {
				calls++
				if calls != 1 {
					return holder(directory)
				}
				emit(map[string]any{"kind": "poll-entered", "directory": directory,
					"checked": fmt.Sprintf("sha256:%x", sha256.Sum256(c.content))})
				await("observe")
				path := filepath.Join(directory, pidName)
				file, err := os.Open(path)
				exitOnError(err)
				defer func() { _ = file.Close() }()
				var stat syscall.Stat_t
				exitOnError(syscall.Fstat(int(file.Fd()), &stat))
				held, err := probeHolder(file)
				exitOnError(err)
				content, err := os.ReadFile(path)
				exitOnError(err)
				if !held || len(content) != 0 {
					exitOnError(fmt.Errorf("wiring: restart observation has held=%t, bytes=%d", held, len(content)))
				}
				pid, session, observed := holder(directory)
				want := fmt.Sprintf("a session holds %s and has not activated yet, so it answers nothing", path)
				if observed == nil || observed.Error() != want || errors.Is(observed, errNotRunning) || pid != 0 || session != "" {
					exitOnError(fmt.Errorf("wiring: real holder returned %d %q %v, want the held-empty observation", pid, session, observed))
				}
				emit(map[string]any{"kind": "held-empty", "held": held, "bytes": len(content),
					"device": uint64(stat.Dev), "inode": stat.Ino, "pid": pid, "session": session,
					"error": observed.Error(), "not_running": errors.Is(observed, errNotRunning)})
				await("released")
				emit(map[string]any{"kind": "returning-observation", "error": observed.Error()})
				return pid, session, observed
			})
		}
	}
	main()
	os.Exit(0)
}
