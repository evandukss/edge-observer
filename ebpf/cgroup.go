package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// CgroupID is the cgroup v2 id of a process: its cgroup directory's inode,
// which bpf_get_current_cgroup_id reports in the kernel and which, unlike a
// path, answers whether two processes share a cgroup. The allowlist is not
// keyed on it: a cgroup holds everything a supervisor started. It reads
// /proc/<pid>/cgroup ("0::/path" on a unified hierarchy) and stats the path
// under the cgroup mount. A legacy-only host has no such id, and this says so.
func CgroupID(procfs, mount string, pid int32) (uint64, error) {
	content, err := os.ReadFile(filepath.Join(procfs, strconv.FormatInt(int64(pid), 10), "cgroup"))
	if err != nil {
		return 0, fmt.Errorf("read the cgroup of pid %d: %w", pid, err)
	}

	var relative string
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		// The unified hierarchy's line has an empty controller list: "0::/...".
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			relative = rest
			break
		}
	}
	if relative == "" {
		return 0, fmt.Errorf("pid %d is on no cgroup v2 hierarchy, which is what the allowlist needs", pid)
	}

	path := filepath.Join(mount, filepath.Clean("/"+relative))
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, fmt.Errorf("stat the cgroup %s: %w", path, err)
	}
	return stat.Ino, nil
}

// DefaultCgroupMount is where a unified cgroup hierarchy is usually mounted.
const DefaultCgroupMount = "/sys/fs/cgroup"
