package bpf

import "golang.org/x/sys/unix"

// SocketCalls is the system calls the program follows as a TLS call's socket
// I/O (obs_supported in ssl.bpf.h), by this architecture's numbers, each named
// as the program names it (OBS_SYS_*, in lower case). It lives beside the
// program because a reader outside it decides from it whether a thread is
// inside such a call; TestTheSocketCallsAreTheOnesTheProgramFollows pins the
// names against the program's own list.
var SocketCalls = map[int64]string{
	unix.SYS_READ: "read", unix.SYS_WRITE: "write", unix.SYS_READV: "readv", unix.SYS_WRITEV: "writev",
	unix.SYS_PREAD64: "pread64", unix.SYS_PWRITE64: "pwrite64", unix.SYS_PREADV: "preadv",
	unix.SYS_PWRITEV: "pwritev", unix.SYS_SENDTO: "sendto", unix.SYS_RECVFROM: "recvfrom",
	unix.SYS_SENDMSG: "sendmsg", unix.SYS_RECVMSG: "recvmsg", unix.SYS_RECVMMSG: "recvmmsg",
	unix.SYS_SENDMMSG: "sendmmsg",
}
