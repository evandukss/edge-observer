// SPDX-License-Identifier: GPL-2.0-only
//
// Shared body of the two OpenSSL plaintext probes: one file compiled twice,
// differing in one guarded region. sslfull.bpf.c defines READ_PAYLOAD 1 and
// reads the caller's buffer; sslmeta.bpf.c defines READ_PAYLOAD 0 and reads no
// process memory. The observer loads the first. A build-time check over the
// compiled objects proves the second calls no user-memory read helper
// (verify.go).
//
// The allowlist is in the kernel, ahead of every read: a uprobe fires for every
// process running the file, so an unapproved process is refused here, before
// its bytes are read into an event.
//
// It holds process instances, which are what an operator approves and what a
// fragment is attributed to. A cgroup is not one: a supervisor puts everything
// it starts in one cgroup. Threads need no entry, since the key is the thread
// group. A pid alone is not an instance: the key is the pid namespace (its
// nsfs device and inode) and the thread group id inside it, and the value
// carries an admission generation separating this occupant of the number from
// the next.
//
// The kernel changes the set while probes are placed: a child is added at the
// fork event that creates it, before it runs, and a process is removed where it
// exits. A userspace walk of the process table cannot do this in time: a
// forking server can finish a loopback conversation within milliseconds.
//
// An entry names its occupant: a grant carries the birth of the thread group it
// was written for and is authenticated against the running group before use.
//
// The kernel floor is 5.15, forced by the atomic allocators: three use their
// fetch-and-add result (BPF_ATOMIC with BPF_FETCH, 5.12). The ring buffer (5.8)
// and bpf_get_ns_current_pid_tgid (5.7) do not bind (package ebpf,
// MinimumKernel). The host must publish its own BTF for the kernel reads to
// relocate; without CONFIG_DEBUG_INFO_BTF the program does not load.
#ifndef OBSERVER_SSL_BPF_H
#define OBSERVER_SSL_BPF_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// The kernel structures this program reads, declared here rather than taken
// from vmlinux.h, field by field, so what it can reach is written down. Every
// access goes through CO-RE and is relocated against the running kernel's BTF,
// so these declarations decide nothing about layout. That needs BTF on the host
// at load time, not a toolchain. The helper set is checked at build time
// (verify.go).
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

// upid is one process's number in one pid namespace. struct pid holds one per
// level, and the deepest is the task's own active namespace.
struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct ns_common {
	unsigned int inum;
};

struct pid_namespace {
	struct ns_common ns;
};

struct pid {
	unsigned int level;
	struct upid numbers[1];
};

struct task_struct {
	int pid;
	int tgid;
	struct task_struct *group_leader;
	struct pid *thread_pid;
	unsigned long long start_boottime;
	struct signal_struct *signal;
};

// signal_struct is what a thread group's threads share. live counts those that
// have not begun to exit: do_exit decrements it before sched_process_exit is
// raised, so a thread reading zero there is its group's last. It is an
// atomic_t in the kernel, a structure around one int.
struct obs_atomic {
	int counter;
};

struct signal_struct {
	struct obs_atomic live;
};

// The socket evidence reads these and nothing else, declared field by field for
// the reason above.
//
// sock_common carries the family, which separates an IP socket from everything
// this build does not cover. It heads struct sock, so sk->__sk_common is the
// socket's own family and protocol. The endpoints and their namespace are read
// from the same object at the same moment. The addresses are read at the hook
// and no pointer is kept: what leaves the read is bytes.
//
// skc_daddr and skc_rcv_saddr are __be32, already in wire order. skc_num is the
// local port in host order and skc_dport the peer's in network order, so
// exactly one is swapped. Four of these sit in anonymous unions (skc_addrpair,
// skc_portpair); CO-RE walks anonymous members, so they are named flat.
struct in6_addr {
	__u8 in6_u[16];
};

typedef struct {
	struct net *net;
} possible_net_t;

struct net {
	struct ns_common ns;
};

struct sock_common {
	__u32 skc_daddr;
	__u32 skc_rcv_saddr;
	__u16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
	possible_net_t skc_net;
};

struct sock {
	struct sock_common __sk_common;
};

struct socket {
	short type;
	struct file *file;
	struct sock *sk;
};

// i_mode answers whether the acquired file is a socket (S_ISSOCK). i_ino is the
// socket's inode number, the one ss and /proc/net report.
struct inode {
	unsigned short i_mode;
	unsigned long i_ino;
};

struct file {
	struct inode *f_inode;
};

#pragma clang attribute pop

// S_IFMT and S_IFSOCK are the file-type bits of i_mode: ABI, the same on every
// architecture, so written here rather than taken from a kernel header.
#define OBS_S_IFMT 0170000
#define OBS_S_IFSOCK 0140000

// The address families this build claims. Anything else, such as a unix-domain
// socket carrying TLS, is reported as an unsupported route.
#define OBS_AF_INET 2
#define OBS_AF_INET6 10

// OBS_NSEC_PER_TICK converts a kernel birth to the unit /proc reports. Field 22
// of /proc/<pid>/stat is nsec_to_clock_t(start_boottime), and USER_HZ is 100 on
// both targets whatever CONFIG_HZ is. /proc also adds the reader's time
// namespace boot offset, which the kernel side cannot see; a session with a
// non-zero offset refuses to attach (package process, StartTimesAreOffset).
#define OBS_NSEC_PER_TICK 10000000ULL

// The deepest pid namespace resolved here. The kernel's limit is 32; beyond it
// a read went wrong.
#define OBS_PID_LEVEL_MAX 32

// The probe context is the saved user registers. bpf_tracing.h needs a full
// struct pt_regs from vmlinux.h or a kernel header; the calling-convention
// layout is small and defined here for both architectures, so a probe reads
// its arguments without BTF. PARM1..4 are the first four integer arguments, RC
// the return value.
#if defined(__TARGET_ARCH_arm64)
struct obs_pt_regs { __u64 regs[31]; __u64 sp; __u64 pc; __u64 pstate; };
#define OBS_PARM1(c) (((const struct obs_pt_regs *)(c))->regs[0])
#define OBS_PARM2(c) (((const struct obs_pt_regs *)(c))->regs[1])
#define OBS_PARM3(c) (((const struct obs_pt_regs *)(c))->regs[2])
#define OBS_PARM4(c) (((const struct obs_pt_regs *)(c))->regs[3])
#define OBS_PARM5(c) (((const struct obs_pt_regs *)(c))->regs[4])
#define OBS_RC(c)    (((const struct obs_pt_regs *)(c))->regs[0])
// Where the first syscall argument sits in the saved registers, as an offset:
// behind a raw syscall tracepoint the registers are kernel memory and are read
// as such, unlike a uprobe's context.
#define OBS_SYSCALL_ARG1 __builtin_offsetof(struct obs_pt_regs, regs)
#elif defined(__TARGET_ARCH_x86)
struct obs_pt_regs {
	__u64 r15, r14, r13, r12, bp, bx, r11, r10, r9, r8, ax, cx, dx, si, di;
	__u64 orig_ax, ip, cs, flags, sp, ss;
};
#define OBS_PARM1(c) (((const struct obs_pt_regs *)(c))->di)
#define OBS_PARM2(c) (((const struct obs_pt_regs *)(c))->si)
#define OBS_PARM3(c) (((const struct obs_pt_regs *)(c))->dx)
#define OBS_PARM4(c) (((const struct obs_pt_regs *)(c))->cx)
#define OBS_PARM5(c) (((const struct obs_pt_regs *)(c))->r8)
#define OBS_RC(c)    (((const struct obs_pt_regs *)(c))->ax)
#define OBS_SYSCALL_ARG1 __builtin_offsetof(struct obs_pt_regs, di)
#else
#error "no argument registers are known for this target architecture"
#endif

// The syscalls followed, by number, per architecture (read is 0 on x86-64 and
// 63 on arm64). Recording every syscall in a call window instead cannot work:
// an unresolved read and a successful futex are the same absence of evidence.
// The list is the scalar, vector and messaging families. sendfile and splice
// (no user buffer) and io_uring (completes on another thread) are reported as
// unsupported routes.
#if defined(__TARGET_ARCH_arm64)
#define OBS_SYS_READ 63
#define OBS_SYS_WRITE 64
#define OBS_SYS_READV 65
#define OBS_SYS_WRITEV 66
#define OBS_SYS_PREAD64 67
#define OBS_SYS_PWRITE64 68
#define OBS_SYS_PREADV 69
#define OBS_SYS_PWRITEV 70
#define OBS_SYS_SENDTO 206
#define OBS_SYS_RECVFROM 207
#define OBS_SYS_SENDMSG 211
#define OBS_SYS_RECVMSG 212
#define OBS_SYS_RECVMMSG 243
#define OBS_SYS_SENDMMSG 269
#define OBS_SYS_SENDFILE 71
#define OBS_SYS_SPLICE 76
#define OBS_SYS_IO_URING_ENTER 426
#elif defined(__TARGET_ARCH_x86)
#define OBS_SYS_READ 0
#define OBS_SYS_WRITE 1
#define OBS_SYS_READV 19
#define OBS_SYS_WRITEV 20
#define OBS_SYS_PREAD64 17
#define OBS_SYS_PWRITE64 18
#define OBS_SYS_PREADV 295
#define OBS_SYS_PWRITEV 296
#define OBS_SYS_SENDTO 44
#define OBS_SYS_RECVFROM 45
#define OBS_SYS_SENDMSG 46
#define OBS_SYS_RECVMSG 47
#define OBS_SYS_RECVMMSG 299
#define OBS_SYS_SENDMMSG 307
#define OBS_SYS_SENDFILE 40
#define OBS_SYS_SPLICE 275
#define OBS_SYS_IO_URING_ENTER 426
#else
#error "no syscall numbers are known for this target architecture"
#endif

// The most bytes one event carries from a call. A larger call becomes a
// truncated fragment, read as a gap at its end rather than a shift of the
// stream (package fragment). The metadata-only program keeps none.
#define OBS_CHUNK 4096

// dir
#define OBS_SENT 1
#define OBS_RECEIVED 2

// kind
#define OBS_TRANSFER 1
#define OBS_CLOSED 2
// OBS_ENDED is an execution this program delivered events for that has ended:
// whatever userspace keeps for it can go. It carries no bytes and no ending of
// any connection; its connections' endings come before it.
#define OBS_ENDED 3

// how a call reports the count it moved
#define OBS_COUNT_RETURNED 1     // the return value is the count
#define OBS_COUNT_OUTPARAM 2     // a status returned, count written through a pointer
#define OBS_COUNT_NONE 3         // moves no bytes (a connection ending)

// function codes: which entry point an in-flight call belongs to. The table is
// keyed by thread and function, so SSL_write_early_data calling SSL_write on
// the same thread does not clobber the outer call's state.
#define OBS_FUNC_READ 1
#define OBS_FUNC_WRITE 2
#define OBS_FUNC_READ_EX 3
#define OBS_FUNC_WRITE_EX 4
#define OBS_FUNC_READ_EARLY 5
#define OBS_FUNC_WRITE_EARLY 6
#define OBS_FUNC_WRITE_EX2 7
// OBS_FUNC_MAX bounds the per-function arrays: one past the last code, so a
// code is its own index.
#define OBS_FUNC_MAX 8

// stats indices
#define OBS_STAT_RESERVE_FAILED 0  // a ring-buffer reservation the kernel refused
#define OBS_STAT_UNMATCHED 1       // a return whose entry was never seen
#define OBS_STAT_DESCENDANTS 2     // processes authorised because their parent was
#define OBS_STAT_REFUSED 3         // an in-flight call whose approval had gone by its return
#define OBS_STAT_CALL_UNRECORDED 4 // an entry the in-flight table would not take
#define OBS_STAT_READ_UNRECORDED 5 // a user-memory read that could not be filed against its admission
#define OBS_STAT_DESCENDANT_UNRECORDED 6 // a descendant the allowlist would not take
#define OBS_STAT_DENIAL_UNRECORDED 7 // a child of a denied instance the allowlist would not take
#define OBS_STAT_DEFERRED_DISCARDED 8 // a call held through a fork window whose task was never admitted
#define OBS_STAT_SOCKET_UNRECORDED 9  // a descriptor lifetime the socket table would not take
#define OBS_STAT_BINDING_UNRECORDED 10 // a handle binding the binding table would not take
#define OBS_STAT_UNMEASURABLE_CALL 11 // a call through a function this session holds no return probe for
#define OBS_STAT_UNAUTHENTICATED 12 // a task whose birth is not the one the grant on its key was written for
#define OBS_STAT_CHILD_UNNAMEABLE 13 // a child the fork event could not name at all
#define OBS_STAT_STALE_BINDING_DROPPED 14 // a binding a gone occupant of a number left behind, dropped at a free
#define OBS_STAT_CHILD_NS_UNENUMERATED 15 // a child created in a pid namespace this session did not enumerate
// The five ways out of the socket observation: four record nothing and the
// fifth records one. They are counted together, since four failure counters at
// zero and four that cannot move read alike (obs_saw_socket).
#define OBS_STAT_SOCKET_FD_INVALID 16   // socket work whose descriptor is not one
#define OBS_STAT_SOCKET_OUTSIDE_CALL 17 // socket work on a thread with no call in flight
#define OBS_STAT_SOCKET_UNLOCATABLE 18  // socket work inside a call whose task could not be named
#define OBS_STAT_SOCKET_NO_LIFETIME 19  // a descriptor inside a call with no occupancy this run recorded
#define OBS_STAT_SOCKET_RECORDED 20     // a descriptor recorded against the call in flight on its thread
#define OBS_STAT_OPERATION_UNRECORDED 21 // an operation frame the table would not take
#define OBS_STAT_OPERATION_OVERWRITTEN 22 // a frame still live when the next operation opened on that thread
#define OBS_STAT_OPERATION_UNMATCHED 23 // a syscall exit with no frame of its own
#define OBS_STAT_EVIDENCE_UNREADABLE 24 // an acquired object this program could not read
#define OBS_STAT_SOCKET_UNDISCOVERED 25 // a socket the discovery table would not take
#define OBS_STAT_DISCOVERY_CONTENDED 26 // a first discovery that lost its race and took the winner's generation
// The occupancy sequence's: what happened to the numbering of a handle's calls.
#define OBS_STAT_OCCUPANCY_UNRECORDED 27 // an occupancy the table would not take, so its calls carry no number
#define OBS_STAT_NESTED_WRAPPER 28  // a call nested in one on the same handle and direction, whose bytes the outer call reports
#define OBS_STAT_NESTED_ELSEWHERE 29 // a nested call no wrapper explains (another handle or direction), numbered as a loss
#define OBS_STAT_OVERLAPPED 30      // a call entered while another in its direction was in flight on its handle
#define OBS_STAT_BORN 31            // an occupancy begun at its handle's observed birth
#define OBS_STAT_HOLDER_UNRECORDED 32 // an execution the reclamation table would not take, whose entries outlive it
#define OBS_STAT_READS_RECLAIMED 33   // user-memory reads of admissions that ended, folded here as their entries went
#define OBS_STAT_READ_RETRACTED 34   // a read whose grant ended before its bookkeeping settled
#define OBS_STAT_MAX 35

// what is established about which socket a call's bytes crossed. It is on the
// event because it is decided inside the call, where the evidence is. Zero is
// a valid descriptor, so a consumer reads this state, never the number (package
// connection).
#define OBS_FD_NONE 0        // no valid binding, and the descriptor field means nothing
#define OBS_FD_ESTABLISHED 1 // one descriptor, seen inside this call or inherited from the handle
#define OBS_FD_AMBIGUOUS 2   // the call's window held socket work on more than one descriptor
#define OBS_FD_INVALIDATED 3 // the handle's descriptor was replaced or its lifetime evidence ended

// What happened to a call's own kernel I/O, worst first. A call keeps the worst:
// a later good operation does not clean an unreadable one, and none falls
// through to OBS_OUTCOME_NONE (no kernel I/O, a buffered read or write), the
// only case that inherits an earlier binding.
#define OBS_OUTCOME_NONE 0        // no kernel I/O in this call
#define OBS_OUTCOME_SOCKET 1      // I/O on a socket, and the socket was established
#define OBS_OUTCOME_FILE 2        // I/O the kernel classified as an ordinary file
#define OBS_OUTCOME_UNRESOLVED 3  // a positive supported syscall that reached no evidence
#define OBS_OUTCOME_UNSUPPORTED 4 // I/O through a route this build does not follow
#define OBS_OUTCOME_UNREADABLE 5  // an acquired object this program could not read
#define OBS_OUTCOME_BROKEN 6      // an operation frame that was overwritten or unmatched

// how an instance came to be in the allowlist. What it may pass on to its
// children is the mode below (the operator's permission); whether this program
// can name its children is the propagate field (a fact about the host)
// (package admission, Kind and Propagation).
#define OBS_BY_TARGET 1   // a target the operator wrote named it
#define OBS_BY_DESCENT 2  // an admitted process created it
#define OBS_DENIED 3      // an exclusion denies it, and everything it forks

// A denial occupies the key an admission would, so a target naming an excluded
// instance finds the denial and does not overwrite it: a direct include does
// not override a subtree exclusion.

// the descendant mode a target carries. There is no default: an entry with no
// mode is refused by the policy.
#define OBS_MODE_NONE 1      // the matched instances only
#define OBS_MODE_EXISTING 2  // those, plus descendants already running at resolution
#define OBS_MODE_FOLLOW 3    // those, plus descendants created afterwards

// whether this program can name what an instance forks. A child is named in its
// own pid namespace, which must be one the program was given.
#define OBS_PROPAGATE_NO 1
#define OBS_PROPAGATE_YES 2

// The most pid namespaces one session enumerates. A process in a namespace
// userspace did not pass in is refused (package ebpf, Session.authorise).
#define OBS_NAMESPACES 8

// obs_ns is one pid namespace as bpf_get_ns_current_pid_tgid names it: the
// device and inode of its nsfs entry, as /proc/<pid>/ns/pid shows.
struct obs_ns {
	__u64 dev;
	__u64 ino;
};

// instance_key identifies one process instance: the thread group id inside the
// named namespace, the numbering the process and its own fork use.
struct instance_key {
	__u64 ns_dev;
	__u64 ns_ino;
	__u32 pid;
	__u32 reserved;
};

// admission is why an instance is in the allowlist, read again before every
// user-memory read.
//
// birth is who the grant was written for: the thread group leader's start, in
// the clock ticks /proc/<pid>/stat field 22 reports (per task in the kernel,
// the leader's for the whole group in /proc). A read or propagation checks the
// current thread group against it first (obs_birth, obs_grant).
//
// generation separates one admission of an instance from the next: birth says
// which process holds the number, generation which grant. Userspace counts up
// from one and the kernel from 1<<63, so they never collide (package
// admission, Generation).
struct admission {
	__u64 generation;
	__u64 birth;
	__u64 parent_generation;
	__u64 parent_ns_dev;
	__u64 parent_ns_ino;
	__u32 parent_pid;
	// target is the target that admitted it or, by descent, its ancestor: the
	// session's identity for that target, which a reload never gives to another
	// (package ebpf, targetIdentity). A denial carries its exclusion's number.
	__u32 target;
	__u32 rule;      // which condition inside that target matched, counting from one

	// threads is how many of the instance's threads still run, and leader_gone
	// whether its leader has exited. A thread group can outlive its leader
	// (pthread_exit from main), and non-leader exits never end a process, so: the
	// leader's exit ends the grant unless other threads remain, in which case it is
	// recorded; a non-leader's exit ends it only after that. Userspace seeds the
	// count from /proc/<pid>/status and the fork hook seeds a child with one. Too
	// low ends the grant at the leader's exit; too high leaves an entry that
	// reconciliation withdraws (package ebpf, Reconcile).
	__u32 threads;

	__u8  kind;        // OBS_BY_TARGET or OBS_BY_DESCENT
	__u8  mode;        // OBS_MODE_*, the operator's permission
	__u8  propagate;   // OBS_PROPAGATE_*, what this host can actually do
	__u8  leader_gone; // the thread-group leader has exited and threads remain

	// Explicit padding so the C and Go structures have one size; otherwise the C
	// one gains four bytes at the end (package ebpf, abi_test.go).
	__u8  reserved[4];
};

// call is what an entry probe records for its matching return. It is kept per
// thread: a thread is inside two only by recursion.
struct call {
	__u64 ssl;        // the connection handle, argument one
	__u64 buf;        // the caller's buffer, argument two
	__u64 cap;        // the buffer's capacity, argument three
	__u64 pcount;     // the out-parameter the _ex family writes its count through
	__u64 generation; // the admission this call was entered under

	// sequence separates this call from the next on the same thread and handle.
	// The admission generation cannot (every call of the process carries it), and
	// without this a frame left by a returned call would fill the next one with
	// older evidence.
	__u64 sequence;
	__u32 func;       // which entry point, so a nested return is not mistaken for this one

	// The socket work this call did, recorded by the socket probes while it is in
	// flight. This entry is the mark: a socket probe finding a live call knows its
	// syscall happened inside a TLS call on this thread, and one finding none
	// returns at once. The syscall need not come from the TLS library: libcurl
	// sends from its own custom BIO. fds is capped at two, since two is already
	// ambiguous.
	__s32 fd;         // the first descriptor seen in the window
	__u8  fds;        // how many DISTINCT descriptors the window held, capped at two

	// What the kernel acquired for this call's own I/O, from which the association
	// is built. The descriptor above is what the process passed; this is what the
	// operation used, and they differ where a descriptor arrived without a syscall
	// or was replaced mid-call. sockets is capped at two for the same reason.
	__u64 socket;      // the identity of the first socket this call's I/O used
	__u64 socket_ino;  // that socket's own inode, which is what a reader outside can compare
	__u64 socket_gen;  // the discovery generation of that socket
	__u64 socket_occ;  // what was behind that descriptor number when the operation opened

	// The socket's endpoints, read at the hook that acquired it and never
	// re-derived from a pointer; they belong to the socket, so an inherited binding
	// carries them. The field order leaves no compiler padding in this block, so
	// the Go mirror is written field for field.
	__u64 net_ino;     // the SOCKET's own network namespace, not the process's
	__u64 opened;      // when this run saw the socket created, monotonic; zero where it did not
	__u8  local[16];   // the local address, v4 written in its v4-mapped form
	__u8  peer[16];    // the peer's, the same way
	__u16 lport;       // host order
	__u16 dport;       // host order, swapped from the kernel's network order

	__s32 socket_fd;   // the descriptor the operation passed for it
	__u8  sockets;     // how many DISTINCT sockets the call's I/O used, capped at two
	__u8  ends;        // whether the two addresses were read
	__u8  outcome;     // the worst thing that happened to this call's I/O, OBS_OUTCOME_*

	// io says this call performed kernel I/O of its own, whatever came of it. The
	// outcome is folded worst first, so an operation moving nothing (zero, EAGAIN,
	// an error) can leave it unchanged: a write that met EAGAIN and succeeded on
	// retry is one transfer. Such a call is still not the no-I/O case, the only
	// one that may inherit an earlier binding.
	__u8  io;

	__u8  dir;
	__u8  count;      // one of OBS_COUNT_*
	__u8  early;

	// deferred says the call was recorded during a fork window for a task with no
	// admission, so its generation is not an admission. It is a field rather than
	// a generation of zero, which would mean "no grant" only by allocator floors.
	__u8  deferred;

	// live says whether the call is still in flight. A completed call leaves its
	// entry with this clear, because returns of entry points reached inside it
	// arrive afterwards and an empty table cannot tell those from a return whose
	// entry was never seen (OpenSSL 3.5.7: two SSL_write_ex calls gave two
	// SSL_write_ex2 returns with no entries, in varying order).
	__u8  live;

	// nested is how many calls through this same function are open inside this
	// one, so their returns are not taken for this call's (a TLS connection
	// carried inside another, through a BIO that writes into the outer handle).
	__u8  nested;

	// To eight-byte alignment, so the size is fixed too; the Go mirror's total is
	// asserted against the loaded program.
	__u8  live_padding[6];

	// occupancy is the occupancy this call's number is taken in, read at entry;
	// zero where none could be kept. A return finding another occupancy held for
	// the handle numbers nothing in it.
	__u64 occupancy;

	// number is this call's place in its occupancy and direction, taken at ENTRY
	// (obs_take), so a return that never fires leaves this number missing from the
	// occupancy, which capture reads as a gap. A return that fires fills it: with a
	// transfer when bytes moved, or a zero-byte resolution when none did, so
	// "returned with nothing" is told from "never returned". Zero for a deferred
	// call (no occupancy at entry; numbered at return instead).
	__u64 number;
};

// event is one firing delivered to userspace. The metadata-only program
// submits it with kept always zero and data untouched. It carries the whole
// instance (ns_dev, ns_ino, nspid, generation) and pid, the observer's own
// numbering for /proc; grouping by pid alone would splice streams.
struct event {
	// stamp is this event's place in the session-wide production order, taken
	// before the reservation (attempts). It counts what was produced; which
	// connection lost an event is said by the occupancy and number below.
	__u64 stamp;

	// binding is the generation of the fd occupancy this event's association rests
	// on: a number closed and reused, or replaced under a live handle by dup2, is a
	// different socket with the same number.
	__u64 binding;

	__u64 ssl;
	__u64 generation;
	__u64 ns_dev;
	__u64 ns_ino;

	// socket is the inode of the socket this call's I/O crossed, the kernel's own
	// identity for it. Zero is a socket with no file, an absence.
	__u64 socket;

	__u32 pid;      // the observer's numbering
	__u32 tid;
	__u32 nspid;    // the thread group id inside ns_dev:ns_ino
	__u32 length;   // bytes the call moved, when measured
	__u32 kept;     // bytes copied into data (full program only)

	// fd is the descriptor this call's bytes crossed; fd_state says what is
	// established about it, and is what a consumer reads.
	__s32 fd;

	__u8  dir;
	__u8  early;
	__u8  measured; // whether length is a real count
	__u8  kind;     // OBS_TRANSFER, OBS_CLOSED or OBS_ENDED
	__u8  fd_state; // one of OBS_FD_*

	// outcome is what this call's own kernel I/O came to (OBS_OUTCOME_*): why
	// there is no binding, where fd_state says there is none. Only a call with no
	// I/O may carry an earlier binding forward.
	__u8  outcome;

	// The socket's endpoints, appended after every earlier field so no offset
	// above moves; only the payload's start does (one constant in package ebpf).
	// Flat rather than nested, because the layout guard does not descend (Fields).
	__u8  ends;         // whether the two addresses were read
	__u8  padding;      // to the next eight-byte boundary, so net_ino's offset
	//                     does not depend on a compiler's choice
	__u64 net_ino;      // the SOCKET's own network namespace
	__u8  local[16];    // the local address, v4 in its v4-mapped form
	__u8  peer[16];     // the peer's, the same way
	__u16 lport;        // host order
	__u16 dport;        // host order
	__u8  padding_end[4];

	// The socket's own start, monotonic, appended after the endpoints.
	__u64 opened;

	// The admission the event was taken under (struct origin), appended after
	// everything else. A process the fork hook admitted is written by nothing in
	// userspace, and its grant is gone once it exits, which can be before its
	// events are read; so what a record of it needs travels with its events.
	__u64 parent_generation;
	__u64 parent_ns_dev;
	__u64 parent_ns_ino;
	__u32 parent_pid;
	__u32 target;
	__u32 rule;
	__u8  admitted_by;  // OBS_BY_TARGET or OBS_BY_DESCENT
	__u8  padding_origin[3];

	// The event's place in its occupancy of the handle (struct occupancy),
	// appended after the origin. occupancy zero is an event the program kept no
	// occupancy for. number is a transfer's place in its direction, zero on an
	// ending and on a call that moved no bytes. last_sent and last_received are an
	// ending's last numbers, and in_flight which directions had a call that had
	// not returned (bit OBS_SENT, bit OBS_RECEIVED). unlocated is the count of
	// losses no occupancy could take, read as this event was produced. dropped is
	// this direction's refused-reservation count read as this event was produced,
	// so a reader knows how many drops lie below this number and never counts one
	// twice at the tail (capture settleLocked). It is appended after the padding so
	// no offset above it moves; only the payload's start does (rawHeader).
	__u64 occupancy;
	__u64 number;
	__u64 unlocated;
	__u64 last_sent;
	__u64 last_received;
	__u8  born;
	__u8  overlapped;
	__u8  in_flight;
	// exited says an ending was raised because its execution ended (exit, or an
	// exec replacing its image) with the handle's occupancy still held, rather than
	// by a release of the handle.
	__u8  exited;
	__u8  padding_place[4];
	__u64 dropped;
	__u64 begin_unlocated;
	__u8  data[OBS_CHUNK];
};

// inflight holds the outermost probed call on each thread. A TLS library
// implements one entry point by calling another (SSL_write_early_data reaches
// SSL_write), and probing both would count the same bytes more than once (on
// Debian trixie one early write reached the wire as three transfers). Only the
// outermost call is recorded; inner ones are ignored.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct call);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// allowed_processes is the in-kernel allowlist, keyed by process instance.
// Empty admits nothing. The value says why the entry is here (target, rule,
// parent), so withdrawing one target cannot take another's grant.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct instance_key);
	__type(value, struct admission);
} allowed_processes SEC(".maps");

// namespaces is every pid namespace userspace enumerated. A process whose own
// namespace is not here resolves in none and is refused.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, OBS_NAMESPACES);
	__type(key, __u32);
	__type(value, struct obs_ns);
} namespaces SEC(".maps");

// generations is the kernel's admission-generation allocator. Userspace seeds
// it at attach beyond its own allocator's range (package admission,
// KernelGenerations).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} generations SEC(".maps");

// forking is how many admitted instances are inside a fork right now. A call
// by an unadmitted task during that window is recorded without reading
// anything, and decided again at its return against the admission then in
// force. The ordered fork event (obs_fork) already admits a child before it can
// run, so this window rarely decides anything; removing it would also remove
// the deferred mark, its counter and reason, both libc fork probes and their
// tests.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} forking SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, OBS_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// unmatched is when a return with no entry of its own was seen, so the count
// beside it can be correlated after the run. The clock is bpf_ktime_get_ns:
// CLOCK_MONOTONIC nanoseconds since this boot, not advancing across suspend,
// resolution per the host clocksource. The first and last occasions bound the
// interval; the handle and task are the first one's. Timing supports a
// correlation, not a cause: a call entered before attach can return long after.
struct unmatched {
	__u64 first;
	__u64 last;
	__u64 ssl;
	__u32 pid;
	__u32 tid;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct unmatched);
} unmatched_at SEC(".maps");

// unmeasurable is the functions this session holds no return probe for, by
// function code. The kernel can take an entry probe and refuse its return; the
// entry would then stay in flight and every later call on that thread would
// read as nested. So a call through one of these records nothing and is
// counted. Userspace marks every function before placing any probe and clears
// those whose return probe the kernel confirms (package ebpf, Session.place).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, OBS_FUNC_MAX);
	__type(key, __u32);
	__type(value, __u8);
} unmeasurable SEC(".maps");

// attempts is the event-order allocator: stamped on every event before its
// reservation is attempted, and read as a value rather than summed. Its final
// value counts what was produced: attempted reservations plus calls refused at
// the read boundary (package connection, Counters). It does not locate a loss:
// two producers can take stamps in one order and reserve in the other, so a
// missing stamp can be an event not yet handed over. A loss is located by the
// occupancy sequence (occupancies).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} attempts SEC(".maps");

#if READ_PAYLOAD
// reads counts the user-memory reads taken, by the admission generation each
// was taken under (the saved call's, so a read for a gone admission is filed
// under it). It exists in the full program only. It proves the read boundary
// where output absence cannot: a read whose output is discarded still counts,
// because the count is taken at the read.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u64);
} reads SEC(".maps");
#endif

// socket_key names one descriptor of one admitted execution; the value carries
// a generation, since descriptor numbers are reused.
struct socket_key {
	__u64 ns_dev;
	__u64 ns_ino;
	__u32 pid;
	__s32 fd;
};

// socket_life is one occupancy of a descriptor. A binding remembers the
// generation it was made against, and a descriptor closed and reopened, or
// replaced by dup2, carries a different one, so nothing has to find the
// binding to invalidate it.
struct socket_life {
	__u64 generation;

	// opened is when this run saw the socket created (return of socket, accept or
	// connect), on the monotonic clock. The kernel keeps no creation time: sockfs
	// inodes carry no times, and struct sock and struct tcp_sock timestamps are
	// about packets. A kernel stamping sockfs inode times would let this be read
	// at acquisition instead, covering sockets opened before attach. Zero means the
	// socket existed before the probes were placed.
	__u64 opened;
};

// handle_key names one TLS handle of one admitted execution, which a binding
// belongs to, never a thread: thread history misattributes pooled connections.
struct handle_key {
	__u64 ns_dev;
	__u64 ns_ino;
	__u32 pid;
	__u32 reserved;
	__u64 ssl;
};

// binding is a handle's descriptor and the occupancy it was made against. A
// call with no syscall of its own (a read served from the library's buffer)
// inherits this and nothing else.
struct binding {
	__s32 fd;
	__u32 reserved;

	// generation is the socket's discovery generation.
	__u64 generation;

	// inode is the socket's number, so a continuing call names the same socket.
	__u64 inode;

	// occupancy is what this run last saw behind the descriptor number when the
	// binding was made, or zero. It never establishes a binding (only the object
	// the kernel acquired does); it can only withdraw one, when the number was
	// reused or replaced by dup2.
	__u64 occupancy;

	// The socket's endpoints, inherited with the binding, ordered without
	// compiler padding as in struct call.
	__u64 net_ino;
	__u64 opened;
	__u8  local[16];
	__u8  peer[16];
	__u16 lport;
	__u16 dport;
	__u8  ends;
	__u8  ends_padding[3];

};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct socket_key);
	__type(value, struct socket_life);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct handle_key);
	__type(value, struct binding);
} handles SEC(".maps");

// bindings is the socket-generation allocator. Userspace seeds nothing: every
// occupancy recorded is one this program stamped.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} bindings SEC(".maps");

// sequences allocates call sequence numbers, apart from the event stamps.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sequences SEC(".maps");

// occupancy is one occupancy of a TLS handle: from the handle's birth, or from
// the first call recorded on an existing handle, to its release. It is the
// producer's, so a handle address reused after an ending nobody delivered is a
// different occupancy here whatever userspace saw.
//
// Each direction numbers its byte-moving calls from one, the number taken
// where the call's bytes are known to have moved and before its event is
// reserved. A call whose bytes moved and that delivers nothing still takes
// its number, so a number missing downstream is bytes this occupancy lost, in
// that direction. A call that moved no bytes takes none.
//
// The order of numbers is the order of reservations only while one call at a
// time is in flight per direction, which OpenSSL requires of the application
// (one SSL object is not used from two threads at once). busy holds the thread
// in a call per direction; a second thread entering meanwhile marks the
// direction overlapped, and every later event of it carries the mark.
struct occupancy {
	__u64 id;          // the occupancy's name, never zero (occupancy_ids)
	__u64 generation;  // the admission it was begun under
	__u64 unlocated;   // the unlocated count when it began
	__u64 sent;        // the last number taken in each direction
	__u64 received;
	// How many byte-moving calls in each direction lost their event to a refused ring
	// reservation (the event did not fit). This is the located loss at the tail of an
	// open connection: settle counts it, less what capture already located mid-stream,
	// so a drop that sits below a later submitted-but-abandoned event is still counted
	// and an abandoned event is not (decision 476; settleLocked, package capture). A
	// return refused for a lost grant and a nested call nothing numbers are gaps too,
	// but not reservation failures, so they are the uncounted incomplete tail, not
	// this.
	__u64 dropped_sent;
	__u64 dropped_received;
	__u64 busy_sent;   // the pid_tgid of the call in flight in each direction, or zero
	__u64 busy_received;
	__u8  overlapped_sent;
	__u8  overlapped_received;
	__u8  born;        // begun at the handle's observed birth (obs_new_return)
	__u8  padding[5];
};

// occupancies is the occupancy each live handle is in, keyed as a binding is.
// An entry is begun at the handle's birth or its first recorded call and
// deleted at its release. A full table is a refusal counted as itself, and
// the calls of a handle it refused carry no number.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct handle_key);
	__type(value, struct occupancy);
} occupancies SEC(".maps");

// occupancy_ids allocates occupancy names.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} occupancy_ids SEC(".maps");

// unlocated counts the losses no occupancy could take: bytes moved by a call
// of a handle the program held no occupancy for, and occupancies the table
// refused. Every event carries its value as it was produced, and an occupancy
// records it when it begins, so a rise says such a loss fell before.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} unlocated SEC(".maps");

// capture_live is zero until userspace has placed and confirmed every transfer
// probe, then one. An occupancy forms only once it is one, so a handle born, or
// a call made, in the window after a lifecycle or socket probe is live but
// before the data probes are cannot be numbered from a false origin: it forms no
// occupancy, its calls are unsequenced, and its bytes are an unlocated loss.
// Probes are placed in symbol order, so SSL_new precedes SSL_read and SSL_write;
// this flag, not the placement order, is what makes Born sound. Userspace seeds
// it (package ebpf, Session.markCaptureLive); a session that never sets it
// numbers nothing, the closed direction of the fail.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} capture_live SEC(".maps");

// operation is one syscall the kernel is executing for a live TLS call on this
// thread: the join between the syscall tracepoints (descriptor, result) and the
// kernel hooks (the acquired object). It is keyed by thread, never CPU: a
// blocked operation resumes on any CPU. call and entered name the live call, so
// a frame left by an older call on the thread is counted as broken rather than
// used.
struct operation {
	__u64 call;     // the ssl handle of the call this frame belongs to
	__u64 entered;  // that call's own generation, so an older frame cannot be reused
	__u64 socket;   // the socket the kernel acquired, once a hook has said
	__u64 ino;      // that socket's own inode number, or zero where it has no file
	__u64 gen;      // the discovery generation of that socket
	__u32 syscall;
	__s32 fd;
	__u8  family;   // OBS_AF_INET, OBS_AF_INET6, or zero for one not read yet
	__u8  outcome;  // what is known about this operation so far, OBS_OUTCOME_*
	__u8  live;

	// socket_known says this operation is on a socket, whether or not a protocol
	// hook named which. rw_verify_area's inode mode settles the scalar and vector
	// family; on the messaging path the syscall itself does (obs_socket_only). It
	// separates a route not followed, such as a unix-domain socket carrying TLS,
	// from an operation that reached no evidence.
	__u8  socket_known;

	// occupancy is what this run last saw behind the descriptor number when the
	// operation opened, or zero. It shows the number was replaced under a blocked
	// operation, which keeps its socket but must not write it into the handle's
	// cache.
	__u64 occupancy;

	// The socket's endpoints and namespace, copied at the hook that acquired it,
	// here because they belong to the object this operation used. Addresses are
	// sixteen bytes; v4 is written v4-mapped.
	__u8  local[16];
	__u8  peer[16];
	__u64 net_ino;  // the socket's network namespace, or zero where unread
	__u64 opened;   // when this run saw the socket created, or zero where it did not
	__u16 lport;    // host order, as the kernel keeps it
	__u16 dport;    // host order, byte-swapped from the kernel's network order
	__u8  ends;     // whether the two addresses above were read
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct operation);
} operations SEC(".maps");

// socket_ident names one socket the kernel acquired for an operation. The
// kernel address is unique while the socket lives and the inode number is what
// ss and /proc/net report; both are reused, so with the generation below they
// separate occupancies together. The address is copied at the hook and never
// dereferenced afterwards.
struct socket_ident {
	__u64 sock;
	__u64 ino;
};

struct socket_life_kernel {
	__u64 generation;
};

// discovered is every socket this run has seen an operation acquire, with its
// discovery generation. An unknown socket is a discovery, not a refusal: the
// kernel hands the socket to the operation whatever route its descriptor took.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct socket_ident);
	__type(value, struct socket_life_kernel);
} discovered SEC(".maps");

// discoveries is the generation allocator for the table above. It uses its
// add's result, which puts the floor at 5.12 (package ebpf, MinimumKernel).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} discoveries SEC(".maps");

// holders is every execution this program keeps something for that must go
// when it does: an occupancy, a handle's binding or a descriptor's lifetime
// (entries), and whether it delivered events, for which userspace keeps
// something too (events). The tables are keyed by the execution and never hear
// of its end, so its last thread looks itself up here and, only where present,
// walks them for its entries (obs_reclaim): an exit this program holds nothing
// for costs one lookup. A refused insertion is counted, and that execution's
// entries outlive it. Each flag is only ever set to one, so concurrent setters
// need no atomic.
struct holding {
	__u8 entries;
	__u8 events;
	__u8 padding[6];
};

#define OBS_HOLDS_ENTRIES 1
#define OBS_HOLDS_EVENTS 2

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct instance_key);
	__type(value, struct holding);
} holders SEC(".maps");

static __always_inline void obs_count(__u32 index)
{
	__u64 *slot = bpf_map_lookup_elem(&stats, &index);
	if (slot)
		__sync_fetch_and_add(slot, 1);
}

// obs_locate names the current task as the allowlist is keyed: its pid
// namespace and its thread group id there. bpf_get_ns_current_pid_tgid
// resolves only within the task's own active namespace, so walking the
// enumerated namespaces answers which one and what number; a task in none is
// refused rather than admitted under an ancestor's numbering. It reads no
// process memory. The walk is unrolled: as a loop whose counter is the map key,
// the counter lives on the stack and the verifier rejects it as an infinite
// loop.
static __always_inline int obs_locate(struct instance_key *key)
{
	struct bpf_pidns_info info = {};
	__u32 slot;
	int index;

#pragma unroll
	for (index = 0; index < OBS_NAMESPACES; index++) {
		slot = index;
		struct obs_ns *ns = bpf_map_lookup_elem(&namespaces, &slot);
		if (!ns)
			continue;
		if (!ns->dev && !ns->ino)
			continue;
		if (bpf_get_ns_current_pid_tgid(ns->dev, ns->ino, &info, sizeof(info)) != 0)
			continue;
		key->ns_dev = ns->dev;
		key->ns_ino = ns->ino;
		key->pid = info.tgid;
		key->reserved = 0;
		return 1;
	}
	return 0;
}

// obs_ticks is a task's birth in the unit /proc reports, or zero where the
// kernel read failed. A task started in the first tick after boot also reads
// zero and is refused, the closed direction.
static __always_inline __u64 obs_ticks(struct task_struct *task)
{
	__u64 started = 0;
	if (!task || bpf_core_read(&started, sizeof(started), &task->start_boottime) != 0)
		return 0;
	return started / OBS_NSEC_PER_TICK;
}

// obs_birth is the current thread group's birth: the leader's start, since
// start_boottime is per task and the grant belongs to the group. It survives
// the leader's exit (pthread_exit leaves a zombie leader, still named by
// group_leader while workers serve). A non-leader exec ends the grant anyway.
static __always_inline __u64 obs_birth(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *leader = 0;
	if (!task || bpf_core_read(&leader, sizeof(leader), &task->group_leader) != 0)
		return 0;
	return obs_ticks(leader);
}

// obs_authentic is whether the running thread group is the one this grant was
// written for. A grant is authority for one occupant of a number, and numbers
// are reused. A birth of zero in the entry authenticates nothing.
static __always_inline int obs_authentic(const struct admission *entry)
{
	__u64 born = obs_birth();
	return born != 0 && entry->birth == born;
}

// Why a lookup produced no grant: a task refused because its key's entry
// belongs to somebody else is counted; a task with no entry is every other
// process on the host.
#define OBS_GRANT_NONE 0
#define OBS_GRANT_HELD 1
#define OBS_GRANT_IMPOSTOR 2

// obs_grant_why is the current task's admission, or nothing and the reason. It
// fills key with the instance looked up, so a caller admitting a child knows
// which namespace the parent numbers it in.
static __always_inline struct admission *obs_grant_why(struct instance_key *key, int *why)
{
	*why = OBS_GRANT_NONE;
	if (!obs_locate(key))
		return 0;
	struct admission *entry = bpf_map_lookup_elem(&allowed_processes, key);
	if (!entry)
		return 0;
	// A denial is not a grant and is not authenticated: an exclusion denies a
	// subtree, and a stale denial only observes less.
	if (entry->kind == OBS_DENIED)
		return 0;
	if (!obs_authentic(entry)) {
		*why = OBS_GRANT_IMPOSTOR;
		return 0;
	}
	*why = OBS_GRANT_HELD;
	return entry;
}

// obs_grant is the same lookup where the reason does not matter.
static __always_inline struct admission *obs_grant(struct instance_key *key)
{
	int why = OBS_GRANT_NONE;
	return obs_grant_why(key, &why);
}

// obs_forking reports whether an admitted instance is inside a fork. An
// implausible count reads as closed: racing decrements could wrap it, and a
// wrong counter should turn the deferral off, not on for the whole host.
#define OBS_FORK_WINDOWS_MAX 4096
static __always_inline int obs_forking(void)
{
	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&forking, &index);
	return slot && *slot > 0 && *slot < OBS_FORK_WINDOWS_MAX;
}

// A decrement without its increment happens (a fork entered before attach
// returns into a placed probe), and an unsigned counter below zero reads as
// enormous, which would hold the window open for every unadmitted task.
static __always_inline void obs_fork_window(__s64 by)
{
	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&forking, &index);
	if (!slot)
		return;
	if (by < 0 && *slot == 0)
		return;
	__sync_fetch_and_add(slot, by);
}

// obs_unmatched records the occasion of a return whose entry was never seen.
// Both counting sites call it after the same grant check, so it measures this
// capture's loss and not the host's other traffic.
static __always_inline void obs_unmatched(__u64 ssl)
{
	__u32 index = 0;
	struct unmatched *seen = bpf_map_lookup_elem(&unmatched_at, &index);
	if (!seen)
		return;

	__u64 now = bpf_ktime_get_ns();
	__u64 id = bpf_get_current_pid_tgid();
	if (seen->first == 0) {
		seen->first = now;
		seen->ssl = ssl;
		seen->pid = (__u32)(id >> 32);
		seen->tid = (__u32)id;
	}
	seen->last = now;
}

// obs_stamp_event hands out the next event stamp. An unreadable counter gives
// zero, not a valid stamp, which userspace reads as an unusable ordering
// (package ebpf, Session.decode).
static __always_inline __u64 obs_stamp_event(void)
{
	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&attempts, &index);
	if (!slot)
		return 0;
	return __sync_fetch_and_add(slot, 1) + 1;
}

// obs_sequence hands out the next call sequence.
static __always_inline __u64 obs_sequence(void)
{
	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&sequences, &index);
	if (!slot)
		return 0;
	return __sync_fetch_and_add(slot, 1) + 1;
}

// obs_unlocate counts a loss no occupancy could take.
static __always_inline void obs_unlocate(void)
{
	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&unlocated, &index);
	if (slot)
		__sync_fetch_and_add(slot, 1);
}

// obs_unlocated_now reads the count of losses no occupancy could take.
static __always_inline __u64 obs_unlocated_now(void)
{
	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&unlocated, &index);
	if (!slot)
		return 0;
	return *(volatile __u64 *)slot;
}

// obs_capture_live reports whether every transfer probe is placed, so an
// occupancy formed now is numbered from a true origin.
static __always_inline int obs_capture_live(void)
{
	__u32 index = 0;
	__u8 *slot = bpf_map_lookup_elem(&capture_live, &index);
	return slot && *slot;
}

// obs_holds records what the program keeps for the execution who, for its end
// to take away (holders). The lookup first: almost every call finds the
// execution already there with the same bits.
static __always_inline void obs_holds(const struct instance_key *who, __u32 what)
{
	struct holding *held = bpf_map_lookup_elem(&holders, who);
	if (!held) {
		struct holding fresh = {};
		if (bpf_map_update_elem(&holders, who, &fresh, BPF_NOEXIST) != 0 &&
		    !bpf_map_lookup_elem(&holders, who)) {
			obs_count(OBS_STAT_HOLDER_UNRECORDED);
			return;
		}
		held = bpf_map_lookup_elem(&holders, who);
		if (!held)
			return;
	}
	if (what == OBS_HOLDS_ENTRIES)
		held->entries = 1;
	else
		held->events = 1;
}

// obs_handle_key names a handle of the instance who.
static __always_inline void obs_handle_key(struct handle_key *hk, const struct instance_key *who, __u64 ssl)
{
	hk->ns_dev = who->ns_dev;
	hk->ns_ino = who->ns_ino;
	hk->pid = who->pid;
	hk->reserved = 0;
	hk->ssl = ssl;
}

// obs_occupy is the occupancy a handle's call is numbered in, begun here where
// the handle has none, where the one held was begun under another admission
// (a reused pid, or a readmission), or at a birth. Two first calls on one
// handle in different directions can race to begin it: the insertion is
// conditional and the loser takes the winner's, as a discovery does. A refused
// occupancy is counted, and so is the loss it means: every byte this handle
// moves until one is begun has no number (unlocated).
static __always_inline struct occupancy *obs_occupy(const struct instance_key *who, __u64 ssl,
						    __u64 generation, __u8 born)
{
	// No occupancy forms before every transfer probe is live: an origin taken now
	// would be false, since bytes may have moved through a data probe not yet
	// placed. The calls of this window are unsequenced and their bytes unlocated.
	if (!obs_capture_live())
		return 0;

	struct handle_key hk = {};
	obs_handle_key(&hk, who, ssl);
	struct occupancy *held = bpf_map_lookup_elem(&occupancies, &hk);
	if (held && held->generation == generation && !born)
		return held;

	__u32 index = 0;
	__u64 *ids = bpf_map_lookup_elem(&occupancy_ids, &index);
	if (!ids) {
		obs_count(OBS_STAT_OCCUPANCY_UNRECORDED);
		obs_unlocate();
		return 0;
	}
	struct occupancy fresh = {};
	fresh.id = __sync_fetch_and_add(ids, 1) + 1;
	fresh.generation = generation;
	fresh.unlocated = obs_unlocated_now();
	fresh.born = born;

	// A held entry is replaced; a missing one is inserted only if still missing.
	__u64 flags = held ? BPF_ANY : BPF_NOEXIST;
	if (bpf_map_update_elem(&occupancies, &hk, &fresh, flags) != 0) {
		held = bpf_map_lookup_elem(&occupancies, &hk);
		if (held && held->generation == generation && !born)
			return held;
		obs_count(OBS_STAT_OCCUPANCY_UNRECORDED);
		obs_unlocate();
		return 0;
	}
	obs_holds(who, OBS_HOLDS_ENTRIES);
	if (born)
		obs_count(OBS_STAT_BORN);
	return bpf_map_lookup_elem(&occupancies, &hk);
}

// obs_held_occupancy is the occupancy the handle is in, if it is still the one
// a call was entered in; a call outliving its occupancy (a release on another
// thread mid-call, which the supported use forbids) numbers nothing in its
// successor.
static __always_inline struct occupancy *obs_held_occupancy(const struct instance_key *who, __u64 ssl,
							    __u64 id)
{
	if (!id)
		return 0;
	struct handle_key hk = {};
	obs_handle_key(&hk, who, ssl);
	struct occupancy *held = bpf_map_lookup_elem(&occupancies, &hk);
	if (!held || held->id != id)
		return 0;
	return held;
}

// obs_take takes the next number in one direction of an occupancy.
static __always_inline __u64 obs_take(struct occupancy *occ, __u8 dir)
{
	if (dir == OBS_SENT)
		return __sync_fetch_and_add(&occ->sent, 1) + 1;
	return __sync_fetch_and_add(&occ->received, 1) + 1;
}

// obs_lost accounts for a call that moved bytes and delivers nothing: a number
// taken in its occupancy, or, with no occupancy to take it, an unlocated loss.
static __always_inline void obs_lost(struct occupancy *occ, __u8 dir)
{
	if (occ)
		obs_take(occ, dir);
	else
		obs_unlocate();
}

// obs_hold marks a call in flight in one direction of an occupancy. A second
// thread already there is an overlap the supported use forbids: the direction
// is marked for good and this call does not take the mark it found.
static __always_inline void obs_hold(struct occupancy *occ, __u8 dir, __u64 thread)
{
	__u64 *busy = dir == OBS_SENT ? &occ->busy_sent : &occ->busy_received;
	__u64 found = __sync_val_compare_and_swap(busy, 0, thread);
	if (found == 0 || found == thread)
		return;
	if (dir == OBS_SENT)
		occ->overlapped_sent = 1;
	else
		occ->overlapped_received = 1;
	obs_count(OBS_STAT_OVERLAPPED);
}

// obs_unhold clears the mark a call took, and only its own.
static __always_inline void obs_unhold(struct occupancy *occ, __u8 dir, __u64 thread)
{
	if (!occ)
		return;
	__u64 *busy = dir == OBS_SENT ? &occ->busy_sent : &occ->busy_received;
	__sync_val_compare_and_swap(busy, thread, 0);
}

// place is what an event says about its occupancy: the carrier obs_emit fills
// the event's place fields from. bytes says the call moved bytes, so losing its
// event with no occupancy to take its number is an unlocated loss.
struct place {
	__u64 begin_unlocated;
	__u64 occupancy;
	__u64 number;
	__u64 dropped;
	__u8  born;
	__u8  overlapped;
	__u8  exited;
};

// obs_stamp hands out the next kernel-side admission generation.
static __always_inline __u64 obs_stamp(void)
{
	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&generations, &index);
	if (!slot)
		return 0;
	return __sync_fetch_and_add(slot, 1);
}

#if READ_PAYLOAD
// obs_read_taken records a user-memory read against its admission, at the read
// rather than at the emit (the reads map).
static __always_inline void obs_file_read(__u64 generation)
{
	__u64 *slot = bpf_map_lookup_elem(&reads, &generation);
	if (slot) {
		__sync_fetch_and_add(slot, 1);
		return;
	}
	// BPF_NOEXIST rather than BPF_ANY: two threads taking a generation's first read
	// at once would both write 1. The loser finds the entry on the second lookup
	// and adds to it.
	__u64 first = 1;
	if (bpf_map_update_elem(&reads, &generation, &first, BPF_NOEXIST) == 0)
		return;
	slot = bpf_map_lookup_elem(&reads, &generation);
	if (slot) {
		__sync_fetch_and_add(slot, 1);
		return;
	}
	// The map is full, so this read has no entry. It is counted, and userspace
	// refuses to answer from the map while the count is non-zero.
	obs_count(OBS_STAT_READ_UNRECORDED);
}
#endif

#if READ_PAYLOAD
#ifdef OBS_TEST_READ_BARRIER
// Attach-test object only: the loop holds a return after it checked its grant.
// State 2 is held, 3 released, 4 timed out. Production objects contain neither
// this map nor the helper, whose kernel floor is higher than theirs.
struct read_barrier_state { __u64 generation; __u32 state; __u32 padding; };
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct read_barrier_state);
} read_barrier SEC(".maps");

static long obs_read_wait(__u32 index, void *context)
{
	__u32 key = 0;
	struct read_barrier_state *state = bpf_map_lookup_elem(&read_barrier, &key);
	return !state || state->state != 2;
}

static __always_inline void obs_hold_read(__u64 generation)
{
	__u32 key = 0;
	struct read_barrier_state *state = bpf_map_lookup_elem(&read_barrier, &key);
	if (!state || state->generation != generation || state->state != 1)
		return;
	state->state = 2;
	bpf_loop(1 << 23, obs_read_wait, 0, 0);
	if (state->state == 2)
		state->state = 4;
}
#else
static __always_inline void obs_hold_read(__u64 generation) {}
#endif

static __always_inline int obs_read_taken(const struct instance_key *who, __u64 generation)
{
	obs_hold_read(generation);
	struct admission *grant = bpf_map_lookup_elem(&allowed_processes, who);
	if (!grant || grant->generation != generation || grant->kind == OBS_DENIED) {
		obs_count(OBS_STAT_READ_RETRACTED);
		return 0;
	}
	obs_file_read(generation);
	// A retraction can fold between the first check and the insertion. The
	// second check removes any entry recreated in that window. Generations are
	// unique, so this cannot remove a subsequent admission's counter.
	grant = bpf_map_lookup_elem(&allowed_processes, who);
	if (!grant || grant->generation != generation || grant->kind == OBS_DENIED) {
		bpf_map_delete_elem(&reads, &generation);
		obs_count(OBS_STAT_READ_RETRACTED);
		return 0;
	}
	return 1;
}
#endif

// The association. Which socket a call's bytes crossed is not the TLS
// library's to tell (a custom BIO may answer no descriptor). What is
// observable is that the call and the socket work happen synchronously on one
// thread: mark the thread at the call's entry, let socket observations record
// against the mark, and read it at the return. Refused here:
//
//   - dropping an unassociated transfer: it is emitted, with its state
//   - taking the first of two descriptors in a window: that is ambiguous
//   - inheriting a thread's history: a call without socket work inherits only
//     the handle's still-valid binding
//   - reading descriptor zero as no descriptor: the state says whether there
//     is a binding, never the number

// obs_discover names the socket an operation acquired, allocating a generation
// for one not seen before. The insertion is conditional (BPF_NOEXIST): two
// threads reaching a new socket at once would otherwise give it two
// generations. The loser reads the winner's entry, and its own number is
// simply spent. A full table is the same map return: the second lookup tells
// them apart (a lost race finds the winner, a full table nothing), and a full
// table is counted.
static __always_inline __u64 obs_discover(struct socket_ident *who)
{
	struct socket_life_kernel *known = bpf_map_lookup_elem(&discovered, who);
	if (known)
		return known->generation;

	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&discoveries, &index);
	if (!slot)
		return 0;

	struct socket_life_kernel life = {};
	life.generation = __sync_fetch_and_add(slot, 1) + 1;
	if (bpf_map_update_elem(&discovered, who, &life, BPF_NOEXIST) == 0)
		return life.generation;

	known = bpf_map_lookup_elem(&discovered, who);
	if (known) {
		obs_count(OBS_STAT_DISCOVERY_CONTENDED);
		return known->generation;
	}
	obs_count(OBS_STAT_SOCKET_UNDISCOVERED);
	return 0;
}

// obs_worse is which of two outcomes a call reports when it saw both: an order,
// not a numeric maximum. An unreadable evidence read is not made good by a
// later established socket. OBS_OUTCOME_NONE (no I/O) loses to everything.
static __always_inline __u8 obs_worse(__u8 held, __u8 next)
{
	if (held == OBS_OUTCOME_NONE)
		return next;
	if (next == OBS_OUTCOME_NONE)
		return held;
	return next > held ? next : held;
}

// obs_socket_generation stamps one occupancy of a descriptor.
static __always_inline __u64 obs_socket_generation(void)
{
	__u32 index = 0;
	__u64 *slot = bpf_map_lookup_elem(&bindings, &index);
	if (!slot)
		return 0;
	return __sync_fetch_and_add(slot, 1) + 1;
}

// obs_socket_key names one descriptor of the current task's execution, or says
// the task could not be located (a task in an unenumerated namespace).
static __always_inline int obs_socket_key(struct socket_key *key, __s32 fd)
{
	struct instance_key who = {};
	if (!obs_locate(&who))
		return 0;
	key->ns_dev = who.ns_dev;
	key->ns_ino = who.ns_ino;
	key->pid = who.pid;
	key->fd = fd;
	return 1;
}

// obs_socket_opened records a new occupancy of a descriptor. A refused
// insertion is counted: otherwise a full table would make later bindings read
// as descriptors nothing followed.
static __always_inline void obs_socket_opened(__s32 fd)
{
	if (fd < 0)
		return;
	struct socket_key key = {};
	if (!obs_socket_key(&key, fd))
		return;
	struct socket_life life = {};
	life.generation = obs_socket_generation();
	life.opened = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&sockets, &key, &life, BPF_ANY) != 0) {
		obs_count(OBS_STAT_SOCKET_UNRECORDED);
		return;
	}
	struct instance_key who = {};
	who.ns_dev = key.ns_dev;
	who.ns_ino = key.ns_ino;
	who.pid = key.pid;
	obs_holds(&who, OBS_HOLDS_ENTRIES);
}

// obs_socket_closed ends an occupancy; a binding made against it then finds no
// entry, which is lifetime evidence running out.
static __always_inline void obs_socket_closed(__s32 fd)
{
	if (fd < 0)
		return;
	struct socket_key key = {};
	if (!obs_socket_key(&key, fd))
		return;
	bpf_map_delete_elem(&sockets, &key);
}

// obs_saw_socket records a descriptor against the call in flight on this
// thread. The early return is one hash lookup: a thread with no live TLS call
// is ordinary traffic.
//
// socket_only says the syscall can only be a socket operation (sendto and its
// family). For read, write, readv and writev the descriptor must be one this
// run saw created as a socket, or a file operation would be taken for network
// I/O.
//
// Every way out is counted: the four that record nothing are unmet
// preconditions, without which a run whose probes fired and a run whose probes
// never fired look alike; the fifth counts the success, which shows the
// counters can move. The two counted above the in-flight lookup fire for
// ordinary traffic and measure the host. The uncounted fall-through, a second
// distinct descriptor, makes the association ambiguous on the event.
static __always_inline void obs_saw_socket(__s32 fd, int socket_only)
{
	if (fd < 0) {
		obs_count(OBS_STAT_SOCKET_FD_INVALID);
		return;
	}

	__u64 id = bpf_get_current_pid_tgid();
	struct call *c = bpf_map_lookup_elem(&inflight, &id);
	if (!c || !c->live) {
		obs_count(OBS_STAT_SOCKET_OUTSIDE_CALL);
		return;
	}

	if (!socket_only) {
		struct socket_key key = {};
		if (!obs_socket_key(&key, fd)) {
			obs_count(OBS_STAT_SOCKET_UNLOCATABLE);
			return;
		}
		if (!bpf_map_lookup_elem(&sockets, &key)) {
			obs_count(OBS_STAT_SOCKET_NO_LIFETIME);
			return;
		}
	}

	if (c->fds == 0) {
		c->fd = fd;
		c->fds = 1;
		obs_count(OBS_STAT_SOCKET_RECORDED);
		return;
	}
	if (c->fd != fd && c->fds < 2)
		c->fds = 2;
}

// obs_occupancy is what this run last saw behind a descriptor number of the
// current execution, or zero. It establishes nothing and is asked only when a
// binding is carried across a call with no I/O (struct binding, occupancy).
// opened is filled from the same lookup: this runs at every supported syscall
// inside a live TLS call.
static __always_inline __u64 obs_occupancy(const struct instance_key *who, __s32 fd, __u64 *opened)
{
	if (opened)
		*opened = 0;

	struct socket_key sk = {};
	sk.ns_dev = who->ns_dev;
	sk.ns_ino = who->ns_ino;
	sk.pid = who->pid;
	sk.fd = fd;

	struct socket_life *life = bpf_map_lookup_elem(&sockets, &sk);
	if (!life)
		return 0;
	if (opened)
		*opened = life->opened;
	return life->generation;
}

// ends is one socket's endpoints as they leave this program: addresses in
// v4-mapped form, ports in host order, the socket's network namespace, and
// whether the addresses were read. It is a carrier, not a record.
struct ends {
	__u8  local[16];
	__u8  peer[16];
	__u64 net_ino;

	// opened is the socket's start, monotonic, with the addresses because it
	// belongs to the same occupancy. Zero: this run did not see it open.
	__u64 opened;
	__u16 lport;
	__u16 dport;
	__u8  known;
};

static __always_inline void obs_ends_from_call(struct ends *ends, const struct call *call)
{
	__builtin_memcpy(ends->local, call->local, sizeof(ends->local));
	__builtin_memcpy(ends->peer, call->peer, sizeof(ends->peer));
	ends->net_ino = call->net_ino;
	ends->opened = call->opened;
	ends->lport = call->lport;
	ends->dport = call->dport;
	ends->known = call->ends;
}

// obs_associate reads what this call's own kernel I/O established, writes it
// onto the event's fields, and updates the handle's binding where the call
// resolved one. It is called at the return, with the grant re-checked. The
// evidence is the object the kernel acquired; the descriptor number is carried
// because people recognise it, and decides nothing. Four answers:
//
//   - more than one socket in the window is ambiguous
//   - one socket is established, on its discovery generation
//   - a call with I/O whose socket is not established carries no binding, and
//     its outcome says why
//   - a call with no kernel I/O inherits the handle's binding, and only while
//     the occupancy it was made against is still behind it
static __always_inline void obs_associate(const struct instance_key *who, const struct call *call,
					  __s32 *fd, __u64 *binding, __u64 *socket, __u8 *state,
					  struct ends *ends)
{
	*fd = 0;
	*binding = 0;
	*socket = 0;
	*state = OBS_FD_NONE;
	__builtin_memset(ends, 0, sizeof(*ends));

	struct handle_key hk = {};
	hk.ns_dev = who->ns_dev;
	hk.ns_ino = who->ns_ino;
	hk.pid = who->pid;
	hk.ssl = call->ssl;

	if (call->sockets >= 2) {
		// Two sockets in one window: which carried these bytes is undecidable. The
		// first one's descriptor is reported; the state is what a consumer reads.
		*fd = call->socket_fd;
		*state = OBS_FD_AMBIGUOUS;
		return;
	}

	if (call->sockets == 1) {
		// The socket the operation acquired, whatever the number names now: a
		// descriptor replaced while a read blocked does not change what it read.
		*fd = call->socket_fd;
		*binding = call->socket_gen;
		*socket = call->socket_ino;
		*state = OBS_FD_ESTABLISHED;
		obs_ends_from_call(ends, call);

		// The cache is a different question: where the number's occupancy moved since
		// this operation opened, the descriptor was replaced under it, so this socket
		// is not written into the handle. The association stands.
		__u64 now = obs_occupancy(who, call->socket_fd, 0);
		if (call->socket_occ != 0 && now != call->socket_occ)
			return;

		struct binding made = {};
		made.fd = call->socket_fd;
		made.generation = call->socket_gen;
		made.inode = call->socket_ino;
		made.occupancy = now;
		__builtin_memcpy(made.local, call->local, sizeof(made.local));
		__builtin_memcpy(made.peer, call->peer, sizeof(made.peer));
		made.net_ino = call->net_ino;
		made.opened = call->opened;
		made.lport = call->lport;
		made.dport = call->dport;
		made.ends = call->ends;
		if (bpf_map_update_elem(&handles, &hk, &made, BPF_ANY) != 0)
			obs_count(OBS_STAT_BINDING_UNRECORDED);
		else
			obs_holds(who, OBS_HOLDS_ENTRIES);
		return;
	}

	// I/O happened and its socket was not established. This must not fall through
	// to the no-I/O case: an unresolved operation, an unreadable evidence read, an
	// unsupported route or a broken frame inheriting the handle's binding would be
	// a cached success standing in for evidence. The io flag catches a call whose
	// every operation returned zero, which leaves the outcome untouched.
	if (call->outcome != OBS_OUTCOME_NONE || call->io)
		return;

	// No kernel I/O in the window: a read served from the library's buffer, or a
	// buffered write. The handle's binding and nothing else is inherited, while
	// its occupancy is still the one behind that socket.
	struct binding *held = bpf_map_lookup_elem(&handles, &hk);
	if (!held)
		return;

	*fd = held->fd;
	*binding = held->generation;
	*socket = held->inode;
	// The endpoints come with the binding and are not re-derived.
	__builtin_memcpy(ends->local, held->local, sizeof(ends->local));
	__builtin_memcpy(ends->peer, held->peer, sizeof(ends->peer));
	ends->net_ino = held->net_ino;
	ends->opened = held->opened;
	ends->lport = held->lport;
	ends->dport = held->dport;
	ends->known = held->ends;

	// The number's occupancy as last seen. Where it has moved, the binding is
	// reported invalidated rather than dropped, so a consumer sees one was
	// established and stopped being true. Two unknowns withdraw nothing.
	__u64 now = obs_occupancy(who, held->fd, 0);
	if (held->occupancy != 0 && now != held->occupancy) {
		*state = OBS_FD_INVALIDATED;
		return;
	}
	*state = OBS_FD_ESTABLISHED;
}

// origin is what an event says about the admission it was taken under: the
// target and condition, how the instance was admitted, and for one admitted by
// descent the instance it was admitted below. Copied out of the grant where the
// grant is checked, beside the generation the event carries.
struct origin {
	__u64 parent_generation;
	__u64 parent_ns_dev;
	__u64 parent_ns_ino;
	__u32 parent_pid;
	__u32 target;
	__u32 rule;
	__u8  kind;
};

static __always_inline void obs_origin(const struct admission *grant, struct origin *into)
{
	into->parent_generation = grant->parent_generation;
	into->parent_ns_dev = grant->parent_ns_dev;
	into->parent_ns_ino = grant->parent_ns_ino;
	into->parent_pid = grant->parent_pid;
	into->target = grant->target;
	into->rule = grant->rule;
	into->kind = grant->kind;
}

// obs_emit submits an event. length is meaningful only when measured is set.
// who, generation and origin come from the grant that was checked, not the pid
// alone. It returns 1 when the event reached the ring and 0 when the reservation
// was refused, so a byte-moving call's return can count its number as submitted
// only where it was (obs_submitted).
static __always_inline int obs_emit(const struct instance_key *who, __u64 generation,
				     const struct origin *origin,
				     __u64 ssl, __u32 length, __u8 dir,
				     __u8 early, __u8 measured, __u8 kind,
				     __u64 buf, __s32 fd, __u64 binding, __u64 socket,
				     __u8 fd_state, __u8 outcome, const struct ends *ends,
				     const struct place *at,
				     __u64 last_sent, __u64 last_received, __u8 in_flight)
{
	// The stamp is taken before the reservation, so attempts counts every event
	// tried. A transfer's number was taken before this too: a refused reservation
	// leaves it missing from its occupancy, which is the loss located.
	__u64 stamp = obs_stamp_event();
	__u64 unlocated_then = obs_unlocated_now();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		obs_count(OBS_STAT_RESERVE_FAILED);
		// A byte-moving transfer no occupancy numbered, now lost with nothing to
		// locate it. A transfer the occupancy numbered leaves its gap there instead.
		if (kind == OBS_TRANSFER && length > 0 && !at->occupancy)
			obs_unlocate();
		return 0;
	}
	e->occupancy = at->occupancy;
	e->number = at->number;
	e->unlocated = unlocated_then;
	e->last_sent = last_sent;
	e->last_received = last_received;
	e->born = at->born;
	e->overlapped = at->overlapped;
	e->in_flight = in_flight;
	e->exited = at->exited;
	e->dropped = at->dropped;
	e->begin_unlocated = at->begin_unlocated;
	__builtin_memset(e->padding_place, 0, sizeof(e->padding_place));
	__u64 id = bpf_get_current_pid_tgid();
	e->stamp = stamp;
	e->fd = fd;
	e->binding = binding;
	e->socket = socket;
	e->fd_state = fd_state;
	e->outcome = outcome;
	__builtin_memcpy(e->local, ends->local, sizeof(e->local));
	__builtin_memcpy(e->peer, ends->peer, sizeof(e->peer));
	e->net_ino = ends->net_ino;
	e->lport = ends->lport;
	e->dport = ends->dport;
	e->ends = ends->known;
	e->opened = ends->opened;
	e->ssl = ssl;
	e->generation = generation;
	e->parent_generation = origin->parent_generation;
	e->parent_ns_dev = origin->parent_ns_dev;
	e->parent_ns_ino = origin->parent_ns_ino;
	e->parent_pid = origin->parent_pid;
	e->target = origin->target;
	e->rule = origin->rule;
	e->admitted_by = origin->kind;
	__builtin_memset(e->padding_origin, 0, sizeof(e->padding_origin));
	e->ns_dev = who->ns_dev;
	e->ns_ino = who->ns_ino;
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->nspid = who->pid;
	e->length = length;
	e->dir = dir;
	e->early = early;
	e->measured = measured;
	e->kind = kind;
	e->kept = 0;

#if READ_PAYLOAD
	// The one region separating the two programs: a read of the observed
	// process's memory, absent from the metadata-only object, as the helper check
	// proves. The length is bounded by the two comparisons alone: a mask would
	// disagree at exactly OBS_CHUNK (a power of two masks to zero) and copy nothing
	// while reporting a full chunk. The compiler barrier keeps the verifier's
	// bound on kept.
	if (measured && kind == OBS_TRANSFER && buf) {
		__u32 kept = length;
		if (kept > OBS_CHUNK)
			kept = OBS_CHUNK;
		barrier_var(kept);
		if (kept > 0 && kept <= OBS_CHUNK) {
			if (obs_read_taken(who, generation) &&
			    bpf_probe_read_user(&e->data, kept, (void *)buf) == 0)
				e->kept = kept;
		}
	}
#endif

	bpf_ringbuf_submit(e, 0);
	// Userspace keeps something for an execution once it has an event of it,
	// so the execution's end is reported to it (obs_reclaim).
	if (kind != OBS_ENDED)
		obs_holds(who, OBS_HOLDS_EVENTS);
	return 1;
}

// obs_dropped records that a byte-moving call's event did NOT reach the ring, so
// its number is a located loss the settle can count at the tail. occ is the one
// obs_return already holds, so this takes no further lookup and no stack; a call
// with no occupancy counts nothing (it was an unlocated loss already). Counting
// each failed reservation, rather than the highest number submitted, is what keeps
// a drop below a later submitted-but-abandoned event counted.
static __always_inline void obs_dropped(struct occupancy *occ, __u8 dir, int reserved)
{
	if (!occ || reserved)
		return;
	if (dir == OBS_SENT)
		occ->dropped_sent++;
	else
		occ->dropped_received++;
}

// obs_wraps says an entry point reaches another on the same handle and
// direction as part of its own work, so the outer call reports the inner one's
// bytes: SSL_write_ex reaches SSL_write_ex2, the early-data functions reach the
// _ex family (and the plain one in older releases). Any other call nested on
// the same handle and direction, such as one entered while an entry whose
// return never fired is still live, is reported by nothing.
static __always_inline int obs_wraps(__u32 outer, __u32 inner)
{
	switch (outer) {
	case OBS_FUNC_WRITE_EX:
		return inner == OBS_FUNC_WRITE_EX2;
	case OBS_FUNC_WRITE_EARLY:
		return inner == OBS_FUNC_WRITE_EX || inner == OBS_FUNC_WRITE_EX2 || inner == OBS_FUNC_WRITE;
	case OBS_FUNC_READ_EARLY:
		return inner == OBS_FUNC_READ_EX || inner == OBS_FUNC_READ;
	default:
		return 0;
	}
}

// obs_entry records a call so its return can complete it. pcount is the _ex
// family's count out-parameter, from argument four, or five for SSL_write_ex2
// (whose fourth is a flags word).
//
// Every way an admitted call can go unrecorded here is a call whose bytes no
// return will report, so each takes a number in its occupancy as a loss, now:
// a function with no return probe, a call nested inside another on a different
// handle or direction, and an entry the in-flight table refused. A call that
// turns out to have moved nothing then leaves a number missing that lost
// nothing, which costs completeness and never hides a loss.
static __always_inline int obs_entry(void *ctx, __u32 func, __u8 dir, __u8 count, __u8 early, __u64 pcount)
{
	struct instance_key key = {};
	int why = OBS_GRANT_NONE;
	struct admission *grant = obs_grant_why(&key, &why);
	__u64 generation = 0;
	if (grant) {
		generation = grant->generation;
	} else {
		// The number of an admitted instance held by a process the grant was not
		// written for. Counted here only, so the count is refused calls, not lookups.
		if (why == OBS_GRANT_IMPOSTOR)
			obs_count(OBS_STAT_UNAUTHENTICATED);
		if (!obs_forking())
			return 0;
	}
	__u64 ssl = OBS_PARM1(ctx);

	// The occupancy this call is numbered in. A call held through a fork window
	// has no admission yet and is placed at its return.
	struct occupancy *occ = 0;
	if (grant)
		occ = obs_occupy(&key, ssl, generation, 0);

	// A function whose return probe this session does not hold: an entry could
	// never complete and would hold the thread's slot, so nothing is recorded and
	// the call is counted (the unmeasurable map).
	__u32 which = func;
	__u8 *blind = bpf_map_lookup_elem(&unmeasurable, &which);
	if (blind && *blind) {
		// A function whose return probe the kernel did not confirm: its return never
		// fires for us, so it is recorded nowhere. The entry number is taken all the
		// same, so the call shows as a gap in its direction rather than vanishing -
		// this is the return-that-never-fires path, reached deterministically by
		// leaving a return probe unplaced.
		if (grant) {
			obs_count(OBS_STAT_UNMEASURABLE_CALL);
			obs_lost(occ, dir);
		}
		return 0;
	}

	// An admitted instance, or an unadmitted task during a fork window; the second
	// is recorded with no generation and decided again at obs_return (forking).
	__u64 id = bpf_get_current_pid_tgid();
	// A call already in flight on this thread means this one is nested and is not
	// recorded; a cleared entry is a completed call and is overwritten. Only an
	// entry of this admission occupies: a non-leader thread that execs is
	// renumbered, leaving its entry under the old id, and a later thread taking
	// that id would otherwise lose every call. A deferred entry still occupies,
	// protecting tail-call nesting during the window.
	struct call *held = bpf_map_lookup_elem(&inflight, &id);
	if (held && held->live && (held->deferred || held->generation == generation)) {
		if (held->ssl == ssl && held->dir == dir && obs_wraps(held->func, func)) {
			// An entry point the outer call reached on its own handle and direction
			// (SSL_write_early_data reaches SSL_write_ex): the outer call reports these
			// bytes, and probing both would count them twice.
			if (grant)
				obs_count(OBS_STAT_NESTED_WRAPPER);
		} else if (grant) {
			// A call on another handle or direction made inside this one (a TLS
			// connection carried through another's BIO), or one no wrapper explains:
			// nothing reports its bytes.
			obs_count(OBS_STAT_NESTED_ELSEWHERE);
			obs_lost(occ, dir);
		}
		// A return of this same function now belongs to the nested call.
		if (held->func == func && held->nested < 255)
			held->nested++;
		return 0;
	}

	if (occ)
		obs_hold(occ, dir, id);
	struct call c = {};
	c.ssl = ssl;
	c.buf = OBS_PARM2(ctx);
	c.cap = OBS_PARM3(ctx);
	c.pcount = pcount;
	c.generation = generation;
	c.sequence = obs_sequence();
	c.deferred = grant ? 0 : 1;
	c.func = func;
	c.dir = dir;
	c.count = count;
	c.early = early;
	c.live = 1;
	c.occupancy = occ ? occ->id : 0;
	// The number is taken HERE, at entry, so a return that never fires leaves it
	// missing from the occupancy. A deferred call has no occupancy yet and is
	// numbered at its return instead.
	c.number = occ ? obs_take(occ, dir) : 0;
	// A refused insertion would land on the unmatched counter as a return whose
	// entry was never seen; it is counted as itself.
	if (bpf_map_update_elem(&inflight, &id, &c, BPF_ANY) != 0) {
		// The entry number is taken and no return will complete this call, so it is
		// already a gap; the unhold releases the direction for the next call.
		obs_count(OBS_STAT_CALL_UNRECORDED);
		obs_unhold(occ, dir, id);
	}
	return 0;
}

// obs_return completes the matching call.
//
// A return with no entry of its own takes no number. Under the supported use no
// other call on its handle and direction runs while it is in flight, so its
// entry preceded every number its occupancy holds in that direction, or was
// refused at entry, which numbered it there: it entered before the probes were
// placed or before its process was admitted, and its bytes precede the
// occupancy's first.
static __always_inline int obs_return(void *ctx, __u32 func)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct call *c = bpf_map_lookup_elem(&inflight, &id);
	// The grant, read once after the return fires and before any user memory is
	// read, and used by both unmatched counters and the read boundary so they
	// cannot disagree about approval.
	struct instance_key key = {};
	struct admission *grant = obs_grant(&key);
	if (!c) {
		// A probed return with nothing recorded on entry. For an approved process it
		// is a transfer this session cannot report. It may be a call already inside
		// the function when the probes were placed: whether a uretprobe fires for a
		// frame already on the stack varies between runs on some kernels, so this is a
		// floor for that case. An unapproved process reaches here on every call and is
		// not counted.
		if (grant) {
			obs_count(OBS_STAT_UNMATCHED);
			obs_unmatched(OBS_PARM1(ctx));
		}
		return 0;
	}
	// The in-flight call is the outermost. A nested call's return carries another
	// function and is ignored, also after the outer call completed: SSL_write_ex
	// reaches SSL_write_ex2 by a tail call, so both returns arrive at one address
	// in either order, and the inner one may find a cleared entry.
	if (c->func != func)
		return 0;
	if (!c->live) {
		// A second return of the same function with nothing in flight: its entry was
		// not seen (a call already inside the function at placement reaches only the
		// return probe). Counted only with a grant, since a cleared entry outlives its
		// admission and an unapproved process can acquire one.
		if (grant) {
			obs_count(OBS_STAT_UNMATCHED);
			obs_unmatched(c->ssl);
		}
		return 0;
	}
	// The return of a call through this same function nested inside this one.
	if (c->nested) {
		c->nested--;
		return 0;
	}
	// No full copy of the entry is taken: this thread owns its in-flight slot, so
	// the fields are read through the map pointer and only the two the deferred
	// path reassigns are held in locals. Copying the whole struct onto the stack
	// put obs_return over the BPF stack limit once the entry grew a number.
	c->live = 0;
	__u64 generation = c->generation;
	__u64 number = c->number;

	// Whether the call moved bytes, from its return alone. An out-parameter call's
	// status is 1 where bytes moved and their count was written. Every other status
	// moved none: 0 is a failure, including a retry such as SSL_ERROR_WANT_READ on a
	// non-blocking socket, which reads nothing; SSL_read_early_data's 2,
	// SSL_READ_EARLY_DATA_FINISH, is the end of early data with a count of zero. A
	// write that fails part way keeps what it has sent for its retry, whose
	// success reports every byte of the buffer.
	__s64 rc = (__s64)(__s32)OBS_RC(ctx);
	int moved = c->count == OBS_COUNT_RETURNED ? rc > 0 : rc == 1;
	struct occupancy *occ = obs_held_occupancy(&key, c->ssl, c->occupancy);

	// The read boundary. Approval at entry is not a lease through return: between
	// the two the process can lose its grant (exec, exit, withdrawal) or the key
	// can pass to another thread. The read is taken under the grant read at the top
	// of this return, and the saved call is used only if its generation matches,
	// so a readmission of the number is a different instance. A refusal loses the
	// transfer and is counted.
	if (!grant) {
		// A refusal takes a place in the production order. Its number was taken at
		// entry and no event fills it, so it is already a gap in its occupancy,
		// whether or not it moved bytes (a refused call that moved nothing
		// over-invalidates its direction, the conservative way). A deferred call was
		// never on an approved stream and took no number (attempts; package
		// connection, Placement).
		if (c->deferred) {
			obs_count(OBS_STAT_DEFERRED_DISCARDED);
			return 0;
		}
		obs_stamp_event();
		obs_count(OBS_STAT_REFUSED);
		obs_unhold(occ, c->dir, id);
		return 0;
	}
	if (c->deferred) {
		// A call held through a fork window whose admission arrived while in flight:
		// it had no occupancy at entry, so it is numbered here, under the admission in
		// force now. This return-time numbering is the one exception to numbering at
		// entry, and it is sound because the call's admission did not exist at entry.
		generation = grant->generation;
		occ = obs_occupy(&key, c->ssl, generation, 0);
		number = occ ? obs_take(occ, c->dir) : 0;
	} else if (grant->generation != generation) {
		// The call's admission has gone and another is in force; its bytes are absent
		// from an approved stream. Its entry number stays a gap in the occupancy it
		// was entered in; nothing new is taken here.
		obs_stamp_event();
		obs_count(OBS_STAT_REFUSED);
		obs_unhold(occ, c->dir, id);
		return 0;
	}
	struct origin origin = {};
	obs_origin(grant, &origin);

	// What the window established about the socket, read once so every way this
	// function emits carries the same answer.
	__s32 fd = 0;
	__u64 binding = 0;
	__u64 socket = 0;
	__u8 fd_state = OBS_FD_NONE;
	struct ends ends = {};
	obs_associate(&key, c, &fd, &binding, &socket, &fd_state, &ends);

	struct place at = {};
	if (occ) {
		at.occupancy = occ->id;
		at.number = number;
		at.born = occ->born;
	at.begin_unlocated = occ->unlocated;
		at.overlapped = c->dir == OBS_SENT ? occ->overlapped_sent : occ->overlapped_received;
		// The drops in this direction so far, read before this call's own reservation:
		// a delivered event carries the count of refused reservations below its number,
		// so the tail counts only drops capture has not already located (settleLocked).
		at.dropped = c->dir == OBS_SENT ? occ->dropped_sent : occ->dropped_received;
	}
	if (!moved) {
		// The call returned having moved nothing, which its status measures: a known
		// zero, never an unknown length. Its entry number is filled with this zero-byte
		// resolution, so it is told from a return that never fires (which leaves the
		// number a gap).
		obs_dropped(occ, c->dir,
			obs_emit(&key, generation, &origin, c->ssl, 0, c->dir, c->early, 1, OBS_TRANSFER, 0,
				 fd, binding, socket, fd_state, c->outcome, &ends, &at, 0, 0, 0));
		obs_unhold(occ, c->dir, id);
		return 0;
	}

	if (c->count == OBS_COUNT_RETURNED) {
		if ((__u64)rc > c->cap) {
			// A count the buffer could not have held: bytes moved that no offset can
			// follow. The entry number stays a gap; nothing is emitted.
			obs_unhold(occ, c->dir, id);
			return 0;
		}
		obs_dropped(occ, c->dir,
			obs_emit(&key, generation, &origin, c->ssl, (__u32)rc, c->dir, c->early, 1,
				 OBS_TRANSFER, c->buf, fd, binding, socket, fd_state, c->outcome, &ends, &at, 0, 0, 0));
		obs_unhold(occ, c->dir, id);
		return 0;
	}

	// The out-parameter family writes the count through a caller's pointer, a read
	// of process memory: only the full program measures it, and the metadata-only
	// one reports the transfer as seen and not measured. Either way it moved bytes;
	// its number was taken at entry and is carried in at.
#if READ_PAYLOAD
	__u64 count = 0;
	if (c->pcount) {
		// Reading the count is a read of process memory like any other, recorded at
		// the read under the same admission (the reads map).
		if (obs_read_taken(&key, generation) &&
		    bpf_probe_read_user(&count, sizeof(count), (void *)c->pcount) == 0 &&
		    count > 0 && count <= c->cap) {
			obs_dropped(occ, c->dir,
				obs_emit(&key, generation, &origin, c->ssl, (__u32)count, c->dir, c->early, 1,
					 OBS_TRANSFER, c->buf, fd, binding, socket, fd_state, c->outcome, &ends, &at, 0, 0, 0));
			obs_unhold(occ, c->dir, id);
			return 0;
		}
	}
#endif
	obs_dropped(occ, c->dir,
		obs_emit(&key, generation, &origin, c->ssl, 0, c->dir, c->early, 0, OBS_TRANSFER, 0,
			 fd, binding, socket, fd_state, c->outcome, &ends, &at, 0, 0, 0));
	obs_unhold(occ, c->dir, id);
	return 0;
}

// The probes, one per function of the OpenSSL plaintext family, placed by
// userspace at the offsets it resolved.

SEC("uprobe") int obs_read_entry(void *ctx)  { return obs_entry(ctx, OBS_FUNC_READ, OBS_RECEIVED, OBS_COUNT_RETURNED, 0, 0); }
SEC("uretprobe") int obs_read_return(void *ctx) { return obs_return(ctx, OBS_FUNC_READ); }

SEC("uprobe") int obs_write_entry(void *ctx) { return obs_entry(ctx, OBS_FUNC_WRITE, OBS_SENT, OBS_COUNT_RETURNED, 0, 0); }
SEC("uretprobe") int obs_write_return(void *ctx) { return obs_return(ctx, OBS_FUNC_WRITE); }

SEC("uprobe") int obs_read_ex_entry(void *ctx)  { return obs_entry(ctx, OBS_FUNC_READ_EX, OBS_RECEIVED, OBS_COUNT_OUTPARAM, 0, OBS_PARM4(ctx)); }
SEC("uretprobe") int obs_read_ex_return(void *ctx) { return obs_return(ctx, OBS_FUNC_READ_EX); }

SEC("uprobe") int obs_write_ex_entry(void *ctx) { return obs_entry(ctx, OBS_FUNC_WRITE_EX, OBS_SENT, OBS_COUNT_OUTPARAM, 0, OBS_PARM4(ctx)); }
SEC("uretprobe") int obs_write_ex_return(void *ctx) { return obs_return(ctx, OBS_FUNC_WRITE_EX); }

SEC("uprobe") int obs_read_early_entry(void *ctx)  { return obs_entry(ctx, OBS_FUNC_READ_EARLY, OBS_RECEIVED, OBS_COUNT_OUTPARAM, 1, OBS_PARM4(ctx)); }
SEC("uretprobe") int obs_read_early_return(void *ctx) { return obs_return(ctx, OBS_FUNC_READ_EARLY); }

SEC("uprobe") int obs_write_early_entry(void *ctx) { return obs_entry(ctx, OBS_FUNC_WRITE_EARLY, OBS_SENT, OBS_COUNT_OUTPARAM, 1, OBS_PARM4(ctx)); }
SEC("uretprobe") int obs_write_early_return(void *ctx) { return obs_return(ctx, OBS_FUNC_WRITE_EARLY); }

// SSL_write_ex2(ssl, buf, num, flags, *written): the out-parameter is the fifth
// argument; otherwise as SSL_write_ex.
SEC("uprobe") int obs_write_ex2_entry(void *ctx) { return obs_entry(ctx, OBS_FUNC_WRITE_EX2, OBS_SENT, OBS_COUNT_OUTPARAM, 0, OBS_PARM5(ctx)); }
SEC("uretprobe") int obs_write_ex2_return(void *ctx) { return obs_return(ctx, OBS_FUNC_WRITE_EX2); }

// The socket probes are placed on the observed process's own C library, like
// the fork probe: a formatted tracepoint needs its id from tracefs, which most
// hosts do not mount. A process reaching the kernel without these entry points
// (a static binary, its own syscall stubs, another libc) makes socket calls not
// seen here, and its transfers carry no binding rather than a wrong one. Each
// is one hash lookup for a thread with no TLS call in flight.

// The kernel evidence. Everything below establishes the socket from the object
// the kernel acquired for the operation, which the descriptor table cannot do
// for a descriptor that arrived without a syscall. The syscall entry opens an
// operation frame against the live TLS call, the kernel hooks write what the
// operation acquired into it, and the syscall exit consumes it with the
// result. Every step is keyed by thread, never CPU.

// obs_supported says whether this build follows a syscall, naming the three
// unsupported ones: a call that went out through sendfile is one this build
// cannot attribute and knows it, a coverage limit to report.
static __always_inline int obs_supported(__u32 number)
{
	switch (number) {
	case OBS_SYS_READ:
	case OBS_SYS_WRITE:
	case OBS_SYS_READV:
	case OBS_SYS_WRITEV:
	case OBS_SYS_PREAD64:
	case OBS_SYS_PWRITE64:
	case OBS_SYS_PREADV:
	case OBS_SYS_PWRITEV:
	case OBS_SYS_SENDTO:
	case OBS_SYS_RECVFROM:
	case OBS_SYS_SENDMSG:
	case OBS_SYS_RECVMSG:
	case OBS_SYS_RECVMMSG:
	case OBS_SYS_SENDMMSG:
		return 1;
	default:
		return 0;
	}
}

// obs_socket_only says a syscall can only be operating on a socket: the
// messaging family returns ENOTSOCK on anything else. Without it a unix-domain
// sendmsg, which meets no protocol hook and no classifier (rw_verify_area is
// not on the messaging path), would report no socket evidence where the truth
// is a socket this build does not follow.
static __always_inline int obs_socket_only(__u32 number)
{
	switch (number) {
	case OBS_SYS_SENDTO:
	case OBS_SYS_RECVFROM:
	case OBS_SYS_SENDMSG:
	case OBS_SYS_RECVMSG:
	case OBS_SYS_RECVMMSG:
	case OBS_SYS_SENDMMSG:
		return 1;
	default:
		return 0;
	}
}

static __always_inline int obs_unsupported_route(__u32 number)
{
	switch (number) {
	case OBS_SYS_SENDFILE:
	case OBS_SYS_SPLICE:
	case OBS_SYS_IO_URING_ENTER:
		return 1;
	default:
		return 0;
	}
}

// obs_call_outcome folds one operation's outcome into the call it belongs to.
static __always_inline void obs_call_outcome(struct call *c, __u8 outcome)
{
	c->outcome = obs_worse(c->outcome, outcome);
}

// obs_call_socket records a socket the call's own I/O used. A second distinct
// socket makes the call ambiguous. The comparison is by socket identity, never
// descriptor: two descriptors naming one socket are one, and one descriptor
// replaced mid-call is two.
static __always_inline void obs_call_socket(struct call *c, const struct operation *op)
{
	if (c->sockets == 0) {
		c->socket = op->socket;
		c->socket_ino = op->ino;
		c->socket_gen = op->gen;
		c->socket_fd = op->fd;
		c->socket_occ = op->occupancy;
		c->sockets = 1;
		// The endpoints move with their identity, written only for the first socket;
		// an ambiguous call publishes none.
		__builtin_memcpy(c->local, op->local, sizeof(c->local));
		__builtin_memcpy(c->peer, op->peer, sizeof(c->peer));
		c->net_ino = op->net_ino;
		c->opened = op->opened;
		c->lport = op->lport;
		c->dport = op->dport;
		c->ends = op->ends;
		return;
	}
	if (c->socket != op->socket && c->sockets < 2)
		c->sockets = 2;
}

// obs_operation is this thread's live frame, or nothing where it belongs to a
// returned call: a frame naming another handle or an earlier sequence is
// counted as broken and not used.
static __always_inline struct operation *obs_operation(__u64 id, const struct call *c)
{
	struct operation *op = bpf_map_lookup_elem(&operations, &id);
	if (!op || !op->live)
		return 0;
	if (op->call != c->ssl || op->entered != c->sequence)
		return 0;
	return op;
}

// sys_enter opens an operation frame for a supported syscall inside a live TLS
// call on this thread; the first lookup is the filter. The descriptor is read
// from the kernel's saved registers, which covers a direct syscall that never
// went through the C library. Those registers are kernel memory and must be
// read as such, not dereferenced.
SEC("raw_tracepoint/sys_enter")
int obs_sys_enter(void *ctx)
{
	struct bpf_raw_tracepoint_args *raised = ctx;
	__u64 id = bpf_get_current_pid_tgid();
	struct call *c = bpf_map_lookup_elem(&inflight, &id);
	if (!c || !c->live)
		return 0;

	__u32 number = (__u32)raised->args[1];
	if (obs_unsupported_route(number)) {
		obs_call_outcome(c, OBS_OUTCOME_UNSUPPORTED);
		return 0;
	}
	if (!obs_supported(number))
		return 0;

	// A frame still live here belongs to an operation that never reached its exit
	// (an interrupted syscall, or unexpected nesting). It is counted and replaced,
	// not allowed to donate its evidence.
	struct operation *held = bpf_map_lookup_elem(&operations, &id);
	if (held && held->live) {
		obs_count(OBS_STAT_OPERATION_OVERWRITTEN);
		obs_call_outcome(c, OBS_OUTCOME_BROKEN);
	}

	struct operation op = {};
	op.call = c->ssl;
	op.entered = c->sequence;
	op.syscall = number;
	op.outcome = OBS_OUTCOME_UNRESOLVED;
	op.live = 1;

	// A messaging syscall is on a socket by construction; the classifier is not on
	// its path.
	op.socket_known = obs_socket_only(number) ? 1 : 0;

	void *regs = (void *)raised->args[0];
	__u64 fd = 0;
	if (bpf_probe_read_kernel(&fd, sizeof(fd), (char *)regs + OBS_SYSCALL_ARG1) != 0) {
		obs_count(OBS_STAT_EVIDENCE_UNREADABLE);
		obs_call_outcome(c, OBS_OUTCOME_UNREADABLE);
		return 0;
	}
	op.fd = (__s32)fd;

	// What is behind that number now, so a replacement under a blocked operation
	// is visible at completion.
	struct instance_key who = {};
	if (obs_locate(&who))
		op.occupancy = obs_occupancy(&who, op.fd, &op.opened);

	if (bpf_map_update_elem(&operations, &id, &op, BPF_ANY) != 0) {
		obs_count(OBS_STAT_OPERATION_UNRECORDED);
		obs_call_outcome(c, OBS_OUTCOME_BROKEN);
	}
	return 0;
}

// obs_completed consumes a live frame with its syscall's result. An error, an
// EAGAIN and a zero are not transfers, so none makes an association; a message
// count is not a byte count either. It consumes saved metadata, never a saved
// pointer.
static __always_inline void obs_completed(void *ctx, __u64 id, struct operation *op)
{
	struct bpf_raw_tracepoint_args *raised = ctx;
	op->live = 0;

	struct call *c = bpf_map_lookup_elem(&inflight, &id);
	if (!c || !c->live)
		return;
	if (op->call != c->ssl || op->entered != c->sequence) {
		// The frame outlived its call: not this call's evidence, and counted rather
		// than left as a gap.
		obs_count(OBS_STAT_OPERATION_UNMATCHED);
		obs_call_outcome(c, OBS_OUTCOME_BROKEN);
		return;
	}

	// The call performed I/O, whatever the result: recorded before the result is
	// read, because an error, EAGAIN or zero is I/O and forbids inheriting a
	// binding.
	c->io = 1;

	__s64 result = (__s64)raised->args[1];
	if (result <= 0)
		return;

	// A socket the classifier recognised and no protocol hook named is a route not
	// followed (unix-domain, or an unclaimed IP family), not an absence of
	// evidence.
	__u8 outcome = op->outcome;
	if (outcome == OBS_OUTCOME_UNRESOLVED && op->socket_known)
		outcome = OBS_OUTCOME_UNSUPPORTED;

	obs_call_outcome(c, outcome);
	if (outcome == OBS_OUTCOME_SOCKET)
		obs_call_socket(c, op);
}

SEC("raw_tracepoint/sys_exit")
int obs_sys_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct operation *op = bpf_map_lookup_elem(&operations, &id);
	if (!op)
		return 0;
	if (op->live)
		obs_completed(ctx, id, op);
	// The frame is this operation's evidence and no other's, so it goes once the
	// operation completes: the table holds only operations under way.
	bpf_map_delete_elem(&operations, &id);
	return 0;
}

// obs_endpoints copies one socket's addresses, ports and network namespace out
// of the object a hook holds, and never keeps the pointer. It runs at the
// transfer hook rather than at a state transition, so a connection already
// open when the observer attached still gets endpoints. ends is set last, and
// only where both addresses were read.
static __always_inline void obs_endpoints(struct sock *sk, unsigned short family, struct operation *op)
{
	__u16 num = 0, dpt = 0;
	if (bpf_core_read(&num, sizeof(num), &sk->__sk_common.skc_num) != 0 ||
	    bpf_core_read(&dpt, sizeof(dpt), &sk->__sk_common.skc_dport) != 0) {
		obs_count(OBS_STAT_EVIDENCE_UNREADABLE);
		return;
	}

	if (family == OBS_AF_INET) {
		__u32 saddr = 0, daddr = 0;
		if (bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr) != 0 ||
		    bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr) != 0) {
			obs_count(OBS_STAT_EVIDENCE_UNREADABLE);
			return;
		}
		// ::ffff:a.b.c.d, which netip.Addr.Unmap reverses. skc_rcv_saddr and skc_daddr
		// are __be32, already in wire order.
		op->local[10] = 0xff;
		op->local[11] = 0xff;
		__builtin_memcpy(&op->local[12], &saddr, sizeof(saddr));
		op->peer[10] = 0xff;
		op->peer[11] = 0xff;
		__builtin_memcpy(&op->peer[12], &daddr, sizeof(daddr));
	} else {
		if (bpf_core_read(op->local, sizeof(op->local), &sk->__sk_common.skc_v6_rcv_saddr) != 0 ||
		    bpf_core_read(op->peer, sizeof(op->peer), &sk->__sk_common.skc_v6_daddr) != 0) {
			obs_count(OBS_STAT_EVIDENCE_UNREADABLE);
			return;
		}
	}

	// The namespace is the socket's own, not its holder's: a descriptor inherited
	// across a namespace transition or passed over a unix socket belongs where it
	// was created (package connection, Endpoints). Its absence leaves the
	// addresses standing, with their scope reported unknown.
	struct net *net = 0;
	if (bpf_core_read(&net, sizeof(net), &sk->__sk_common.skc_net.net) == 0 && net) {
		unsigned int inum = 0;
		if (bpf_core_read(&inum, sizeof(inum), &net->ns.inum) == 0)
			op->net_ino = (__u64)inum;
	}

	// skc_num is host order and skc_dport network order, so exactly one is
	// swapped; both targets are little-endian, so the swap is unconditional.
	op->lport = num;
	op->dport = __builtin_bswap16(dpt);
	op->ends = 1;
}

// obs_acquired records the socket a protocol entry point is operating on,
// copying fields at the hook; the pointer is never saved, since the reference
// is held only while this runs. family decides coverage: AF_INET and AF_INET6
// are claimed, anything else is a route not followed.
static __always_inline int obs_acquired(void *ctx, __u8 expect)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct call *c = bpf_map_lookup_elem(&inflight, &id);
	if (!c || !c->live)
		return 0;

	struct operation *op = obs_operation(id, c);
	if (!op)
		return 0;

	struct socket *held = (struct socket *)OBS_PARM1(ctx);
	struct sock *sk = 0;
	struct file *file = 0;
	unsigned short family = 0;
	unsigned long ino = 0;
	if (bpf_core_read(&sk, sizeof(sk), &held->sk) != 0 || !sk ||
	    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family) != 0) {
		obs_count(OBS_STAT_EVIDENCE_UNREADABLE);
		op->outcome = OBS_OUTCOME_UNREADABLE;
		return 0;
	}
	if (family != OBS_AF_INET && family != OBS_AF_INET6) {
		op->outcome = OBS_OUTCOME_UNSUPPORTED;
		return 0;
	}
	// The entry point's family against the socket's: a disagreement would claim
	// IPv6 coverage from an IPv4 placement.
	if (family != expect) {
		op->outcome = OBS_OUTCOME_UNSUPPORTED;
		return 0;
	}

	// The inode number is what people recognise. A socket without a file has none,
	// a narrower identity: the kernel address and generation still separate it.
	if (bpf_core_read(&file, sizeof(file), &held->file) == 0 && file) {
		struct inode *node = 0;
		if (bpf_core_read(&node, sizeof(node), &file->f_inode) == 0 && node)
			(void)bpf_core_read(&ino, sizeof(ino), &node->i_ino);
	}

	obs_endpoints(sk, family, op);

	struct socket_ident who = {};
	who.sock = (__u64)sk;
	who.ino = (__u64)ino;

	op->socket = who.sock;
	op->ino = who.ino;
	op->gen = obs_discover(&who);
	op->family = (__u8)family;
	op->outcome = OBS_OUTCOME_SOCKET;
	return 0;
}

SEC("kprobe") int obs_inet_sendmsg(void *ctx) { return obs_acquired(ctx, OBS_AF_INET); }
SEC("kprobe") int obs_inet_recvmsg(void *ctx) { return obs_acquired(ctx, OBS_AF_INET); }
SEC("kprobe") int obs_inet6_sendmsg(void *ctx) { return obs_acquired(ctx, OBS_AF_INET6); }
SEC("kprobe") int obs_inet6_recvmsg(void *ctx) { return obs_acquired(ctx, OBS_AF_INET6); }

// inet_release is a socket's release, IPv4 and IPv6 alike (inet6_release calls
// it), once nothing holds it. Its discovery goes with it, keyed as obs_acquired
// keyed it, so the table holds only sockets that exist, and a later socket at
// the same kernel address and inode is a new discovery with a new generation.
SEC("kprobe")
int obs_inet_release(void *ctx)
{
	struct socket *released = (struct socket *)OBS_PARM1(ctx);
	struct sock *sk = 0;
	struct file *file = 0;
	unsigned long ino = 0;
	if (bpf_core_read(&sk, sizeof(sk), &released->sk) != 0 || !sk)
		return 0;
	if (bpf_core_read(&file, sizeof(file), &released->file) == 0 && file) {
		struct inode *node = 0;
		if (bpf_core_read(&node, sizeof(node), &file->f_inode) == 0 && node)
			(void)bpf_core_read(&ino, sizeof(ino), &node->i_ino);
	}
	struct socket_ident who = {};
	who.sock = (__u64)sk;
	who.ino = (__u64)ino;
	bpf_map_delete_elem(&discovered, &who);
	return 0;
}

// rw_verify_area makes a non-socket a positive answer: without it "no network
// hook fired" cannot be told from an ordinary file write inside the call.
// Argument two is the acquired file; S_ISSOCK over its inode mode decides, and
// an unreadable mode is an unreadable evidence read. It does not overwrite a
// socket a protocol hook already established, since their order is not relied
// on.
SEC("kprobe")
int obs_rw_verify_area(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct call *c = bpf_map_lookup_elem(&inflight, &id);
	if (!c || !c->live)
		return 0;

	struct operation *op = obs_operation(id, c);
	if (!op || op->outcome == OBS_OUTCOME_SOCKET)
		return 0;

	struct file *file = (struct file *)OBS_PARM2(ctx);
	struct inode *node = 0;
	unsigned short mode = 0;
	if (bpf_core_read(&node, sizeof(node), &file->f_inode) != 0 || !node ||
	    bpf_core_read(&mode, sizeof(mode), &node->i_mode) != 0) {
		obs_count(OBS_STAT_EVIDENCE_UNREADABLE);
		op->outcome = OBS_OUTCOME_UNREADABLE;
		return 0;
	}
	if ((mode & OBS_S_IFMT) != OBS_S_IFSOCK) {
		op->outcome = OBS_OUTCOME_FILE;
		return 0;
	}
	// A socket, whose protocol hook has not run or will not. The outcome is left
	// alone (an association needs the socket itself), but the fact is recorded: a
	// socket no protocol hook names is a route not followed.
	op->socket_known = 1;
	return 0;
}

// The socket-only family: these can only operate on a socket.
SEC("uprobe") int obs_sendto(void *ctx)   { obs_saw_socket((__s32)OBS_PARM1(ctx), 1); return 0; }
SEC("uprobe") int obs_recvfrom(void *ctx) { obs_saw_socket((__s32)OBS_PARM1(ctx), 1); return 0; }
SEC("uprobe") int obs_sendmsg(void *ctx)  { obs_saw_socket((__s32)OBS_PARM1(ctx), 1); return 0; }
SEC("uprobe") int obs_recvmsg(void *ctx)  { obs_saw_socket((__s32)OBS_PARM1(ctx), 1); return 0; }

// The general family operates on any descriptor, so one counts as network I/O
// only if this run saw its socket created; otherwise a log write inside an SSL
// call would be recorded as the socket.
SEC("uprobe") int obs_read(void *ctx)   { obs_saw_socket((__s32)OBS_PARM1(ctx), 0); return 0; }
SEC("uprobe") int obs_write(void *ctx)  { obs_saw_socket((__s32)OBS_PARM1(ctx), 0); return 0; }
SEC("uprobe") int obs_readv(void *ctx)  { obs_saw_socket((__s32)OBS_PARM1(ctx), 0); return 0; }
SEC("uprobe") int obs_writev(void *ctx) { obs_saw_socket((__s32)OBS_PARM1(ctx), 0); return 0; }

// The descriptor lifetime. A binding remembers the occupancy it was made
// against, so these three are the whole of invalidation.

// socket() returns a new socket and connect() is called on one, so both say
// the number names a socket. connect is taken at entry, since a failed connect
// still leaves a socket behind the number.
SEC("uretprobe") int obs_socket_return(void *ctx)
{
	obs_socket_opened((__s32)(__s64)(__s32)OBS_RC(ctx));
	return 0;
}

SEC("uretprobe") int obs_accept_return(void *ctx)
{
	obs_socket_opened((__s32)(__s64)(__s32)OBS_RC(ctx));
	return 0;
}

SEC("uprobe") int obs_connect(void *ctx)
{
	obs_socket_opened((__s32)OBS_PARM1(ctx));
	return 0;
}

// close ends an occupancy; a binding made against it then finds no entry.
SEC("uprobe") int obs_close(void *ctx)
{
	obs_socket_closed((__s32)OBS_PARM1(ctx));
	return 0;
}

// dup2 replaces the socket behind a descriptor with no call into the TLS
// library. The new descriptor gets a fresh occupancy, so a binding made against
// the old one is invalidated rather than following the number to another
// socket.
SEC("uprobe") int obs_dup2(void *ctx)
{
	obs_socket_closed((__s32)OBS_PARM2(ctx));
	obs_socket_opened((__s32)OBS_PARM2(ctx));
	return 0;
}

// obs_release ends the occupancy of the handle in argument one, at SSL_free or
// SSL_clear: a connection ending, so the handle may be used by another
// connection without continuing this one's stream. No bytes, no buffer.
//
// recycled is SSL_clear, which readies the object for a new connection in
// place. OpenSSL calls it itself, too: inside SSL_new on some releases, and at
// the start of every first handshake, including one a first SSL_write or
// SSL_read starts on its own. None of those has a connection to end, so a
// recycle ends an occupancy only where it has numbered a transfer and no call
// of this thread is in flight on it; the occupancy otherwise stands, born as it
// was.
static __always_inline int obs_release(void *ctx, int recycled)
{
	struct instance_key key = {};
	if (!obs_locate(&key))
		return 0;

	if (recycled) {
		struct handle_key cleared = {};
		obs_handle_key(&cleared, &key, OBS_PARM1(ctx));
		struct occupancy *now = bpf_map_lookup_elem(&occupancies, &cleared);
		__u64 thread = bpf_get_current_pid_tgid();
		if (!now || (!now->sent && !now->received) || now->busy_sent == thread || now->busy_received == thread)
			return 0;
	}

	// The two halves below treat authentication differently, uniquely in this
	// program. Dropping a binding reads, emits and learns nothing: it removes the
	// observer's own stale record, and refusing it would leak a binding to the next
	// admitted occupant of this number at the same handle address (pid reuse and
	// address reuse arrive together). Emitting attributes a connection ending to an
	// instance, so it needs the grant's occupant.
	//
	// Only the observer's own record about an approved occupant can be under that
	// key: the handles map has one writer, obs_associate, called only from
	// obs_return, where three guards stand between a saved call and a binding (a
	// still-unadmitted deferred call is discarded, a gone grant refused, a
	// superseded admission refused).
	//
	// These uprobes have no pid filter, so they already run for every process
	// linking the library; the drop adds one map operation there, unmeasured.

	// The handle's binding is dropped. SSL_free does not prove the connection
	// ended (it is reference counted; SSL_dup and SSL_clear exist), but this
	// occupancy of the address may not be relied on. Keeping it would let a reused
	// address inherit a gone connection's binding; dropping it costs at most a
	// binding the next syscall re-establishes, with unknown in between.
	struct handle_key released = {};
	released.ns_dev = key.ns_dev;
	released.ns_ino = key.ns_ino;
	released.pid = key.pid;
	released.ssl = OBS_PARM1(ctx);
	int dropped = bpf_map_delete_elem(&handles, &released);

	// The occupancy ends here, delivered or not: its last numbers are copied out
	// and the entry deleted, whoever the releasing task is, for the reason the
	// binding is dropped. A later use of the address begins a new occupancy, which
	// is what makes the next occupancy known without anything downstream seeing
	// this ending.
	struct place at = {};
	__u64 last_sent = 0, last_received = 0;
	__u8 in_flight = 0;
	struct occupancy *occ = bpf_map_lookup_elem(&occupancies, &released);
	if (occ) {
		at.occupancy = occ->id;
		at.born = occ->born;
	at.begin_unlocated = occ->unlocated;
		last_sent = occ->sent;
		last_received = occ->received;
		if (occ->busy_sent)
			in_flight |= OBS_SENT;
		if (occ->busy_received)
			in_flight |= OBS_RECEIVED;
		bpf_map_delete_elem(&occupancies, &released);
	}

	struct admission *grant = bpf_map_lookup_elem(&allowed_processes, &key);
	if (!grant || grant->kind == OBS_DENIED || !obs_authentic(grant)) {
		// A record removed by a task that is not its occupant is a binding a gone
		// occupant left behind, reported only when the delete really removed one.
		if (dropped == 0)
			obs_count(OBS_STAT_STALE_BINDING_DROPPED);
		return 0;
	}

	// A connection ending crossed no socket: no association (OBS_FD_NONE) and no
	// endpoints (an empty carrier says they were not read).
	struct ends none = {};
	struct origin origin = {};
	obs_origin(grant, &origin);
	obs_emit(&key, grant->generation, &origin, OBS_PARM1(ctx), 0, 0, 0, 0, OBS_CLOSED, 0,
		 0, 0, 0, OBS_FD_NONE, OBS_OUTCOME_NONE, &none, &at, last_sent, last_received, in_flight);
	return 0;
}

// SSL_free: the handle is released.
SEC("uprobe") int obs_free_entry(void *ctx) { return obs_release(ctx, 0); }

// SSL_clear: the handle is recycled in place for a new connection, with no
// SSL_free and no SSL_new. Its next transfer begins a fresh occupancy, numbered
// from one, with no binding inherited from the connection before.
SEC("uprobe") int obs_clear_entry(void *ctx) { return obs_release(ctx, 1); }

// SSL_sendfile moves plaintext from a file through kTLS without a user buffer,
// so it is outside the plaintext catalogue and this build cannot read its bytes.
// It is observed count-only: on entry it takes a SENT number in the handle's
// occupancy and emits nothing, so its use shows as a gap in the sent direction
// rather than as bytes nothing numbered. Numbered at ENTRY, so a call that fails
// (no kTLS on the host) still marks the gap; the cost is that a failed
// SSL_sendfile over-invalidates the sent direction, the conservative way. It is
// the only plaintext-moving entry point libssl exports outside the catalogue.
SEC("uprobe") int obs_sendfile(void *ctx)
{
	struct instance_key key = {};
	struct admission *grant = obs_grant(&key);
	if (!grant)
		return 0;
	struct occupancy *occ = obs_occupy(&key, OBS_PARM1(ctx), grant->generation, 0);
	obs_lost(occ, OBS_SENT);
	return 0;
}

// SSL_new's return: a handle's birth. The occupancy begun here holds every
// number the handle takes, so number one is its first transfer in each
// direction whatever was lost before it existed (struct occupancy, born).
SEC("uretprobe") int obs_new_return(void *ctx)
{
	struct instance_key key = {};
	struct admission *grant = obs_grant(&key);
	if (!grant)
		return 0;
	__u64 ssl = OBS_RC(ctx);
	if (!ssl)
		return 0;
	obs_occupy(&key, ssl, grant->generation, 1);
	return 0;
}

// The three hooks keeping the allowlist current while probes are placed: fork,
// exec and exit. None needs tracefs: a formatted tracepoint's id is read from
// /sys/kernel/tracing, which most hosts do not mount (attaching that way fails
// with "neither debugfs nor tracefs are mounted"). All three are raw
// tracepoints attached by name through bpf(2); walking their kernel-pointer
// arguments needs the host's BTF, and the fork event names the new task from
// the task_struct it is handed, before the child has run.

// obs_fork_entry opens the window an unadmitted task's call may be held
// through, on the observed process's own libc fork.
SEC("uprobe")
int obs_fork_entry(void *ctx)
{
	struct instance_key key = {};
	struct admission *grant = obs_grant(&key);
	if (!grant || grant->propagate != OBS_PROPAGATE_YES || grant->mode != OBS_MODE_FOLLOW)
		return 0;
	obs_fork_window(1);
	return 0;
}

SEC("uretprobe")
int obs_fork_return(void *ctx)
{
	struct instance_key parent = {};
	struct admission *grant = obs_grant(&parent);
	if (!grant || grant->propagate != OBS_PROPAGATE_YES || grant->mode != OBS_MODE_FOLLOW)
		return 0;

	// Nothing is admitted here: the child is established at the ordered kernel
	// event below. This return only closes the window its entry opened. It also
	// fires in the child (zero) and on failure (negative); only the parent's
	// return closes the window, by the predicate that opened it.
	__s64 born_pid = (__s64)(__s32)OBS_RC(ctx);
	if (born_pid != 0)
		obs_fork_window(-1);
	return 0;
}

// obs_fork establishes what a fork created at the kernel event ordered against
// the new task running: sched_process_fork is raised inside the clone, before
// wake_up_new_task, so the task exists and has a birth but cannot have run,
// execed or exited. Naming the child at the parent's libc fork return instead
// would let a child exec an unapproved image before the grant exists, or exit
// before its entry, leaving the entry forever.
//
// Creator, parent and thread group are distinct here: the first argument is
// the creating task (the one this runs in), CLONE_PARENT makes real_parent the
// creator's parent, and the event is also raised for a new thread, which gets
// no entry. Everything is read off the new task.
SEC("raw_tracepoint/sched_process_fork")
int obs_fork(void *ctx)
{
	struct bpf_raw_tracepoint_args *raised = ctx;
	struct task_struct *child = (struct task_struct *)raised->args[1];
	if (!child)
		return 0;

	// The creator names itself as everywhere else, from the raw entry rather than
	// the grant, because a denied creator has no grant and must be acted on.
	struct instance_key parent = {};
	if (!obs_locate(&parent))
		return 0;
	struct admission *grant = bpf_map_lookup_elem(&allowed_processes, &parent);
	if (!grant)
		return 0;

	// A new thread rather than a process (the new task is not its own group
	// leader). The allowlist is keyed by thread group, so it gets no entry.
	__s32 pid = 0;
	__s32 tgid = 0;
	if (bpf_core_read(&pid, sizeof(pid), &child->pid) != 0 ||
	    bpf_core_read(&tgid, sizeof(tgid), &child->tgid) != 0) {
		obs_count(OBS_STAT_CHILD_UNNAMEABLE);
		return 0;
	}
	if (pid != tgid)
		return 0;

	// The child's pid namespace and number in it: its active namespace is the
	// deepest level its pid is numbered in.
	struct pid *identity = 0;
	__u32 level = 0;
	if (bpf_core_read(&identity, sizeof(identity), &child->thread_pid) != 0 || !identity ||
	    bpf_core_read(&level, sizeof(level), &identity->level) != 0 ||
	    level > OBS_PID_LEVEL_MAX) {
		obs_count(OBS_STAT_CHILD_UNNAMEABLE);
		return 0;
	}

	// numbers[] is a flexible array indexed by level: the member offset and the
	// element stride both come from the loading kernel (access index and target
	// type size).
	__u64 numbers = (__u64)__builtin_preserve_access_index(&identity->numbers[0]);
	__u64 stride = bpf_core_type_size(struct upid);
	// A stride of zero is unreachable in a loaded program and is guarded anyway,
	// observing nothing. The size is patched from the host's BTF, and an
	// unresolvable CO-RE relocation fails the load (reasoned from loader behaviour,
	// not measured).
	if (!stride) {
		obs_count(OBS_STAT_CHILD_UNNAMEABLE);
		return 0;
	}
	struct upid *number = (struct upid *)(numbers + (__u64)level * stride);
	__s32 nr = 0;
	struct pid_namespace *namespace = 0;
	__u32 inum = 0;
	if (bpf_core_read(&nr, sizeof(nr), &number->nr) != 0 || nr <= 0 ||
	    bpf_core_read(&namespace, sizeof(namespace), &number->ns) != 0 || !namespace ||
	    bpf_core_read(&inum, sizeof(inum), &namespace->ns.inum) != 0) {
		obs_count(OBS_STAT_CHILD_UNNAMEABLE);
		return 0;
	}
	// A child whose namespace is not its creator's got a new one from this clone,
	// which nobody enumerated, so it is refused and counted as itself: not a
	// naming failure (a host condition), but a short enumeration an operator can
	// lengthen.
	if ((__u64)inum != parent.ns_ino) {
		obs_count(OBS_STAT_CHILD_NS_UNENUMERATED);
		return 0;
	}

	// The child's own start; a new process is its own and only thread.
	__u64 birth = obs_ticks(child);
	if (!birth) {
		obs_count(OBS_STAT_CHILD_UNNAMEABLE);
		return 0;
	}

	struct instance_key born = parent;
	born.pid = (__u32)nr;

	if (grant->kind == OBS_DENIED) {
		// An exclusion denies its instances and their descendants, so a denied
		// creator's child is denied as it is created. A denial confers nothing and is
		// not authenticated.
		struct admission denied = *grant;
		denied.generation = obs_stamp();
		if (!denied.generation) {
			obs_count(OBS_STAT_DENIAL_UNRECORDED);
			return 0;
		}
		denied.birth = birth;
		// A new process has one thread and none of its creator's lifetime state.
		denied.threads = 1;
		denied.leader_gone = 0;
		denied.parent_generation = grant->generation;
		denied.parent_ns_dev = parent.ns_dev;
		denied.parent_ns_ino = parent.ns_ino;
		denied.parent_pid = parent.pid;
		if (bpf_map_update_elem(&allowed_processes, &born, &denied, BPF_ANY) != 0)
			obs_count(OBS_STAT_DENIAL_UNRECORDED);
		return 0;
	}

	// The creator's grant is authenticated before anything is passed on.
	if (!obs_authentic(grant)) {
		obs_count(OBS_STAT_UNAUTHENTICATED);
		return 0;
	}
	// The ability, then the permission. Only follow covers descendants created
	// after resolution; none covers none, and existing covers those already
	// running, which userspace found and this event never sees.
	if (grant->propagate != OBS_PROPAGATE_YES)
		return 0;
	if (grant->mode != OBS_MODE_FOLLOW)
		return 0;

	struct admission inherited = {};
	// A stamp of zero is unreachable (index 0 of a one-element array) and refused:
	// an entry with no generation would match an uninitialised saved call.
	inherited.generation = obs_stamp();
	if (!inherited.generation) {
		obs_count(OBS_STAT_DESCENDANT_UNRECORDED);
		return 0;
	}
	inherited.birth = birth;
	inherited.parent_generation = grant->generation;
	inherited.parent_ns_dev = parent.ns_dev;
	inherited.parent_ns_ino = parent.ns_ino;
	inherited.parent_pid = parent.pid;
	inherited.target = grant->target;
	inherited.rule = grant->rule;
	inherited.kind = OBS_BY_DESCENT;
	inherited.mode = grant->mode;
	inherited.propagate = grant->propagate;
	inherited.threads = 1;

	if (bpf_map_update_elem(&allowed_processes, &born, &inherited, BPF_ANY) == 0)
		obs_count(OBS_STAT_DESCENDANTS);
	else
		// The allowlist refused the child, so it is not observed; counted as a child
		// named and not written down.
		obs_count(OBS_STAT_DESCENDANT_UNRECORDED);
	return 0;
}

// What an execution's end takes away. The occupancies, handle bindings and
// descriptor lifetimes are keyed by the execution and nothing else tells them
// it has ended, so they are walked for its entries when it does (holders says
// whether there are any). An occupancy still held is the producer's last
// evidence about a connection the execution never released: it is reported as
// an ending carrying its last numbers, marked as raised by the execution's end,
// before its entry goes, exactly as a release reports it.
// The map a walk's callback is handed; its layout is the kernel's and is never
// read here.
struct bpf_map;

struct reclaim {
	struct instance_key who;
	struct origin origin; // the grant's, where it is the one the occupancy began under
	__u64 granted;        // that grant's generation, zero where there is none
};

static __always_inline int obs_reclaimed(const struct instance_key *who, __u64 ns_dev, __u64 ns_ino, __u32 pid)
{
	return ns_dev == who->ns_dev && ns_ino == who->ns_ino && pid == who->pid;
}

static long obs_reclaim_occupancy(struct bpf_map *map, struct handle_key *key, struct occupancy *occ,
				  struct reclaim *r)
{
	if (!obs_reclaimed(&r->who, key->ns_dev, key->ns_ino, key->pid))
		return 0;
	struct place at = {};
	at.occupancy = occ->id;
	at.born = occ->born;
	at.begin_unlocated = occ->unlocated;
	at.exited = 1;
	__u8 in_flight = 0;
	if (occ->busy_sent)
		in_flight |= OBS_SENT;
	if (occ->busy_received)
		in_flight |= OBS_RECEIVED;
	struct origin origin = {};
	if (occ->generation == r->granted)
		origin = r->origin;
	struct ends none = {};
	obs_emit(&r->who, occ->generation, &origin, key->ssl, 0, 0, 0, 0, OBS_CLOSED, 0,
		 0, 0, 0, OBS_FD_NONE, OBS_OUTCOME_NONE, &none, &at, occ->sent, occ->received, in_flight);
	bpf_map_delete_elem(map, key);
	return 0;
}

static long obs_reclaim_binding(struct bpf_map *map, struct handle_key *key, struct binding *held,
				struct reclaim *r)
{
	if (obs_reclaimed(&r->who, key->ns_dev, key->ns_ino, key->pid))
		bpf_map_delete_elem(map, key);
	return 0;
}

static long obs_reclaim_descriptor(struct bpf_map *map, struct socket_key *key, struct socket_life *life,
				   struct reclaim *r)
{
	if (obs_reclaimed(&r->who, key->ns_dev, key->ns_ino, key->pid))
		bpf_map_delete_elem(map, key);
	return 0;
}

// obs_reclaim takes away what the program keeps for the execution who, whose
// image has ended: at its last thread's exit, with its descriptors too, and at
// an exec, which keeps its descriptors (a descriptor survives an exec) and ends
// every handle of the image it replaces. entry is its allowlist entry, if any,
// whose user-memory reads are folded into one count before their entry goes.
static __always_inline void obs_reclaim(const struct instance_key *who, const struct admission *entry,
					int descriptors)
{
	struct reclaim r = {};
	r.who = *who;
	if (entry && entry->kind != OBS_DENIED) {
		r.granted = entry->generation;
		obs_origin(entry, &r.origin);
#if READ_PAYLOAD
		__u64 generation = entry->generation;
		__u64 *taken = bpf_map_lookup_elem(&reads, &generation);
		if (taken) {
			// No thread of the execution is left to take a read under this
			// generation, so the count is final when it is folded.
			__u32 index = OBS_STAT_READS_RECLAIMED;
			__u64 *slot = bpf_map_lookup_elem(&stats, &index);
			if (slot)
				__sync_fetch_and_add(slot, *taken);
			bpf_map_delete_elem(&reads, &generation);
		}
#endif
	}
	struct holding *holding = bpf_map_lookup_elem(&holders, who);
	if (!holding)
		return;
	__u8 delivered = holding->events;
	bpf_for_each_map_elem(&occupancies, obs_reclaim_occupancy, &r, 0);
	bpf_for_each_map_elem(&handles, obs_reclaim_binding, &r, 0);
	if (!descriptors)
		return;
	bpf_for_each_map_elem(&sockets, obs_reclaim_descriptor, &r, 0);
	bpf_map_delete_elem(&holders, who);
	if (!delivered)
		return;
	// The execution's end, after every ending above, so userspace lets go of what
	// it keeps for the execution only once nothing of it is still to come.
	struct place at = {};
	struct origin origin = {};
	struct ends none = {};
	obs_emit(who, r.granted, &origin, 0, 0, 0, 0, 0, OBS_ENDED, 0, 0, 0, 0, OBS_FD_NONE, OBS_OUTCOME_NONE,
		 &none, &at, 0, 0, 0);
}

// obs_group_dead says the current thread is the last of its group to exit:
// do_exit decrements signal->live before sched_process_exit is raised. A read
// that fails says no, which leaves the execution's entries in place rather
// than ending another's.
static __always_inline int obs_group_dead(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct signal_struct *shared = 0;
	int live = 1;
	if (!task || bpf_core_read(&shared, sizeof(shared), &task->signal) != 0 || !shared ||
	    bpf_core_read(&live, sizeof(live), &shared->live.counter) != 0)
		return 0;
	return live == 0;
}

// obs_exit removes an exiting process, so a reused number is not observed on
// its predecessor's approval. It reads only the current task's id, so it needs
// no BTF. It fires per thread and the entry belongs to the group.
SEC("raw_tracepoint/sched_process_exit")
int obs_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();

	// The saved call and the operation frame of an exiting thread: its thread and
	// group numbers are reused, so they are removed here rather than left for the
	// generation and sequence checks to refuse.
	bpf_map_delete_elem(&inflight, &id);
	bpf_map_delete_elem(&operations, &id);

	// Every thread's exit counts: the group is gone when its last thread is, not
	// its leader (pthread_exit leaves a zombie leader with live workers). Each exit
	// takes one thread off and the last removes the entry.
	__u32 tgid = id >> 32;
	struct instance_key key = {};
	if (!obs_locate(&key))
		return 0;
	struct admission *entry = bpf_map_lookup_elem(&allowed_processes, &key);
	if (obs_group_dead())
		obs_reclaim(&key, entry, 1);
	if (!entry)
		return 0;

	__u32 before = entry->threads;
	if (before > 1) {
		// No subtracting atomic on this target; adding minus one compiles.
		__sync_fetch_and_add(&entry->threads, -1);
	}
	__u32 remaining = before > 0 ? before - 1 : 0;

	if ((__u32)id == tgid) {
		// The leader. Where threads remain the execution runs on, and the zombie
		// leader keeps the pid reserved meanwhile.
		if (remaining > 0) {
			entry->leader_gone = 1;
			return 0;
		}
		bpf_map_delete_elem(&allowed_processes, &key);
		return 0;
	}
	// A worker ends the grant only after the leader has gone, as the last thread.
	if (entry->leader_gone && remaining == 0)
		bpf_map_delete_elem(&allowed_processes, &key);
	return 0;
}

// obs_exec ends a grant at a successful exec and disposes of the thread's saved
// call. Inherited authority does not survive an exec: the pid is the same and
// the program is not. A new image is covered only once a policy resolution (at
// a restart) approves it. A failed exec never reaches here and keeps its grant.
SEC("raw_tracepoint/sched_process_exec")
int obs_exec(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&inflight, &id);
	bpf_map_delete_elem(&operations, &id);

	struct instance_key key = {};
	if (!obs_locate(&key))
		return 0;
	struct admission *entry = bpf_map_lookup_elem(&allowed_processes, &key);
	// The image every handle belonged to is gone, whatever the allowlist says.
	obs_reclaim(&key, entry, 0);
	if (!entry)
		return 0;
	// A denial survives an exec: same execution, same subtree, and an excluded
	// process cannot leave its exclusion by changing image. A grant does not.
	if (entry->kind == OBS_DENIED)
		return 0;
	bpf_map_delete_elem(&allowed_processes, &key);
	return 0;
}

// The kernel offers bpf_probe_read_kernel, bpf_probe_read_user and
// bpf_get_current_task only to GPL-compatible programs, which is what this
// declaration makes this one.
char _license[] SEC("license") = "GPL";

#endif
