#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/* A real SSL_write with a controlled synchronous BIO. The BIO deliberately
 * accepts plaintext even in the no-transport cases: those cases ask whether a
 * successful library return can borrow a binding from an unsuccessful syscall.
 * The two TCP peers witness ciphertext, not a claim supplied by the observer.
 * Binary control uses inherited pipes 3 and 4; neither output stream is used. */
static int fd = -1, replacement = -1, ordinary = -1, mode, wire, result;
static int unix_pair[2];
static int actor_tid, initial_cpu, resumed_cpu, next_cpu;
static pthread_t replacer;
static char unix_ciphertext[4096];
static int unix_filler;
static pthread_t unix_drain;
static void exact(int file, void *buffer, size_t size, int writing) {
    char *p = buffer;
    while (size) {
        ssize_t n = writing ? write(file, p, size) : read(file, p, size);
        if (n <= 0) _exit(90);
        p += n;
        size -= n;
    }
}
static int connect_to(int port) {
    if (port < 0) {
        int s = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(-port), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        if (s < 0 || connect(s, (void *)&a, sizeof(a))) _exit(91);
        return s;
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s < 0 || connect(s, (void *)&a, sizeof(a))) _exit(91);
    return s;
}
static int create(BIO *b) { BIO_set_init(b, 1); return 1; }
static void *drain_unix_after_witness(void *unused) {
    (void)unused;
    int32_t request[3];
    exact(3, request, sizeof(request), 0);
    if (request[0] != 28) _exit(114);
    char buffer[1024];
    int remaining = unix_filler;
    while (remaining) {
        int count = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        exact(unix_pair[1], buffer, count, 0);
        remaining -= count;
    }
    return NULL;
}
static long control(BIO *b, int command, long n, void *p) {
    (void)b; (void)n; (void)p;
    return command == BIO_CTRL_FLUSH;
}
static void *replace_while_acquired(void *unused) {
    (void)unused;
    int32_t request[3];
    exact(3, request, sizeof(request), 0);
    if (request[0] != 18 || dup2(replacement, fd) != fd) _exit(101);
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(next_cpu, &set);
    if (sched_setaffinity(actor_tid, sizeof(set), &set)) _exit(102);
    int32_t reply[4] = {18, fd, actor_tid, next_cpu};
    exact(4, reply, sizeof(reply), 1);
    return NULL;
}
static int transport(BIO *b, const char *data, int n) {
    (void)b;
    struct iovec vector[2] = {{(void *)data, 1}, {(void *)(data + 1), n - 1}};
    struct msghdr message = {.msg_iov = vector, .msg_iovlen = 2};
    result = 0;
    switch (mode) {
    case 2: result = write(fd, data, n); break;
    case 3: break; /* No kernel I/O whatsoever. */
    case 4: result = write(ordinary, data, n); break;
    case 5: /* Several acquired operations, one binding, one SSL call. */
        result = write(fd, data, 1);
        if (result != 1) _exit(92);
        wire += result;
        result = write(fd, data + 1, n - 1);
        break;
    case 6: /* Same integer, two different sockets inside one SSL call. */
        result = write(fd, data, 1);
        if (result != 1) _exit(93);
        wire += result;
        if (dup2(replacement, fd) != fd) _exit(94);
        result = write(fd, data + 1, n - 1);
        break;
    case 7: result = syscall(SYS_write, fd, data, n); break;
    case 8: result = syscall(SYS_writev, fd, vector, 2); break;
    case 9: result = syscall(SYS_sendmsg, fd, &message, 0); break;
    case 10: result = write(-1, data, n); if (result != -1 || errno != EBADF) _exit(95); break;
    case 11: result = write(fd, data, 0); if (result != 0) _exit(96); break;
    case 12: {
        char byte;
        result = recv(fd, &byte, 1, MSG_DONTWAIT);
        if (result != -1 || errno != EAGAIN) _exit(97);
        break;
    }
    case 13: result = write(unix_pair[0], data, n); break;
    case 25:
        if (n > sizeof(unix_ciphertext)) _exit(107);
        memcpy(unix_ciphertext, data, n);
        {
            int32_t entered[4] = {25, unix_pair[0], 0, unix_filler};
            exact(4, entered, sizeof(entered), 1);
        }
        result = syscall(SYS_sendmsg, unix_pair[0], &message, 0);
        if (result != n) _exit(108);
        break;
    case 14: /* The replacement is after SSL entry, before any acquisition. */
        if (dup2(replacement, fd) != fd) _exit(98);
        result = write(fd, data, n);
        break;
    case 15: /* A determinate file operation beside a confirmed socket. */
        if (write(ordinary, data, n) != n) _exit(99);
        result = write(fd, data, n);
        break;
    case 17: {
        int32_t entered[4] = {17, fd, actor_tid, initial_cpu};
        exact(4, entered, sizeof(entered), 1);
        char byte;
        result = read(fd, &byte, 1);
        if (result != 1 || byte != 'A') _exit(103);
        resumed_cpu = sched_getcpu();
        break;
    }
    case 19: {
        struct iovec parts[2] = {{(void *)data, 1}, {(void *)(data + 1), n - 1}};
        struct mmsghdr batch[2] = {0};
        for (int i = 0; i < 2; ++i) { batch[i].msg_hdr.msg_iov = &parts[i]; batch[i].msg_hdr.msg_iovlen = 1; }
        result = syscall(SYS_sendmmsg, fd, batch, 2, 0);
        if (result != 2) _exit(104);
        wire += batch[0].msg_len + batch[1].msg_len;
        return n; /* result is messages; wire is bytes. */
    }
    case 20: case 21: case 22: case 23: {
        char received[2] = {0};
        struct iovec part = {received, 1};
        struct msghdr msg = {.msg_iov = &part, .msg_iovlen = 1};
        if (mode == 20) result = syscall(SYS_read, fd, received, 1);
        if (mode == 21) result = syscall(SYS_readv, fd, &part, 1);
        if (mode == 22) result = syscall(SYS_recvmsg, fd, &msg, 0);
        if (mode == 23) {
            struct mmsghdr batch = {.msg_hdr = msg};
            result = syscall(SYS_recvmmsg, fd, &batch, 1, 0, NULL);
            if (result != 1 || batch.msg_len != 1) _exit(105);
        }
        if (result != 1 || received[0] != 'R') _exit(106);
        break;
    }
    default: _exit(100);
    }
    if (result > 0) wire += result;
    return n;
}

struct concurrent_call {
    SSL *ssl;
    int socket, slot, wire;
};
static int concurrent_transport(BIO *bio, const char *data, int n) {
    struct concurrent_call *call = BIO_get_data(bio);
    int32_t entered[4] = {27, call->socket, syscall(SYS_gettid), call->slot};
    exact(4, entered, sizeof(entered), 1);
    /* Both threads block in acquired TCP reads before either peer releases
     * one. The test witnesses their kernel stacks, not these announcements. */
    char token;
    if (syscall(SYS_read, call->socket, &token, 1) != 1 || token != 'A' + call->slot) _exit(109);
    call->wire = syscall(SYS_write, call->socket, data, n);
    if (call->wire != n) _exit(110);
    return n;
}
static void *concurrent_write(void *argument) {
    struct concurrent_call *call = argument;
    const char *plaintext = call->slot ? "connection-b-distinct-message" : "connection-a";
    int n = strlen(plaintext);
    if (SSL_write(call->ssl, plaintext, n) != n) _exit(111);
    return NULL;
}
static SSL *concurrent_client(SSL_CTX *client_context, SSL_CTX *server_context) {
    SSL *client = SSL_new(client_context), *server = SSL_new(server_context);
    BIO *a, *b;
    if (!client || !server || BIO_new_bio_pair(&a, 0, &b, 0) != 1) _exit(112);
    SSL_set_bio(client, a, a); SSL_set_bio(server, b, b);
    SSL_set_connect_state(client); SSL_set_accept_state(server);
    for (int i = 0; i < 100 && (!SSL_is_init_finished(client) || !SSL_is_init_finished(server)); ++i) {
        SSL_do_handshake(client); SSL_do_handshake(server);
    }
    if (!SSL_is_init_finished(client) || !SSL_is_init_finished(server)) _exit(113);
    SSL_free(server);
    return client;
}
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
    SSL_CTX *server_context = SSL_CTX_new(TLS_server_method());
    if (!client_context || !server_context) return 2;
    SSL_CTX_set_max_proto_version(client_context, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(server_context, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(server_context, argv[1], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(server_context, argv[2], SSL_FILETYPE_PEM) != 1) return 3;
    SSL *client = SSL_new(client_context), *server = SSL_new(server_context);
    BIO *a, *b;
    if (!client || !server || BIO_new_bio_pair(&a, 0, &b, 0) != 1) return 4;
    SSL_set_bio(client, a, a); SSL_set_bio(server, b, b);
    SSL_set_connect_state(client); SSL_set_accept_state(server);
    for (int i = 0; i < 100 && (!SSL_is_init_finished(client) || !SSL_is_init_finished(server)); ++i) {
        SSL_do_handshake(client); SSL_do_handshake(server);
    }
    if (!SSL_is_init_finished(client) || !SSL_is_init_finished(server)) return 5;
    BIO_METHOD *method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "controlled socket evidence");
    BIO_meth_set_create(method, create); BIO_meth_set_write(method, transport);
    BIO_meth_set_ctrl(method, control);
    SSL_set0_wbio(client, BIO_new(method));
    struct concurrent_call concurrent[2] = {0};
    int32_t reply[4] = {0, 0, 0, 0};
    exact(4, reply, sizeof(reply), 1);
    for (;;) {
        int32_t request[3];
        exact(3, request, sizeof(request), 0);
        mode = request[0]; wire = 0; result = 0;
        int requested_mode = mode;
        if (mode == 1) {
            fd = connect_to(request[1]); replacement = connect_to(request[2]);
            ordinary = memfd_create("ordinary-evidence", 0);
            if (ordinary < 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, unix_pair)) return 6;
        } else if (mode == 16) {
            if (dup2(replacement, fd) != fd) return 7;
        } else if (mode == 26) {
            BIO_METHOD *parallel = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "concurrent socket evidence");
            BIO_meth_set_create(parallel, create); BIO_meth_set_write(parallel, concurrent_transport);
            BIO_meth_set_ctrl(parallel, control);
            for (int i = 0; i < 2; ++i) {
                concurrent[i].ssl = concurrent_client(client_context, server_context);
                concurrent[i].socket = i ? replacement : fd; concurrent[i].slot = i;
                BIO *bio = BIO_new(parallel);
                BIO_set_data(bio, &concurrent[i]); SSL_set0_wbio(concurrent[i].ssl, bio);
            }
        } else if (mode == 27) {
            pthread_t threads[2];
            for (int i = 0; i < 2; ++i)
                if (pthread_create(&threads[i], NULL, concurrent_write, &concurrent[i])) return 16;
            for (int i = 0; i < 2; ++i) pthread_join(threads[i], NULL);
            result = concurrent[0].wire; wire = concurrent[1].wire;
        } else {
            if (mode == 25) {
                /* Fill before TLS entry. The sendmsg must remain acquired until
                 * the independent reader witnesses its syscall number and fd. */
                int size = 4096;
                if (setsockopt(unix_pair[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))) return 17;
                char filler[1024] = {0};
                unix_filler = 0;
                for (;;) {
                    int count = send(unix_pair[0], filler, sizeof(filler), MSG_DONTWAIT);
                    if (count < 0) {
                        if (errno != EAGAIN) return 18;
                        break;
                    }
                    if (count == 0) return 19;
                    unix_filler += count;
                }
                if (!unix_filler || pthread_create(&unix_drain, NULL, drain_unix_after_witness, NULL)) return 20;
            }
            if (mode == 24) {
                /* The raw operation completes before SSL_write enters. */
                if (write(replacement, "X", 1) != 1) return 14;
                mode = 2;
            }
            if (mode == 17) {
                cpu_set_t allowed, first;
                if (sched_getaffinity(0, sizeof(allowed), &allowed)) return 9;
                initial_cpu = next_cpu = -1;
                for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) if (CPU_ISSET(cpu, &allowed)) {
                    if (initial_cpu < 0) initial_cpu = cpu;
                    else { next_cpu = cpu; break; }
                }
                if (next_cpu < 0) return 10;
                actor_tid = syscall(SYS_gettid);
                CPU_ZERO(&first); CPU_SET(initial_cpu, &first);
                if (sched_setaffinity(0, sizeof(first), &first)) return 11;
                if (pthread_create(&replacer, NULL, replace_while_acquired, NULL)) return 12;
            }
            const char plaintext[] = "independent-socket-evidence";
            if (SSL_write(client, plaintext, sizeof(plaintext) - 1) != sizeof(plaintext) - 1) return 8;
            if (mode == 25) {
                /* Drain OUTSIDE SSL_write: an in-call scalar read would mask
                 * missing evidence for the messaging operation being tested. */
                char received[sizeof(unix_ciphertext)];
                pthread_join(unix_drain, NULL);
                exact(unix_pair[1], received, wire, 0);
                if (memcmp(received, unix_ciphertext, wire)) return 15;
            }
            if (mode == 17) {
                pthread_join(replacer, NULL);
                if (resumed_cpu != next_cpu || resumed_cpu == initial_cpu) return 13;
            }
        }
        reply[0] = requested_mode; reply[1] = fd; reply[2] = result; reply[3] = wire;
        if (requested_mode == 25) reply[1] = unix_pair[0];
        exact(4, reply, sizeof(reply), 1);
    }
}
