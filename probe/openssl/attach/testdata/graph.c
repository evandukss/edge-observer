// graph is one process of a constructed process graph: a TLS client that makes
// its exchanges through SSL_write and SSL_read, which the observer's catalogue
// probes.
//
//	graph PORT ROLE WITNESS            told: reads commands on standard input
//	graph PORT ROLE WITNESS loop       exchanges every fifth of a second
//	graph PORT ROLE WITNESS flood      exchanges without pausing
//
// Told mode answers "exchange" with one exchange of its own and "done";
// "fork NAME" with a child that exchanges on a loop as NAME, and its pid; and
// "spawn NAME" with a child started by exec of this program in loop mode, so
// its argument list is its own. A looping process stops once WITNESS holds a
// file named stop. Every exchange answered with a 200 is recorded by the
// process that made it, in WITNESS/ROLE-PID: evidence the observer had no part
// in.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int port;
static const char *witness;

static int connected(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	struct sockaddr_in to;
	memset(&to, 0, sizeof to);
	to.sin_family = AF_INET;
	to.sin_port = htons((unsigned short)port);
	to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void witnessed(const char *role) {
	char path[4096];
	snprintf(path, sizeof path, "%s/%s-%d", witness, role, (int)getpid());
	FILE *record = fopen(path, "a");
	if (record != NULL) {
		fputs("200\n", record);
		fclose(record);
	}
}

// exchange makes one TLS exchange and records it where it was answered with a
// 200, over HTTP/1.0 or HTTP/1.1. It returns 0 on a recorded exchange.
static int exchange(SSL_CTX *context, const char *role) {
	int fd = connected();
	if (fd < 0) {
		return -1;
	}
	SSL *tls = SSL_new(context);
	SSL_set_fd(tls, fd);
	int result = -1;
	if (SSL_connect(tls) == 1) {
		char request[256];
		int length = snprintf(request, sizeof request,
			"GET /?role=%s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", role);
		if (SSL_write(tls, request, length) == length) {
			char first[32];
			char chunk[4096];
			int total = 0;
			int n;
			memset(first, 0, sizeof first);
			while ((n = SSL_read(tls, chunk, (int)sizeof chunk)) > 0) {
				if (total < (int)sizeof first - 1) {
					int room = (int)sizeof first - 1 - total;
					memcpy(first + total, chunk, (size_t)(n < room ? n : room));
				}
				total += n;
			}
			if (strncmp(first, "HTTP/1.", 7) == 0 && strstr(first, " 200") != NULL) {
				result = 0;
			}
		}
		SSL_shutdown(tls);
	}
	SSL_free(tls);
	close(fd);
	if (result == 0) {
		witnessed(role);
	}
	return result;
}

// stopped is the stop file, or the witness directory gone: a test that has
// ended removes its directory, stop file and all, and a process that went on
// looping after that would hold the test's output open with nothing left to
// stop it.
static int stopped(void) {
	char path[4096];
	snprintf(path, sizeof path, "%s/stop", witness);
	return access(path, F_OK) == 0 || access(witness, F_OK) != 0;
}

// orphaned makes this process end when the one that forked it does, so a graph
// is never outlived by its children whatever order a test's clean-ups run in.
static void orphaned(void) {
	prctl(PR_SET_PDEATHSIG, SIGKILL);
}

static void looping(SSL_CTX *context, const char *role, int pause) {
	while (!stopped()) {
		if (exchange(context, role) != 0) {
			usleep(50000);
		}
		if (pause) {
			usleep(200000);
		}
	}
}

int main(int argc, char **argv) {
	if (argc < 4) {
		fprintf(stderr, "usage: graph PORT ROLE WITNESS [loop|flood]\n");
		return 2;
	}
	port = atoi(argv[1]);
	const char *role = argv[2];
	witness = argv[3];
	const char *mode = argc > 4 ? argv[4] : "told";
	signal(SIGPIPE, SIG_IGN);

	SSL_CTX *context = SSL_CTX_new(TLS_client_method());
	if (context == NULL) {
		fprintf(stderr, "no TLS context\n");
		return 1;
	}
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);

	if (strcmp(mode, "loop") == 0 || strcmp(mode, "flood") == 0) {
		looping(context, role, strcmp(mode, "loop") == 0);
		return 0;
	}

	printf("ready %d\n", (int)getpid());
	fflush(stdout);
	char line[256];
	while (fgets(line, sizeof line, stdin) != NULL) {
		char word[32];
		char name[64];
		memset(word, 0, sizeof word);
		memset(name, 0, sizeof name);
		if (sscanf(line, "%31s %63s", word, name) < 1) {
			continue;
		}
		if (strcmp(word, "exchange") == 0) {
			exchange(context, role);
			printf("done\n");
		} else if (strcmp(word, "fork") == 0) {
			pid_t child = fork();
			if (child == 0) {
				orphaned();
				looping(context, name, 1);
				_exit(0);
			}
			printf("%s %d\n", name, (int)child);
		} else if (strcmp(word, "spawn") == 0) {
			pid_t child = fork();
			if (child == 0) {
				// Kept across the exec, which is of this same program.
				orphaned();
				char text[16];
				snprintf(text, sizeof text, "%d", port);
				execl("/proc/self/exe", argv[0], text, name, witness, "loop", (char *)NULL);
				_exit(127);
			}
			printf("%s %d\n", name, (int)child);
		}
		fflush(stdout);
	}
	return 0;
}
