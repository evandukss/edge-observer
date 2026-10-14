#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* One command creates one process. No allocation search or retry can turn an
 * absent reuse into a passing case. The caller owns the private pid namespace. */
static pid_t child;

/* Where a continued child sends one TLS write before it exits; zero for none. */
static int port;

static void fail(const char *operation)
{
	perror(operation);
	exit(1);
}

/* One connection and one write, so the child's own admission delivers an event
 * and its exit is reported as an execution end. */
static int transfer(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port)};
	to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (fd < 0 || connect(fd, (struct sockaddr *)&to, sizeof(to)))
		return 10;
	SSL_CTX *context = SSL_CTX_new(TLS_client_method());
	if (!context)
		return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
	SSL *ssl = SSL_new(context);
	if (!ssl || SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) != 1)
		return 12;
	if (SSL_write(ssl, "identity\n", 9) != 9)
		return 13;
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(context);
	close(fd);
	return 0;
}

static void start(void)
{
	child = fork();
	if (child < 0)
		fail("fork");
	if (child == 0) {
		if (prctl(PR_SET_PDEATHSIG, SIGKILL))
			_exit(2);
		raise(SIGSTOP);
		_exit(port ? transfer() : 0);
	}
	int status;
	if (waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status))
		fail("wait stopped child");
	printf("child %d\n", child);
}

/* procfs birth identity is in clock ticks. Separate births by two ticks once,
 * rather than retrying until distinct evidence appears. */
static void separate(void)
{
	long ticks = sysconf(_SC_CLK_TCK);
	if (ticks <= 0)
		exit(7);
	struct timespec separation = {.tv_sec = 2 / ticks,
		.tv_nsec = (2 % ticks) * 1000000000L / ticks};
	if (nanosleep(&separation, NULL))
		fail("separate birth ticks");
}

/* The next process this namespace creates takes number, if it is free. */
static void start_at(pid_t number)
{
	int fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
	if (fd < 0)
		fail("open ns_last_pid");
	char value[32];
	int n = snprintf(value, sizeof(value), "%d", number - 1);
	if (write(fd, value, n) != n || close(fd))
		fail("set ns_last_pid");
	start();
}

static void finish(void)
{
	if (child <= 0 || kill(child, SIGCONT))
		fail("continue child");
	int status;
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		fail("reap child");
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	SSL_CTX *context = SSL_CTX_new(TLS_method());
	if (!context)
		return 3;
	printf("supervisor %d\n", getpid());
	char command[32];
	while (fgets(command, sizeof(command), stdin)) {
		switch (command[0]) {
		case 'p':
			if (child || sscanf(command + 1, "%d", &port) != 1 || port <= 0)
				return 8;
			puts("port");
			break;
		case 'b':
			if (child)
				return 4;
			start();
			break;
		case 'r': {
			pid_t previous = child;
			separate();
			finish();
			start_at(previous);
			break;
		}
		case 'n': {
			/* Another supervisor's former number: this supervisor is not followed,
			 * so no fork hook writes an entry for the child it creates there. */
			int number;
			if (child || sscanf(command + 1, "%d", &number) != 1 || number <= 1)
				return 9;
			separate();
			start_at(number);
			break;
		}
		case 'x':
			finish();
			child = 0;
			puts("gone");
			break;
		case 'q':
			if (child)
				finish();
			SSL_CTX_free(context);
			return 0;
		default:
			return 5;
		}
	}
	if (child)
		finish();
	SSL_CTX_free(context);
	return ferror(stdin) ? 6 : 0;
}
