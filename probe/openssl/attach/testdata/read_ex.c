// A TLS client that reads with the out-parameter API when told to. One command
// per line on standard input:
//
//   G <path>  send a GET for path with SSL_write and read the whole answer with
//             SSL_read, by its stated length; prints "done <status>"
//   W         one SSL_read_ex while the socket is non-blocking and nothing is
//             pending, which fails with the count unwritten; prints
//             "would-block <return> <error>"
//
// It prints "ready" once connected, and shuts the connection down at the end
// of its input.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

static char answer[1 << 16];

// exchange returns the answer's status, or -1 where it could not be read whole.
static int exchange(SSL *ssl, const char *path) {
	char request[1024];
	int n = snprintf(request, sizeof request, "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", path);
	if (n <= 0 || n >= (int)sizeof request || SSL_write(ssl, request, n) != n)
		return -1;
	int used = 0, header = -1;
	long length = -1;
	for (;;) {
		if (header < 0) {
			char *end = memmem(answer, used, "\r\n\r\n", 4);
			if (end) {
				header = (int)(end - answer) + 4;
				for (char *line = answer; line < end; line = strstr(line, "\r\n") + 2) {
					if (strncasecmp(line, "content-length:", 15) == 0)
						length = strtol(line + 15, NULL, 10);
				}
				if (length < 0)
					return -1;
			}
		}
		if (header >= 0 && used >= header + length)
			break;
		if (used == (int)sizeof answer)
			return -1;
		int got = SSL_read(ssl, answer + used, (int)sizeof answer - used);
		if (got <= 0)
			return -1;
		used += got;
	}
	return atoi(answer + 9);
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		return 2;
	}
	SSL_CTX *context = SSL_CTX_new(TLS_client_method());
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in to;
	memset(&to, 0, sizeof to);
	to.sin_family = AF_INET;
	to.sin_port = htons((unsigned short)atoi(argv[1]));
	inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
	if (!context || fd < 0 || connect(fd, (struct sockaddr *)&to, sizeof to) != 0) {
		perror("connect");
		return 1;
	}
	SSL *ssl = SSL_new(context);
	SSL_set_fd(ssl, fd);
	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		return 1;
	}
	printf("ready\n");
	fflush(stdout);

	char line[1024];
	while (fgets(line, sizeof line, stdin)) {
		line[strcspn(line, "\n")] = 0;
		if (line[0] == 'G' && line[1] == ' ') {
			printf("done %d\n", exchange(ssl, line + 2));
		} else if (strcmp(line, "W") == 0) {
			int flags = fcntl(fd, F_GETFL);
			fcntl(fd, F_SETFL, flags | O_NONBLOCK);
			char buffer[256];
			size_t got = 0;
			int result = SSL_read_ex(ssl, buffer, sizeof buffer, &got);
			int error = SSL_get_error(ssl, result);
			fcntl(fd, F_SETFL, flags);
			printf("would-block %d %d\n", result, error);
		} else {
			printf("unknown %s\n", line);
		}
		fflush(stdout);
	}
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(fd);
	SSL_CTX_free(context);
	return 0;
}
