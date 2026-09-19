// forking_server answers HTTPS on a port, forking a worker per connection that
// does the handshake and everything after it through SSL_read and SSL_write,
// which the observer's catalogue probes. Every worker keeps the listening
// descriptor it inherited, so the port is held by the parent and by every worker
// alive - the shape a port target resolves.
//
//	forking_server PORT CERTIFICATE KEY          a worker per connection
//	forking_server PORT CERTIFICATE KEY single   every connection in this process
//
// A worker answers each request on its connection with a 200 and keeps the
// connection until the client closes it, or until a request asks for it to be
// closed. In single mode the process holding the
// listener is the one doing the TLS, one connection after another.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void serve(SSL_CTX *context, int fd) {
	SSL *tls = SSL_new(context);
	SSL_set_fd(tls, fd);
	if (SSL_accept(tls) == 1) {
		char request[8192];
		int held = 0;
		int closing = 0;
		while (!closing) {
			int n = SSL_read(tls, request + held, (int)sizeof request - 1 - held);
			if (n <= 0) {
				break;
			}
			held += n;
			request[held] = 0;
			char *end;
			while (!closing && (end = strstr(request, "\r\n\r\n")) != NULL) {
				// A request asking for the connection to close is answered and
				// then closed: a client reading to the end of the answer is
				// waiting for exactly that.
				*end = 0;
				closing = strstr(request, "Connection: close") != NULL;
				const char *body = "served\n";
				char answer[256];
				int length = snprintf(answer, sizeof answer,
					"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
					strlen(body), body);
				if (SSL_write(tls, answer, length) != length) {
					break;
				}
				int consumed = (int)(end + 4 - request);
				memmove(request, end + 4, (size_t)(held - consumed + 1));
				held -= consumed;
			}
			if (held >= (int)sizeof request - 1) {
				held = 0;
			}
		}
		SSL_shutdown(tls);
	}
	SSL_free(tls);
	close(fd);
}

int main(int argc, char **argv) {
	if (argc != 4 && !(argc == 5 && strcmp(argv[4], "single") == 0)) {
		fprintf(stderr, "usage: forking_server PORT CERTIFICATE KEY [single]\n");
		return 2;
	}
	int single = argc == 5;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	SSL_CTX *context = SSL_CTX_new(TLS_server_method());
	if (context == NULL || SSL_CTX_use_certificate_file(context, argv[2], SSL_FILETYPE_PEM) != 1 ||
		SSL_CTX_use_PrivateKey_file(context, argv[3], SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "cannot load the certificate and key\n");
		return 1;
	}

	int listener = socket(AF_INET, SOCK_STREAM, 0);
	int on = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
	struct sockaddr_in at;
	memset(&at, 0, sizeof at);
	at.sin_family = AF_INET;
	at.sin_port = htons((unsigned short)atoi(argv[1]));
	at.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listener, (struct sockaddr *)&at, sizeof at) != 0 || listen(listener, 16) != 0) {
		fprintf(stderr, "cannot listen on %s\n", argv[1]);
		return 1;
	}
	printf("ready\n");
	fflush(stdout);

	for (;;) {
		int fd = accept(listener, NULL, NULL);
		if (fd < 0) {
			if (errno == EINTR) {
				continue;
			}
			return 1;
		}
		if (single) {
			serve(context, fd);
			continue;
		}
		pid_t worker = fork();
		if (worker != 0) {
			close(fd);
			continue;
		}
		serve(context, fd);
		_exit(0);
	}
}
