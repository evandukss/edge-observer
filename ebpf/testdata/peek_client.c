// A TLS client that reads the same bytes twice: once with SSL_peek and once
// with SSL_read, on a real connection. SSL_peek is not probed, so the observer
// should capture the response exactly once.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>

int main(int argc, char **argv) {
	int port = atoi(argv[1]);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in address;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
		fprintf(stderr, "connect failed\n");
		return 1;
	}

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	if (SSL_connect(ssl) != 1) {
		fprintf(stderr, "handshake failed\n");
		return 1;
	}

	// libssl is mapped and a connection is open. Announce readiness and wait for
	// the observer to attach before moving any plaintext.
	printf("ready\n");
	fflush(stdout);
	char go[4];
	if (fgets(go, sizeof(go), stdin) == NULL) {
		return 1;
	}

	const char *request = "GET /peek HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
	SSL_write(ssl, request, (int)strlen(request));

	char buffer[4096];
	int peeked = SSL_peek(ssl, buffer, sizeof(buffer));
	int read = SSL_read(ssl, buffer, sizeof(buffer));
	printf("peeked %d read %d\n", peeked, read);
	fflush(stdout);

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(fd);
	return 0;
}
