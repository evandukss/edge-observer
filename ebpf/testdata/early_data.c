// A TLS 1.3 client and server in one process that exchange 0-RTT early data, so
// SSL_write_early_data and SSL_read_early_data are called on a real connection:
// ordinary clients never send early data, so this is what proves the
// early-data path reports a real byte count. Round one is a full handshake
// leaving the client a resumable session; the program then announces readiness
// and waits, so the observer attaches before round two resumes the session and
// sends the planted bytes as early data.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>

static const char *EARLY = "PLANTED-EARLY-DATA-MARKER";
static int PORT;
static char *CERT, *KEY;

// server accepts two connections. The first completes a handshake and issues a
// ticket; the second reads early data.
static void *server(void *ignored) {
	(void)ignored;
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_use_certificate_file(ctx, CERT, SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM);
	SSL_CTX_set_max_early_data(ctx, 16384);
	SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
	unsigned char context[] = "early";
	SSL_CTX_set_session_id_context(ctx, context, sizeof(context));

	int listener = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in address;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(PORT);
	inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
	bind(listener, (struct sockaddr *)&address, sizeof(address));
	listen(listener, 2);

	for (int round = 0; round < 2; round++) {
		int fd = accept(listener, NULL, NULL);
		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, fd);

		if (round == 1) {
			// Read the early data before completing the handshake. This is the
			// call the observer's early-data probe is placed on.
			char buffer[512];
			size_t got = 0;
			int status = SSL_read_early_data(ssl, buffer, sizeof(buffer), &got);
			(void)status;
		}
		SSL_accept(ssl);
		// Read the request so the client's write does not block, then send a
		// short reply.
		char request[512];
		SSL_read(ssl, request, sizeof(request));
		const char *reply = "ok";
		SSL_write(ssl, reply, 2);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(fd);
	}
	SSL_CTX_free(ctx);
	return NULL;
}

static int dial(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in address;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(PORT);
	inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
	while (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
		usleep(10000);
	}
	return fd;
}

int main(int argc, char **argv) {
	PORT = atoi(argv[1]);
	CERT = argv[2];
	KEY = argv[3];

	pthread_t thread;
	pthread_create(&thread, NULL, server, NULL);

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);

	// Round one: a full handshake that leaves us holding a session the server
	// will accept early data on. The ticket arrives after the handshake, so we
	// read once to let it be processed.
	int fd1 = dial();
	SSL *first = SSL_new(ctx);
	SSL_set_fd(first, fd1);
	SSL_connect(first);
	const char *request = "GET / HTTP/1.0\r\n\r\n";
	SSL_write(first, request, (int)strlen(request));
	char reply[64];
	SSL_read(first, reply, sizeof(reply));
	SSL_SESSION *session = SSL_get1_session(first);

	printf("ready\n");
	fflush(stdout);
	char go[4];
	if (fgets(go, sizeof(go), stdin) == NULL) {
		return 1;
	}

	// Round two: resume the session and send the planted bytes as early data.
	int fd2 = dial();
	SSL *second = SSL_new(ctx);
	SSL_set_fd(second, fd2);
	SSL_set_session(second, session);
	size_t written = 0;
	int ok = SSL_write_early_data(second, EARLY, strlen(EARLY), &written);
	SSL_connect(second);
	SSL_write(second, request, (int)strlen(request));
	SSL_read(second, reply, sizeof(reply));
	printf("early %d wrote %zu\n", ok, written);
	fflush(stdout);

	SSL_shutdown(second);
	SSL_free(second);
	SSL_free(first);
	SSL_SESSION_free(session);
	SSL_CTX_free(ctx);
	close(fd1);
	close(fd2);
	pthread_join(thread, NULL);
	return 0;
}
