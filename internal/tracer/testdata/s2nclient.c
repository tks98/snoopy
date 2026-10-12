/*
 * Minimal s2n-tls client for the integration tests:
 *   s2nclient <port> <path>
 * sends a GET for <path> to 127.0.0.1:<port>, accepting any certificate.
 */
#include <s2n.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, s2n_strerror(s2n_errno, "EN"));
	return 1;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: s2nclient <port> <path>\n");
		return 2;
	}
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[1]))};
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("connect");
		return 1;
	}

	if (s2n_init() < 0)
		return fail("init");
	struct s2n_config *config = s2n_config_new();
	if (s2n_config_set_cipher_preferences(config, "default_tls13") < 0 ||
	    s2n_config_disable_x509_verification(config) < 0)
		return fail("config");
	struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
	if (s2n_connection_set_config(conn, config) < 0 || s2n_connection_set_fd(conn, fd) < 0 ||
	    s2n_set_server_name(conn, "localhost") < 0)
		return fail("connection");
	s2n_blocked_status blocked;
	if (s2n_negotiate(conn, &blocked) < 0)
		return fail("handshake");

	char req[512];
	ssize_t len = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: localhost\r\n\r\n", argv[2]);
	for (ssize_t off = 0; off < len;) {
		ssize_t n = s2n_send(conn, req + off, len - off, &blocked);
		if (n < 0)
			return fail("send");
		off += n;
	}
	char buf[4096];
	ssize_t n;
	while ((n = s2n_recv(conn, buf, sizeof(buf), &blocked)) > 0)
		fwrite(buf, 1, n, stdout);

	s2n_connection_free(conn);
	s2n_config_free(config);
	s2n_cleanup();
	close(fd);
	return 0;
}
