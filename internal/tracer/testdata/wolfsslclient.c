/*
 * Minimal wolfSSL TLS client for the integration tests:
 *   wolfsslclient <port> <path>
 * sends a GET for <path> to 127.0.0.1:<port>, accepting any certificate.
 */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: wolfsslclient <port> <path>\n");
		return 2;
	}
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[1]))};
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("connect");
		return 1;
	}

	wolfSSL_Init();
	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
	wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
	WOLFSSL *ssl = wolfSSL_new(ctx);
	wolfSSL_set_fd(ssl, fd);
	if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
		fprintf(stderr, "handshake: error %d\n", wolfSSL_get_error(ssl, 0));
		return 1;
	}

	char req[512];
	int len = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: localhost\r\n\r\n", argv[2]);
	if (wolfSSL_write(ssl, req, len) != len) {
		fprintf(stderr, "write: error %d\n", wolfSSL_get_error(ssl, 0));
		return 1;
	}
	char buf[4096];
	int n;
	while ((n = wolfSSL_read(ssl, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);

	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
	close(fd);
	return 0;
}
