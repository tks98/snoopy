/*
 * Minimal NSS TLS client for the integration tests:
 *   nssclient <port> <path>
 * sends a GET for <path> to 127.0.0.1:<port>, accepting any certificate.
 */
#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <stdio.h>
#include <stdlib.h>

static SECStatus accept_any(void *arg, PRFileDesc *fd, PRBool checksig, PRBool isserver)
{
	return SECSuccess;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: nssclient <port> <path>\n");
		return 2;
	}
	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
	if (NSS_NoDB_Init(NULL) != SECSuccess || NSS_SetDomesticPolicy() != SECSuccess) {
		fprintf(stderr, "NSS init failed\n");
		return 1;
	}

	PRFileDesc *fd = SSL_ImportFD(NULL, PR_NewTCPSocket());
	SSL_OptionSet(fd, SSL_SECURITY, PR_TRUE);
	SSL_OptionSet(fd, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
	SSL_AuthCertificateHook(fd, accept_any, NULL);
	SSL_SetURL(fd, "localhost");

	PRNetAddr addr;
	PR_InitializeNetAddr(PR_IpAddrLoopback, (PRUint16)atoi(argv[1]), &addr);
	if (PR_Connect(fd, &addr, PR_INTERVAL_NO_TIMEOUT) != PR_SUCCESS) {
		fprintf(stderr, "connect: error %d\n", PR_GetError());
		return 1;
	}

	char req[512];
	int n = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: localhost\r\n\r\n", argv[2]);
	if (PR_Write(fd, req, n) != n) {
		fprintf(stderr, "write: error %d\n", PR_GetError());
		return 1;
	}
	char buf[4096];
	while (PR_Read(fd, buf, sizeof(buf)) > 0)
		;
	PR_Close(fd);
	NSS_Shutdown();
	return 0;
}
