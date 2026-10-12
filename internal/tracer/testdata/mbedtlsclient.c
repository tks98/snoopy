/*
 * Minimal Mbed TLS client for the integration tests:
 *   mbedtlsclient <port> <path>
 * sends a GET for <path> to 127.0.0.1:<port>, accepting any certificate.
 * Builds against Mbed TLS 2.28 and 3.x.
 */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_MAJOR >= 3
#include <psa/crypto.h>
#endif
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: mbedtlsclient <port> <path>\n");
		return 2;
	}
#if MBEDTLS_VERSION_MAJOR >= 3
	psa_crypto_init(); // needed for TLS 1.3
#endif
	mbedtls_net_context net;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	mbedtls_net_init(&net);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&drbg);

	int ret;
	if ((ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0 ||
	    (ret = mbedtls_net_connect(&net, "127.0.0.1", argv[1], MBEDTLS_NET_PROTO_TCP)) != 0 ||
	    (ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
					       MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		fprintf(stderr, "setup: error -0x%x\n", -ret);
		return 1;
	}
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		fprintf(stderr, "ssl setup: error -0x%x\n", -ret);
		return 1;
	}
	mbedtls_ssl_set_hostname(&ssl, "localhost");
	mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			fprintf(stderr, "handshake: error -0x%x\n", -ret);
			return 1;
		}
	}

	unsigned char req[512];
	size_t len = snprintf((char *)req, sizeof(req), "GET %s HTTP/1.0\r\nHost: localhost\r\n\r\n", argv[2]);
	for (size_t off = 0; off < len; off += ret) {
		ret = mbedtls_ssl_write(&ssl, req + off, len - off);
		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			ret = 0;
			continue;
		}
		if (ret < 0) {
			fprintf(stderr, "write: error -0x%x\n", -ret);
			return 1;
		}
	}
	unsigned char buf[4096];
	for (;;) {
		ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		if (ret <= 0)
			break; // 0 or MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY at the end
		fwrite(buf, 1, ret, stdout);
	}

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&net);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&drbg);
	mbedtls_entropy_free(&entropy);
	return 0;
}
