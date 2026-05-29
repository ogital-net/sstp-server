// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * test_sstp.c — userspace lifecycle test for the sstp kmod.
 *
 * Exercises /dev/sstp + SSTP_IOC_{ATTACH,DETACH,GETSTATS} +
 * session_fd poll/read/close. Covers:
 *   1. /dev/sstp open + version sanity (negative ATTACH).
 *   2. ATTACH error paths: bad ABI, reserved nonzero, bad fd,
 *      non-socket fd, plain TCP fd without kTLS.
 *   3. Happy path: loopback TCP + OpenSSL TLS 1.3 with
 *      SSL_OP_ENABLE_KTLS so the kernel sees a kTLS-equipped
 *      socket; ATTACH succeeds; GETSTATS; poll(); DETACH; close.
 *
 * Must run as root (CAP_NET_ADMIN). Returns 0 on success, 1 on
 * failure. Verbose pass/fail per check.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/tls.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Pull the UAPI from the in-tree copy so the test tracks the
 * kmod's view of the ABI exactly. */
#include "../../kernel-abi/sstp.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                          \
	if (cond) {                                                              \
		fprintf(stdout, "  PASS  " fmt "\n", ##__VA_ARGS__);                 \
		g_pass++;                                                            \
	} else {                                                                 \
		fprintf(stdout, "  FAIL  " fmt " (errno=%d %s)\n",                   \
			##__VA_ARGS__, errno, strerror(errno));                          \
		g_fail++;                                                            \
	}                                                                        \
} while (0)

#define SECTION(name) \
	fprintf(stdout, "\n[%s]\n", name)

static void ossl_die(const char *what)
{
	fprintf(stderr, "openssl: %s\n", what);
	ERR_print_errors_fp(stderr);
	exit(2);
}

/* ------------------------------------------------------------------
 * Ephemeral self-signed RSA cert for the loopback TLS server side.
 * ------------------------------------------------------------------ */
static void gen_self_signed(EVP_PKEY **out_key, X509 **out_cert)
{
	EVP_PKEY *pkey = EVP_RSA_gen(2048);
	if (!pkey)
		ossl_die("EVP_RSA_gen");

	X509 *x = X509_new();
	if (!x)
		ossl_die("X509_new");

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), 60 * 60);
	X509_set_pubkey(x, pkey);

	X509_NAME *name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (const unsigned char *)"sstp-test", -1, -1, 0);
	X509_set_issuer_name(x, name);

	if (!X509_sign(x, pkey, EVP_sha256()))
		ossl_die("X509_sign");

	*out_key = pkey;
	*out_cert = x;
}

/* ------------------------------------------------------------------
 * Loopback TCP pair: returns (server_fd, client_fd) both connected.
 * ------------------------------------------------------------------ */
static int tcp_loopback_pair(int *srv_fd, int *cli_fd)
{
	int lst = socket(AF_INET, SOCK_STREAM, 0);
	if (lst < 0)
		return -1;

	int yes = 1;
	setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	if (bind(lst, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(lst);
		return -1;
	}
	if (listen(lst, 1) < 0) {
		close(lst);
		return -1;
	}
	socklen_t sl = sizeof(sa);
	if (getsockname(lst, (struct sockaddr *)&sa, &sl) < 0) {
		close(lst);
		return -1;
	}

	int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (c < 0) {
		close(lst);
		return -1;
	}
	int rc = connect(c, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0 && errno != EINPROGRESS) {
		close(lst);
		close(c);
		return -1;
	}

	int s = accept(lst, NULL, NULL);
	close(lst);
	if (s < 0) {
		close(c);
		return -1;
	}

	/* Reset client to blocking for the OpenSSL handshake. */
	int fl = fcntl(c, F_GETFL, 0);
	fcntl(c, F_SETFL, fl & ~O_NONBLOCK);

	/* TCP_NODELAY keeps the handshake responsive. */
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

	*srv_fd = s;
	*cli_fd = c;
	return 0;
}

/* ------------------------------------------------------------------
 * Drive the TLS handshake to completion on both ends concurrently.
 *
 * SSL_OP_ENABLE_KTLS makes OpenSSL 3.x install kTLS via
 * setsockopt(SOL_TLS, TLS_{RX,TX}, ...) after the handshake. The
 * kernel's tls ULP must be available (modprobe tls).
 * ------------------------------------------------------------------ */
struct hs_arg {
	SSL *ssl;
	int  ret;
};

static void *hs_thread(void *p)
{
	struct hs_arg *a = p;
	int rc = SSL_do_handshake(a->ssl);
	if (rc != 1)
		a->ret = SSL_get_error(a->ssl, rc);
	else
		a->ret = 0;
	return NULL;
}

static int do_tls_handshake(int srv_fd, int cli_fd,
			    SSL **out_srv_ssl, SSL **out_cli_ssl,
			    SSL_CTX **out_srv_ctx, SSL_CTX **out_cli_ctx)
{
	EVP_PKEY *key = NULL;
	X509 *cert = NULL;
	gen_self_signed(&key, &cert);

	SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
	if (!sctx || !cctx)
		ossl_die("SSL_CTX_new");

	/* TLS 1.2 + AES-GCM is the most reliable kTLS path in OpenSSL
	 * 3.x — both RX and TX are installed at handshake completion,
	 * with no NewSessionTicket / KeyUpdate caveats to dance around. */
	SSL_CTX_set_min_proto_version(sctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(sctx, TLS1_2_VERSION);
	SSL_CTX_set_min_proto_version(cctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
	SSL_CTX_set_cipher_list(sctx, "ECDHE-RSA-AES128-GCM-SHA256");
	SSL_CTX_set_cipher_list(cctx, "ECDHE-RSA-AES128-GCM-SHA256");

	SSL_CTX_set_options(sctx, SSL_OP_ENABLE_KTLS);
	SSL_CTX_set_options(cctx, SSL_OP_ENABLE_KTLS);

	if (SSL_CTX_use_certificate(sctx, cert) != 1)
		ossl_die("SSL_CTX_use_certificate");
	if (SSL_CTX_use_PrivateKey(sctx, key) != 1)
		ossl_die("SSL_CTX_use_PrivateKey");

	SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

	SSL *s_ssl = SSL_new(sctx);
	SSL *c_ssl = SSL_new(cctx);
	if (!s_ssl || !c_ssl)
		ossl_die("SSL_new");
	SSL_set_fd(s_ssl, srv_fd);
	SSL_set_fd(c_ssl, cli_fd);
	SSL_set_accept_state(s_ssl);
	SSL_set_connect_state(c_ssl);

	struct hs_arg sa = { .ssl = s_ssl }, ca = { .ssl = c_ssl };
	pthread_t tc, ts;
	pthread_create(&ts, NULL, hs_thread, &sa);
	pthread_create(&tc, NULL, hs_thread, &ca);
	pthread_join(ts, NULL);
	pthread_join(tc, NULL);

	if (sa.ret != 0 || ca.ret != 0) {
		fprintf(stderr,
			"handshake failed: srv=%d cli=%d\n", sa.ret, ca.ret);
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/* For the kernel attach we additionally need RX kTLS on the
	 * server side (the side we hand to the kmod). OpenSSL enables
	 * TX automatically; RX needs at least one record to have been
	 * decoded with kTLS. The cleanest way to *force* TLS_RX
	 * setsockopt is to issue an SSL_read after the client sends
	 * a small record. */
	const char ping[] = "ping";
	int n = SSL_write(c_ssl, ping, sizeof(ping));
	(void)n;
	char buf[8] = {0};
	n = SSL_read(s_ssl, buf, sizeof(buf));
	(void)n;

	*out_srv_ssl = s_ssl;
	*out_cli_ssl = c_ssl;
	*out_srv_ctx = sctx;
	*out_cli_ctx = cctx;
	EVP_PKEY_free(key);
	X509_free(cert);
	return 0;
}

/* ------------------------------------------------------------------ */
static void test_negative_open(int devfd)
{
	SECTION("ATTACH negative paths");

	struct sstp_attach a;

	/* Bad ABI major. */
	memset(&a, 0, sizeof(a));
	a.abi_major = 99;
	a.abi_minor = 0;
	a.tcp_fd = 0;
	a.ppp_unit = 0;
	int rc = ioctl(devfd, SSTP_IOC_ATTACH, &a);
	CHECK(rc == -1 && errno == EINVAL, "bad ABI major rejected with EINVAL");

	/* Reserved field nonzero. */
	memset(&a, 0, sizeof(a));
	a.abi_major = SSTP_ABI_VERSION_MAJOR;
	a.abi_minor = SSTP_ABI_VERSION_MINOR;
	a.tcp_fd = 0;
	a.ppp_unit = 0;
	a.reserved[2] = 0xdeadbeef;
	rc = ioctl(devfd, SSTP_IOC_ATTACH, &a);
	CHECK(rc == -1 && errno == EINVAL,
	      "reserved-nonzero rejected with EINVAL");

	/* Negative tcp_fd. */
	memset(&a, 0, sizeof(a));
	a.abi_major = SSTP_ABI_VERSION_MAJOR;
	a.abi_minor = SSTP_ABI_VERSION_MINOR;
	a.tcp_fd = -1;
	a.ppp_unit = 0;
	rc = ioctl(devfd, SSTP_IOC_ATTACH, &a);
	CHECK(rc == -1 && errno == EINVAL, "negative tcp_fd rejected with EINVAL");

	/* fd that is not a socket (re-use /dev/sstp itself). */
	memset(&a, 0, sizeof(a));
	a.abi_major = SSTP_ABI_VERSION_MAJOR;
	a.abi_minor = SSTP_ABI_VERSION_MINOR;
	a.tcp_fd = devfd;
	a.ppp_unit = 0;
	rc = ioctl(devfd, SSTP_IOC_ATTACH, &a);
	CHECK(rc == -1 && errno == ENOTSOCK,
	      "non-socket fd rejected with ENOTSOCK");

	/* Plain TCP socket with no kTLS installed. */
	int s = socket(AF_INET, SOCK_STREAM, 0);
	memset(&a, 0, sizeof(a));
	a.abi_major = SSTP_ABI_VERSION_MAJOR;
	a.abi_minor = SSTP_ABI_VERSION_MINOR;
	a.tcp_fd = s;
	a.ppp_unit = 0;
	rc = ioctl(devfd, SSTP_IOC_ATTACH, &a);
	CHECK(rc == -1 && errno == EOPNOTSUPP,
	      "TCP without kTLS rejected with EOPNOTSUPP");
	close(s);
}

/* ------------------------------------------------------------------ */
static void test_happy_path(int devfd)
{
	SECTION("ATTACH happy path (kTLS + loopback TCP)");

	int srv_fd = -1, cli_fd = -1;
	if (tcp_loopback_pair(&srv_fd, &cli_fd) < 0) {
		fprintf(stderr, "tcp_loopback_pair: %s\n", strerror(errno));
		g_fail++;
		return;
	}

	SSL *s_ssl = NULL, *c_ssl = NULL;
	SSL_CTX *sctx = NULL, *cctx = NULL;
	if (do_tls_handshake(srv_fd, cli_fd, &s_ssl, &c_ssl,
			     &sctx, &cctx) < 0) {
		close(srv_fd);
		close(cli_fd);
		g_fail++;
		return;
	}

	/* Confirm kTLS is actually installed (both directions) on the
	 * server-side fd we're about to hand to the kmod. */
	int ktls_tx = BIO_get_ktls_send(SSL_get_wbio(s_ssl));
	int ktls_rx = BIO_get_ktls_recv(SSL_get_rbio(s_ssl));
	CHECK(ktls_tx == 1, "server-side kTLS TX installed");
	CHECK(ktls_rx == 1, "server-side kTLS RX installed");

	if (!ktls_tx || !ktls_rx) {
		fprintf(stderr,
			"  (kTLS not active; check `modprobe tls` and that the\n"
			"   kernel was built with CONFIG_TLS=y/m)\n");
		goto cleanup;
	}

	struct sstp_attach a = {
		.abi_major = SSTP_ABI_VERSION_MAJOR,
		.abi_minor = SSTP_ABI_VERSION_MINOR,
		.tcp_fd = srv_fd,
		.ppp_unit = 0,
		.flags = 0,
		.mtu = 1500,
	};
	int rc = ioctl(devfd, SSTP_IOC_ATTACH, &a);
	CHECK(rc == 0, "SSTP_IOC_ATTACH returned 0");
	if (rc != 0)
		goto cleanup;

	int sess_fd = a.session_fd;
	CHECK(sess_fd >= 0, "session_fd populated (=%d)", sess_fd);

	/* GET_CHAN_INDEX returns a non-negative PPP channel id. */
	int chan_idx = -1;
	rc = ioctl(sess_fd, SSTP_IOC_GET_CHAN_INDEX, &chan_idx);
	CHECK(rc == 0 && chan_idx >= 0,
	      "SSTP_IOC_GET_CHAN_INDEX returned chan=%d", chan_idx);

	/* GETSTATS on the session_fd. All counters should be zero. */
	struct sstp_stats st;
	memset(&st, 0xaa, sizeof(st));
	rc = ioctl(sess_fd, SSTP_IOC_GETSTATS, &st);
	CHECK(rc == 0, "SSTP_IOC_GETSTATS returned 0");
	CHECK(st.sstp_frames_rx == 0 && st.sstp_frames_tx == 0 &&
	      st.ppp_frames_rx == 0 && st.ppp_frames_tx == 0,
	      "stats counters zero (rx=%llu tx=%llu ppp_rx=%llu ppp_tx=%llu)",
	      (unsigned long long)st.sstp_frames_rx,
	      (unsigned long long)st.sstp_frames_tx,
	      (unsigned long long)st.ppp_frames_rx,
	      (unsigned long long)st.ppp_frames_tx);

	/* Poll: no events queued yet → 0 ready in non-zero timeout. */
	struct pollfd pf = { .fd = sess_fd, .events = POLLIN };
	rc = poll(&pf, 1, 50);
	CHECK(rc == 0, "poll() returns 0 (no events queued)");

	/* -- RX path test --
	 *
	 * Send three real SSTP data packets through the TLS client. The
	 * kernel's sk_data_ready hook should fire, the rx_worker should
	 * recvmsg, parse the framing, and bump sstp_frames_rx +
	 * ppp_frames_rx. We don't bind a PPP unit, so ppp_input drops
	 * the skb silently — that's fine, the counters tell us the
	 * demux ran end-to-end.
	 *
	 * Frame layout ([MS-SSTP] §2.2.3):
	 *   ver=0x10  flags=0x00 (C=0,data)  len_be=total_len (12-bit)
	 *   ... PPP frame ...
	 *
	 * Use a minimal "PPP" payload — the kernel demux doesn't parse
	 * PPP itself, only the SSTP outer framing. */
	const unsigned char ppp_payload[] = {
		0xff, 0x03,             /* PPP Address + Control */
		0x80, 0x21,             /* IPCP protocol */
		0xde, 0xad, 0xbe, 0xef, /* nonsense body */
	};
	unsigned int payload_len = sizeof(ppp_payload);
	unsigned int total = 4 + payload_len;
	unsigned char frame[64];
	frame[0] = 0x10;
	frame[1] = 0x00;
	frame[2] = (total >> 8) & 0x0F;
	frame[3] = total & 0xFF;
	memcpy(frame + 4, ppp_payload, payload_len);

	for (int i = 0; i < 3; i++) {
		int n = SSL_write(c_ssl, frame, total);
		CHECK(n == (int)total, "client SSL_write frame %d (n=%d)", i, n);
	}

	/* Give the workqueue a moment to drain. */
	for (int i = 0; i < 50; i++) {
		struct sstp_stats poll_st;
		ioctl(sess_fd, SSTP_IOC_GETSTATS, &poll_st);
		if (poll_st.sstp_frames_rx >= 3 && poll_st.ppp_frames_rx >= 3)
			break;
		usleep(10 * 1000);
	}

	rc = ioctl(sess_fd, SSTP_IOC_GETSTATS, &st);
	CHECK(rc == 0, "GETSTATS after RX returned 0");
	CHECK(st.sstp_frames_rx == 3,
	      "sstp_frames_rx == 3 (got %llu)",
	      (unsigned long long)st.sstp_frames_rx);
	CHECK(st.ppp_frames_rx == 3,
	      "ppp_frames_rx == 3 (got %llu)",
	      (unsigned long long)st.ppp_frames_rx);
	CHECK(st.tls_records_rx >= 1,
	      "tls_records_rx >= 1 (got %llu)",
	      (unsigned long long)st.tls_records_rx);

	/* -- Malformed framing -> POLLIN + SSTP_EVT_PROTOCOL_ERROR -- */
	unsigned char bad[] = { 0x99, 0x00, 0x00, 0x08, 0, 0, 0, 0 };
	int n = SSL_write(c_ssl, bad, sizeof(bad));
	CHECK(n == (int)sizeof(bad), "client SSL_write bad frame (n=%d)", n);

	pf.revents = 0;
	rc = poll(&pf, 1, 500);
	CHECK(rc == 1 && (pf.revents & POLLIN),
	      "poll() after bad framing returns POLLIN (revents=0x%x)",
	      pf.revents);

	struct sstp_event ev;
	ssize_t en = read(sess_fd, &ev, sizeof(ev));
	CHECK(en == (ssize_t)sizeof(ev),
	      "read(session_fd) returned full event (n=%zd)", en);
	CHECK(ev.type == SSTP_EVT_PROTOCOL_ERROR,
	      "event type = SSTP_EVT_PROTOCOL_ERROR (got %u)", ev.type);

	/* DETACH. */
	struct sstp_detach d = { 0 };
	rc = ioctl(sess_fd, SSTP_IOC_DETACH, &d);
	CHECK(rc == 0, "SSTP_IOC_DETACH returned 0");

	/* After DETACH, poll should report HUP. */
	pf.revents = 0;
	rc = poll(&pf, 1, 50);
	CHECK(rc == 1 && (pf.revents & POLLHUP),
	      "poll() after DETACH reports POLLHUP (revents=0x%x)", pf.revents);

	close(sess_fd);

cleanup:
	SSL_shutdown(c_ssl);
	SSL_free(c_ssl);
	SSL_free(s_ssl);
	SSL_CTX_free(sctx);
	SSL_CTX_free(cctx);
	close(cli_fd);
	close(srv_fd);
}

/* ------------------------------------------------------------------ */
int main(void)
{
	if (geteuid() != 0) {
		fprintf(stderr, "must run as root (CAP_NET_ADMIN)\n");
		return 77;
	}

	struct stat st;
	if (stat("/dev/sstp", &st) < 0) {
		fprintf(stderr, "/dev/sstp not present — is the sstp module loaded?\n");
		return 77;
	}

	int devfd = open("/dev/sstp", O_RDWR | O_CLOEXEC);
	if (devfd < 0) {
		fprintf(stderr, "open /dev/sstp: %s\n", strerror(errno));
		return 1;
	}
	printf("opened /dev/sstp (fd=%d)\n", devfd);

	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
			 OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

	test_negative_open(devfd);
	test_happy_path(devfd);

	close(devfd);

	printf("\n========================================\n");
	printf("  %d passed, %d failed\n", g_pass, g_fail);
	printf("========================================\n");
	return g_fail == 0 ? 0 : 1;
}
