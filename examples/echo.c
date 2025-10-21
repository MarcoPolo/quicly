/*
 * Copyright (c) 2019 Fastly, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

/**
 * ALPN identifier for QUIC performance protocol
 */
static const char *alpn_perf = "perf";

/**
 * the QUIC context
 */
static quicly_context_t ctx;
/**
 * CID seed
 */
static quicly_cid_plaintext_t next_cid;

/**
 * Performance protocol stream state
 */
typedef struct {
    quicly_streambuf_t super;
    uint8_t header_buf[8];      /* buffer for reading the 8-byte request size header */
    size_t header_bytes_read;    /* how many bytes of header have been read */
    uint64_t response_size;      /* requested response size from client */
    uint64_t response_sent;      /* how many response bytes have been queued */
    int client_mode;             /* 1 if this is a client stream, 0 if server */
    int header_sent;             /* 1 if client has sent the request header */
} perf_stream_t;

static int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type,
                           int proto)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

static void usage(const char *progname)
{
    printf("Usage: %s [options] [host]\n"
           "Options:\n"
           "  -c <file>    specifies the certificate chain file (PEM format)\n"
           "  -k <file>    specifies the private key file (PEM format)\n"
           "  -p <number>  specifies the port number (default: 4433)\n"
           "  -h           prints this help\n"
           "\n"
           "When both `-c` and `-k` is specified, runs as a server.  Otherwise, runs as a\n"
           "client connecting to host:port.  If omitted, host defaults to 127.0.0.1.\n",
           progname);
    exit(0);
}

static int is_server(void)
{
    return ctx.tls->certificates.count != 0;
}

/**
 * Server-side ALPN negotiation callback
 */
static int on_client_hello_cb(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    size_t i;

    /* Check if client proposed "perf" ALPN */
    for (i = 0; i < params->negotiated_protocols.count; ++i) {
        const ptls_iovec_t *protocol = &params->negotiated_protocols.list[i];
        if (protocol->len == strlen(alpn_perf) && memcmp(protocol->base, alpn_perf, protocol->len) == 0) {
            /* Set the negotiated protocol */
            return ptls_set_negotiated_protocol(tls, alpn_perf, strlen(alpn_perf));
        }
    }

    /* If "perf" not found in client's list, reject */
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

static ptls_on_client_hello_t on_client_hello = {on_client_hello_cb};

/**
 * Convert 64-bit value from host to network byte order
 */
static uint64_t hton64(uint64_t val)
{
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low = (uint32_t)(val & 0xFFFFFFFF);
    return ((uint64_t)htonl(low) << 32) | htonl(high);
}

/**
 * Convert 64-bit value from network to host byte order
 */
static uint64_t ntoh64(uint64_t val)
{
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low = (uint32_t)(val & 0xFFFFFFFF);
    return ((uint64_t)ntohl(low) << 32) | ntohl(high);
}

static int forward_stdin(quicly_conn_t *conn)
{
    quicly_stream_t *stream0;
    perf_stream_t *perf;
    char buf[4096];
    size_t rret;

    if ((stream0 = quicly_get_stream(conn, 0)) == NULL || !quicly_sendstate_is_open(&stream0->sendstate))
        return 0;

    perf = (perf_stream_t *)stream0->data;

    /* Send the 8-byte request header first (client mode) */
    if (perf->client_mode && !perf->header_sent) {
        /* For this example, request 1MB response (can be made configurable) */
        uint64_t request_size = 1024 * 1024; /* 1 MB */
        uint64_t request_size_net = hton64(request_size);
        quicly_streambuf_egress_write(stream0, &request_size_net, sizeof(request_size_net));
        perf->header_sent = 1;
    }

    while ((rret = read(0, buf, sizeof(buf))) == -1 && errno == EINTR)
        ;
    if (rret == 0) {
        /* stdin closed, close the send-side of stream0 */
        quicly_streambuf_egress_shutdown(stream0);
        return 0;
    } else {
        /* write data to send buffer */
        quicly_streambuf_egress_write(stream0, buf, rret);
        return 1;
    }
}

#define PERF_CHUNK_SIZE 65536

static int perf_queue_next_chunk(quicly_stream_t *stream, perf_stream_t *perf)
{
    if (perf->response_size == 0 || perf->response_sent >= perf->response_size)
        return 0;
    if (!quicly_sendstate_is_open(&stream->sendstate))
        return 0;
    if (perf->super.egress.vecs.size != 0)
        return 0;

    static uint8_t zero_buf[PERF_CHUNK_SIZE] = {0}; /* reused between calls */
    uint64_t remaining = perf->response_size - perf->response_sent;
    size_t to_send = remaining < sizeof(zero_buf) ? (size_t)remaining : sizeof(zero_buf);
    int ret = quicly_streambuf_egress_write(stream, zero_buf, to_send);
    if (ret != 0) {
        quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "perf: failed to buffer response");
        return ret;
    }

    perf->response_sent += to_send;
    return 0;
}

static int perf_maybe_send_more(quicly_stream_t *stream, perf_stream_t *perf)
{
    int ret;

    if ((ret = perf_queue_next_chunk(stream, perf)) != 0)
        return ret;

    if (perf->response_size != 0 && perf->response_sent >= perf->response_size && perf->super.egress.vecs.size == 0 &&
        quicly_recvstate_transfer_complete(&stream->recvstate)) {
        quicly_streambuf_egress_shutdown(stream);
    }

    return 0;
}

static void perf_on_send_shift(quicly_stream_t *stream, size_t delta)
{
    quicly_streambuf_egress_shift(stream, delta);

    perf_stream_t *perf = (perf_stream_t *)stream->data;
    if (perf == NULL)
        return;

    perf_maybe_send_more(stream, perf);
}

static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    perf_stream_t *perf = (perf_stream_t *)stream->data;

    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (is_server()) {
        /* Server-side: implement performance protocol */
        size_t consumed = 0;

        /* Read the 8-byte request size header first */
        if (perf->header_bytes_read < 8) {
            size_t needed = 8 - perf->header_bytes_read;
            size_t available = input.len < needed ? input.len : needed;

            memcpy(perf->header_buf + perf->header_bytes_read, input.base, available);
            perf->header_bytes_read += available;
            consumed += available;

            /* If we've read all 8 bytes, parse the request size */
            if (perf->header_bytes_read == 8) {
                uint64_t request_size_net;
                memcpy(&request_size_net, perf->header_buf, 8);
                perf->response_size = ntoh64(request_size_net);
            }
        }

        /* Drain any remaining client data */
        if (perf->header_bytes_read >= 8 && consumed < input.len) {
            consumed = input.len; /* consume all remaining data */
        }

        /* Remove consumed bytes from receive buffer */
        quicly_streambuf_ingress_shift(stream, consumed);

        /* Send response data once we know the response size */
        if (perf->header_bytes_read >= 8 && quicly_sendstate_is_open(&stream->sendstate)) {
            if (perf_maybe_send_more(stream, perf) != 0)
                return;
        }
    } else {
        /* Client: print received data to stdout */
        fwrite(input.base, 1, input.len, stdout);
        fflush(stdout);
        /* initiate connection close after receiving all data */
        if (quicly_recvstate_transfer_complete(&stream->recvstate))
            quicly_close(stream->conn, 0, "");

        /* remove used bytes from receive buffer */
        quicly_streambuf_ingress_shift(stream, input.len);
    }
}

static void process_msg(int is_client, quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0, i;

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX)
            return;
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], NULL, msg->msg_name, &decoded))
                break;
        if (conns[i] != NULL) {
            /* let the current connection handle ingress packets */
            quicly_receive(conns[i], NULL, msg->msg_name, &decoded);
        } else if (!is_client) {
            /* assume that the packet is a new connection */
            quicly_accept(conns + i, &ctx, NULL, msg->msg_name, &decoded, NULL, &next_cid, NULL, NULL);
        }
    }
}

static int send_one(int fd, struct sockaddr *dest, struct iovec *vec)
{
    struct msghdr mess = {.msg_name = dest, .msg_namelen = quicly_get_socklen(dest), .msg_iov = vec, .msg_iovlen = 1};
    int ret;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

static int run_loop(int fd, quicly_conn_t *client)
{
    quicly_conn_t *conns[256] = {client}; /* a null-terminated list of connections; proper app should use a hashmap or something */
    size_t i;
    int read_stdin = client != NULL;

    while (1) {

        /* wait for sockets to become readable, or some event in the QUIC stack to fire */
        fd_set readfds;
        struct timeval tv;
        do {
            int64_t first_timeout = INT64_MAX, now = ctx.now->cb(ctx.now);
            for (i = 0; conns[i] != NULL; ++i) {
                int64_t conn_timeout = quicly_get_first_timeout(conns[i]);
                if (conn_timeout < first_timeout)
                    first_timeout = conn_timeout;
            }
            if (now < first_timeout) {
                int64_t delta = first_timeout - now;
                if (delta > 1000 * 1000)
                    delta = 1000 * 1000;
                tv.tv_sec = delta / 1000;
                tv.tv_usec = (delta % 1000) * 1000;
            } else {
                tv.tv_sec = 0;
                tv.tv_usec = 0;
            }
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
            /* we want to read input from stdin */
            if (read_stdin)
                FD_SET(0, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);

        /* read the QUIC fd */
        if (FD_ISSET(fd, &readfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage sa;
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR)
                ;
            if (rret > 0)
                process_msg(client != NULL, conns, &msg, rret);
        }

        /* read stdin, send the input to the active stram */
        if (FD_ISSET(0, &readfds)) {
            assert(client != NULL);
            if (!forward_stdin(client))
                read_stdin = 0;
        }

        /* send QUIC packets, if any */
        for (i = 0; conns[i] != NULL; ++i) {
            quicly_address_t dest, src;
            struct iovec dgrams[10];
            uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx.transport_params.max_udp_payload_size];
            size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
            int ret = quicly_send(conns[i], &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
            switch (ret) {
            case 0: {
                size_t j;
                for (j = 0; j != num_dgrams; ++j) {
                    send_one(fd, &dest.sa, &dgrams[j]);
                }
            } break;
            case QUICLY_ERROR_FREE_CONNECTION:
                /* connection has been closed, free, and exit when running as a client */
                quicly_free(conns[i]);
                memmove(conns + i, conns + i + 1, sizeof(conns) - sizeof(conns[0]) * (i + 1));
                --i;
                if (!is_server())
                    return 0;
                break;
            default:
                fprintf(stderr, "quicly_send returned %d\n", ret);
                return 1;
            }
        }
    }

    return 0;
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, perf_on_send_shift, quicly_streambuf_egress_emit, on_stop_sending, on_receive,
        on_receive_reset};
    int ret;

    /* Allocate perf_stream_t instead of quicly_streambuf_t */
    if ((ret = quicly_streambuf_create(stream, sizeof(perf_stream_t))) != 0)
        return ret;

    /* Initialize perf-specific fields */
    perf_stream_t *perf = (perf_stream_t *)stream->data;
    memset(perf->header_buf, 0, sizeof(perf->header_buf));
    perf->header_bytes_read = 0;
    perf->response_size = 0;
    perf->response_sent = 0;
    perf->header_sent = 0;
    perf->client_mode = !is_server(); /* client if not server */

    stream->callbacks = &stream_callbacks;
    return 0;
}

int main(int argc, char **argv)
{
    ptls_openssl_sign_certificate_t sign_certificate;
    static ptls_iovec_t alpn_list[1];
    alpn_list[0] = ptls_iovec_init(alpn_perf, strlen(alpn_perf));
    ptls_context_t tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
        .require_dhe_on_psk = 1,
        .on_client_hello = &on_client_hello,
    };
    quicly_stream_open_t stream_open = {on_stream_open};
    char *host = "127.0.0.1", *port = "4433";
    struct sockaddr_storage sa;
    socklen_t salen;
    int ch, fd;

    /* setup quic context */
    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    quicly_amend_ptls_context(ctx.tls);
    ctx.stream_open = &stream_open;

    /* resolve command line options and arguments */
    while ((ch = getopt(argc, argv, "c:k:p:h")) != -1) {
        switch (ch) {
        case 'c': /* load certificate chain */ {
            int ret;
            if ((ret = ptls_load_certificates(&tlsctx, optarg)) != 0) {
                fprintf(stderr, "failed to load certificates from file %s:%d\n", optarg, ret);
                exit(1);
            }
        } break;
        case 'k': /* load private key */ {
            FILE *fp;
            if ((fp = fopen(optarg, "r")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                exit(1);
            }
            EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
            if (pkey == NULL) {
                fprintf(stderr, "failed to load private key from file:%s\n", optarg);
                exit(1);
            }
            ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
            EVP_PKEY_free(pkey);
            tlsctx.sign_certificate = &sign_certificate.super;
        } break;
        case 'p': /* port */
            port = optarg;
            break;
        case 'h': /* help */
            usage(argv[0]);
            break;
        default:
            exit(1);
            break;
        }
    }
    if ((tlsctx.certificates.count != 0) != (tlsctx.sign_certificate != NULL)) {
        fprintf(stderr, "-c and -k options must be used together\n");
        exit(1);
    }
    argc -= optind;
    argv += optind;
    if (argc != 0)
        host = *argv++;
    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, 0) != 0)
        exit(1);

    /* open socket, on the specified port (as a server), or on any port (as a client) */
    if ((fd = socket(sa.ss_family, SOCK_DGRAM, 0)) == -1) {
        perror("socket(2) failed");
        exit(1);
    }
    // fcntl(fd, F_SETFL, O_NONBLOCK);
    if (is_server()) {
        int reuseaddr = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
        if (bind(fd, (struct sockaddr *)&sa, salen) != 0) {
            perror("bind(2) failed");
            exit(1);
        }
    } else {
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
            perror("bind(2) failed");
            exit(1);
        }
    }

    quicly_conn_t *client = NULL;
    if (!is_server()) {
        /* initiate a connection, and open a stream */
        int ret;
        ptls_handshake_properties_t hs_properties;
        memset(&hs_properties, 0, sizeof(hs_properties));
        hs_properties.client.negotiated_protocols.list = alpn_list;
        hs_properties.client.negotiated_protocols.count = 1;

        if ((ret = quicly_connect(&client, &ctx, host, (struct sockaddr *)&sa, NULL, &next_cid, ptls_iovec_init(NULL, 0),
                                  &hs_properties, NULL, NULL)) != 0) {
            fprintf(stderr, "quicly_connect failed:%d\n", ret);
            exit(1);
        }
        quicly_stream_t *stream; /* we retain the opened stream via the on_stream_open callback */
        quicly_open_stream(client, &stream, 0);
    }

    /* enter the event loop with a connection object */
    return run_loop(fd, client);
}
