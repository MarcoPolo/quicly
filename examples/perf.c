/*
 * QUIC performance protocol example.
 *
 * This implements the draft described in
 * https://www.ietf.org/archive/id/draft-banks-quic-performance-00.txt using
 * quicly. The client negotiates the "perf" ALPN, requests that the server
 * send a configurable number of bytes, optionally uploads client data, and
 * prints the elapsed time from stream open until the server closes the
 * stream.
 */
#include "quicly/constants.h"
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdint.h>
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "quicly/loss.h"

static const char *alpn_perf = "perf";

static quicly_context_t ctx;
static quicly_cid_plaintext_t next_cid;

static uint64_t perf_request_bytes = 1024 * 1024; /* default bytes server should send */
static uint64_t perf_client_send_bytes = 0;       /* default client upload size */

#define PERF_CHUNK_SIZE 1 << 23

static uint8_t zero_buf[PERF_CHUNK_SIZE] = {0};
static uint8_t send_buf[65536 * 10] = {0};
static uint8_t recv_buf[65536 * 10] = {0};

#define ENABLE_GRO 1

typedef struct {
    quicly_streambuf_t super;
    uint8_t header_buf[8];
    size_t header_bytes_read;
    uint64_t response_size;
    uint64_t response_sent;
    uint64_t client_send_target;
    uint64_t client_sent;
    uint64_t response_received;
    uint64_t start_time;
    uint64_t send_complete_time;
    int client_mode;
    int header_sent;
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
           "  -R <bytes>   number of bytes for the server to send (default: 1048576)\n"
           "  -T <bytes>   number of bytes for the client to upload (default: 0)\n"
           "  -h           prints this help\n"
           "\n"
           "When both `-c` and `-k` are specified, runs as a server. Otherwise, runs as a\n"
           "client connecting to host:port (default host: 127.0.0.1).\n",
           progname);
    exit(0);
}

static int is_server(void)
{
    return ctx.tls->certificates.count != 0;
}

static int64_t now_millis(void)
{
    return ctx.now->cb(ctx.now);
}

static int on_client_hello_cb(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    size_t i;

    for (i = 0; i < params->negotiated_protocols.count; ++i) {
        const ptls_iovec_t *protocol = &params->negotiated_protocols.list[i];
        if (protocol->len == strlen(alpn_perf) && memcmp(protocol->base, alpn_perf, protocol->len) == 0)
            return ptls_set_negotiated_protocol(tls, alpn_perf, strlen(alpn_perf));
    }

    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

static ptls_on_client_hello_t on_client_hello = {on_client_hello_cb};

static uint64_t hton64(uint64_t val)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return val;
#else
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low = (uint32_t)(val & 0xFFFFFFFF);
    return ((uint64_t)htonl(low) << 32) | htonl(high);
#endif
}

static uint64_t ntoh64(uint64_t val)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return val;
#else
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low = (uint32_t)(val & 0xFFFFFFFF);
    return ((uint64_t)ntohl(low) << 32) | ntohl(high);
#endif
}

static int perf_queue_request_header(quicly_stream_t *stream, perf_stream_t *perf)
{
    if (!perf->client_mode || perf->header_sent)
        return 0;
    if (!quicly_sendstate_is_open(&stream->sendstate))
        return 0;

    uint64_t request_size_net = hton64(perf->response_size);
    int ret = quicly_streambuf_egress_write(stream, &request_size_net, sizeof(request_size_net));
    if (ret != 0) {
        printf("perf: failed to buffer request header\n");
        quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "perf: failed to buffer request header");
        return ret;
    }

    perf->header_sent = 1;
    return 0;
}

static int perf_queue_client_payload(quicly_stream_t *stream, perf_stream_t *perf)
{
    if (!perf->client_mode)
        return 0;
    if (!quicly_sendstate_is_open(&stream->sendstate))
        return 0;
    if (perf->client_send_target == 0 || perf->client_sent >= perf->client_send_target)
        return 0;
    if (perf->super.egress.vecs.size != 0)
        return 0;

    uint64_t remaining = perf->client_send_target - perf->client_sent;
    size_t to_send = remaining < sizeof(zero_buf) ? (size_t)remaining : sizeof(zero_buf);
    int ret = quicly_streambuf_egress_write(stream, zero_buf, to_send);
    if (ret != 0) {
        printf("perf: failed to buffer client data\n");
        quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "perf: failed to buffer client data");
        return ret;
    }

    perf->client_sent += to_send;
    return 0;
}

static int perf_queue_response_chunk(quicly_stream_t *stream, perf_stream_t *perf)
{
    if (perf->client_mode)
        return 0;
    if (!quicly_sendstate_is_open(&stream->sendstate))
        return 0;
    if (perf->response_size == 0 || perf->response_sent >= perf->response_size)
        return 0;
    if (perf->super.egress.vecs.size != 0)
        return 0;

    uint64_t remaining = perf->response_size - perf->response_sent;
    size_t to_send = remaining < sizeof(zero_buf) ? (size_t)remaining : sizeof(zero_buf);
    int ret = quicly_streambuf_egress_write(stream, zero_buf, to_send);
    if (ret != 0) {
        printf("perf: failed to buffer response\n");
        quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "perf: failed to buffer response");
        return ret;
    }

    perf->response_sent += to_send;
    return 0;
}

static int perf_maybe_send_more(quicly_stream_t *stream, perf_stream_t *perf)
{
    int ret;

    if ((ret = perf_queue_request_header(stream, perf)) != 0)
        return ret;
    if ((ret = perf_queue_client_payload(stream, perf)) != 0)
        return ret;
    if ((ret = perf_queue_response_chunk(stream, perf)) != 0)
        return ret;

    if (!perf->client_mode && perf->header_bytes_read == 8 &&
        (perf->response_size == 0 || perf->response_sent >= perf->response_size) && perf->super.egress.vecs.size == 0 &&
        quicly_recvstate_transfer_complete(&stream->recvstate) && quicly_sendstate_is_open(&stream->sendstate)) {
        quicly_streambuf_egress_shutdown(stream);
    }

    if (perf->client_mode && perf->header_sent && perf->client_sent >= perf->client_send_target &&
        perf->super.egress.vecs.size == 0 && quicly_sendstate_is_open(&stream->sendstate)) {
        if (perf->send_complete_time == 0)
            perf->send_complete_time = now_millis();
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
    fprintf(stderr, "received STOP_SENDING: %" PRIu64 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu64 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    perf_stream_t *perf = (perf_stream_t *)stream->data;

    if (!perf->client_mode) {
        if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
            return;

        ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

        size_t consumed = 0;

        if (perf->header_bytes_read < 8) {
            size_t needed = 8 - perf->header_bytes_read;
            size_t available = input.len < needed ? input.len : needed;

            memcpy(perf->header_buf + perf->header_bytes_read, input.base, available);
            perf->header_bytes_read += available;
            consumed += available;

            if (perf->header_bytes_read == 8) {
                uint64_t request_size_net;
                memcpy(&request_size_net, perf->header_buf, 8);
                perf->response_size = ntoh64(request_size_net);
                printf("Received response size: %zu bytes\n", perf->response_size);
            }
        }

        if (perf->header_bytes_read >= 8 && consumed < input.len)
            consumed = input.len;

        quicly_streambuf_ingress_shift(stream, consumed);

        if (perf_maybe_send_more(stream, perf) != 0)
            return;
    } else {
        if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
            return;

        ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

        // fprintf(stderr, "perf stream on receive : %zu bytes\n", perf->response_received);
        if (input.len != 0) {
            perf->response_received += input.len;
            // fprintf(stderr, "perf stream response received: %zu/%zu bytes\n", perf->response_received, perf->response_size);
            quicly_streambuf_ingress_shift(stream, input.len);
        }

        // if (perf->response_received == perf->response_size) {
        if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
            if (perf->start_time != 0) {
                uint64_t end_time = now_millis();
                double elapsed_ms = (double)(end_time - perf->start_time);
                double elapsed_sec = elapsed_ms / 1000.0;
                double download_mbps = 0.0;
                if (elapsed_sec > 0.0 && perf->response_received != 0)
                    download_mbps = (perf->response_received * 8.0) / (elapsed_sec * 1e6);
                uint64_t upload_end = perf->send_complete_time != 0 ? perf->send_complete_time : end_time;
                double upload_ms = (double)(upload_end - perf->start_time);
                double upload_sec = upload_ms / 1000.0;
                double upload_mbps = 0.0;
                if (upload_sec > 0.0 && perf->client_send_target != 0)
                    upload_mbps = (perf->client_send_target * 8.0) / (upload_sec * 1e6);
                printf("perf stream duration: %.3f ms (down: %.3f Mbps, up: %.3f Mbps)\n", elapsed_ms, download_mbps, upload_mbps);
            }
            // printf("closing conn here\n");
            quicly_close(stream->conn, 0, "");
        }
    }
}

static void process_msg(int is_client, quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0, i;

    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX)
            return;
        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], NULL, msg->msg_name, &decoded))
                break;
        if (conns[i] != NULL) {
            quicly_receive(conns[i], NULL, msg->msg_name, &decoded);
        } else if (!is_client) {
            quicly_accept(conns + i, &ctx, NULL, msg->msg_name, &decoded, NULL, &next_cid, NULL, NULL);
        }
    }
}

static int send_one(int fd, struct sockaddr *dest, struct iovec *vec, size_t veclen, uint16_t gso_size)
{
    // printf("Sending %zu vec\n", veclen);
    char cmsghdr_buf[CMSG_SPACE(sizeof(uint16_t))];
    struct msghdr mess = {.msg_name = dest,
                          .msg_namelen = quicly_get_socklen(dest),
                          .msg_iov = vec,
                          .msg_iovlen = veclen,
                          .msg_control = cmsghdr_buf,
                          .msg_controllen = sizeof(cmsghdr_buf)};
    int ret;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mess);
    if (cm == NULL) {
        printf("cm pointer is NULL;\n");
        exit(1);
    }
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(gso_size));
    *((uint16_t *)CMSG_DATA(cm)) = gso_size;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    if (ret == -1) {
        perror("sendmsg failed");
    }
    return ret;
}

static int run_loop(int fd, quicly_conn_t *client)
{
    quicly_conn_t *conns[256] = {client};
    size_t i;

    while (1) {
        fd_set readfds;
        struct timeval tv;
        int64_t now;
        do {
            int64_t first_timeout = INT64_MAX;
            now = now_millis();
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
        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);

        // int64_t actual_wait = now_millis() - now;
        // fprintf(stderr, "actual wait %ld ms\n", actual_wait);
        if (FD_ISSET(fd, &readfds)) {

            struct sockaddr_storage sa;
            struct iovec vec = {.iov_base = recv_buf, .iov_len = sizeof(recv_buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            char cmsghdr_buf[CMSG_SPACE(sizeof(uint16_t))];
            msg.msg_control = cmsghdr_buf;
            msg.msg_controllen = sizeof(cmsghdr_buf);

            ssize_t rret;
            while ((rret = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR)
                ;

            uint16_t seg_size = 0;
            struct cmsghdr *cmsg;
            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
                    seg_size = *(uint16_t *)CMSG_DATA(cmsg);
                    break;
                }
            }

            // fprintf(stderr, "segment size %hu\n", seg_size);

            // printf("Received %zd bytes\n", rret);

            if (rret > 0) {
                if (seg_size > 0 && msg.msg_iov->iov_len > seg_size) {
                    // fprintf(stderr, "Received %zd bytes\n", rret);
                    void *original_base = msg.msg_iov->iov_base;
                    size_t end = (size_t)original_base + rret;
                    for (size_t i = 0; i < rret; i += seg_size) {
                        msg.msg_iov->iov_base = original_base + i;
                        if ((size_t)msg.msg_iov->iov_base + seg_size > end) {
                            seg_size = end - (size_t)msg.msg_iov->iov_base;
                        }
                        process_msg(client != NULL, conns, &msg, seg_size);
                    }
                } else {
                    process_msg(client != NULL, conns, &msg, rret);
                }
            }
        }

        for (i = 0; conns[i] != NULL; ++i) {
            quicly_address_t dest, src;
            struct iovec dgrams[50];
            // uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx.transport_params.max_udp_payload_size];
            while (1) {
                size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
                int ret = quicly_send(conns[i], &dest, &src, dgrams, &num_dgrams, send_buf, sizeof(send_buf));
                switch (ret) {
                case 0: {
                    if (num_dgrams > 0) {
                        struct iovec consolidated;
                        size_t j;
                        consolidated.iov_base = dgrams[0].iov_base;
                        consolidated.iov_len = 0;
                        size_t first_dgram_len = dgrams[0].iov_len;

                        for (j = 0; j != num_dgrams; ++j) {
                            if (dgrams[j].iov_len != first_dgram_len)
                                break;
                            consolidated.iov_len += dgrams[j].iov_len;
                        }

                        send_one(fd, &dest.sa, &consolidated, 1, first_dgram_len);
                        if (j != num_dgrams) {
                            // printf("Sending remaining %zd datagrams\n", num_dgrams - j);
                            send_one(fd, &dest.sa, &dgrams[j], 1, first_dgram_len);
                        }
                    }
                } break;
                case QUICLY_ERROR_FREE_CONNECTION: {
                    // fprintf(stderr, "Freeing connection\n");
                    quicly_free(conns[i]);
                    memmove(conns + i, conns + i + 1, sizeof(conns) - sizeof(conns[0]) * (i + 1));
                    --i;
                    if (!is_server())
                        return 0;
                    break;
                }
                default:
                    fprintf(stderr, "quicly_send returned %d\n", ret);
                    return 1;
                }

                if (num_dgrams == 0) {
                    break;
                }
            }
        }
    }

    return 0;
}

static void on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err, uint64_t frame_type,
                                const char *reason, size_t reason_len)
{
    fprintf(stderr, "Connection closed by remote %ld %lu\n", err, frame_type);
    if (QUICLY_ERROR_IS_QUIC(err)) {
        fprintf(stderr, "Connection refused quic err: %ld\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    } else if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "Connection refused tpt err\n");
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "Connection refused app\n");
    } else {
        fprintf(stderr, "Connection refused err\n");
    }

    if (reason_len > 0) {
        fprintf(stderr, "Connection closed by remote: %.*s\n", (int)reason_len, reason);
    }
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, perf_on_send_shift, quicly_streambuf_egress_emit, on_stop_sending, on_receive, on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(perf_stream_t))) != 0)
        return ret;

    perf_stream_t *perf = (perf_stream_t *)stream->data;
    memset(perf->header_buf, 0, sizeof(perf->header_buf));
    perf->header_bytes_read = 0;
    perf->response_size = is_server() ? 0 : perf_request_bytes;
    perf->response_sent = 0;
    perf->client_send_target = is_server() ? 0 : perf_client_send_bytes;
    perf->client_sent = 0;
    perf->response_received = 0;
    perf->start_time = 0;
    perf->send_complete_time = 0;
    perf->client_mode = !is_server();
    perf->header_sent = 0;

    if (perf->client_mode)
        perf->start_time = now_millis();

    stream->callbacks = &stream_callbacks;

    perf_maybe_send_more(stream, perf);

    return 0;
}

static int parse_uint64(const char *arg, uint64_t *out)
{
    char *endptr = NULL;
    errno = 0;
    unsigned long long val = strtoull(arg, &endptr, 10);
    if (errno != 0 || endptr == arg || *endptr != '\0')
        return -1;
    *out = (uint64_t)val;
    return 0;
}

static void raise_socket_bufs(int sockfd)
{
    int sndbuf, rcvbuf;
    socklen_t optlen;
    int size = 7.5 * 1024 * 1024; // 7.5 MiB = 7864320 bytes

    // Set send buffer size
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0) {
        perror("setsockopt(SO_SNDBUF)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Set receive buffer size
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0) {
        perror("setsockopt(SO_RCVBUF)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Verify the new send buffer size
    optlen = sizeof(sndbuf);
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) < 0) {
        perror("getsockopt(SO_SNDBUF)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Verify the new receive buffer size
    optlen = sizeof(rcvbuf);
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen) < 0) {
        perror("getsockopt(SO_RCVBUF)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Requested buffer size: %d bytes\n", size);
    printf("Actual send buffer size: %d bytes\n", sndbuf);
    printf("Actual receive buffer size: %d bytes\n", rcvbuf);
}

static void query_socket_bufs(int sockfd)
{
    int sndbuf, rcvbuf;
    socklen_t optlen;

    // Query send buffer size
    optlen = sizeof(sndbuf);
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) < 0) {
        perror("getsockopt(SO_SNDBUF)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Query receive buffer size
    optlen = sizeof(rcvbuf);
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen) < 0) {
        perror("getsockopt(SO_RCVBUF)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("UDP send buffer size: %d bytes\n", sndbuf);
    printf("UDP receive buffer size: %d bytes\n", rcvbuf);
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
        // .key_exchanges = ptls_openssl_key_exchanges_all,
        .cipher_suites = ptls_openssl_cipher_suites,
        // .cipher_suites = ptls_openssl_cipher_suites_all,
        .require_dhe_on_psk = 1,
        .on_client_hello = &on_client_hello,
    };
    quicly_stream_open_t stream_open = {on_stream_open};
    char *host = "127.0.0.1", *port = "4433";
    struct sockaddr_storage sa;
    socklen_t salen;
    int ch, fd;

    // ctx = quicly_spec_context;
    // ctx.loss = quicly_performant_context.loss;
    ctx = quicly_performant_context;
    ctx.tls = &tlsctx;
    quicly_amend_ptls_context(ctx.tls);
    ctx.stream_open = &stream_open;
    quicly_closed_by_remote_t closed_by_remote = {on_closed_by_remote};
    ctx.closed_by_remote = &closed_by_remote;

    while ((ch = getopt(argc, argv, "c:k:p:R:T:h")) != -1) {
        switch (ch) {
        case 'c': {
            int ret;
            if ((ret = ptls_load_certificates(&tlsctx, optarg)) != 0) {
                fprintf(stderr, "failed to load certificates from file %s:%d\n", optarg, ret);
                exit(1);
            }
        } break;
        case 'k': {
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
        case 'p':
            port = optarg;
            break;
        case 'R':
            if (parse_uint64(optarg, &perf_request_bytes) != 0) {
                fprintf(stderr, "invalid value for -R: %s\n", optarg);
                exit(1);
            }
            break;
        case 'T':
            if (parse_uint64(optarg, &perf_client_send_bytes) != 0) {
                fprintf(stderr, "invalid value for -T: %s\n", optarg);
                exit(1);
            }
            break;
        case 'h':
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

    if ((fd = socket(sa.ss_family, SOCK_DGRAM, 0)) == -1) {
        perror("socket(2) failed");
        exit(1);
    }
    query_socket_bufs(fd);
    raise_socket_bufs(fd);

    uint64_t gso_size = ctx.transport_params.max_udp_payload_size;
    fprintf(stderr, "max GSO size: %lu\n", gso_size);
    if (setsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &gso_size, sizeof(gso_size)) != 0) {
        perror("setting GSO failed");
        exit(1);
    }
    if (ENABLE_GRO) {
        fprintf(stderr, "GRO enabled\n");
        if (setsockopt(fd, IPPROTO_UDP, UDP_GRO, &gso_size, sizeof(gso_size)) != 0) {
            perror("setting GRO failed");
            exit(1);
        }
    }
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
        quicly_stream_t *stream;
        quicly_open_stream(client, &stream, 0);
    }

    return run_loop(fd, client);
}
