/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "sysemu/char.h"
#include "io/channel-socket.h"
#include "io/channel-tls.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qapi/clone-visitor.h"

#include "char-io.h"

/***********************************************************/
/* TCP Net console */

#define TCP_MAX_FDS 16

typedef struct {
    Chardev parent;
    QIOChannel *ioc; /* Client I/O channel */
    QIOChannelSocket *sioc; /* Client master channel */
    QIOChannelSocket *listen_ioc;
    guint listen_tag;
    QCryptoTLSCreds *tls_creds;
    int connected;
    int max_size;
    int do_telnetopt;
    int do_nodelay;
    int *read_msgfds;
    size_t read_msgfds_num;
    int *write_msgfds;
    size_t write_msgfds_num;

    SocketAddress *addr;
    bool is_listen;
    bool is_telnet;

    guint reconnect_timer;
    int64_t reconnect_time;
    bool connect_err_reported;
} SocketChardev;

#define SOCKET_CHARDEV(obj)                                     \
    OBJECT_CHECK(SocketChardev, (obj), TYPE_CHARDEV_SOCKET)

static gboolean socket_reconnect_timeout(gpointer opaque);

static void qemu_chr_socket_restart_timer(Chardev *chr)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    char *name;

    assert(s->connected == 0);
    s->reconnect_timer = g_timeout_add_seconds(s->reconnect_time,
                                               socket_reconnect_timeout, chr);
    name = g_strdup_printf("chardev-socket-reconnect-%s", chr->label);
    g_source_set_name_by_id(s->reconnect_timer, name);
    g_free(name);
}

static void check_report_connect_error(Chardev *chr,
                                       Error *err)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);

    if (!s->connect_err_reported) {
        error_report("Unable to connect character device %s: %s",
                     chr->label, error_get_pretty(err));
        s->connect_err_reported = true;
    }
    qemu_chr_socket_restart_timer(chr);
}

static gboolean tcp_chr_accept(QIOChannel *chan,
                               GIOCondition cond,
                               void *opaque);

static int tcp_chr_read_poll(void *opaque);
static void tcp_chr_disconnect(Chardev *chr);

/* Called with chr_write_lock held.  */
static int tcp_chr_write(Chardev *chr, const uint8_t *buf, int len)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);

    if (s->connected) {
        int ret =  io_channel_send_full(s->ioc, buf, len,
                                        s->write_msgfds,
                                        s->write_msgfds_num);

        /* free the written msgfds, no matter what */
        if (s->write_msgfds_num) {
            g_free(s->write_msgfds);
            s->write_msgfds = 0;
            s->write_msgfds_num = 0;
        }

        if (ret < 0 && errno != EAGAIN) {
            if (tcp_chr_read_poll(chr) <= 0) {
                tcp_chr_disconnect(chr);
                return len;
            } /* else let the read handler finish it properly */
        }

        return ret;
    } else {
        /* XXX: indicate an error ? */
        return len;
    }
}

static int tcp_chr_read_poll(void *opaque)
{
    Chardev *chr = CHARDEV(opaque);
    SocketChardev *s = SOCKET_CHARDEV(opaque);
    if (!s->connected) {
        return 0;
    }
    s->max_size = qemu_chr_be_can_write(chr);
    return s->max_size;
}

#define IAC 255
#define IAC_BREAK 243
static void tcp_chr_process_IAC_bytes(Chardev *chr,
                                      SocketChardev *s,
                                      uint8_t *buf, int *size)
{
    /* Handle any telnet client's basic IAC options to satisfy char by
     * char mode with no echo.  All IAC options will be removed from
     * the buf and the do_telnetopt variable will be used to track the
     * state of the width of the IAC information.
     *
     * IAC commands come in sets of 3 bytes with the exception of the
     * "IAC BREAK" command and the double IAC.
     */

    int i;
    int j = 0;

    for (i = 0; i < *size; i++) {
        if (s->do_telnetopt > 1) {
            if ((unsigned char)buf[i] == IAC && s->do_telnetopt == 2) {
                /* Double IAC means send an IAC */
                if (j != i) {
                    buf[j] = buf[i];
                }
                j++;
                s->do_telnetopt = 1;
            } else {
                if ((unsigned char)buf[i] == IAC_BREAK
                    && s->do_telnetopt == 2) {
                    /* Handle IAC break commands by sending a serial break */
                    qemu_chr_be_event(chr, CHR_EVENT_BREAK);
                    s->do_telnetopt++;
                }
                s->do_telnetopt++;
            }
            if (s->do_telnetopt >= 4) {
                s->do_telnetopt = 1;
            }
        } else {
            if ((unsigned char)buf[i] == IAC) {
                s->do_telnetopt = 2;
            } else {
                if (j != i) {
                    buf[j] = buf[i];
                }
                j++;
            }
        }
    }
    *size = j;
}

static int tcp_get_msgfds(Chardev *chr, int *fds, int num)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);

    int to_copy = (s->read_msgfds_num < num) ? s->read_msgfds_num : num;

    assert(num <= TCP_MAX_FDS);

    if (to_copy) {
        int i;

        memcpy(fds, s->read_msgfds, to_copy * sizeof(int));

        /* Close unused fds */
        for (i = to_copy; i < s->read_msgfds_num; i++) {
            close(s->read_msgfds[i]);
        }

        g_free(s->read_msgfds);
        s->read_msgfds = 0;
        s->read_msgfds_num = 0;
    }

    return to_copy;
}

static int tcp_set_msgfds(Chardev *chr, int *fds, int num)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);

    /* clear old pending fd array */
    g_free(s->write_msgfds);
    s->write_msgfds = NULL;
    s->write_msgfds_num = 0;

    if (!s->connected ||
        !qio_channel_has_feature(s->ioc,
                                 QIO_CHANNEL_FEATURE_FD_PASS)) {
        return -1;
    }

    if (num) {
        s->write_msgfds = g_new(int, num);
        memcpy(s->write_msgfds, fds, num * sizeof(int));
    }

    s->write_msgfds_num = num;

    return 0;
}

static ssize_t tcp_chr_recv(Chardev *chr, char *buf, size_t len)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    int ret;
    size_t i;
    int *msgfds = NULL;
    size_t msgfds_num = 0;

    if (qio_channel_has_feature(s->ioc, QIO_CHANNEL_FEATURE_FD_PASS)) {
        ret = qio_channel_readv_full(s->ioc, &iov, 1,
                                     &msgfds, &msgfds_num,
                                     NULL);
    } else {
        ret = qio_channel_readv_full(s->ioc, &iov, 1,
                                     NULL, NULL,
                                     NULL);
    }

    if (ret == QIO_CHANNEL_ERR_BLOCK) {
        errno = EAGAIN;
        ret = -1;
    } else if (ret == -1) {
        errno = EIO;
    }

    if (msgfds_num) {
        /* close and clean read_msgfds */
        for (i = 0; i < s->read_msgfds_num; i++) {
            close(s->read_msgfds[i]);
        }

        if (s->read_msgfds_num) {
            g_free(s->read_msgfds);
        }

        s->read_msgfds = msgfds;
        s->read_msgfds_num = msgfds_num;
    }

    for (i = 0; i < s->read_msgfds_num; i++) {
        int fd = s->read_msgfds[i];
        if (fd < 0) {
            continue;
        }

        /* O_NONBLOCK is preserved across SCM_RIGHTS so reset it */
        qemu_set_block(fd);

#ifndef MSG_CMSG_CLOEXEC
        qemu_set_cloexec(fd);
#endif
    }

    return ret;
}

static GSource *tcp_chr_add_watch(Chardev *chr, GIOCondition cond)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    return qio_channel_create_watch(s->ioc, cond);
}

static void tcp_chr_free_connection(Chardev *chr)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    int i;

    if (!s->connected) {
        return;
    }

    if (s->read_msgfds_num) {
        for (i = 0; i < s->read_msgfds_num; i++) {
            close(s->read_msgfds[i]);
        }
        g_free(s->read_msgfds);
        s->read_msgfds = NULL;
        s->read_msgfds_num = 0;
    }

    tcp_set_msgfds(chr, NULL, 0);
    remove_fd_in_watch(chr, NULL);
    object_unref(OBJECT(s->sioc));
    s->sioc = NULL;
    object_unref(OBJECT(s->ioc));
    s->ioc = NULL;
    g_free(chr->filename);
    chr->filename = NULL;
    s->connected = 0;
}

static char *SocketAddress_to_str(const char *prefix, SocketAddress *addr,
                                  bool is_listen, bool is_telnet)
{
    switch (addr->type) {
    case SOCKET_ADDRESS_KIND_INET:
        return g_strdup_printf("%s%s:%s:%s%s", prefix,
                               is_telnet ? "telnet" : "tcp",
                               addr->u.inet.data->host,
                               addr->u.inet.data->port,
                               is_listen ? ",server" : "");
        break;
    case SOCKET_ADDRESS_KIND_UNIX:
        return g_strdup_printf("%sunix:%s%s", prefix,
                               addr->u.q_unix.data->path,
                               is_listen ? ",server" : "");
        break;
    case SOCKET_ADDRESS_KIND_FD:
        return g_strdup_printf("%sfd:%s%s", prefix, addr->u.fd.data->str,
                               is_listen ? ",server" : "");
        break;
    case SOCKET_ADDRESS_KIND_VSOCK:
        return g_strdup_printf("%svsock:%s:%s", prefix,
                               addr->u.vsock.data->cid,
                               addr->u.vsock.data->port);
    default:
        abort();
    }
}

static void tcp_chr_disconnect(Chardev *chr)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);

    if (!s->connected) {
        return;
    }

    tcp_chr_free_connection(chr);

    if (s->listen_ioc) {
        s->listen_tag = qio_channel_add_watch(
            QIO_CHANNEL(s->listen_ioc), G_IO_IN, tcp_chr_accept, chr, NULL);
    }
    chr->filename = SocketAddress_to_str("disconnected:", s->addr,
                                         s->is_listen, s->is_telnet);
    qemu_chr_be_event(chr, CHR_EVENT_CLOSED);
    if (s->reconnect_time) {
        qemu_chr_socket_restart_timer(chr);
    }
}

static gboolean tcp_chr_read(QIOChannel *chan, GIOCondition cond, void *opaque)
{
    Chardev *chr = CHARDEV(opaque);
    SocketChardev *s = SOCKET_CHARDEV(opaque);
    uint8_t buf[CHR_READ_BUF_LEN];
    int len, size;

    if (!s->connected || s->max_size <= 0) {
        return TRUE;
    }
    len = sizeof(buf);
    if (len > s->max_size) {
        len = s->max_size;
    }
    size = tcp_chr_recv(chr, (void *)buf, len);
    if (size == 0 || size == -1) {
        /* connection closed */
        tcp_chr_disconnect(chr);
    } else if (size > 0) {
        if (s->do_telnetopt) {
            tcp_chr_process_IAC_bytes(chr, s, buf, &size);
        }
        if (size > 0) {
            qemu_chr_be_write(chr, buf, size);
        }
    }

    return TRUE;
}

static int tcp_chr_sync_read(Chardev *chr, const uint8_t *buf, int len)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    int size;

    if (!s->connected) {
        return 0;
    }

    size = tcp_chr_recv(chr, (void *) buf, len);
    if (size == 0) {
        /* connection closed */
        tcp_chr_disconnect(chr);
    }

    return size;
}

static char *sockaddr_to_str(struct sockaddr_storage *ss, socklen_t ss_len,
                             struct sockaddr_storage *ps, socklen_t ps_len,
                             bool is_listen, bool is_telnet)
{
    char shost[NI_MAXHOST], sserv[NI_MAXSERV];
    char phost[NI_MAXHOST], pserv[NI_MAXSERV];
    const char *left = "", *right = "";

    switch (ss->ss_family) {
#ifndef _WIN32
    case AF_UNIX:
        return g_strdup_printf("unix:%s%s",
                               ((struct sockaddr_un *)(ss))->sun_path,
                               is_listen ? ",server" : "");
#endif
    case AF_INET6:
        left  = "[";
        right = "]";
        /* fall through */
    case AF_INET:
        getnameinfo((struct sockaddr *) ss, ss_len, shost, sizeof(shost),
                    sserv, sizeof(sserv), NI_NUMERICHOST | NI_NUMERICSERV);
        getnameinfo((struct sockaddr *) ps, ps_len, phost, sizeof(phost),
                    pserv, sizeof(pserv), NI_NUMERICHOST | NI_NUMERICSERV);
        return g_strdup_printf("%s:%s%s%s:%s%s <-> %s%s%s:%s",
                               is_telnet ? "telnet" : "tcp",
                               left, shost, right, sserv,
                               is_listen ? ",server" : "",
                               left, phost, right, pserv);

    default:
        return g_strdup_printf("unknown");
    }
}

static void tcp_chr_connect(void *opaque)
{
    Chardev *chr = CHARDEV(opaque);
    SocketChardev *s = SOCKET_CHARDEV(opaque);

    g_free(chr->filename);
    chr->filename = sockaddr_to_str(
        &s->sioc->localAddr, s->sioc->localAddrLen,
        &s->sioc->remoteAddr, s->sioc->remoteAddrLen,
        s->is_listen, s->is_telnet);

    s->connected = 1;
    if (s->ioc) {
        chr->fd_in_tag = io_add_watch_poll(chr, s->ioc,
                                           tcp_chr_read_poll,
                                           tcp_chr_read,
                                           chr, NULL);
    }
    qemu_chr_be_generic_open(chr);
}

static void tcp_chr_update_read_handler(Chardev *chr,
                                        GMainContext *context)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);

    if (!s->connected) {
        return;
    }

    remove_fd_in_watch(chr, NULL);
    if (s->ioc) {
        chr->fd_in_tag = io_add_watch_poll(chr, s->ioc,
                                           tcp_chr_read_poll,
                                           tcp_chr_read, chr,
                                           context);
    }
}

typedef struct {
    Chardev *chr;
    char buf[12];
    size_t buflen;
} TCPChardevTelnetInit;

static gboolean tcp_chr_telnet_init_io(QIOChannel *ioc,
                                       GIOCondition cond G_GNUC_UNUSED,
                                       gpointer user_data)
{
    TCPChardevTelnetInit *init = user_data;
    ssize_t ret;

    ret = qio_channel_write(ioc, init->buf, init->buflen, NULL);
    if (ret < 0) {
        if (ret == QIO_CHANNEL_ERR_BLOCK) {
            ret = 0;
        } else {
            tcp_chr_disconnect(init->chr);
            return FALSE;
        }
    }
    init->buflen -= ret;

    if (init->buflen == 0) {
        tcp_chr_connect(init->chr);
        return FALSE;
    }

    memmove(init->buf, init->buf + ret, init->buflen);

    return TRUE;
}

static void tcp_chr_telnet_init(Chardev *chr)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    TCPChardevTelnetInit *init = g_new0(TCPChardevTelnetInit, 1);
    size_t n = 0;

    init->chr = chr;
    init->buflen = 12;

#define IACSET(x, a, b, c)                      \
    do {                                        \
        x[n++] = a;                             \
        x[n++] = b;                             \
        x[n++] = c;                             \
    } while (0)

    /* Prep the telnet negotion to put telnet in binary,
     * no echo, single char mode */
    IACSET(init->buf, 0xff, 0xfb, 0x01);  /* IAC WILL ECHO */
    IACSET(init->buf, 0xff, 0xfb, 0x03);  /* IAC WILL Suppress go ahead */
    IACSET(init->buf, 0xff, 0xfb, 0x00);  /* IAC WILL Binary */
    IACSET(init->buf, 0xff, 0xfd, 0x00);  /* IAC DO Binary */

#undef IACSET

    qio_channel_add_watch(
        s->ioc, G_IO_OUT,
        tcp_chr_telnet_init_io,
        init, NULL);
}


static void tcp_chr_tls_handshake(QIOTask *task,
                                  gpointer user_data)
{
    Chardev *chr = user_data;
    SocketChardev *s = user_data;

    if (qio_task_propagate_error(task, NULL)) {
        tcp_chr_disconnect(chr);
    } else {
        if (s->do_telnetopt) {
            tcp_chr_telnet_init(chr);
        } else {
            tcp_chr_connect(chr);
        }
    }
}


static void tcp_chr_tls_init(Chardev *chr)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    QIOChannelTLS *tioc;
    Error *err = NULL;
    gchar *name;

    if (s->is_listen) {
        tioc = qio_channel_tls_new_server(
            s->ioc, s->tls_creds,
            NULL, /* XXX Use an ACL */
            &err);
    } else {
        tioc = qio_channel_tls_new_client(
            s->ioc, s->tls_creds,
            s->addr->u.inet.data->host,
            &err);
    }
    if (tioc == NULL) {
        error_free(err);
        tcp_chr_disconnect(chr);
        return;
    }
    name = g_strdup_printf("chardev-tls-%s-%s",
                           s->is_listen ? "server" : "client",
                           chr->label);
    qio_channel_set_name(QIO_CHANNEL(tioc), name);
    g_free(name);
    object_unref(OBJECT(s->ioc));
    s->ioc = QIO_CHANNEL(tioc);

    qio_channel_tls_handshake(tioc,
                              tcp_chr_tls_handshake,
                              chr,
                              NULL);
}


static void tcp_chr_set_client_ioc_name(Chardev *chr,
                                        QIOChannelSocket *sioc)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    char *name;
    name = g_strdup_printf("chardev-tcp-%s-%s",
                           s->is_listen ? "server" : "client",
                           chr->label);
    qio_channel_set_name(QIO_CHANNEL(sioc), name);
    g_free(name);

}

static int tcp_chr_new_client(Chardev *chr, QIOChannelSocket *sioc)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);

    if (s->ioc != NULL) {
        return -1;
    }

    s->ioc = QIO_CHANNEL(sioc);
    object_ref(OBJECT(sioc));
    s->sioc = sioc;
    object_ref(OBJECT(sioc));

    qio_channel_set_blocking(s->ioc, false, NULL);

    if (s->do_nodelay) {
        qio_channel_set_delay(s->ioc, false);
    }
    if (s->listen_tag) {
        g_source_remove(s->listen_tag);
        s->listen_tag = 0;
    }

    if (s->tls_creds) {
        tcp_chr_tls_init(chr);
    } else {
        if (s->do_telnetopt) {
            tcp_chr_telnet_init(chr);
        } else {
            tcp_chr_connect(chr);
        }
    }

    return 0;
}


static int tcp_chr_add_client(Chardev *chr, int fd)
{
    int ret;
    QIOChannelSocket *sioc;

    sioc = qio_channel_socket_new_fd(fd, NULL);
    if (!sioc) {
        return -1;
    }
    tcp_chr_set_client_ioc_name(chr, sioc);
    ret = tcp_chr_new_client(chr, sioc);
    object_unref(OBJECT(sioc));
    return ret;
}

static gboolean tcp_chr_accept(QIOChannel *channel,
                               GIOCondition cond,
                               void *opaque)
{
    Chardev *chr = CHARDEV(opaque);
    QIOChannelSocket *sioc;

    sioc = qio_channel_socket_accept(QIO_CHANNEL_SOCKET(channel),
                                     NULL);
    if (!sioc) {
        return TRUE;
    }

    tcp_chr_new_client(chr, sioc);

    object_unref(OBJECT(sioc));

    return TRUE;
}

static int tcp_chr_wait_connected(Chardev *chr, Error **errp)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    QIOChannelSocket *sioc;

    /* It can't wait on s->connected, since it is set asynchronously
     * in TLS and telnet cases, only wait for an accepted socket */
    while (!s->ioc) {
        if (s->is_listen) {
            error_report("QEMU waiting for connection on: %s",
                         chr->filename);
            qio_channel_set_blocking(QIO_CHANNEL(s->listen_ioc), true, NULL);
            tcp_chr_accept(QIO_CHANNEL(s->listen_ioc), G_IO_IN, chr);
            qio_channel_set_blocking(QIO_CHANNEL(s->listen_ioc), false, NULL);
        } else {
            sioc = qio_channel_socket_new();
            tcp_chr_set_client_ioc_name(chr, sioc);
            if (qio_channel_socket_connect_sync(sioc, s->addr, errp) < 0) {
                object_unref(OBJECT(sioc));
                return -1;
            }
            tcp_chr_new_client(chr, sioc);
            object_unref(OBJECT(sioc));
        }
    }

    return 0;
}

static void char_socket_finalize(Object *obj)
{
    Chardev *chr = CHARDEV(obj);
    SocketChardev *s = SOCKET_CHARDEV(obj);

    tcp_chr_free_connection(chr);

    if (s->reconnect_timer) {
        g_source_remove(s->reconnect_timer);
        s->reconnect_timer = 0;
    }
    qapi_free_SocketAddress(s->addr);
    if (s->listen_tag) {
        g_source_remove(s->listen_tag);
        s->listen_tag = 0;
    }
    if (s->listen_ioc) {
        object_unref(OBJECT(s->listen_ioc));
    }
    if (s->tls_creds) {
        object_unref(OBJECT(s->tls_creds));
    }

    qemu_chr_be_event(chr, CHR_EVENT_CLOSED);
}

static void qemu_chr_socket_connected(QIOTask *task, void *opaque)
{
    QIOChannelSocket *sioc = QIO_CHANNEL_SOCKET(qio_task_get_source(task));
    Chardev *chr = CHARDEV(opaque);
    SocketChardev *s = SOCKET_CHARDEV(chr);
    Error *err = NULL;

    if (qio_task_propagate_error(task, &err)) {
        check_report_connect_error(chr, err);
        error_free(err);
        goto cleanup;
    }

    s->connect_err_reported = false;
    tcp_chr_new_client(chr, sioc);

cleanup:
    object_unref(OBJECT(sioc));
}

static gboolean socket_reconnect_timeout(gpointer opaque)
{
    Chardev *chr = CHARDEV(opaque);
    SocketChardev *s = SOCKET_CHARDEV(opaque);
    QIOChannelSocket *sioc;

    s->reconnect_timer = 0;

    if (chr->be_open) {
        return false;
    }

    sioc = qio_channel_socket_new();
    tcp_chr_set_client_ioc_name(chr, sioc);
    qio_channel_socket_connect_async(sioc, s->addr,
                                     qemu_chr_socket_connected,
                                     chr, NULL);

    return false;
}

static void qmp_chardev_open_socket(Chardev *chr,
                                    ChardevBackend *backend,
                                    bool *be_opened,
                                    Error **errp)
{
    SocketChardev *s = SOCKET_CHARDEV(chr);
    ChardevSocket *sock = backend->u.socket.data;
    SocketAddress *addr = sock->addr;
    bool do_nodelay     = sock->has_nodelay ? sock->nodelay : false;
    bool is_listen      = sock->has_server  ? sock->server  : true;
    bool is_telnet      = sock->has_telnet  ? sock->telnet  : false;
    bool is_waitconnect = sock->has_wait    ? sock->wait    : false;
    int64_t reconnect   = sock->has_reconnect ? sock->reconnect : 0;
    QIOChannelSocket *sioc = NULL;

    s->is_listen = is_listen;
    s->is_telnet = is_telnet;
    s->do_nodelay = do_nodelay;
    if (sock->tls_creds) {
        Object *creds;
        creds = object_resolve_path_component(
            object_get_objects_root(), sock->tls_creds);
        if (!creds) {
            error_setg(errp, "No TLS credentials with id '%s'",
                       sock->tls_creds);
            goto error;
        }
        s->tls_creds = (QCryptoTLSCreds *)
            object_dynamic_cast(creds,
                                TYPE_QCRYPTO_TLS_CREDS);
        if (!s->tls_creds) {
            error_setg(errp, "Object with id '%s' is not TLS credentials",
                       sock->tls_creds);
            goto error;
        }
        object_ref(OBJECT(s->tls_creds));
        if (is_listen) {
            if (s->tls_creds->endpoint != QCRYPTO_TLS_CREDS_ENDPOINT_SERVER) {
                error_setg(errp, "%s",
                           "Expected TLS credentials for server endpoint");
                goto error;
            }
        } else {
            if (s->tls_creds->endpoint != QCRYPTO_TLS_CREDS_ENDPOINT_CLIENT) {
                error_setg(errp, "%s",
                           "Expected TLS credentials for client endpoint");
                goto error;
            }
        }
    }

    s->addr = QAPI_CLONE(SocketAddress, sock->addr);

    qemu_chr_set_feature(chr, QEMU_CHAR_FEATURE_RECONNECTABLE);
    /* TODO SOCKET_ADDRESS_FD where fd has AF_UNIX */
    if (addr->type == SOCKET_ADDRESS_KIND_UNIX) {
        qemu_chr_set_feature(chr, QEMU_CHAR_FEATURE_FD_PASS);
    }

    /* be isn't opened until we get a connection */
    *be_opened = false;

    chr->filename = SocketAddress_to_str("disconnected:",
                                         addr, is_listen, is_telnet);

    if (is_listen) {
        if (is_telnet) {
            s->do_telnetopt = 1;
        }
    } else if (reconnect > 0) {
        s->reconnect_time = reconnect;
    }

    if (s->reconnect_time) {
        sioc = qio_channel_socket_new();
        tcp_chr_set_client_ioc_name(chr, sioc);
        qio_channel_socket_connect_async(sioc, s->addr,
                                         qemu_chr_socket_connected,
                                         chr, NULL);
    } else {
        if (s->is_listen) {
            char *name;
            sioc = qio_channel_socket_new();

            name = g_strdup_printf("chardev-tcp-listener-%s", chr->label);
            qio_channel_set_name(QIO_CHANNEL(sioc), name);
            g_free(name);

            if (qio_channel_socket_listen_sync(sioc, s->addr, errp) < 0) {
                goto error;
            }
            s->listen_ioc = sioc;
            if (is_waitconnect &&
                qemu_chr_wait_connected(chr, errp) < 0) {
                return;
            }
            if (!s->ioc) {
                s->listen_tag = qio_channel_add_watch(
                    QIO_CHANNEL(s->listen_ioc), G_IO_IN,
                    tcp_chr_accept, chr, NULL);
            }
        } else if (qemu_chr_wait_connected(chr, errp) < 0) {
            goto error;
        }
    }

    return;

error:
    if (sioc) {
        object_unref(OBJECT(sioc));
    }
}

static void qemu_chr_parse_socket(QemuOpts *opts, ChardevBackend *backend,
                                  Error **errp)
{
    bool is_listen      = qemu_opt_get_bool(opts, "server", false);
    bool is_waitconnect = is_listen && qemu_opt_get_bool(opts, "wait", true);
    bool is_telnet      = qemu_opt_get_bool(opts, "telnet", false);
    bool do_nodelay     = !qemu_opt_get_bool(opts, "delay", true);
    int64_t reconnect   = qemu_opt_get_number(opts, "reconnect", 0);
    const char *path = qemu_opt_get(opts, "path");
    const char *host = qemu_opt_get(opts, "host");
    const char *port = qemu_opt_get(opts, "port");
    const char *tls_creds = qemu_opt_get(opts, "tls-creds");
    SocketAddress *addr;
    ChardevSocket *sock;

    backend->type = CHARDEV_BACKEND_KIND_SOCKET;
    if (!path) {
        if (!host) {
            error_setg(errp, "chardev: socket: no host given");
            return;
        }
        if (!port) {
            error_setg(errp, "chardev: socket: no port given");
            return;
        }
    } else {
        if (tls_creds) {
            error_setg(errp, "TLS can only be used over TCP socket");
            return;
        }
    }

    sock = backend->u.socket.data = g_new0(ChardevSocket, 1);
    qemu_chr_parse_common(opts, qapi_ChardevSocket_base(sock));

    sock->has_nodelay = true;
    sock->nodelay = do_nodelay;
    sock->has_server = true;
    sock->server = is_listen;
    sock->has_telnet = true;
    sock->telnet = is_telnet;
    sock->has_wait = true;
    sock->wait = is_waitconnect;
    sock->has_reconnect = true;
    sock->reconnect = reconnect;
    sock->tls_creds = g_strdup(tls_creds);

    addr = g_new0(SocketAddress, 1);
    if (path) {
        UnixSocketAddress *q_unix;
        addr->type = SOCKET_ADDRESS_KIND_UNIX;
        q_unix = addr->u.q_unix.data = g_new0(UnixSocketAddress, 1);
        q_unix->path = g_strdup(path);
    } else {
        addr->type = SOCKET_ADDRESS_KIND_INET;
        addr->u.inet.data = g_new(InetSocketAddress, 1);
        *addr->u.inet.data = (InetSocketAddress) {
            .host = g_strdup(host),
            .port = g_strdup(port),
            .has_to = qemu_opt_get(opts, "to"),
            .to = qemu_opt_get_number(opts, "to", 0),
            .has_ipv4 = qemu_opt_get(opts, "ipv4"),
            .ipv4 = qemu_opt_get_bool(opts, "ipv4", 0),
            .has_ipv6 = qemu_opt_get(opts, "ipv6"),
            .ipv6 = qemu_opt_get_bool(opts, "ipv6", 0),
        };
    }
    sock->addr = addr;
}

static void char_socket_class_init(ObjectClass *oc, void *data)
{
    ChardevClass *cc = CHARDEV_CLASS(oc);

    cc->parse = qemu_chr_parse_socket;
    cc->open = qmp_chardev_open_socket;
    cc->chr_wait_connected = tcp_chr_wait_connected;
    cc->chr_write = tcp_chr_write;
    cc->chr_sync_read = tcp_chr_sync_read;
    cc->chr_disconnect = tcp_chr_disconnect;
    cc->get_msgfds = tcp_get_msgfds;
    cc->set_msgfds = tcp_set_msgfds;
    cc->chr_add_client = tcp_chr_add_client;
    cc->chr_add_watch = tcp_chr_add_watch;
    cc->chr_update_read_handler = tcp_chr_update_read_handler;
}

static const TypeInfo char_socket_type_info = {
    .name = TYPE_CHARDEV_SOCKET,
    .parent = TYPE_CHARDEV,
    .instance_size = sizeof(SocketChardev),
    .instance_finalize = char_socket_finalize,
    .class_init = char_socket_class_init,
};

static void register_types(void)
{
    type_register_static(&char_socket_type_info);
}

type_init(register_types);
