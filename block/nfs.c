/*
 * QEMU Block driver for native access to files on NFS shares
 *
 * Copyright (c) 2014-2016 Peter Lieven <pl@kamp.de>
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

#include <poll.h>
#include "qemu-common.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "block/block_int.h"
#include "trace.h"
#include "qemu/iov.h"
#include "qemu/uri.h"
#include "qemu/cutils.h"
#include "sysemu/sysemu.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qint.h"
#include "qapi/qmp/qstring.h"
#include "qapi-visit.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/qobject-output-visitor.h"
#include <nfsc/libnfs.h>


#define QEMU_NFS_MAX_READAHEAD_SIZE 1048576
#define QEMU_NFS_MAX_PAGECACHE_SIZE (8388608 / NFS_BLKSIZE)
#define QEMU_NFS_MAX_DEBUG_LEVEL 2

typedef struct NFSClient {
    struct nfs_context *context;
    struct nfsfh *fh;
    int events;
    bool has_zero_init;
    AioContext *aio_context;
    QemuMutex mutex;
    blkcnt_t st_blocks;
    bool cache_used;
    NFSServer *server;
    char *path;
    int64_t uid, gid, tcp_syncnt, readahead, pagecache, debug;
} NFSClient;

typedef struct NFSRPC {
    BlockDriverState *bs;
    int ret;
    int complete;
    QEMUIOVector *iov;
    struct stat *st;
    Coroutine *co;
    NFSClient *client;
} NFSRPC;

static int nfs_parse_uri(const char *filename, QDict *options, Error **errp)
{
    URI *uri = NULL;
    QueryParams *qp = NULL;
    int ret = -EINVAL, i;

    uri = uri_parse(filename);
    if (!uri) {
        error_setg(errp, "Invalid URI specified");
        goto out;
    }
    if (strcmp(uri->scheme, "nfs") != 0) {
        error_setg(errp, "URI scheme must be 'nfs'");
        goto out;
    }

    if (!uri->server) {
        error_setg(errp, "missing hostname in URI");
        goto out;
    }

    if (!uri->path) {
        error_setg(errp, "missing file path in URI");
        goto out;
    }

    qp = query_params_parse(uri->query);
    if (!qp) {
        error_setg(errp, "could not parse query parameters");
        goto out;
    }

    qdict_put(options, "server.host", qstring_from_str(uri->server));
    qdict_put(options, "server.type", qstring_from_str("inet"));
    qdict_put(options, "path", qstring_from_str(uri->path));

    for (i = 0; i < qp->n; i++) {
        unsigned long long val;
        if (!qp->p[i].value) {
            error_setg(errp, "Value for NFS parameter expected: %s",
                       qp->p[i].name);
            goto out;
        }
        if (parse_uint_full(qp->p[i].value, &val, 0)) {
            error_setg(errp, "Illegal value for NFS parameter: %s",
                       qp->p[i].name);
            goto out;
        }
        if (!strcmp(qp->p[i].name, "uid")) {
            qdict_put(options, "user",
                      qstring_from_str(qp->p[i].value));
        } else if (!strcmp(qp->p[i].name, "gid")) {
            qdict_put(options, "group",
                      qstring_from_str(qp->p[i].value));
        } else if (!strcmp(qp->p[i].name, "tcp-syncnt")) {
            qdict_put(options, "tcp-syn-count",
                      qstring_from_str(qp->p[i].value));
        } else if (!strcmp(qp->p[i].name, "readahead")) {
            qdict_put(options, "readahead-size",
                      qstring_from_str(qp->p[i].value));
        } else if (!strcmp(qp->p[i].name, "pagecache")) {
            qdict_put(options, "page-cache-size",
                      qstring_from_str(qp->p[i].value));
        } else if (!strcmp(qp->p[i].name, "debug")) {
            qdict_put(options, "debug",
                      qstring_from_str(qp->p[i].value));
        } else {
            error_setg(errp, "Unknown NFS parameter name: %s",
                       qp->p[i].name);
            goto out;
        }
    }
    ret = 0;
out:
    if (qp) {
        query_params_free(qp);
    }
    if (uri) {
        uri_free(uri);
    }
    return ret;
}

static bool nfs_has_filename_options_conflict(QDict *options, Error **errp)
{
    const QDictEntry *qe;

    for (qe = qdict_first(options); qe; qe = qdict_next(options, qe)) {
        if (!strcmp(qe->key, "host") ||
            !strcmp(qe->key, "path") ||
            !strcmp(qe->key, "user") ||
            !strcmp(qe->key, "group") ||
            !strcmp(qe->key, "tcp-syn-count") ||
            !strcmp(qe->key, "readahead-size") ||
            !strcmp(qe->key, "page-cache-size") ||
            !strcmp(qe->key, "debug") ||
            strstart(qe->key, "server.", NULL))
        {
            error_setg(errp, "Option %s cannot be used with a filename",
                       qe->key);
            return true;
        }
    }

    return false;
}

static void nfs_parse_filename(const char *filename, QDict *options,
                               Error **errp)
{
    if (nfs_has_filename_options_conflict(options, errp)) {
        return;
    }

    nfs_parse_uri(filename, options, errp);
}

static void nfs_process_read(void *arg);
static void nfs_process_write(void *arg);

/* Called with QemuMutex held.  */
static void nfs_set_events(NFSClient *client)
{
    int ev = nfs_which_events(client->context);
    if (ev != client->events) {
        aio_set_fd_handler(client->aio_context, nfs_get_fd(client->context),
                           false,
                           (ev & POLLIN) ? nfs_process_read : NULL,
                           (ev & POLLOUT) ? nfs_process_write : NULL,
                           NULL, client);

    }
    client->events = ev;
}

static void nfs_process_read(void *arg)
{
    NFSClient *client = arg;

    qemu_mutex_lock(&client->mutex);
    nfs_service(client->context, POLLIN);
    nfs_set_events(client);
    qemu_mutex_unlock(&client->mutex);
}

static void nfs_process_write(void *arg)
{
    NFSClient *client = arg;

    qemu_mutex_lock(&client->mutex);
    nfs_service(client->context, POLLOUT);
    nfs_set_events(client);
    qemu_mutex_unlock(&client->mutex);
}

static void nfs_co_init_task(BlockDriverState *bs, NFSRPC *task)
{
    *task = (NFSRPC) {
        .co             = qemu_coroutine_self(),
        .bs             = bs,
        .client         = bs->opaque,
    };
}

static void nfs_co_generic_bh_cb(void *opaque)
{
    NFSRPC *task = opaque;

    task->complete = 1;
    aio_co_wake(task->co);
}

/* Called (via nfs_service) with QemuMutex held.  */
static void
nfs_co_generic_cb(int ret, struct nfs_context *nfs, void *data,
                  void *private_data)
{
    NFSRPC *task = private_data;
    task->ret = ret;
    assert(!task->st);
    if (task->ret > 0 && task->iov) {
        if (task->ret <= task->iov->size) {
            qemu_iovec_from_buf(task->iov, 0, data, task->ret);
        } else {
            task->ret = -EIO;
        }
    }
    if (task->ret < 0) {
        error_report("NFS Error: %s", nfs_get_error(nfs));
    }
    aio_bh_schedule_oneshot(task->client->aio_context,
                            nfs_co_generic_bh_cb, task);
}

static int coroutine_fn nfs_co_preadv(BlockDriverState *bs, uint64_t offset,
                                      uint64_t bytes, QEMUIOVector *iov,
                                      int flags)
{
    NFSClient *client = bs->opaque;
    NFSRPC task;

    nfs_co_init_task(bs, &task);
    task.iov = iov;

    qemu_mutex_lock(&client->mutex);
    if (nfs_pread_async(client->context, client->fh,
                        offset, bytes, nfs_co_generic_cb, &task) != 0) {
        qemu_mutex_unlock(&client->mutex);
        return -ENOMEM;
    }

    nfs_set_events(client);
    qemu_mutex_unlock(&client->mutex);
    while (!task.complete) {
        qemu_coroutine_yield();
    }

    if (task.ret < 0) {
        return task.ret;
    }

    /* zero pad short reads */
    if (task.ret < iov->size) {
        qemu_iovec_memset(iov, task.ret, 0, iov->size - task.ret);
    }

    return 0;
}

static int coroutine_fn nfs_co_pwritev(BlockDriverState *bs, uint64_t offset,
                                       uint64_t bytes, QEMUIOVector *iov,
                                       int flags)
{
    NFSClient *client = bs->opaque;
    NFSRPC task;
    char *buf = NULL;
    bool my_buffer = false;

    nfs_co_init_task(bs, &task);

    if (iov->niov != 1) {
        buf = g_try_malloc(bytes);
        if (bytes && buf == NULL) {
            return -ENOMEM;
        }
        qemu_iovec_to_buf(iov, 0, buf, bytes);
        my_buffer = true;
    } else {
        buf = iov->iov[0].iov_base;
    }

    qemu_mutex_lock(&client->mutex);
    if (nfs_pwrite_async(client->context, client->fh,
                         offset, bytes, buf,
                         nfs_co_generic_cb, &task) != 0) {
        qemu_mutex_unlock(&client->mutex);
        if (my_buffer) {
            g_free(buf);
        }
        return -ENOMEM;
    }

    nfs_set_events(client);
    qemu_mutex_unlock(&client->mutex);
    while (!task.complete) {
        qemu_coroutine_yield();
    }

    if (my_buffer) {
        g_free(buf);
    }

    if (task.ret != bytes) {
        return task.ret < 0 ? task.ret : -EIO;
    }

    return 0;
}

static int coroutine_fn nfs_co_flush(BlockDriverState *bs)
{
    NFSClient *client = bs->opaque;
    NFSRPC task;

    nfs_co_init_task(bs, &task);

    qemu_mutex_lock(&client->mutex);
    if (nfs_fsync_async(client->context, client->fh, nfs_co_generic_cb,
                        &task) != 0) {
        qemu_mutex_unlock(&client->mutex);
        return -ENOMEM;
    }

    nfs_set_events(client);
    qemu_mutex_unlock(&client->mutex);
    while (!task.complete) {
        qemu_coroutine_yield();
    }

    return task.ret;
}

static QemuOptsList runtime_opts = {
    .name = "nfs",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "path",
            .type = QEMU_OPT_STRING,
            .help = "Path of the image on the host",
        },
        {
            .name = "user",
            .type = QEMU_OPT_NUMBER,
            .help = "UID value to use when talking to the server",
        },
        {
            .name = "group",
            .type = QEMU_OPT_NUMBER,
            .help = "GID value to use when talking to the server",
        },
        {
            .name = "tcp-syn-count",
            .type = QEMU_OPT_NUMBER,
            .help = "Number of SYNs to send during the session establish",
        },
        {
            .name = "readahead-size",
            .type = QEMU_OPT_NUMBER,
            .help = "Set the readahead size in bytes",
        },
        {
            .name = "page-cache-size",
            .type = QEMU_OPT_NUMBER,
            .help = "Set the pagecache size in bytes",
        },
        {
            .name = "debug",
            .type = QEMU_OPT_NUMBER,
            .help = "Set the NFS debug level (max 2)",
        },
        { /* end of list */ }
    },
};

static void nfs_detach_aio_context(BlockDriverState *bs)
{
    NFSClient *client = bs->opaque;

    aio_set_fd_handler(client->aio_context, nfs_get_fd(client->context),
                       false, NULL, NULL, NULL, NULL);
    client->events = 0;
}

static void nfs_attach_aio_context(BlockDriverState *bs,
                                   AioContext *new_context)
{
    NFSClient *client = bs->opaque;

    client->aio_context = new_context;
    nfs_set_events(client);
}

static void nfs_client_close(NFSClient *client)
{
    if (client->context) {
        if (client->fh) {
            nfs_close(client->context, client->fh);
        }
        aio_set_fd_handler(client->aio_context, nfs_get_fd(client->context),
                           false, NULL, NULL, NULL, NULL);
        nfs_destroy_context(client->context);
    }
    memset(client, 0, sizeof(NFSClient));
}

static void nfs_file_close(BlockDriverState *bs)
{
    NFSClient *client = bs->opaque;
    nfs_client_close(client);
    qemu_mutex_destroy(&client->mutex);
}

static NFSServer *nfs_config(QDict *options, Error **errp)
{
    NFSServer *server = NULL;
    QDict *addr = NULL;
    QObject *crumpled_addr = NULL;
    Visitor *iv = NULL;
    Error *local_error = NULL;

    qdict_extract_subqdict(options, &addr, "server.");
    if (!qdict_size(addr)) {
        error_setg(errp, "NFS server address missing");
        goto out;
    }

    crumpled_addr = qdict_crumple(addr, errp);
    if (!crumpled_addr) {
        goto out;
    }

    /*
     * Caution: this works only because all scalar members of
     * NFSServer are QString in @crumpled_addr.  The visitor expects
     * @crumpled_addr to be typed according to the QAPI schema.  It
     * is when @options come from -blockdev or blockdev_add.  But when
     * they come from -drive, they're all QString.
     */
    iv = qobject_input_visitor_new(crumpled_addr);
    visit_type_NFSServer(iv, NULL, &server, &local_error);
    if (local_error) {
        error_propagate(errp, local_error);
        goto out;
    }

out:
    QDECREF(addr);
    qobject_decref(crumpled_addr);
    visit_free(iv);
    return server;
}


static int64_t nfs_client_open(NFSClient *client, QDict *options,
                               int flags, Error **errp, int open_flags)
{
    int ret = -EINVAL;
    QemuOpts *opts = NULL;
    Error *local_err = NULL;
    struct stat st;
    char *file = NULL, *strp = NULL;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto fail;
    }

    client->path = g_strdup(qemu_opt_get(opts, "path"));
    if (!client->path) {
        ret = -EINVAL;
        error_setg(errp, "No path was specified");
        goto fail;
    }

    strp = strrchr(client->path, '/');
    if (strp == NULL) {
        error_setg(errp, "Invalid URL specified");
        goto fail;
    }
    file = g_strdup(strp);
    *strp = 0;

    /* Pop the config into our state object, Exit if invalid */
    client->server = nfs_config(options, errp);
    if (!client->server) {
        ret = -EINVAL;
        goto fail;
    }

    client->context = nfs_init_context();
    if (client->context == NULL) {
        error_setg(errp, "Failed to init NFS context");
        goto fail;
    }

    if (qemu_opt_get(opts, "user")) {
        client->uid = qemu_opt_get_number(opts, "user", 0);
        nfs_set_uid(client->context, client->uid);
    }

    if (qemu_opt_get(opts, "group")) {
        client->gid = qemu_opt_get_number(opts, "group", 0);
        nfs_set_gid(client->context, client->gid);
    }

    if (qemu_opt_get(opts, "tcp-syn-count")) {
        client->tcp_syncnt = qemu_opt_get_number(opts, "tcp-syn-count", 0);
        nfs_set_tcp_syncnt(client->context, client->tcp_syncnt);
    }

#ifdef LIBNFS_FEATURE_READAHEAD
    if (qemu_opt_get(opts, "readahead-size")) {
        if (open_flags & BDRV_O_NOCACHE) {
            error_setg(errp, "Cannot enable NFS readahead "
                             "if cache.direct = on");
            goto fail;
        }
        client->readahead = qemu_opt_get_number(opts, "readahead-size", 0);
        if (client->readahead > QEMU_NFS_MAX_READAHEAD_SIZE) {
            error_report("NFS Warning: Truncating NFS readahead "
                         "size to %d", QEMU_NFS_MAX_READAHEAD_SIZE);
            client->readahead = QEMU_NFS_MAX_READAHEAD_SIZE;
        }
        nfs_set_readahead(client->context, client->readahead);
#ifdef LIBNFS_FEATURE_PAGECACHE
        nfs_set_pagecache_ttl(client->context, 0);
#endif
        client->cache_used = true;
    }
#endif

#ifdef LIBNFS_FEATURE_PAGECACHE
    if (qemu_opt_get(opts, "page-cache-size")) {
        if (open_flags & BDRV_O_NOCACHE) {
            error_setg(errp, "Cannot enable NFS pagecache "
                             "if cache.direct = on");
            goto fail;
        }
        client->pagecache = qemu_opt_get_number(opts, "page-cache-size", 0);
        if (client->pagecache > QEMU_NFS_MAX_PAGECACHE_SIZE) {
            error_report("NFS Warning: Truncating NFS pagecache "
                         "size to %d pages", QEMU_NFS_MAX_PAGECACHE_SIZE);
            client->pagecache = QEMU_NFS_MAX_PAGECACHE_SIZE;
        }
        nfs_set_pagecache(client->context, client->pagecache);
        nfs_set_pagecache_ttl(client->context, 0);
        client->cache_used = true;
    }
#endif

#ifdef LIBNFS_FEATURE_DEBUG
    if (qemu_opt_get(opts, "debug")) {
        client->debug = qemu_opt_get_number(opts, "debug", 0);
        /* limit the maximum debug level to avoid potential flooding
         * of our log files. */
        if (client->debug > QEMU_NFS_MAX_DEBUG_LEVEL) {
            error_report("NFS Warning: Limiting NFS debug level "
                         "to %d", QEMU_NFS_MAX_DEBUG_LEVEL);
            client->debug = QEMU_NFS_MAX_DEBUG_LEVEL;
        }
        nfs_set_debug(client->context, client->debug);
    }
#endif

    ret = nfs_mount(client->context, client->server->host, client->path);
    if (ret < 0) {
        error_setg(errp, "Failed to mount nfs share: %s",
                   nfs_get_error(client->context));
        goto fail;
    }

    if (flags & O_CREAT) {
        ret = nfs_creat(client->context, file, 0600, &client->fh);
        if (ret < 0) {
            error_setg(errp, "Failed to create file: %s",
                       nfs_get_error(client->context));
            goto fail;
        }
    } else {
        ret = nfs_open(client->context, file, flags, &client->fh);
        if (ret < 0) {
            error_setg(errp, "Failed to open file : %s",
                       nfs_get_error(client->context));
            goto fail;
        }
    }

    ret = nfs_fstat(client->context, client->fh, &st);
    if (ret < 0) {
        error_setg(errp, "Failed to fstat file: %s",
                   nfs_get_error(client->context));
        goto fail;
    }

    ret = DIV_ROUND_UP(st.st_size, BDRV_SECTOR_SIZE);
    client->st_blocks = st.st_blocks;
    client->has_zero_init = S_ISREG(st.st_mode);
    *strp = '/';
    goto out;

fail:
    nfs_client_close(client);
out:
    qemu_opts_del(opts);
    g_free(file);
    return ret;
}

static int nfs_file_open(BlockDriverState *bs, QDict *options, int flags,
                         Error **errp) {
    NFSClient *client = bs->opaque;
    int64_t ret;

    client->aio_context = bdrv_get_aio_context(bs);

    ret = nfs_client_open(client, options,
                          (flags & BDRV_O_RDWR) ? O_RDWR : O_RDONLY,
                          errp, bs->open_flags);
    if (ret < 0) {
        return ret;
    }
    qemu_mutex_init(&client->mutex);
    bs->total_sectors = ret;
    ret = 0;
    return ret;
}

static QemuOptsList nfs_create_opts = {
    .name = "nfs-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(nfs_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        { /* end of list */ }
    }
};

static int nfs_file_create(const char *url, QemuOpts *opts, Error **errp)
{
    int ret = 0;
    int64_t total_size = 0;
    NFSClient *client = g_new0(NFSClient, 1);
    QDict *options = NULL;

    client->aio_context = qemu_get_aio_context();

    /* Read out options */
    total_size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                          BDRV_SECTOR_SIZE);

    options = qdict_new();
    ret = nfs_parse_uri(url, options, errp);
    if (ret < 0) {
        goto out;
    }

    ret = nfs_client_open(client, options, O_CREAT, errp, 0);
    if (ret < 0) {
        goto out;
    }
    ret = nfs_ftruncate(client->context, client->fh, total_size);
    nfs_client_close(client);
out:
    QDECREF(options);
    g_free(client);
    return ret;
}

static int nfs_has_zero_init(BlockDriverState *bs)
{
    NFSClient *client = bs->opaque;
    return client->has_zero_init;
}

/* Called (via nfs_service) with QemuMutex held.  */
static void
nfs_get_allocated_file_size_cb(int ret, struct nfs_context *nfs, void *data,
                               void *private_data)
{
    NFSRPC *task = private_data;
    task->ret = ret;
    if (task->ret == 0) {
        memcpy(task->st, data, sizeof(struct stat));
    }
    if (task->ret < 0) {
        error_report("NFS Error: %s", nfs_get_error(nfs));
    }
    task->complete = 1;
    bdrv_wakeup(task->bs);
}

static int64_t nfs_get_allocated_file_size(BlockDriverState *bs)
{
    NFSClient *client = bs->opaque;
    NFSRPC task = {0};
    struct stat st;

    if (bdrv_is_read_only(bs) &&
        !(bs->open_flags & BDRV_O_NOCACHE)) {
        return client->st_blocks * 512;
    }

    task.bs = bs;
    task.st = &st;
    if (nfs_fstat_async(client->context, client->fh, nfs_get_allocated_file_size_cb,
                        &task) != 0) {
        return -ENOMEM;
    }

    nfs_set_events(client);
    BDRV_POLL_WHILE(bs, !task.complete);

    return (task.ret < 0 ? task.ret : st.st_blocks * 512);
}

static int nfs_file_truncate(BlockDriverState *bs, int64_t offset)
{
    NFSClient *client = bs->opaque;
    return nfs_ftruncate(client->context, client->fh, offset);
}

/* Note that this will not re-establish a connection with the NFS server
 * - it is effectively a NOP.  */
static int nfs_reopen_prepare(BDRVReopenState *state,
                              BlockReopenQueue *queue, Error **errp)
{
    NFSClient *client = state->bs->opaque;
    struct stat st;
    int ret = 0;

    if (state->flags & BDRV_O_RDWR && bdrv_is_read_only(state->bs)) {
        error_setg(errp, "Cannot open a read-only mount as read-write");
        return -EACCES;
    }

    if ((state->flags & BDRV_O_NOCACHE) && client->cache_used) {
        error_setg(errp, "Cannot disable cache if libnfs readahead or"
                         " pagecache is enabled");
        return -EINVAL;
    }

    /* Update cache for read-only reopens */
    if (!(state->flags & BDRV_O_RDWR)) {
        ret = nfs_fstat(client->context, client->fh, &st);
        if (ret < 0) {
            error_setg(errp, "Failed to fstat file: %s",
                       nfs_get_error(client->context));
            return ret;
        }
        client->st_blocks = st.st_blocks;
    }

    return 0;
}

static void nfs_refresh_filename(BlockDriverState *bs, QDict *options)
{
    NFSClient *client = bs->opaque;
    QDict *opts = qdict_new();
    QObject *server_qdict;
    Visitor *ov;

    qdict_put(opts, "driver", qstring_from_str("nfs"));

    if (client->uid && !client->gid) {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename),
                 "nfs://%s%s?uid=%" PRId64, client->server->host, client->path,
                 client->uid);
    } else if (!client->uid && client->gid) {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename),
                 "nfs://%s%s?gid=%" PRId64, client->server->host, client->path,
                 client->gid);
    } else if (client->uid && client->gid) {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename),
                 "nfs://%s%s?uid=%" PRId64 "&gid=%" PRId64,
                 client->server->host, client->path, client->uid, client->gid);
    } else {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename),
                 "nfs://%s%s", client->server->host, client->path);
    }

    ov = qobject_output_visitor_new(&server_qdict);
    visit_type_NFSServer(ov, NULL, &client->server, &error_abort);
    visit_complete(ov, &server_qdict);
    qdict_put_obj(opts, "server", server_qdict);
    qdict_put(opts, "path", qstring_from_str(client->path));

    if (client->uid) {
        qdict_put(opts, "user", qint_from_int(client->uid));
    }
    if (client->gid) {
        qdict_put(opts, "group", qint_from_int(client->gid));
    }
    if (client->tcp_syncnt) {
        qdict_put(opts, "tcp-syn-cnt",
                  qint_from_int(client->tcp_syncnt));
    }
    if (client->readahead) {
        qdict_put(opts, "readahead-size",
                  qint_from_int(client->readahead));
    }
    if (client->pagecache) {
        qdict_put(opts, "page-cache-size",
                  qint_from_int(client->pagecache));
    }
    if (client->debug) {
        qdict_put(opts, "debug", qint_from_int(client->debug));
    }

    visit_free(ov);
    qdict_flatten(opts);
    bs->full_open_options = opts;
}

#ifdef LIBNFS_FEATURE_PAGECACHE
static void nfs_invalidate_cache(BlockDriverState *bs,
                                 Error **errp)
{
    NFSClient *client = bs->opaque;
    nfs_pagecache_invalidate(client->context, client->fh);
}
#endif

static BlockDriver bdrv_nfs = {
    .format_name                    = "nfs",
    .protocol_name                  = "nfs",

    .instance_size                  = sizeof(NFSClient),
    .bdrv_parse_filename            = nfs_parse_filename,
    .create_opts                    = &nfs_create_opts,

    .bdrv_has_zero_init             = nfs_has_zero_init,
    .bdrv_get_allocated_file_size   = nfs_get_allocated_file_size,
    .bdrv_truncate                  = nfs_file_truncate,

    .bdrv_file_open                 = nfs_file_open,
    .bdrv_close                     = nfs_file_close,
    .bdrv_create                    = nfs_file_create,
    .bdrv_reopen_prepare            = nfs_reopen_prepare,

    .bdrv_co_preadv                 = nfs_co_preadv,
    .bdrv_co_pwritev                = nfs_co_pwritev,
    .bdrv_co_flush_to_disk          = nfs_co_flush,

    .bdrv_detach_aio_context        = nfs_detach_aio_context,
    .bdrv_attach_aio_context        = nfs_attach_aio_context,
    .bdrv_refresh_filename          = nfs_refresh_filename,

#ifdef LIBNFS_FEATURE_PAGECACHE
    .bdrv_invalidate_cache          = nfs_invalidate_cache,
#endif
};

static void nfs_block_init(void)
{
    bdrv_register(&bdrv_nfs);
}

block_init(nfs_block_init);
