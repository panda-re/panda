/*
 * Quorum Block filter
 *
 * Copyright (C) 2012-2014 Nodalink, EURL.
 *
 * Author:
 *   Benoît Canet <benoit.canet@irqsave.net>
 *
 * Based on the design and code of blkverify.c (Copyright (C) 2010 IBM, Corp)
 * and blkmirror.c (Copyright (C) 2011 Red Hat, Inc).
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "block/block_int.h"
#include "qapi/qmp/qbool.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qmp/qint.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qstring.h"
#include "qapi-event.h"
#include "crypto/hash.h"

#define HASH_LENGTH 32

#define QUORUM_OPT_VOTE_THRESHOLD "vote-threshold"
#define QUORUM_OPT_BLKVERIFY      "blkverify"
#define QUORUM_OPT_REWRITE        "rewrite-corrupted"
#define QUORUM_OPT_READ_PATTERN   "read-pattern"

/* This union holds a vote hash value */
typedef union QuorumVoteValue {
    uint8_t h[HASH_LENGTH];    /* SHA-256 hash */
    int64_t l;                 /* simpler 64 bits hash */
} QuorumVoteValue;

/* A vote item */
typedef struct QuorumVoteItem {
    int index;
    QLIST_ENTRY(QuorumVoteItem) next;
} QuorumVoteItem;

/* this structure is a vote version. A version is the set of votes sharing the
 * same vote value.
 * The set of votes will be tracked with the items field and its cardinality is
 * vote_count.
 */
typedef struct QuorumVoteVersion {
    QuorumVoteValue value;
    int index;
    int vote_count;
    QLIST_HEAD(, QuorumVoteItem) items;
    QLIST_ENTRY(QuorumVoteVersion) next;
} QuorumVoteVersion;

/* this structure holds a group of vote versions together */
typedef struct QuorumVotes {
    QLIST_HEAD(, QuorumVoteVersion) vote_list;
    bool (*compare)(QuorumVoteValue *a, QuorumVoteValue *b);
} QuorumVotes;

/* the following structure holds the state of one quorum instance */
typedef struct BDRVQuorumState {
    BdrvChild **children;  /* children BlockDriverStates */
    int num_children;      /* children count */
    unsigned next_child_index;  /* the index of the next child that should
                                 * be added
                                 */
    int threshold;         /* if less than threshold children reads gave the
                            * same result a quorum error occurs.
                            */
    bool is_blkverify;     /* true if the driver is in blkverify mode
                            * Writes are mirrored on two children devices.
                            * On reads the two children devices' contents are
                            * compared and if a difference is spotted its
                            * location is printed and the code aborts.
                            * It is useful to debug other block drivers by
                            * comparing them with a reference one.
                            */
    bool rewrite_corrupted;/* true if the driver must rewrite-on-read corrupted
                            * block if Quorum is reached.
                            */

    QuorumReadPattern read_pattern;
} BDRVQuorumState;

typedef struct QuorumAIOCB QuorumAIOCB;

/* Quorum will create one instance of the following structure per operation it
 * performs on its children.
 * So for each read/write operation coming from the upper layer there will be
 * $children_count QuorumChildRequest.
 */
typedef struct QuorumChildRequest {
    BlockDriverState *bs;
    QEMUIOVector qiov;
    uint8_t *buf;
    int ret;
    QuorumAIOCB *parent;
} QuorumChildRequest;

/* Quorum will use the following structure to track progress of each read/write
 * operation received by the upper layer.
 * This structure hold pointers to the QuorumChildRequest structures instances
 * used to do operations on each children and track overall progress.
 */
struct QuorumAIOCB {
    BlockDriverState *bs;
    Coroutine *co;

    /* Request metadata */
    uint64_t offset;
    uint64_t bytes;

    QEMUIOVector *qiov;         /* calling IOV */

    QuorumChildRequest *qcrs;   /* individual child requests */
    int count;                  /* number of completed AIOCB */
    int success_count;          /* number of successfully completed AIOCB */

    int rewrite_count;          /* number of replica to rewrite: count down to
                                 * zero once writes are fired
                                 */

    QuorumVotes votes;

    bool is_read;
    int vote_ret;
    int children_read;          /* how many children have been read from */
};

typedef struct QuorumCo {
    QuorumAIOCB *acb;
    int idx;
} QuorumCo;

static void quorum_aio_finalize(QuorumAIOCB *acb)
{
    g_free(acb->qcrs);
    g_free(acb);
}

static bool quorum_sha256_compare(QuorumVoteValue *a, QuorumVoteValue *b)
{
    return !memcmp(a->h, b->h, HASH_LENGTH);
}

static bool quorum_64bits_compare(QuorumVoteValue *a, QuorumVoteValue *b)
{
    return a->l == b->l;
}

static QuorumAIOCB *quorum_aio_get(BlockDriverState *bs,
                                   QEMUIOVector *qiov,
                                   uint64_t offset,
                                   uint64_t bytes)
{
    BDRVQuorumState *s = bs->opaque;
    QuorumAIOCB *acb = g_new(QuorumAIOCB, 1);
    int i;

    *acb = (QuorumAIOCB) {
        .co                 = qemu_coroutine_self(),
        .bs                 = bs,
        .offset             = offset,
        .bytes              = bytes,
        .qiov               = qiov,
        .votes.compare      = quorum_sha256_compare,
        .votes.vote_list    = QLIST_HEAD_INITIALIZER(acb.votes.vote_list),
    };

    acb->qcrs = g_new0(QuorumChildRequest, s->num_children);
    for (i = 0; i < s->num_children; i++) {
        acb->qcrs[i].buf = NULL;
        acb->qcrs[i].ret = 0;
        acb->qcrs[i].parent = acb;
    }

    return acb;
}

static void quorum_report_bad(QuorumOpType type, uint64_t offset,
                              uint64_t bytes, char *node_name, int ret)
{
    const char *msg = NULL;
    int64_t start_sector = offset / BDRV_SECTOR_SIZE;
    int64_t end_sector = DIV_ROUND_UP(offset + bytes, BDRV_SECTOR_SIZE);

    if (ret < 0) {
        msg = strerror(-ret);
    }

    qapi_event_send_quorum_report_bad(type, !!msg, msg, node_name, start_sector,
                                      end_sector - start_sector, &error_abort);
}

static void quorum_report_failure(QuorumAIOCB *acb)
{
    const char *reference = bdrv_get_device_or_node_name(acb->bs);
    int64_t start_sector = acb->offset / BDRV_SECTOR_SIZE;
    int64_t end_sector = DIV_ROUND_UP(acb->offset + acb->bytes,
                                      BDRV_SECTOR_SIZE);

    qapi_event_send_quorum_failure(reference, start_sector,
                                   end_sector - start_sector, &error_abort);
}

static int quorum_vote_error(QuorumAIOCB *acb);

static bool quorum_has_too_much_io_failed(QuorumAIOCB *acb)
{
    BDRVQuorumState *s = acb->bs->opaque;

    if (acb->success_count < s->threshold) {
        acb->vote_ret = quorum_vote_error(acb);
        quorum_report_failure(acb);
        return true;
    }

    return false;
}

static int read_fifo_child(QuorumAIOCB *acb);

static void quorum_copy_qiov(QEMUIOVector *dest, QEMUIOVector *source)
{
    int i;
    assert(dest->niov == source->niov);
    assert(dest->size == source->size);
    for (i = 0; i < source->niov; i++) {
        assert(dest->iov[i].iov_len == source->iov[i].iov_len);
        memcpy(dest->iov[i].iov_base,
               source->iov[i].iov_base,
               source->iov[i].iov_len);
    }
}

static void quorum_report_bad_acb(QuorumChildRequest *sacb, int ret)
{
    QuorumAIOCB *acb = sacb->parent;
    QuorumOpType type = acb->is_read ? QUORUM_OP_TYPE_READ : QUORUM_OP_TYPE_WRITE;
    quorum_report_bad(type, acb->offset, acb->bytes, sacb->bs->node_name, ret);
}

static void quorum_report_bad_versions(BDRVQuorumState *s,
                                       QuorumAIOCB *acb,
                                       QuorumVoteValue *value)
{
    QuorumVoteVersion *version;
    QuorumVoteItem *item;

    QLIST_FOREACH(version, &acb->votes.vote_list, next) {
        if (acb->votes.compare(&version->value, value)) {
            continue;
        }
        QLIST_FOREACH(item, &version->items, next) {
            quorum_report_bad(QUORUM_OP_TYPE_READ, acb->offset, acb->bytes,
                              s->children[item->index]->bs->node_name, 0);
        }
    }
}

static void quorum_rewrite_entry(void *opaque)
{
    QuorumCo *co = opaque;
    QuorumAIOCB *acb = co->acb;
    BDRVQuorumState *s = acb->bs->opaque;

    /* Ignore any errors, it's just a correction attempt for already
     * corrupted data. */
    bdrv_co_pwritev(s->children[co->idx], acb->offset, acb->bytes,
                    acb->qiov, 0);

    /* Wake up the caller after the last rewrite */
    acb->rewrite_count--;
    if (!acb->rewrite_count) {
        qemu_coroutine_enter_if_inactive(acb->co);
    }
}

static bool quorum_rewrite_bad_versions(QuorumAIOCB *acb,
                                        QuorumVoteValue *value)
{
    QuorumVoteVersion *version;
    QuorumVoteItem *item;
    int count = 0;

    /* first count the number of bad versions: done first to avoid concurrency
     * issues.
     */
    QLIST_FOREACH(version, &acb->votes.vote_list, next) {
        if (acb->votes.compare(&version->value, value)) {
            continue;
        }
        QLIST_FOREACH(item, &version->items, next) {
            count++;
        }
    }

    /* quorum_rewrite_entry will count down this to zero */
    acb->rewrite_count = count;

    /* now fire the correcting rewrites */
    QLIST_FOREACH(version, &acb->votes.vote_list, next) {
        if (acb->votes.compare(&version->value, value)) {
            continue;
        }
        QLIST_FOREACH(item, &version->items, next) {
            Coroutine *co;
            QuorumCo data = {
                .acb = acb,
                .idx = item->index,
            };

            co = qemu_coroutine_create(quorum_rewrite_entry, &data);
            qemu_coroutine_enter(co);
        }
    }

    /* return true if any rewrite is done else false */
    return count;
}

static void quorum_count_vote(QuorumVotes *votes,
                              QuorumVoteValue *value,
                              int index)
{
    QuorumVoteVersion *v = NULL, *version = NULL;
    QuorumVoteItem *item;

    /* look if we have something with this hash */
    QLIST_FOREACH(v, &votes->vote_list, next) {
        if (votes->compare(&v->value, value)) {
            version = v;
            break;
        }
    }

    /* It's a version not yet in the list add it */
    if (!version) {
        version = g_new0(QuorumVoteVersion, 1);
        QLIST_INIT(&version->items);
        memcpy(&version->value, value, sizeof(version->value));
        version->index = index;
        version->vote_count = 0;
        QLIST_INSERT_HEAD(&votes->vote_list, version, next);
    }

    version->vote_count++;

    item = g_new0(QuorumVoteItem, 1);
    item->index = index;
    QLIST_INSERT_HEAD(&version->items, item, next);
}

static void quorum_free_vote_list(QuorumVotes *votes)
{
    QuorumVoteVersion *version, *next_version;
    QuorumVoteItem *item, *next_item;

    QLIST_FOREACH_SAFE(version, &votes->vote_list, next, next_version) {
        QLIST_REMOVE(version, next);
        QLIST_FOREACH_SAFE(item, &version->items, next, next_item) {
            QLIST_REMOVE(item, next);
            g_free(item);
        }
        g_free(version);
    }
}

static int quorum_compute_hash(QuorumAIOCB *acb, int i, QuorumVoteValue *hash)
{
    QEMUIOVector *qiov = &acb->qcrs[i].qiov;
    size_t len = sizeof(hash->h);
    uint8_t *data = hash->h;

    /* XXX - would be nice if we could pass in the Error **
     * and propagate that back, but this quorum code is
     * restricted to just errno values currently */
    if (qcrypto_hash_bytesv(QCRYPTO_HASH_ALG_SHA256,
                            qiov->iov, qiov->niov,
                            &data, &len,
                            NULL) < 0) {
        return -EINVAL;
    }

    return 0;
}

static QuorumVoteVersion *quorum_get_vote_winner(QuorumVotes *votes)
{
    int max = 0;
    QuorumVoteVersion *candidate, *winner = NULL;

    QLIST_FOREACH(candidate, &votes->vote_list, next) {
        if (candidate->vote_count > max) {
            max = candidate->vote_count;
            winner = candidate;
        }
    }

    return winner;
}

/* qemu_iovec_compare is handy for blkverify mode because it returns the first
 * differing byte location. Yet it is handcoded to compare vectors one byte
 * after another so it does not benefit from the libc SIMD optimizations.
 * quorum_iovec_compare is written for speed and should be used in the non
 * blkverify mode of quorum.
 */
static bool quorum_iovec_compare(QEMUIOVector *a, QEMUIOVector *b)
{
    int i;
    int result;

    assert(a->niov == b->niov);
    for (i = 0; i < a->niov; i++) {
        assert(a->iov[i].iov_len == b->iov[i].iov_len);
        result = memcmp(a->iov[i].iov_base,
                        b->iov[i].iov_base,
                        a->iov[i].iov_len);
        if (result) {
            return false;
        }
    }

    return true;
}

static void GCC_FMT_ATTR(2, 3) quorum_err(QuorumAIOCB *acb,
                                          const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "quorum: offset=%" PRIu64 " bytes=%" PRIu64 " ",
            acb->offset, acb->bytes);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static bool quorum_compare(QuorumAIOCB *acb,
                           QEMUIOVector *a,
                           QEMUIOVector *b)
{
    BDRVQuorumState *s = acb->bs->opaque;
    ssize_t offset;

    /* This driver will replace blkverify in this particular case */
    if (s->is_blkverify) {
        offset = qemu_iovec_compare(a, b);
        if (offset != -1) {
            quorum_err(acb, "contents mismatch at offset %" PRIu64,
                       acb->offset + offset);
        }
        return true;
    }

    return quorum_iovec_compare(a, b);
}

/* Do a vote to get the error code */
static int quorum_vote_error(QuorumAIOCB *acb)
{
    BDRVQuorumState *s = acb->bs->opaque;
    QuorumVoteVersion *winner = NULL;
    QuorumVotes error_votes;
    QuorumVoteValue result_value;
    int i, ret = 0;
    bool error = false;

    QLIST_INIT(&error_votes.vote_list);
    error_votes.compare = quorum_64bits_compare;

    for (i = 0; i < s->num_children; i++) {
        ret = acb->qcrs[i].ret;
        if (ret) {
            error = true;
            result_value.l = ret;
            quorum_count_vote(&error_votes, &result_value, i);
        }
    }

    if (error) {
        winner = quorum_get_vote_winner(&error_votes);
        ret = winner->value.l;
    }

    quorum_free_vote_list(&error_votes);

    return ret;
}

static void quorum_vote(QuorumAIOCB *acb)
{
    bool quorum = true;
    int i, j, ret;
    QuorumVoteValue hash;
    BDRVQuorumState *s = acb->bs->opaque;
    QuorumVoteVersion *winner;

    if (quorum_has_too_much_io_failed(acb)) {
        return;
    }

    /* get the index of the first successful read */
    for (i = 0; i < s->num_children; i++) {
        if (!acb->qcrs[i].ret) {
            break;
        }
    }

    assert(i < s->num_children);

    /* compare this read with all other successful reads stopping at quorum
     * failure
     */
    for (j = i + 1; j < s->num_children; j++) {
        if (acb->qcrs[j].ret) {
            continue;
        }
        quorum = quorum_compare(acb, &acb->qcrs[i].qiov, &acb->qcrs[j].qiov);
        if (!quorum) {
            break;
       }
    }

    /* Every successful read agrees */
    if (quorum) {
        quorum_copy_qiov(acb->qiov, &acb->qcrs[i].qiov);
        return;
    }

    /* compute hashes for each successful read, also store indexes */
    for (i = 0; i < s->num_children; i++) {
        if (acb->qcrs[i].ret) {
            continue;
        }
        ret = quorum_compute_hash(acb, i, &hash);
        /* if ever the hash computation failed */
        if (ret < 0) {
            acb->vote_ret = ret;
            goto free_exit;
        }
        quorum_count_vote(&acb->votes, &hash, i);
    }

    /* vote to select the most represented version */
    winner = quorum_get_vote_winner(&acb->votes);

    /* if the winner count is smaller than threshold the read fails */
    if (winner->vote_count < s->threshold) {
        quorum_report_failure(acb);
        acb->vote_ret = -EIO;
        goto free_exit;
    }

    /* we have a winner: copy it */
    quorum_copy_qiov(acb->qiov, &acb->qcrs[winner->index].qiov);

    /* some versions are bad print them */
    quorum_report_bad_versions(s, acb, &winner->value);

    /* corruption correction is enabled */
    if (s->rewrite_corrupted) {
        quorum_rewrite_bad_versions(acb, &winner->value);
    }

free_exit:
    /* free lists */
    quorum_free_vote_list(&acb->votes);
}

static void read_quorum_children_entry(void *opaque)
{
    QuorumCo *co = opaque;
    QuorumAIOCB *acb = co->acb;
    BDRVQuorumState *s = acb->bs->opaque;
    int i = co->idx;
    QuorumChildRequest *sacb = &acb->qcrs[i];

    sacb->bs = s->children[i]->bs;
    sacb->ret = bdrv_co_preadv(s->children[i], acb->offset, acb->bytes,
                               &acb->qcrs[i].qiov, 0);

    if (sacb->ret == 0) {
        acb->success_count++;
    } else {
        quorum_report_bad_acb(sacb, sacb->ret);
    }

    acb->count++;
    assert(acb->count <= s->num_children);
    assert(acb->success_count <= s->num_children);

    /* Wake up the caller after the last read */
    if (acb->count == s->num_children) {
        qemu_coroutine_enter_if_inactive(acb->co);
    }
}

static int read_quorum_children(QuorumAIOCB *acb)
{
    BDRVQuorumState *s = acb->bs->opaque;
    int i, ret;

    acb->children_read = s->num_children;
    for (i = 0; i < s->num_children; i++) {
        acb->qcrs[i].buf = qemu_blockalign(s->children[i]->bs, acb->qiov->size);
        qemu_iovec_init(&acb->qcrs[i].qiov, acb->qiov->niov);
        qemu_iovec_clone(&acb->qcrs[i].qiov, acb->qiov, acb->qcrs[i].buf);
    }

    for (i = 0; i < s->num_children; i++) {
        Coroutine *co;
        QuorumCo data = {
            .acb = acb,
            .idx = i,
        };

        co = qemu_coroutine_create(read_quorum_children_entry, &data);
        qemu_coroutine_enter(co);
    }

    while (acb->count < s->num_children) {
        qemu_coroutine_yield();
    }

    /* Do the vote on read */
    quorum_vote(acb);
    for (i = 0; i < s->num_children; i++) {
        qemu_vfree(acb->qcrs[i].buf);
        qemu_iovec_destroy(&acb->qcrs[i].qiov);
    }

    while (acb->rewrite_count) {
        qemu_coroutine_yield();
    }

    ret = acb->vote_ret;

    return ret;
}

static int read_fifo_child(QuorumAIOCB *acb)
{
    BDRVQuorumState *s = acb->bs->opaque;
    int n, ret;

    /* We try to read the next child in FIFO order if we failed to read */
    do {
        n = acb->children_read++;
        acb->qcrs[n].bs = s->children[n]->bs;
        ret = bdrv_co_preadv(s->children[n], acb->offset, acb->bytes,
                             acb->qiov, 0);
        if (ret < 0) {
            quorum_report_bad_acb(&acb->qcrs[n], ret);
        }
    } while (ret < 0 && acb->children_read < s->num_children);

    /* FIXME: rewrite failed children if acb->children_read > 1? */

    return ret;
}

static int quorum_co_preadv(BlockDriverState *bs, uint64_t offset,
                            uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVQuorumState *s = bs->opaque;
    QuorumAIOCB *acb = quorum_aio_get(bs, qiov, offset, bytes);
    int ret;

    acb->is_read = true;
    acb->children_read = 0;

    if (s->read_pattern == QUORUM_READ_PATTERN_QUORUM) {
        ret = read_quorum_children(acb);
    } else {
        ret = read_fifo_child(acb);
    }
    quorum_aio_finalize(acb);

    return ret;
}

static void write_quorum_entry(void *opaque)
{
    QuorumCo *co = opaque;
    QuorumAIOCB *acb = co->acb;
    BDRVQuorumState *s = acb->bs->opaque;
    int i = co->idx;
    QuorumChildRequest *sacb = &acb->qcrs[i];

    sacb->bs = s->children[i]->bs;
    sacb->ret = bdrv_co_pwritev(s->children[i], acb->offset, acb->bytes,
                                acb->qiov, 0);
    if (sacb->ret == 0) {
        acb->success_count++;
    } else {
        quorum_report_bad_acb(sacb, sacb->ret);
    }
    acb->count++;
    assert(acb->count <= s->num_children);
    assert(acb->success_count <= s->num_children);

    /* Wake up the caller after the last write */
    if (acb->count == s->num_children) {
        qemu_coroutine_enter_if_inactive(acb->co);
    }
}

static int quorum_co_pwritev(BlockDriverState *bs, uint64_t offset,
                             uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    BDRVQuorumState *s = bs->opaque;
    QuorumAIOCB *acb = quorum_aio_get(bs, qiov, offset, bytes);
    int i, ret;

    for (i = 0; i < s->num_children; i++) {
        Coroutine *co;
        QuorumCo data = {
            .acb = acb,
            .idx = i,
        };

        co = qemu_coroutine_create(write_quorum_entry, &data);
        qemu_coroutine_enter(co);
    }

    while (acb->count < s->num_children) {
        qemu_coroutine_yield();
    }

    quorum_has_too_much_io_failed(acb);

    ret = acb->vote_ret;
    quorum_aio_finalize(acb);

    return ret;
}

static int64_t quorum_getlength(BlockDriverState *bs)
{
    BDRVQuorumState *s = bs->opaque;
    int64_t result;
    int i;

    /* check that all file have the same length */
    result = bdrv_getlength(s->children[0]->bs);
    if (result < 0) {
        return result;
    }
    for (i = 1; i < s->num_children; i++) {
        int64_t value = bdrv_getlength(s->children[i]->bs);
        if (value < 0) {
            return value;
        }
        if (value != result) {
            return -EIO;
        }
    }

    return result;
}

static coroutine_fn int quorum_co_flush(BlockDriverState *bs)
{
    BDRVQuorumState *s = bs->opaque;
    QuorumVoteVersion *winner = NULL;
    QuorumVotes error_votes;
    QuorumVoteValue result_value;
    int i;
    int result = 0;
    int success_count = 0;

    QLIST_INIT(&error_votes.vote_list);
    error_votes.compare = quorum_64bits_compare;

    for (i = 0; i < s->num_children; i++) {
        result = bdrv_co_flush(s->children[i]->bs);
        if (result) {
            quorum_report_bad(QUORUM_OP_TYPE_FLUSH, 0,
                              bdrv_getlength(s->children[i]->bs),
                              s->children[i]->bs->node_name, result);
            result_value.l = result;
            quorum_count_vote(&error_votes, &result_value, i);
        } else {
            success_count++;
        }
    }

    if (success_count >= s->threshold) {
        result = 0;
    } else {
        winner = quorum_get_vote_winner(&error_votes);
        result = winner->value.l;
    }
    quorum_free_vote_list(&error_votes);

    return result;
}

static bool quorum_recurse_is_first_non_filter(BlockDriverState *bs,
                                               BlockDriverState *candidate)
{
    BDRVQuorumState *s = bs->opaque;
    int i;

    for (i = 0; i < s->num_children; i++) {
        bool perm = bdrv_recurse_is_first_non_filter(s->children[i]->bs,
                                                     candidate);
        if (perm) {
            return true;
        }
    }

    return false;
}

static int quorum_valid_threshold(int threshold, int num_children, Error **errp)
{

    if (threshold < 1) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "vote-threshold", "value >= 1");
        return -ERANGE;
    }

    if (threshold > num_children) {
        error_setg(errp, "threshold may not exceed children count");
        return -ERANGE;
    }

    return 0;
}

static QemuOptsList quorum_runtime_opts = {
    .name = "quorum",
    .head = QTAILQ_HEAD_INITIALIZER(quorum_runtime_opts.head),
    .desc = {
        {
            .name = QUORUM_OPT_VOTE_THRESHOLD,
            .type = QEMU_OPT_NUMBER,
            .help = "The number of vote needed for reaching quorum",
        },
        {
            .name = QUORUM_OPT_BLKVERIFY,
            .type = QEMU_OPT_BOOL,
            .help = "Trigger block verify mode if set",
        },
        {
            .name = QUORUM_OPT_REWRITE,
            .type = QEMU_OPT_BOOL,
            .help = "Rewrite corrupted block on read quorum",
        },
        {
            .name = QUORUM_OPT_READ_PATTERN,
            .type = QEMU_OPT_STRING,
            .help = "Allowed pattern: quorum, fifo. Quorum is default",
        },
        { /* end of list */ }
    },
};

static int parse_read_pattern(const char *opt)
{
    int i;

    if (!opt) {
        /* Set quorum as default */
        return QUORUM_READ_PATTERN_QUORUM;
    }

    for (i = 0; i < QUORUM_READ_PATTERN__MAX; i++) {
        if (!strcmp(opt, QuorumReadPattern_lookup[i])) {
            return i;
        }
    }

    return -EINVAL;
}

static int quorum_open(BlockDriverState *bs, QDict *options, int flags,
                       Error **errp)
{
    BDRVQuorumState *s = bs->opaque;
    Error *local_err = NULL;
    QemuOpts *opts = NULL;
    bool *opened;
    int i;
    int ret = 0;

    qdict_flatten(options);

    /* count how many different children are present */
    s->num_children = qdict_array_entries(options, "children.");
    if (s->num_children < 0) {
        error_setg(&local_err, "Option children is not a valid array");
        ret = -EINVAL;
        goto exit;
    }
    if (s->num_children < 1) {
        error_setg(&local_err,
                   "Number of provided children must be 1 or more");
        ret = -EINVAL;
        goto exit;
    }

    opts = qemu_opts_create(&quorum_runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        ret = -EINVAL;
        goto exit;
    }

    s->threshold = qemu_opt_get_number(opts, QUORUM_OPT_VOTE_THRESHOLD, 0);
    /* and validate it against s->num_children */
    ret = quorum_valid_threshold(s->threshold, s->num_children, &local_err);
    if (ret < 0) {
        goto exit;
    }

    ret = parse_read_pattern(qemu_opt_get(opts, QUORUM_OPT_READ_PATTERN));
    if (ret < 0) {
        error_setg(&local_err, "Please set read-pattern as fifo or quorum");
        goto exit;
    }
    s->read_pattern = ret;

    if (s->read_pattern == QUORUM_READ_PATTERN_QUORUM) {
        /* is the driver in blkverify mode */
        if (qemu_opt_get_bool(opts, QUORUM_OPT_BLKVERIFY, false) &&
            s->num_children == 2 && s->threshold == 2) {
            s->is_blkverify = true;
        } else if (qemu_opt_get_bool(opts, QUORUM_OPT_BLKVERIFY, false)) {
            fprintf(stderr, "blkverify mode is set by setting blkverify=on "
                    "and using two files with vote_threshold=2\n");
        }

        s->rewrite_corrupted = qemu_opt_get_bool(opts, QUORUM_OPT_REWRITE,
                                                 false);
        if (s->rewrite_corrupted && s->is_blkverify) {
            error_setg(&local_err,
                       "rewrite-corrupted=on cannot be used with blkverify=on");
            ret = -EINVAL;
            goto exit;
        }
    }

    /* allocate the children array */
    s->children = g_new0(BdrvChild *, s->num_children);
    opened = g_new0(bool, s->num_children);

    for (i = 0; i < s->num_children; i++) {
        char indexstr[32];
        ret = snprintf(indexstr, 32, "children.%d", i);
        assert(ret < 32);

        s->children[i] = bdrv_open_child(NULL, options, indexstr, bs,
                                         &child_format, false, &local_err);
        if (local_err) {
            ret = -EINVAL;
            goto close_exit;
        }

        opened[i] = true;
    }
    s->next_child_index = s->num_children;

    g_free(opened);
    goto exit;

close_exit:
    /* cleanup on error */
    for (i = 0; i < s->num_children; i++) {
        if (!opened[i]) {
            continue;
        }
        bdrv_unref_child(bs, s->children[i]);
    }
    g_free(s->children);
    g_free(opened);
exit:
    qemu_opts_del(opts);
    /* propagate error */
    error_propagate(errp, local_err);
    return ret;
}

static void quorum_close(BlockDriverState *bs)
{
    BDRVQuorumState *s = bs->opaque;
    int i;

    for (i = 0; i < s->num_children; i++) {
        bdrv_unref_child(bs, s->children[i]);
    }

    g_free(s->children);
}

static void quorum_add_child(BlockDriverState *bs, BlockDriverState *child_bs,
                             Error **errp)
{
    BDRVQuorumState *s = bs->opaque;
    BdrvChild *child;
    char indexstr[32];
    int ret;

    assert(s->num_children <= INT_MAX / sizeof(BdrvChild *));
    if (s->num_children == INT_MAX / sizeof(BdrvChild *) ||
        s->next_child_index == UINT_MAX) {
        error_setg(errp, "Too many children");
        return;
    }

    ret = snprintf(indexstr, 32, "children.%u", s->next_child_index);
    if (ret < 0 || ret >= 32) {
        error_setg(errp, "cannot generate child name");
        return;
    }
    s->next_child_index++;

    bdrv_drained_begin(bs);

    /* We can safely add the child now */
    bdrv_ref(child_bs);

    child = bdrv_attach_child(bs, child_bs, indexstr, &child_format, errp);
    if (child == NULL) {
        s->next_child_index--;
        bdrv_unref(child_bs);
        goto out;
    }
    s->children = g_renew(BdrvChild *, s->children, s->num_children + 1);
    s->children[s->num_children++] = child;

out:
    bdrv_drained_end(bs);
}

static void quorum_del_child(BlockDriverState *bs, BdrvChild *child,
                             Error **errp)
{
    BDRVQuorumState *s = bs->opaque;
    int i;

    for (i = 0; i < s->num_children; i++) {
        if (s->children[i] == child) {
            break;
        }
    }

    /* we have checked it in bdrv_del_child() */
    assert(i < s->num_children);

    if (s->num_children <= s->threshold) {
        error_setg(errp,
            "The number of children cannot be lower than the vote threshold %d",
            s->threshold);
        return;
    }

    bdrv_drained_begin(bs);

    /* We can safely remove this child now */
    memmove(&s->children[i], &s->children[i + 1],
            (s->num_children - i - 1) * sizeof(BdrvChild *));
    s->children = g_renew(BdrvChild *, s->children, --s->num_children);
    bdrv_unref_child(bs, child);

    bdrv_drained_end(bs);
}

static void quorum_refresh_filename(BlockDriverState *bs, QDict *options)
{
    BDRVQuorumState *s = bs->opaque;
    QDict *opts;
    QList *children;
    int i;

    for (i = 0; i < s->num_children; i++) {
        bdrv_refresh_filename(s->children[i]->bs);
        if (!s->children[i]->bs->full_open_options) {
            return;
        }
    }

    children = qlist_new();
    for (i = 0; i < s->num_children; i++) {
        QINCREF(s->children[i]->bs->full_open_options);
        qlist_append(children, s->children[i]->bs->full_open_options);
    }

    opts = qdict_new();
    qdict_put_str(opts, "driver", "quorum");
    qdict_put_int(opts, QUORUM_OPT_VOTE_THRESHOLD, s->threshold);
    qdict_put_bool(opts, QUORUM_OPT_BLKVERIFY, s->is_blkverify);
    qdict_put_bool(opts, QUORUM_OPT_REWRITE, s->rewrite_corrupted);
    qdict_put(opts, "children", children);

    bs->full_open_options = opts;
}

static BlockDriver bdrv_quorum = {
    .format_name                        = "quorum",
    .protocol_name                      = "quorum",

    .instance_size                      = sizeof(BDRVQuorumState),

    .bdrv_file_open                     = quorum_open,
    .bdrv_close                         = quorum_close,
    .bdrv_refresh_filename              = quorum_refresh_filename,

    .bdrv_co_flush_to_disk              = quorum_co_flush,

    .bdrv_getlength                     = quorum_getlength,

    .bdrv_co_preadv                     = quorum_co_preadv,
    .bdrv_co_pwritev                    = quorum_co_pwritev,

    .bdrv_add_child                     = quorum_add_child,
    .bdrv_del_child                     = quorum_del_child,

    .bdrv_child_perm                    = bdrv_filter_default_perms,

    .is_filter                          = true,
    .bdrv_recurse_is_first_non_filter   = quorum_recurse_is_first_non_filter,
};

static void bdrv_quorum_init(void)
{
    if (!qcrypto_hash_supports(QCRYPTO_HASH_ALG_SHA256)) {
        /* SHA256 hash support is required for quorum device */
        return;
    }
    bdrv_register(&bdrv_quorum);
}

block_init(bdrv_quorum_init);
