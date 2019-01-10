/*
 * QEMU Block backends
 *
 * Copyright (C) 2014-2016 Red Hat, Inc.
 *
 * Authors:
 *  Markus Armbruster <armbru@redhat.com>,
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1
 * or later.  See the COPYING.LIB file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "sysemu/block-backend.h"
#include "block/block_int.h"
#include "block/blockjob.h"
#include "block/throttle-groups.h"
#include "sysemu/blockdev.h"
#include "sysemu/sysemu.h"
#include "qapi-event.h"
#include "qemu/id.h"
#include "trace.h"

/* Number of coroutines to reserve per attached device model */
#define COROUTINE_POOL_RESERVATION 64

#define NOT_DONE 0x7fffffff /* used while emulated sync operation in progress */

static AioContext *blk_aiocb_get_aio_context(BlockAIOCB *acb);

struct BlockBackend {
    char *name;
    int refcnt;
    BdrvChild *root;
    DriveInfo *legacy_dinfo;    /* null unless created by drive_new() */
    QTAILQ_ENTRY(BlockBackend) link;         /* for block_backends */
    QTAILQ_ENTRY(BlockBackend) monitor_link; /* for monitor_block_backends */
    BlockBackendPublic public;

    void *dev;                  /* attached device model, if any */
    bool legacy_dev;            /* true if dev is not a DeviceState */
    /* TODO change to DeviceState when all users are qdevified */
    const BlockDevOps *dev_ops;
    void *dev_opaque;

    /* the block size for which the guest device expects atomicity */
    int guest_block_size;

    /* If the BDS tree is removed, some of its options are stored here (which
     * can be used to restore those options in the new BDS on insert) */
    BlockBackendRootState root_state;

    bool enable_write_cache;

    /* I/O stats (display with "info blockstats"). */
    BlockAcctStats stats;

    BlockdevOnError on_read_error, on_write_error;
    bool iostatus_enabled;
    BlockDeviceIoStatus iostatus;

    uint64_t perm;
    uint64_t shared_perm;

    bool allow_write_beyond_eof;

    NotifierList remove_bs_notifiers, insert_bs_notifiers;

    int quiesce_counter;
};

typedef struct BlockBackendAIOCB {
    BlockAIOCB common;
    BlockBackend *blk;
    int ret;
} BlockBackendAIOCB;

static const AIOCBInfo block_backend_aiocb_info = {
    .get_aio_context = blk_aiocb_get_aio_context,
    .aiocb_size = sizeof(BlockBackendAIOCB),
};

static void drive_info_del(DriveInfo *dinfo);
static BlockBackend *bdrv_first_blk(BlockDriverState *bs);
static char *blk_get_attached_dev_id(BlockBackend *blk);

/* All BlockBackends */
static QTAILQ_HEAD(, BlockBackend) block_backends =
    QTAILQ_HEAD_INITIALIZER(block_backends);

/* All BlockBackends referenced by the monitor and which are iterated through by
 * blk_next() */
static QTAILQ_HEAD(, BlockBackend) monitor_block_backends =
    QTAILQ_HEAD_INITIALIZER(monitor_block_backends);

static void blk_root_inherit_options(int *child_flags, QDict *child_options,
                                     int parent_flags, QDict *parent_options)
{
    /* We're not supposed to call this function for root nodes */
    abort();
}
static void blk_root_drained_begin(BdrvChild *child);
static void blk_root_drained_end(BdrvChild *child);

static void blk_root_change_media(BdrvChild *child, bool load);
static void blk_root_resize(BdrvChild *child);

static char *blk_root_get_parent_desc(BdrvChild *child)
{
    BlockBackend *blk = child->opaque;
    char *dev_id;

    if (blk->name) {
        return g_strdup(blk->name);
    }

    dev_id = blk_get_attached_dev_id(blk);
    if (*dev_id) {
        return dev_id;
    } else {
        /* TODO Callback into the BB owner for something more detailed */
        g_free(dev_id);
        return g_strdup("a block device");
    }
}

static const char *blk_root_get_name(BdrvChild *child)
{
    return blk_name(child->opaque);
}

static const BdrvChildRole child_root = {
    .inherit_options    = blk_root_inherit_options,

    .change_media       = blk_root_change_media,
    .resize             = blk_root_resize,
    .get_name           = blk_root_get_name,
    .get_parent_desc    = blk_root_get_parent_desc,

    .drained_begin      = blk_root_drained_begin,
    .drained_end        = blk_root_drained_end,
};

/*
 * Create a new BlockBackend with a reference count of one.
 *
 * @perm is a bitmasks of BLK_PERM_* constants which describes the permissions
 * to request for a block driver node that is attached to this BlockBackend.
 * @shared_perm is a bitmask which describes which permissions may be granted
 * to other users of the attached node.
 * Both sets of permissions can be changed later using blk_set_perm().
 *
 * Return the new BlockBackend on success, null on failure.
 */
BlockBackend *blk_new(uint64_t perm, uint64_t shared_perm)
{
    BlockBackend *blk;

    blk = g_new0(BlockBackend, 1);
    blk->refcnt = 1;
    blk->perm = perm;
    blk->shared_perm = shared_perm;
    blk_set_enable_write_cache(blk, true);

    qemu_co_queue_init(&blk->public.throttled_reqs[0]);
    qemu_co_queue_init(&blk->public.throttled_reqs[1]);

    notifier_list_init(&blk->remove_bs_notifiers);
    notifier_list_init(&blk->insert_bs_notifiers);

    QTAILQ_INSERT_TAIL(&block_backends, blk, link);
    return blk;
}

/*
 * Creates a new BlockBackend, opens a new BlockDriverState, and connects both.
 *
 * Just as with bdrv_open(), after having called this function the reference to
 * @options belongs to the block layer (even on failure).
 *
 * TODO: Remove @filename and @flags; it should be possible to specify a whole
 * BDS tree just by specifying the @options QDict (or @reference,
 * alternatively). At the time of adding this function, this is not possible,
 * though, so callers of this function have to be able to specify @filename and
 * @flags.
 */
BlockBackend *blk_new_open(const char *filename, const char *reference,
                           QDict *options, int flags, Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    uint64_t perm;

    /* blk_new_open() is mainly used in .bdrv_create implementations and the
     * tools where sharing isn't a concern because the BDS stays private, so we
     * just request permission according to the flags.
     *
     * The exceptions are xen_disk and blockdev_init(); in these cases, the
     * caller of blk_new_open() doesn't make use of the permissions, but they
     * shouldn't hurt either. We can still share everything here because the
     * guest devices will add their own blockers if they can't share. */
    perm = BLK_PERM_CONSISTENT_READ;
    if (flags & BDRV_O_RDWR) {
        perm |= BLK_PERM_WRITE;
    }
    if (flags & BDRV_O_RESIZE) {
        perm |= BLK_PERM_RESIZE;
    }

    blk = blk_new(perm, BLK_PERM_ALL);
    bs = bdrv_open(filename, reference, options, flags, errp);
    if (!bs) {
        blk_unref(blk);
        return NULL;
    }

    blk->root = bdrv_root_attach_child(bs, "root", &child_root,
                                       perm, BLK_PERM_ALL, blk, errp);
    if (!blk->root) {
        bdrv_unref(bs);
        blk_unref(blk);
        return NULL;
    }

    return blk;
}

static void blk_delete(BlockBackend *blk)
{
    assert(!blk->refcnt);
    assert(!blk->name);
    assert(!blk->dev);
    if (blk->root) {
        blk_remove_bs(blk);
    }
    assert(QLIST_EMPTY(&blk->remove_bs_notifiers.notifiers));
    assert(QLIST_EMPTY(&blk->insert_bs_notifiers.notifiers));
    QTAILQ_REMOVE(&block_backends, blk, link);
    drive_info_del(blk->legacy_dinfo);
    block_acct_cleanup(&blk->stats);
    g_free(blk);
}

static void drive_info_del(DriveInfo *dinfo)
{
    if (!dinfo) {
        return;
    }
    qemu_opts_del(dinfo->opts);
    g_free(dinfo->serial);
    g_free(dinfo);
}

int blk_get_refcnt(BlockBackend *blk)
{
    return blk ? blk->refcnt : 0;
}

/*
 * Increment @blk's reference count.
 * @blk must not be null.
 */
void blk_ref(BlockBackend *blk)
{
    blk->refcnt++;
}

/*
 * Decrement @blk's reference count.
 * If this drops it to zero, destroy @blk.
 * For convenience, do nothing if @blk is null.
 */
void blk_unref(BlockBackend *blk)
{
    if (blk) {
        assert(blk->refcnt > 0);
        if (!--blk->refcnt) {
            blk_delete(blk);
        }
    }
}

/*
 * Behaves similarly to blk_next() but iterates over all BlockBackends, even the
 * ones which are hidden (i.e. are not referenced by the monitor).
 */
static BlockBackend *blk_all_next(BlockBackend *blk)
{
    return blk ? QTAILQ_NEXT(blk, link)
               : QTAILQ_FIRST(&block_backends);
}

void blk_remove_all_bs(void)
{
    BlockBackend *blk = NULL;

    while ((blk = blk_all_next(blk)) != NULL) {
        AioContext *ctx = blk_get_aio_context(blk);

        aio_context_acquire(ctx);
        if (blk->root) {
            blk_remove_bs(blk);
        }
        aio_context_release(ctx);
    }
}

/*
 * Return the monitor-owned BlockBackend after @blk.
 * If @blk is null, return the first one.
 * Else, return @blk's next sibling, which may be null.
 *
 * To iterate over all BlockBackends, do
 * for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
 *     ...
 * }
 */
BlockBackend *blk_next(BlockBackend *blk)
{
    return blk ? QTAILQ_NEXT(blk, monitor_link)
               : QTAILQ_FIRST(&monitor_block_backends);
}

/* Iterates over all top-level BlockDriverStates, i.e. BDSs that are owned by
 * the monitor or attached to a BlockBackend */
BlockDriverState *bdrv_next(BdrvNextIterator *it)
{
    BlockDriverState *bs;

    /* First, return all root nodes of BlockBackends. In order to avoid
     * returning a BDS twice when multiple BBs refer to it, we only return it
     * if the BB is the first one in the parent list of the BDS. */
    if (it->phase == BDRV_NEXT_BACKEND_ROOTS) {
        do {
            it->blk = blk_all_next(it->blk);
            bs = it->blk ? blk_bs(it->blk) : NULL;
        } while (it->blk && (bs == NULL || bdrv_first_blk(bs) != it->blk));

        if (bs) {
            return bs;
        }
        it->phase = BDRV_NEXT_MONITOR_OWNED;
    }

    /* Then return the monitor-owned BDSes without a BB attached. Ignore all
     * BDSes that are attached to a BlockBackend here; they have been handled
     * by the above block already */
    do {
        it->bs = bdrv_next_monitor_owned(it->bs);
        bs = it->bs;
    } while (bs && bdrv_has_blk(bs));

    return bs;
}

BlockDriverState *bdrv_first(BdrvNextIterator *it)
{
    *it = (BdrvNextIterator) {
        .phase = BDRV_NEXT_BACKEND_ROOTS,
    };

    return bdrv_next(it);
}

/*
 * Add a BlockBackend into the list of backends referenced by the monitor, with
 * the given @name acting as the handle for the monitor.
 * Strictly for use by blockdev.c.
 *
 * @name must not be null or empty.
 *
 * Returns true on success and false on failure. In the latter case, an Error
 * object is returned through @errp.
 */
bool monitor_add_blk(BlockBackend *blk, const char *name, Error **errp)
{
    assert(!blk->name);
    assert(name && name[0]);

    if (!id_wellformed(name)) {
        error_setg(errp, "Invalid device name");
        return false;
    }
    if (blk_by_name(name)) {
        error_setg(errp, "Device with id '%s' already exists", name);
        return false;
    }
    if (bdrv_find_node(name)) {
        error_setg(errp,
                   "Device name '%s' conflicts with an existing node name",
                   name);
        return false;
    }

    blk->name = g_strdup(name);
    QTAILQ_INSERT_TAIL(&monitor_block_backends, blk, monitor_link);
    return true;
}

/*
 * Remove a BlockBackend from the list of backends referenced by the monitor.
 * Strictly for use by blockdev.c.
 */
void monitor_remove_blk(BlockBackend *blk)
{
    if (!blk->name) {
        return;
    }

    QTAILQ_REMOVE(&monitor_block_backends, blk, monitor_link);
    g_free(blk->name);
    blk->name = NULL;
}

/*
 * Return @blk's name, a non-null string.
 * Returns an empty string iff @blk is not referenced by the monitor.
 */
const char *blk_name(BlockBackend *blk)
{
    return blk->name ?: "";
}

/*
 * Return the BlockBackend with name @name if it exists, else null.
 * @name must not be null.
 */
BlockBackend *blk_by_name(const char *name)
{
    BlockBackend *blk = NULL;

    assert(name);
    while ((blk = blk_next(blk)) != NULL) {
        if (!strcmp(name, blk->name)) {
            return blk;
        }
    }
    return NULL;
}

/*
 * Return the BlockDriverState attached to @blk if any, else null.
 */
BlockDriverState *blk_bs(BlockBackend *blk)
{
    return blk->root ? blk->root->bs : NULL;
}

static BlockBackend *bdrv_first_blk(BlockDriverState *bs)
{
    BdrvChild *child;
    QLIST_FOREACH(child, &bs->parents, next_parent) {
        if (child->role == &child_root) {
            return child->opaque;
        }
    }

    return NULL;
}

/*
 * Returns true if @bs has an associated BlockBackend.
 */
bool bdrv_has_blk(BlockDriverState *bs)
{
    return bdrv_first_blk(bs) != NULL;
}

/*
 * Returns true if @bs has only BlockBackends as parents.
 */
bool bdrv_is_root_node(BlockDriverState *bs)
{
    BdrvChild *c;

    QLIST_FOREACH(c, &bs->parents, next_parent) {
        if (c->role != &child_root) {
            return false;
        }
    }

    return true;
}

/*
 * Return @blk's DriveInfo if any, else null.
 */
DriveInfo *blk_legacy_dinfo(BlockBackend *blk)
{
    return blk->legacy_dinfo;
}

/*
 * Set @blk's DriveInfo to @dinfo, and return it.
 * @blk must not have a DriveInfo set already.
 * No other BlockBackend may have the same DriveInfo set.
 */
DriveInfo *blk_set_legacy_dinfo(BlockBackend *blk, DriveInfo *dinfo)
{
    assert(!blk->legacy_dinfo);
    return blk->legacy_dinfo = dinfo;
}

/*
 * Return the BlockBackend with DriveInfo @dinfo.
 * It must exist.
 */
BlockBackend *blk_by_legacy_dinfo(DriveInfo *dinfo)
{
    BlockBackend *blk = NULL;

    while ((blk = blk_next(blk)) != NULL) {
        if (blk->legacy_dinfo == dinfo) {
            return blk;
        }
    }
    abort();
}

/*
 * Returns a pointer to the publicly accessible fields of @blk.
 */
BlockBackendPublic *blk_get_public(BlockBackend *blk)
{
    return &blk->public;
}

/*
 * Returns a BlockBackend given the associated @public fields.
 */
BlockBackend *blk_by_public(BlockBackendPublic *public)
{
    return container_of(public, BlockBackend, public);
}

/*
 * Disassociates the currently associated BlockDriverState from @blk.
 */
void blk_remove_bs(BlockBackend *blk)
{
    notifier_list_notify(&blk->remove_bs_notifiers, blk);
    if (blk->public.throttle_state) {
        throttle_timers_detach_aio_context(&blk->public.throttle_timers);
    }

    blk_update_root_state(blk);

    bdrv_root_unref_child(blk->root);
    blk->root = NULL;
}

/*
 * Associates a new BlockDriverState with @blk.
 */
int blk_insert_bs(BlockBackend *blk, BlockDriverState *bs, Error **errp)
{
    blk->root = bdrv_root_attach_child(bs, "root", &child_root,
                                       blk->perm, blk->shared_perm, blk, errp);
    if (blk->root == NULL) {
        return -EPERM;
    }
    bdrv_ref(bs);

    notifier_list_notify(&blk->insert_bs_notifiers, blk);
    if (blk->public.throttle_state) {
        throttle_timers_attach_aio_context(
            &blk->public.throttle_timers, bdrv_get_aio_context(bs));
    }

    return 0;
}

/*
 * Sets the permission bitmasks that the user of the BlockBackend needs.
 */
int blk_set_perm(BlockBackend *blk, uint64_t perm, uint64_t shared_perm,
                 Error **errp)
{
    int ret;

    if (blk->root) {
        ret = bdrv_child_try_set_perm(blk->root, perm, shared_perm, errp);
        if (ret < 0) {
            return ret;
        }
    }

    blk->perm = perm;
    blk->shared_perm = shared_perm;

    return 0;
}

void blk_get_perm(BlockBackend *blk, uint64_t *perm, uint64_t *shared_perm)
{
    *perm = blk->perm;
    *shared_perm = blk->shared_perm;
}

static int blk_do_attach_dev(BlockBackend *blk, void *dev)
{
    if (blk->dev) {
        return -EBUSY;
    }
    blk_ref(blk);
    blk->dev = dev;
    blk->legacy_dev = false;
    blk_iostatus_reset(blk);
    return 0;
}

/*
 * Attach device model @dev to @blk.
 * Return 0 on success, -EBUSY when a device model is attached already.
 */
int blk_attach_dev(BlockBackend *blk, DeviceState *dev)
{
    return blk_do_attach_dev(blk, dev);
}

/*
 * Attach device model @dev to @blk.
 * @blk must not have a device model attached already.
 * TODO qdevified devices don't use this, remove when devices are qdevified
 */
void blk_attach_dev_legacy(BlockBackend *blk, void *dev)
{
    if (blk_do_attach_dev(blk, dev) < 0) {
        abort();
    }
    blk->legacy_dev = true;
}

/*
 * Detach device model @dev from @blk.
 * @dev must be currently attached to @blk.
 */
void blk_detach_dev(BlockBackend *blk, void *dev)
/* TODO change to DeviceState *dev when all users are qdevified */
{
    assert(blk->dev == dev);
    blk->dev = NULL;
    blk->dev_ops = NULL;
    blk->dev_opaque = NULL;
    blk->guest_block_size = 512;
    blk_set_perm(blk, 0, BLK_PERM_ALL, &error_abort);
    blk_unref(blk);
}

/*
 * Return the device model attached to @blk if any, else null.
 */
void *blk_get_attached_dev(BlockBackend *blk)
/* TODO change to return DeviceState * when all users are qdevified */
{
    return blk->dev;
}

/* Return the qdev ID, or if no ID is assigned the QOM path, of the block
 * device attached to the BlockBackend. */
static char *blk_get_attached_dev_id(BlockBackend *blk)
{
    DeviceState *dev;

    assert(!blk->legacy_dev);
    dev = blk->dev;

    if (!dev) {
        return g_strdup("");
    } else if (dev->id) {
        return g_strdup(dev->id);
    }
    return object_get_canonical_path(OBJECT(dev));
}

/*
 * Return the BlockBackend which has the device model @dev attached if it
 * exists, else null.
 *
 * @dev must not be null.
 */
BlockBackend *blk_by_dev(void *dev)
{
    BlockBackend *blk = NULL;

    assert(dev != NULL);
    while ((blk = blk_all_next(blk)) != NULL) {
        if (blk->dev == dev) {
            return blk;
        }
    }
    return NULL;
}

/*
 * Set @blk's device model callbacks to @ops.
 * @opaque is the opaque argument to pass to the callbacks.
 * This is for use by device models.
 */
void blk_set_dev_ops(BlockBackend *blk, const BlockDevOps *ops,
                     void *opaque)
{
    /* All drivers that use blk_set_dev_ops() are qdevified and we want to keep
     * it that way, so we can assume blk->dev, if present, is a DeviceState if
     * blk->dev_ops is set. Non-device users may use dev_ops without device. */
    assert(!blk->legacy_dev);

    blk->dev_ops = ops;
    blk->dev_opaque = opaque;

    /* Are we currently quiesced? Should we enforce this right now? */
    if (blk->quiesce_counter && ops->drained_begin) {
        ops->drained_begin(opaque);
    }
}

/*
 * Notify @blk's attached device model of media change.
 *
 * If @load is true, notify of media load. This action can fail, meaning that
 * the medium cannot be loaded. @errp is set then.
 *
 * If @load is false, notify of media eject. This can never fail.
 *
 * Also send DEVICE_TRAY_MOVED events as appropriate.
 */
void blk_dev_change_media_cb(BlockBackend *blk, bool load, Error **errp)
{
    if (blk->dev_ops && blk->dev_ops->change_media_cb) {
        bool tray_was_open, tray_is_open;
        Error *local_err = NULL;

        assert(!blk->legacy_dev);

        tray_was_open = blk_dev_is_tray_open(blk);
        blk->dev_ops->change_media_cb(blk->dev_opaque, load, &local_err);
        if (local_err) {
            assert(load == true);
            error_propagate(errp, local_err);
            return;
        }
        tray_is_open = blk_dev_is_tray_open(blk);

        if (tray_was_open != tray_is_open) {
            char *id = blk_get_attached_dev_id(blk);
            qapi_event_send_device_tray_moved(blk_name(blk), id, tray_is_open,
                                              &error_abort);
            g_free(id);
        }
    }
}

static void blk_root_change_media(BdrvChild *child, bool load)
{
    blk_dev_change_media_cb(child->opaque, load, NULL);
}

/*
 * Does @blk's attached device model have removable media?
 * %true if no device model is attached.
 */
bool blk_dev_has_removable_media(BlockBackend *blk)
{
    return !blk->dev || (blk->dev_ops && blk->dev_ops->change_media_cb);
}

/*
 * Does @blk's attached device model have a tray?
 */
bool blk_dev_has_tray(BlockBackend *blk)
{
    return blk->dev_ops && blk->dev_ops->is_tray_open;
}

/*
 * Notify @blk's attached device model of a media eject request.
 * If @force is true, the medium is about to be yanked out forcefully.
 */
void blk_dev_eject_request(BlockBackend *blk, bool force)
{
    if (blk->dev_ops && blk->dev_ops->eject_request_cb) {
        blk->dev_ops->eject_request_cb(blk->dev_opaque, force);
    }
}

/*
 * Does @blk's attached device model have a tray, and is it open?
 */
bool blk_dev_is_tray_open(BlockBackend *blk)
{
    if (blk_dev_has_tray(blk)) {
        return blk->dev_ops->is_tray_open(blk->dev_opaque);
    }
    return false;
}

/*
 * Does @blk's attached device model have the medium locked?
 * %false if the device model has no such lock.
 */
bool blk_dev_is_medium_locked(BlockBackend *blk)
{
    if (blk->dev_ops && blk->dev_ops->is_medium_locked) {
        return blk->dev_ops->is_medium_locked(blk->dev_opaque);
    }
    return false;
}

/*
 * Notify @blk's attached device model of a backend size change.
 */
static void blk_root_resize(BdrvChild *child)
{
    BlockBackend *blk = child->opaque;

    if (blk->dev_ops && blk->dev_ops->resize_cb) {
        blk->dev_ops->resize_cb(blk->dev_opaque);
    }
}

void blk_iostatus_enable(BlockBackend *blk)
{
    blk->iostatus_enabled = true;
    blk->iostatus = BLOCK_DEVICE_IO_STATUS_OK;
}

/* The I/O status is only enabled if the drive explicitly
 * enables it _and_ the VM is configured to stop on errors */
bool blk_iostatus_is_enabled(const BlockBackend *blk)
{
    return (blk->iostatus_enabled &&
           (blk->on_write_error == BLOCKDEV_ON_ERROR_ENOSPC ||
            blk->on_write_error == BLOCKDEV_ON_ERROR_STOP   ||
            blk->on_read_error == BLOCKDEV_ON_ERROR_STOP));
}

BlockDeviceIoStatus blk_iostatus(const BlockBackend *blk)
{
    return blk->iostatus;
}

void blk_iostatus_disable(BlockBackend *blk)
{
    blk->iostatus_enabled = false;
}

void blk_iostatus_reset(BlockBackend *blk)
{
    if (blk_iostatus_is_enabled(blk)) {
        BlockDriverState *bs = blk_bs(blk);
        blk->iostatus = BLOCK_DEVICE_IO_STATUS_OK;
        if (bs && bs->job) {
            block_job_iostatus_reset(bs->job);
        }
    }
}

void blk_iostatus_set_err(BlockBackend *blk, int error)
{
    assert(blk_iostatus_is_enabled(blk));
    if (blk->iostatus == BLOCK_DEVICE_IO_STATUS_OK) {
        blk->iostatus = error == ENOSPC ? BLOCK_DEVICE_IO_STATUS_NOSPACE :
                                          BLOCK_DEVICE_IO_STATUS_FAILED;
    }
}

void blk_set_allow_write_beyond_eof(BlockBackend *blk, bool allow)
{
    blk->allow_write_beyond_eof = allow;
}

static int blk_check_byte_request(BlockBackend *blk, int64_t offset,
                                  size_t size)
{
    int64_t len;

    if (size > INT_MAX) {
        return -EIO;
    }

    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    if (offset < 0) {
        return -EIO;
    }

    if (!blk->allow_write_beyond_eof) {
        len = blk_getlength(blk);
        if (len < 0) {
            return len;
        }

        if (offset > len || len - offset < size) {
            return -EIO;
        }
    }

    return 0;
}

int coroutine_fn blk_co_preadv(BlockBackend *blk, int64_t offset,
                               unsigned int bytes, QEMUIOVector *qiov,
                               BdrvRequestFlags flags)
{
    int ret;
    BlockDriverState *bs = blk_bs(blk);

    trace_blk_co_preadv(blk, bs, offset, bytes, flags);

    ret = blk_check_byte_request(blk, offset, bytes);
    if (ret < 0) {
        return ret;
    }

    bdrv_inc_in_flight(bs);

    /* throttling disk I/O */
    if (blk->public.throttle_state) {
        throttle_group_co_io_limits_intercept(blk, bytes, false);
    }

    ret = bdrv_co_preadv(blk->root, offset, bytes, qiov, flags);
    bdrv_dec_in_flight(bs);
    return ret;
}

int coroutine_fn blk_co_pwritev(BlockBackend *blk, int64_t offset,
                                unsigned int bytes, QEMUIOVector *qiov,
                                BdrvRequestFlags flags)
{
    int ret;
    BlockDriverState *bs = blk_bs(blk);

    trace_blk_co_pwritev(blk, bs, offset, bytes, flags);

    ret = blk_check_byte_request(blk, offset, bytes);
    if (ret < 0) {
        return ret;
    }

    bdrv_inc_in_flight(bs);

    /* throttling disk I/O */
    if (blk->public.throttle_state) {
        throttle_group_co_io_limits_intercept(blk, bytes, true);
    }

    if (!blk->enable_write_cache) {
        flags |= BDRV_REQ_FUA;
    }

    ret = bdrv_co_pwritev(blk->root, offset, bytes, qiov, flags);
    bdrv_dec_in_flight(bs);
    return ret;
}

typedef struct BlkRwCo {
    BlockBackend *blk;
    int64_t offset;
    QEMUIOVector *qiov;
    int ret;
    BdrvRequestFlags flags;
} BlkRwCo;

static void blk_read_entry(void *opaque)
{
    BlkRwCo *rwco = opaque;

    rwco->ret = blk_co_preadv(rwco->blk, rwco->offset, rwco->qiov->size,
                              rwco->qiov, rwco->flags);
}

static void blk_write_entry(void *opaque)
{
    BlkRwCo *rwco = opaque;

    rwco->ret = blk_co_pwritev(rwco->blk, rwco->offset, rwco->qiov->size,
                               rwco->qiov, rwco->flags);
}

static int blk_prw(BlockBackend *blk, int64_t offset, uint8_t *buf,
                   int64_t bytes, CoroutineEntry co_entry,
                   BdrvRequestFlags flags)
{
    QEMUIOVector qiov;
    struct iovec iov;
    BlkRwCo rwco;

    iov = (struct iovec) {
        .iov_base = buf,
        .iov_len = bytes,
    };
    qemu_iovec_init_external(&qiov, &iov, 1);

    rwco = (BlkRwCo) {
        .blk    = blk,
        .offset = offset,
        .qiov   = &qiov,
        .flags  = flags,
        .ret    = NOT_DONE,
    };

    if (qemu_in_coroutine()) {
        /* Fast-path if already in coroutine context */
        co_entry(&rwco);
    } else {
        Coroutine *co = qemu_coroutine_create(co_entry, &rwco);
        qemu_coroutine_enter(co);
        BDRV_POLL_WHILE(blk_bs(blk), rwco.ret == NOT_DONE);
    }

    return rwco.ret;
}

int blk_pread_unthrottled(BlockBackend *blk, int64_t offset, uint8_t *buf,
                          int count)
{
    int ret;

    ret = blk_check_byte_request(blk, offset, count);
    if (ret < 0) {
        return ret;
    }

    blk_root_drained_begin(blk->root);
    ret = blk_pread(blk, offset, buf, count);
    blk_root_drained_end(blk->root);
    return ret;
}

int blk_pwrite_zeroes(BlockBackend *blk, int64_t offset,
                      int count, BdrvRequestFlags flags)
{
    return blk_prw(blk, offset, NULL, count, blk_write_entry,
                   flags | BDRV_REQ_ZERO_WRITE);
}

int blk_make_zero(BlockBackend *blk, BdrvRequestFlags flags)
{
    return bdrv_make_zero(blk->root, flags);
}

static void error_callback_bh(void *opaque)
{
    struct BlockBackendAIOCB *acb = opaque;

    bdrv_dec_in_flight(acb->common.bs);
    acb->common.cb(acb->common.opaque, acb->ret);
    qemu_aio_unref(acb);
}

BlockAIOCB *blk_abort_aio_request(BlockBackend *blk,
                                  BlockCompletionFunc *cb,
                                  void *opaque, int ret)
{
    struct BlockBackendAIOCB *acb;

    bdrv_inc_in_flight(blk_bs(blk));
    acb = blk_aio_get(&block_backend_aiocb_info, blk, cb, opaque);
    acb->blk = blk;
    acb->ret = ret;

    aio_bh_schedule_oneshot(blk_get_aio_context(blk), error_callback_bh, acb);
    return &acb->common;
}

typedef struct BlkAioEmAIOCB {
    BlockAIOCB common;
    BlkRwCo rwco;
    int bytes;
    bool has_returned;
} BlkAioEmAIOCB;

static const AIOCBInfo blk_aio_em_aiocb_info = {
    .aiocb_size         = sizeof(BlkAioEmAIOCB),
};

static void blk_aio_complete(BlkAioEmAIOCB *acb)
{
    if (acb->has_returned) {
        bdrv_dec_in_flight(acb->common.bs);
        acb->common.cb(acb->common.opaque, acb->rwco.ret);
        qemu_aio_unref(acb);
    }
}

static void blk_aio_complete_bh(void *opaque)
{
    BlkAioEmAIOCB *acb = opaque;
    assert(acb->has_returned);
    blk_aio_complete(acb);
}

static BlockAIOCB *blk_aio_prwv(BlockBackend *blk, int64_t offset, int bytes,
                                QEMUIOVector *qiov, CoroutineEntry co_entry,
                                BdrvRequestFlags flags,
                                BlockCompletionFunc *cb, void *opaque)
{
    BlkAioEmAIOCB *acb;
    Coroutine *co;

    bdrv_inc_in_flight(blk_bs(blk));
    acb = blk_aio_get(&blk_aio_em_aiocb_info, blk, cb, opaque);
    acb->rwco = (BlkRwCo) {
        .blk    = blk,
        .offset = offset,
        .qiov   = qiov,
        .flags  = flags,
        .ret    = NOT_DONE,
    };
    acb->bytes = bytes;
    acb->has_returned = false;

    co = qemu_coroutine_create(co_entry, acb);
    qemu_coroutine_enter(co);

    acb->has_returned = true;
    if (acb->rwco.ret != NOT_DONE) {
        aio_bh_schedule_oneshot(blk_get_aio_context(blk),
                                blk_aio_complete_bh, acb);
    }

    return &acb->common;
}

static void blk_aio_read_entry(void *opaque)
{
    BlkAioEmAIOCB *acb = opaque;
    BlkRwCo *rwco = &acb->rwco;

    assert(rwco->qiov->size == acb->bytes);
    rwco->ret = blk_co_preadv(rwco->blk, rwco->offset, acb->bytes,
                              rwco->qiov, rwco->flags);
    blk_aio_complete(acb);
}

static void blk_aio_write_entry(void *opaque)
{
    BlkAioEmAIOCB *acb = opaque;
    BlkRwCo *rwco = &acb->rwco;

    assert(!rwco->qiov || rwco->qiov->size == acb->bytes);
    rwco->ret = blk_co_pwritev(rwco->blk, rwco->offset, acb->bytes,
                               rwco->qiov, rwco->flags);
    blk_aio_complete(acb);
}

BlockAIOCB *blk_aio_pwrite_zeroes(BlockBackend *blk, int64_t offset,
                                  int count, BdrvRequestFlags flags,
                                  BlockCompletionFunc *cb, void *opaque)
{
    return blk_aio_prwv(blk, offset, count, NULL, blk_aio_write_entry,
                        flags | BDRV_REQ_ZERO_WRITE, cb, opaque);
}

int blk_pread(BlockBackend *blk, int64_t offset, void *buf, int count)
{
    int ret = blk_prw(blk, offset, buf, count, blk_read_entry, 0);
    if (ret < 0) {
        return ret;
    }
    return count;
}

int blk_pwrite(BlockBackend *blk, int64_t offset, const void *buf, int count,
               BdrvRequestFlags flags)
{
    int ret = blk_prw(blk, offset, (void *) buf, count, blk_write_entry,
                      flags);
    if (ret < 0) {
        return ret;
    }
    return count;
}

int64_t blk_getlength(BlockBackend *blk)
{
    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    return bdrv_getlength(blk_bs(blk));
}

void blk_get_geometry(BlockBackend *blk, uint64_t *nb_sectors_ptr)
{
    if (!blk_bs(blk)) {
        *nb_sectors_ptr = 0;
    } else {
        bdrv_get_geometry(blk_bs(blk), nb_sectors_ptr);
    }
}

int64_t blk_nb_sectors(BlockBackend *blk)
{
    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    return bdrv_nb_sectors(blk_bs(blk));
}

BlockAIOCB *blk_aio_preadv(BlockBackend *blk, int64_t offset,
                           QEMUIOVector *qiov, BdrvRequestFlags flags,
                           BlockCompletionFunc *cb, void *opaque)
{
    return blk_aio_prwv(blk, offset, qiov->size, qiov,
                        blk_aio_read_entry, flags, cb, opaque);
}

BlockAIOCB *blk_aio_pwritev(BlockBackend *blk, int64_t offset,
                            QEMUIOVector *qiov, BdrvRequestFlags flags,
                            BlockCompletionFunc *cb, void *opaque)
{
    return blk_aio_prwv(blk, offset, qiov->size, qiov,
                        blk_aio_write_entry, flags, cb, opaque);
}

static void blk_aio_flush_entry(void *opaque)
{
    BlkAioEmAIOCB *acb = opaque;
    BlkRwCo *rwco = &acb->rwco;

    rwco->ret = blk_co_flush(rwco->blk);
    blk_aio_complete(acb);
}

BlockAIOCB *blk_aio_flush(BlockBackend *blk,
                          BlockCompletionFunc *cb, void *opaque)
{
    return blk_aio_prwv(blk, 0, 0, NULL, blk_aio_flush_entry, 0, cb, opaque);
}

static void blk_aio_pdiscard_entry(void *opaque)
{
    BlkAioEmAIOCB *acb = opaque;
    BlkRwCo *rwco = &acb->rwco;

    rwco->ret = blk_co_pdiscard(rwco->blk, rwco->offset, acb->bytes);
    blk_aio_complete(acb);
}

BlockAIOCB *blk_aio_pdiscard(BlockBackend *blk,
                             int64_t offset, int count,
                             BlockCompletionFunc *cb, void *opaque)
{
    return blk_aio_prwv(blk, offset, count, NULL, blk_aio_pdiscard_entry, 0,
                        cb, opaque);
}

void blk_aio_cancel(BlockAIOCB *acb)
{
    bdrv_aio_cancel(acb);
}

void blk_aio_cancel_async(BlockAIOCB *acb)
{
    bdrv_aio_cancel_async(acb);
}

int blk_co_ioctl(BlockBackend *blk, unsigned long int req, void *buf)
{
    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    return bdrv_co_ioctl(blk_bs(blk), req, buf);
}

static void blk_ioctl_entry(void *opaque)
{
    BlkRwCo *rwco = opaque;
    rwco->ret = blk_co_ioctl(rwco->blk, rwco->offset,
                             rwco->qiov->iov[0].iov_base);
}

int blk_ioctl(BlockBackend *blk, unsigned long int req, void *buf)
{
    return blk_prw(blk, req, buf, 0, blk_ioctl_entry, 0);
}

static void blk_aio_ioctl_entry(void *opaque)
{
    BlkAioEmAIOCB *acb = opaque;
    BlkRwCo *rwco = &acb->rwco;

    rwco->ret = blk_co_ioctl(rwco->blk, rwco->offset,
                             rwco->qiov->iov[0].iov_base);
    blk_aio_complete(acb);
}

BlockAIOCB *blk_aio_ioctl(BlockBackend *blk, unsigned long int req, void *buf,
                          BlockCompletionFunc *cb, void *opaque)
{
    QEMUIOVector qiov;
    struct iovec iov;

    iov = (struct iovec) {
        .iov_base = buf,
        .iov_len = 0,
    };
    qemu_iovec_init_external(&qiov, &iov, 1);

    return blk_aio_prwv(blk, req, 0, &qiov, blk_aio_ioctl_entry, 0, cb, opaque);
}

int blk_co_pdiscard(BlockBackend *blk, int64_t offset, int count)
{
    int ret = blk_check_byte_request(blk, offset, count);
    if (ret < 0) {
        return ret;
    }

    return bdrv_co_pdiscard(blk_bs(blk), offset, count);
}

int blk_co_flush(BlockBackend *blk)
{
    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    return bdrv_co_flush(blk_bs(blk));
}

static void blk_flush_entry(void *opaque)
{
    BlkRwCo *rwco = opaque;
    rwco->ret = blk_co_flush(rwco->blk);
}

int blk_flush(BlockBackend *blk)
{
    return blk_prw(blk, 0, NULL, 0, blk_flush_entry, 0);
}

void blk_drain(BlockBackend *blk)
{
    if (blk_bs(blk)) {
        bdrv_drain(blk_bs(blk));
    }
}

void blk_drain_all(void)
{
    bdrv_drain_all();
}

void blk_set_on_error(BlockBackend *blk, BlockdevOnError on_read_error,
                      BlockdevOnError on_write_error)
{
    blk->on_read_error = on_read_error;
    blk->on_write_error = on_write_error;
}

BlockdevOnError blk_get_on_error(BlockBackend *blk, bool is_read)
{
    return is_read ? blk->on_read_error : blk->on_write_error;
}

BlockErrorAction blk_get_error_action(BlockBackend *blk, bool is_read,
                                      int error)
{
    BlockdevOnError on_err = blk_get_on_error(blk, is_read);

    switch (on_err) {
    case BLOCKDEV_ON_ERROR_ENOSPC:
        return (error == ENOSPC) ?
               BLOCK_ERROR_ACTION_STOP : BLOCK_ERROR_ACTION_REPORT;
    case BLOCKDEV_ON_ERROR_STOP:
        return BLOCK_ERROR_ACTION_STOP;
    case BLOCKDEV_ON_ERROR_REPORT:
        return BLOCK_ERROR_ACTION_REPORT;
    case BLOCKDEV_ON_ERROR_IGNORE:
        return BLOCK_ERROR_ACTION_IGNORE;
    case BLOCKDEV_ON_ERROR_AUTO:
    default:
        abort();
    }
}

static void send_qmp_error_event(BlockBackend *blk,
                                 BlockErrorAction action,
                                 bool is_read, int error)
{
    IoOperationType optype;

    optype = is_read ? IO_OPERATION_TYPE_READ : IO_OPERATION_TYPE_WRITE;
    qapi_event_send_block_io_error(blk_name(blk),
                                   bdrv_get_node_name(blk_bs(blk)), optype,
                                   action, blk_iostatus_is_enabled(blk),
                                   error == ENOSPC, strerror(error),
                                   &error_abort);
}

/* This is done by device models because, while the block layer knows
 * about the error, it does not know whether an operation comes from
 * the device or the block layer (from a job, for example).
 */
void blk_error_action(BlockBackend *blk, BlockErrorAction action,
                      bool is_read, int error)
{
    assert(error >= 0);

    if (action == BLOCK_ERROR_ACTION_STOP) {
        /* First set the iostatus, so that "info block" returns an iostatus
         * that matches the events raised so far (an additional error iostatus
         * is fine, but not a lost one).
         */
        blk_iostatus_set_err(blk, error);

        /* Then raise the request to stop the VM and the event.
         * qemu_system_vmstop_request_prepare has two effects.  First,
         * it ensures that the STOP event always comes after the
         * BLOCK_IO_ERROR event.  Second, it ensures that even if management
         * can observe the STOP event and do a "cont" before the STOP
         * event is issued, the VM will not stop.  In this case, vm_start()
         * also ensures that the STOP/RESUME pair of events is emitted.
         */
        qemu_system_vmstop_request_prepare();
        send_qmp_error_event(blk, action, is_read, error);
        qemu_system_vmstop_request(RUN_STATE_IO_ERROR);
    } else {
        send_qmp_error_event(blk, action, is_read, error);
    }
}

int blk_is_read_only(BlockBackend *blk)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        return bdrv_is_read_only(bs);
    } else {
        return blk->root_state.read_only;
    }
}

int blk_is_sg(BlockBackend *blk)
{
    BlockDriverState *bs = blk_bs(blk);

    if (!bs) {
        return 0;
    }

    return bdrv_is_sg(bs);
}

int blk_enable_write_cache(BlockBackend *blk)
{
    return blk->enable_write_cache;
}

void blk_set_enable_write_cache(BlockBackend *blk, bool wce)
{
    blk->enable_write_cache = wce;
}

void blk_invalidate_cache(BlockBackend *blk, Error **errp)
{
    BlockDriverState *bs = blk_bs(blk);

    if (!bs) {
        error_setg(errp, "Device '%s' has no medium", blk->name);
        return;
    }

    bdrv_invalidate_cache(bs, errp);
}

bool blk_is_inserted(BlockBackend *blk)
{
    BlockDriverState *bs = blk_bs(blk);

    return bs && bdrv_is_inserted(bs);
}

bool blk_is_available(BlockBackend *blk)
{
    return blk_is_inserted(blk) && !blk_dev_is_tray_open(blk);
}

void blk_lock_medium(BlockBackend *blk, bool locked)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        bdrv_lock_medium(bs, locked);
    }
}

void blk_eject(BlockBackend *blk, bool eject_flag)
{
    BlockDriverState *bs = blk_bs(blk);
    char *id;

    /* blk_eject is only called by qdevified devices */
    assert(!blk->legacy_dev);

    if (bs) {
        bdrv_eject(bs, eject_flag);
    }

    /* Whether or not we ejected on the backend,
     * the frontend experienced a tray event. */
    id = blk_get_attached_dev_id(blk);
    qapi_event_send_device_tray_moved(blk_name(blk), id,
                                      eject_flag, &error_abort);
    g_free(id);
}

int blk_get_flags(BlockBackend *blk)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        return bdrv_get_flags(bs);
    } else {
        return blk->root_state.open_flags;
    }
}

/* Returns the maximum transfer length, in bytes; guaranteed nonzero */
uint32_t blk_get_max_transfer(BlockBackend *blk)
{
    BlockDriverState *bs = blk_bs(blk);
    uint32_t max = 0;

    if (bs) {
        max = bs->bl.max_transfer;
    }
    return MIN_NON_ZERO(max, INT_MAX);
}

int blk_get_max_iov(BlockBackend *blk)
{
    return blk->root->bs->bl.max_iov;
}

void blk_set_guest_block_size(BlockBackend *blk, int align)
{
    blk->guest_block_size = align;
}

void *blk_try_blockalign(BlockBackend *blk, size_t size)
{
    return qemu_try_blockalign(blk ? blk_bs(blk) : NULL, size);
}

void *blk_blockalign(BlockBackend *blk, size_t size)
{
    return qemu_blockalign(blk ? blk_bs(blk) : NULL, size);
}

bool blk_op_is_blocked(BlockBackend *blk, BlockOpType op, Error **errp)
{
    BlockDriverState *bs = blk_bs(blk);

    if (!bs) {
        return false;
    }

    return bdrv_op_is_blocked(bs, op, errp);
}

void blk_op_unblock(BlockBackend *blk, BlockOpType op, Error *reason)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        bdrv_op_unblock(bs, op, reason);
    }
}

void blk_op_block_all(BlockBackend *blk, Error *reason)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        bdrv_op_block_all(bs, reason);
    }
}

void blk_op_unblock_all(BlockBackend *blk, Error *reason)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        bdrv_op_unblock_all(bs, reason);
    }
}

AioContext *blk_get_aio_context(BlockBackend *blk)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        return bdrv_get_aio_context(bs);
    } else {
        return qemu_get_aio_context();
    }
}

static AioContext *blk_aiocb_get_aio_context(BlockAIOCB *acb)
{
    BlockBackendAIOCB *blk_acb = DO_UPCAST(BlockBackendAIOCB, common, acb);
    return blk_get_aio_context(blk_acb->blk);
}

void blk_set_aio_context(BlockBackend *blk, AioContext *new_context)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        if (blk->public.throttle_state) {
            throttle_timers_detach_aio_context(&blk->public.throttle_timers);
        }
        bdrv_set_aio_context(bs, new_context);
        if (blk->public.throttle_state) {
            throttle_timers_attach_aio_context(&blk->public.throttle_timers,
                                               new_context);
        }
    }
}

void blk_add_aio_context_notifier(BlockBackend *blk,
        void (*attached_aio_context)(AioContext *new_context, void *opaque),
        void (*detach_aio_context)(void *opaque), void *opaque)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        bdrv_add_aio_context_notifier(bs, attached_aio_context,
                                      detach_aio_context, opaque);
    }
}

void blk_remove_aio_context_notifier(BlockBackend *blk,
                                     void (*attached_aio_context)(AioContext *,
                                                                  void *),
                                     void (*detach_aio_context)(void *),
                                     void *opaque)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        bdrv_remove_aio_context_notifier(bs, attached_aio_context,
                                         detach_aio_context, opaque);
    }
}

void blk_add_remove_bs_notifier(BlockBackend *blk, Notifier *notify)
{
    notifier_list_add(&blk->remove_bs_notifiers, notify);
}

void blk_add_insert_bs_notifier(BlockBackend *blk, Notifier *notify)
{
    notifier_list_add(&blk->insert_bs_notifiers, notify);
}

void blk_io_plug(BlockBackend *blk)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        bdrv_io_plug(bs);
    }
}

void blk_io_unplug(BlockBackend *blk)
{
    BlockDriverState *bs = blk_bs(blk);

    if (bs) {
        bdrv_io_unplug(bs);
    }
}

BlockAcctStats *blk_get_stats(BlockBackend *blk)
{
    return &blk->stats;
}

void *blk_aio_get(const AIOCBInfo *aiocb_info, BlockBackend *blk,
                  BlockCompletionFunc *cb, void *opaque)
{
    return qemu_aio_get(aiocb_info, blk_bs(blk), cb, opaque);
}

int coroutine_fn blk_co_pwrite_zeroes(BlockBackend *blk, int64_t offset,
                                      int count, BdrvRequestFlags flags)
{
    return blk_co_pwritev(blk, offset, count, NULL,
                          flags | BDRV_REQ_ZERO_WRITE);
}

int blk_pwrite_compressed(BlockBackend *blk, int64_t offset, const void *buf,
                          int count)
{
    return blk_prw(blk, offset, (void *) buf, count, blk_write_entry,
                   BDRV_REQ_WRITE_COMPRESSED);
}

int blk_truncate(BlockBackend *blk, int64_t offset)
{
    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    return bdrv_truncate(blk->root, offset);
}

static void blk_pdiscard_entry(void *opaque)
{
    BlkRwCo *rwco = opaque;
    rwco->ret = blk_co_pdiscard(rwco->blk, rwco->offset, rwco->qiov->size);
}

int blk_pdiscard(BlockBackend *blk, int64_t offset, int count)
{
    return blk_prw(blk, offset, NULL, count, blk_pdiscard_entry, 0);
}

int blk_save_vmstate(BlockBackend *blk, const uint8_t *buf,
                     int64_t pos, int size)
{
    int ret;

    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    ret = bdrv_save_vmstate(blk_bs(blk), buf, pos, size);
    if (ret < 0) {
        return ret;
    }

    if (ret == size && !blk->enable_write_cache) {
        ret = bdrv_flush(blk_bs(blk));
    }

    return ret < 0 ? ret : size;
}

int blk_load_vmstate(BlockBackend *blk, uint8_t *buf, int64_t pos, int size)
{
    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    return bdrv_load_vmstate(blk_bs(blk), buf, pos, size);
}

int blk_probe_blocksizes(BlockBackend *blk, BlockSizes *bsz)
{
    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    return bdrv_probe_blocksizes(blk_bs(blk), bsz);
}

int blk_probe_geometry(BlockBackend *blk, HDGeometry *geo)
{
    if (!blk_is_available(blk)) {
        return -ENOMEDIUM;
    }

    return bdrv_probe_geometry(blk_bs(blk), geo);
}

/*
 * Updates the BlockBackendRootState object with data from the currently
 * attached BlockDriverState.
 */
void blk_update_root_state(BlockBackend *blk)
{
    assert(blk->root);

    blk->root_state.open_flags    = blk->root->bs->open_flags;
    blk->root_state.read_only     = blk->root->bs->read_only;
    blk->root_state.detect_zeroes = blk->root->bs->detect_zeroes;
}

/*
 * Returns the detect-zeroes setting to be used for bdrv_open() of a
 * BlockDriverState which is supposed to inherit the root state.
 */
bool blk_get_detect_zeroes_from_root_state(BlockBackend *blk)
{
    return blk->root_state.detect_zeroes;
}

/*
 * Returns the flags to be used for bdrv_open() of a BlockDriverState which is
 * supposed to inherit the root state.
 */
int blk_get_open_flags_from_root_state(BlockBackend *blk)
{
    int bs_flags;

    bs_flags = blk->root_state.read_only ? 0 : BDRV_O_RDWR;
    bs_flags |= blk->root_state.open_flags & ~BDRV_O_RDWR;

    return bs_flags;
}

BlockBackendRootState *blk_get_root_state(BlockBackend *blk)
{
    return &blk->root_state;
}

int blk_commit_all(void)
{
    BlockBackend *blk = NULL;

    while ((blk = blk_all_next(blk)) != NULL) {
        AioContext *aio_context = blk_get_aio_context(blk);

        aio_context_acquire(aio_context);
        if (blk_is_inserted(blk) && blk->root->bs->backing) {
            int ret = bdrv_commit(blk->root->bs);
            if (ret < 0) {
                aio_context_release(aio_context);
                return ret;
            }
        }
        aio_context_release(aio_context);
    }
    return 0;
}


/* throttling disk I/O limits */
void blk_set_io_limits(BlockBackend *blk, ThrottleConfig *cfg)
{
    throttle_group_config(blk, cfg);
}

void blk_io_limits_disable(BlockBackend *blk)
{
    assert(blk->public.throttle_state);
    bdrv_drained_begin(blk_bs(blk));
    throttle_group_unregister_blk(blk);
    bdrv_drained_end(blk_bs(blk));
}

/* should be called before blk_set_io_limits if a limit is set */
void blk_io_limits_enable(BlockBackend *blk, const char *group)
{
    assert(!blk->public.throttle_state);
    throttle_group_register_blk(blk, group);
}

void blk_io_limits_update_group(BlockBackend *blk, const char *group)
{
    /* this BB is not part of any group */
    if (!blk->public.throttle_state) {
        return;
    }

    /* this BB is a part of the same group than the one we want */
    if (!g_strcmp0(throttle_group_get_name(blk), group)) {
        return;
    }

    /* need to change the group this bs belong to */
    blk_io_limits_disable(blk);
    blk_io_limits_enable(blk, group);
}

static void blk_root_drained_begin(BdrvChild *child)
{
    BlockBackend *blk = child->opaque;

    if (++blk->quiesce_counter == 1) {
        if (blk->dev_ops && blk->dev_ops->drained_begin) {
            blk->dev_ops->drained_begin(blk->dev_opaque);
        }
    }

    /* Note that blk->root may not be accessible here yet if we are just
     * attaching to a BlockDriverState that is drained. Use child instead. */

    if (blk->public.io_limits_disabled++ == 0) {
        throttle_group_restart_blk(blk);
    }
}

static void blk_root_drained_end(BdrvChild *child)
{
    BlockBackend *blk = child->opaque;
    assert(blk->quiesce_counter);

    assert(blk->public.io_limits_disabled);
    --blk->public.io_limits_disabled;

    if (--blk->quiesce_counter == 0) {
        if (blk->dev_ops && blk->dev_ops->drained_end) {
            blk->dev_ops->drained_end(blk->dev_opaque);
        }
    }
}
