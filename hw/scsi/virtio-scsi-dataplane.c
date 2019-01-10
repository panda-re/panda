/*
 * Virtio SCSI dataplane
 *
 * Copyright Red Hat, Inc. 2014
 *
 * Authors:
 *   Fam Zheng <famz@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/virtio/virtio-scsi.h"
#include "qemu/error-report.h"
#include "sysemu/block-backend.h"
#include "hw/scsi/scsi.h"
#include "block/scsi.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"

/* Context: QEMU global mutex held */
void virtio_scsi_dataplane_setup(VirtIOSCSI *s, Error **errp)
{
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(s);
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    BusState *qbus = qdev_get_parent_bus(DEVICE(vdev));
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(qbus);

    if (vs->conf.iothread) {
        if (!k->set_guest_notifiers || !k->ioeventfd_assign) {
            error_setg(errp,
                       "device is incompatible with iothread "
                       "(transport does not support notifiers)");
            return;
        }
        if (!virtio_device_ioeventfd_enabled(vdev)) {
            error_setg(errp, "ioeventfd is required for iothread");
            return;
        }
        s->ctx = iothread_get_aio_context(vs->conf.iothread);
    } else {
        if (!virtio_device_ioeventfd_enabled(vdev)) {
            return;
        }
        s->ctx = qemu_get_aio_context();
    }
}

static bool virtio_scsi_data_plane_handle_cmd(VirtIODevice *vdev,
                                              VirtQueue *vq)
{
    bool progress;
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);

    virtio_scsi_acquire(s);
    assert(s->ctx && s->dataplane_started);
    progress = virtio_scsi_handle_cmd_vq(s, vq);
    virtio_scsi_release(s);
    return progress;
}

static bool virtio_scsi_data_plane_handle_ctrl(VirtIODevice *vdev,
                                               VirtQueue *vq)
{
    bool progress;
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);

    virtio_scsi_acquire(s);
    assert(s->ctx && s->dataplane_started);
    progress = virtio_scsi_handle_ctrl_vq(s, vq);
    virtio_scsi_release(s);
    return progress;
}

static bool virtio_scsi_data_plane_handle_event(VirtIODevice *vdev,
                                                VirtQueue *vq)
{
    bool progress;
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);

    virtio_scsi_acquire(s);
    assert(s->ctx && s->dataplane_started);
    progress = virtio_scsi_handle_event_vq(s, vq);
    virtio_scsi_release(s);
    return progress;
}

static int virtio_scsi_vring_init(VirtIOSCSI *s, VirtQueue *vq, int n,
                                  VirtIOHandleAIOOutput fn)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(s)));
    int rc;

    /* Set up virtqueue notify */
    rc = virtio_bus_set_host_notifier(VIRTIO_BUS(qbus), n, true);
    if (rc != 0) {
        fprintf(stderr, "virtio-scsi: Failed to set host notifier (%d)\n",
                rc);
        s->dataplane_fenced = true;
        return rc;
    }

    virtio_queue_aio_set_host_notifier_handler(vq, s->ctx, fn);
    return 0;
}

/* assumes s->ctx held */
static void virtio_scsi_clear_aio(VirtIOSCSI *s)
{
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(s);
    int i;

    virtio_queue_aio_set_host_notifier_handler(vs->ctrl_vq, s->ctx, NULL);
    virtio_queue_aio_set_host_notifier_handler(vs->event_vq, s->ctx, NULL);
    for (i = 0; i < vs->conf.num_queues; i++) {
        virtio_queue_aio_set_host_notifier_handler(vs->cmd_vqs[i], s->ctx, NULL);
    }
}

/* Context: QEMU global mutex held */
int virtio_scsi_dataplane_start(VirtIODevice *vdev)
{
    int i;
    int rc;
    BusState *qbus = qdev_get_parent_bus(DEVICE(vdev));
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(qbus);
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(vdev);
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);

    if (s->dataplane_started ||
        s->dataplane_starting ||
        s->dataplane_fenced) {
        return 0;
    }

    s->dataplane_starting = true;

    /* Set up guest notifier (irq) */
    rc = k->set_guest_notifiers(qbus->parent, vs->conf.num_queues + 2, true);
    if (rc != 0) {
        fprintf(stderr, "virtio-scsi: Failed to set guest notifiers (%d), "
                "ensure -enable-kvm is set\n", rc);
        goto fail_guest_notifiers;
    }

    aio_context_acquire(s->ctx);
    rc = virtio_scsi_vring_init(s, vs->ctrl_vq, 0,
                                virtio_scsi_data_plane_handle_ctrl);
    if (rc) {
        goto fail_vrings;
    }
    rc = virtio_scsi_vring_init(s, vs->event_vq, 1,
                                virtio_scsi_data_plane_handle_event);
    if (rc) {
        goto fail_vrings;
    }
    for (i = 0; i < vs->conf.num_queues; i++) {
        rc = virtio_scsi_vring_init(s, vs->cmd_vqs[i], i + 2,
                                    virtio_scsi_data_plane_handle_cmd);
        if (rc) {
            goto fail_vrings;
        }
    }

    s->dataplane_starting = false;
    s->dataplane_started = true;
    aio_context_release(s->ctx);
    return 0;

fail_vrings:
    virtio_scsi_clear_aio(s);
    aio_context_release(s->ctx);
    for (i = 0; i < vs->conf.num_queues + 2; i++) {
        virtio_bus_set_host_notifier(VIRTIO_BUS(qbus), i, false);
    }
    k->set_guest_notifiers(qbus->parent, vs->conf.num_queues + 2, false);
fail_guest_notifiers:
    s->dataplane_fenced = true;
    s->dataplane_starting = false;
    s->dataplane_started = true;
    return -ENOSYS;
}

/* Context: QEMU global mutex held */
void virtio_scsi_dataplane_stop(VirtIODevice *vdev)
{
    BusState *qbus = qdev_get_parent_bus(DEVICE(vdev));
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(qbus);
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(vdev);
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);
    int i;

    if (!s->dataplane_started || s->dataplane_stopping) {
        return;
    }

    /* Better luck next time. */
    if (s->dataplane_fenced) {
        s->dataplane_fenced = false;
        s->dataplane_started = false;
        return;
    }
    s->dataplane_stopping = true;

    aio_context_acquire(s->ctx);
    virtio_scsi_clear_aio(s);
    aio_context_release(s->ctx);

    blk_drain_all(); /* ensure there are no in-flight requests */

    for (i = 0; i < vs->conf.num_queues + 2; i++) {
        virtio_bus_set_host_notifier(VIRTIO_BUS(qbus), i, false);
    }

    /* Clean up guest notifier (irq) */
    k->set_guest_notifiers(qbus->parent, vs->conf.num_queues + 2, false);
    s->dataplane_stopping = false;
    s->dataplane_started = false;
}
