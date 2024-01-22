/*
 * vhost-net support
 *
 * Copyright Red Hat, Inc. 2010
 *
 * Authors:
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "net/net.h"
#include "net/tap.h"
#include "net/vhost-user.h"

#include "hw/virtio/virtio-net.h"
#include "net/vhost_net.h"
#include "qemu/error-report.h"


#ifdef CONFIG_VHOST_NET
#include <linux/vhost.h>
#include <sys/socket.h>
#include <linux/kvm.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>


#include "standard-headers/linux/virtio_ring.h"
#include "hw/virtio/vhost.h"
#include "hw/virtio/virtio-bus.h"

struct vhost_net {
    struct vhost_dev dev;
    struct vhost_virtqueue vqs[2];
    int backend;
    NetClientState *nc;
};

/* Features supported by host kernel. */
static const int kernel_feature_bits[] = {
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_NET_F_MRG_RXBUF,
    VIRTIO_F_VERSION_1,
    VIRTIO_NET_F_MTU,
    VIRTIO_F_IOMMU_PLATFORM,
    VHOST_INVALID_FEATURE_BIT
};

/* Features supported by others. */
static const int user_feature_bits[] = {
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,

    VIRTIO_F_ANY_LAYOUT,
    VIRTIO_F_VERSION_1,
    VIRTIO_NET_F_CSUM,
    VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GSO,
    VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_ECN,
    VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_TSO4,
    VIRTIO_NET_F_HOST_TSO6,
    VIRTIO_NET_F_HOST_ECN,
    VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MRG_RXBUF,
    VIRTIO_NET_F_MTU,
    VIRTIO_F_IOMMU_PLATFORM,

    /* This bit implies RARP isn't sent by QEMU out of band */
    VIRTIO_NET_F_GUEST_ANNOUNCE,

    VIRTIO_NET_F_MQ,

    VHOST_INVALID_FEATURE_BIT
};

static const int *vhost_net_get_feature_bits(struct vhost_net *net)
{
    const int *feature_bits = 0;

    switch (net->nc->info->type) {
    case NET_CLIENT_DRIVER_TAP:
        feature_bits = kernel_feature_bits;
        break;
    case NET_CLIENT_DRIVER_VHOST_USER:
        feature_bits = user_feature_bits;
        break;
    default:
        error_report("Feature bits not defined for this type: %d",
                net->nc->info->type);
        break;
    }

    return feature_bits;
}

uint64_t vhost_net_get_features(struct vhost_net *net, uint64_t features)
{
    return vhost_get_features(&net->dev, vhost_net_get_feature_bits(net),
            features);
}

void vhost_net_ack_features(struct vhost_net *net, uint64_t features)
{
    net->dev.acked_features = net->dev.backend_features;
    vhost_ack_features(&net->dev, vhost_net_get_feature_bits(net), features);
}

uint64_t vhost_net_get_max_queues(VHostNetState *net)
{
    return net->dev.max_queues;
}

uint64_t vhost_net_get_acked_features(VHostNetState *net)
{
    return net->dev.acked_features;
}

static int vhost_net_get_fd(NetClientState *backend)
{
    switch (backend->info->type) {
    case NET_CLIENT_DRIVER_TAP:
        return tap_get_fd(backend);
    default:
        fprintf(stderr, "vhost-net requires tap backend\n");
        return -EBADFD;
    }
}

struct vhost_net *vhost_net_init(VhostNetOptions *options)
{
    int r;
    bool backend_kernel = options->backend_type == VHOST_BACKEND_TYPE_KERNEL;
    struct vhost_net *net = g_new0(struct vhost_net, 1);
    uint64_t features = 0;

    if (!options->net_backend) {
        fprintf(stderr, "vhost-net requires net backend to be setup\n");
        goto fail;
    }
    net->nc = options->net_backend;

    net->dev.max_queues = 1;
    net->dev.nvqs = 2;
    net->dev.vqs = net->vqs;

    if (backend_kernel) {
        r = vhost_net_get_fd(options->net_backend);
        if (r < 0) {
            goto fail;
        }
        net->dev.backend_features = qemu_has_vnet_hdr(options->net_backend)
            ? 0 : (1ULL << VHOST_NET_F_VIRTIO_NET_HDR);
        net->backend = r;
        net->dev.protocol_features = 0;
    } else {
        net->dev.backend_features = 0;
        net->dev.protocol_features = 0;
        net->backend = -1;

        /* vhost-user needs vq_index to initiate a specific queue pair */
        net->dev.vq_index = net->nc->queue_index * net->dev.nvqs;
    }

    r = vhost_dev_init(&net->dev, options->opaque,
                       options->backend_type, options->busyloop_timeout);
    if (r < 0) {
        goto fail;
    }
    if (backend_kernel) {
        if (!qemu_has_vnet_hdr_len(options->net_backend,
                               sizeof(struct virtio_net_hdr_mrg_rxbuf))) {
            net->dev.features &= ~(1ULL << VIRTIO_NET_F_MRG_RXBUF);
        }
        if (~net->dev.features & net->dev.backend_features) {
            fprintf(stderr, "vhost lacks feature mask %" PRIu64
                   " for backend\n",
                   (uint64_t)(~net->dev.features & net->dev.backend_features));
            goto fail;
        }
    }

    /* Set sane init value. Override when guest acks. */
    if (net->nc->info->type == NET_CLIENT_DRIVER_VHOST_USER) {
        features = vhost_user_get_acked_features(net->nc);
        if (~net->dev.features & features) {
            fprintf(stderr, "vhost lacks feature mask %" PRIu64
                    " for backend\n",
                    (uint64_t)(~net->dev.features & features));
            goto fail;
        }
    }

    vhost_net_ack_features(net, features);

    return net;

fail:
    vhost_dev_cleanup(&net->dev);
    g_free(net);
    return NULL;
}

static void vhost_net_set_vq_index(struct vhost_net *net, int vq_index)
{
    net->dev.vq_index = vq_index;
}

static int vhost_net_start_one(struct vhost_net *net,
                               VirtIODevice *dev)
{
    struct vhost_vring_file file = { };
    int r;

    net->dev.nvqs = 2;
    net->dev.vqs = net->vqs;

    r = vhost_dev_enable_notifiers(&net->dev, dev);
    if (r < 0) {
        goto fail_notifiers;
    }

    r = vhost_dev_start(&net->dev, dev);
    if (r < 0) {
        goto fail_start;
    }

    if (net->nc->info->poll) {
        net->nc->info->poll(net->nc, false);
    }

    if (net->nc->info->type == NET_CLIENT_DRIVER_TAP) {
        qemu_set_fd_handler(net->backend, NULL, NULL, NULL);
        file.fd = net->backend;
        for (file.index = 0; file.index < net->dev.nvqs; ++file.index) {
            r = vhost_net_set_backend(&net->dev, &file);
            if (r < 0) {
                r = -errno;
                goto fail;
            }
        }
    }
    return 0;
fail:
    file.fd = -1;
    if (net->nc->info->type == NET_CLIENT_DRIVER_TAP) {
        while (file.index-- > 0) {
            int r = vhost_net_set_backend(&net->dev, &file);
            assert(r >= 0);
        }
    }
    if (net->nc->info->poll) {
        net->nc->info->poll(net->nc, true);
    }
    vhost_dev_stop(&net->dev, dev);
fail_start:
    vhost_dev_disable_notifiers(&net->dev, dev);
fail_notifiers:
    return r;
}

static void vhost_net_stop_one(struct vhost_net *net,
                               VirtIODevice *dev)
{
    struct vhost_vring_file file = { .fd = -1 };

    if (net->nc->info->type == NET_CLIENT_DRIVER_TAP) {
        for (file.index = 0; file.index < net->dev.nvqs; ++file.index) {
            int r = vhost_net_set_backend(&net->dev, &file);
            assert(r >= 0);
        }
    }
    if (net->nc->info->poll) {
        net->nc->info->poll(net->nc, true);
    }
    vhost_dev_stop(&net->dev, dev);
    vhost_dev_disable_notifiers(&net->dev, dev);
}

int vhost_net_start(VirtIODevice *dev, NetClientState *ncs,
                    int total_queues)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    int r, e, i;

    if (!k->set_guest_notifiers) {
        error_report("binding does not support guest notifiers");
        return -ENOSYS;
    }

    for (i = 0; i < total_queues; i++) {
        struct vhost_net *net;

        net = get_vhost_net(ncs[i].peer);
        vhost_net_set_vq_index(net, i * 2);

        /* Suppress the masking guest notifiers on vhost user
         * because vhost user doesn't interrupt masking/unmasking
         * properly.
         */
        if (net->nc->info->type == NET_CLIENT_DRIVER_VHOST_USER) {
            dev->use_guest_notifier_mask = false;
        }
     }

    r = k->set_guest_notifiers(qbus->parent, total_queues * 2, true);
    if (r < 0) {
        error_report("Error binding guest notifier: %d", -r);
        goto err;
    }

    for (i = 0; i < total_queues; i++) {
        r = vhost_net_start_one(get_vhost_net(ncs[i].peer), dev);

        if (r < 0) {
            goto err_start;
        }

        if (ncs[i].peer->vring_enable) {
            /* restore vring enable state */
            r = vhost_set_vring_enable(ncs[i].peer, ncs[i].peer->vring_enable);

            if (r < 0) {
                goto err_start;
            }
        }
    }

    return 0;

err_start:
    while (--i >= 0) {
        vhost_net_stop_one(get_vhost_net(ncs[i].peer), dev);
    }
    e = k->set_guest_notifiers(qbus->parent, total_queues * 2, false);
    if (e < 0) {
        fprintf(stderr, "vhost guest notifier cleanup failed: %d\n", e);
        fflush(stderr);
    }
err:
    return r;
}

void vhost_net_stop(VirtIODevice *dev, NetClientState *ncs,
                    int total_queues)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    int i, r;

    for (i = 0; i < total_queues; i++) {
        vhost_net_stop_one(get_vhost_net(ncs[i].peer), dev);
    }

    r = k->set_guest_notifiers(qbus->parent, total_queues * 2, false);
    if (r < 0) {
        fprintf(stderr, "vhost guest notifier cleanup failed: %d\n", r);
        fflush(stderr);
    }
    assert(r >= 0);
}

void vhost_net_cleanup(struct vhost_net *net)
{
    vhost_dev_cleanup(&net->dev);
}

int vhost_net_notify_migration_done(struct vhost_net *net, char* mac_addr)
{
    const VhostOps *vhost_ops = net->dev.vhost_ops;

    assert(vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);
    assert(vhost_ops->vhost_migration_done);

    return vhost_ops->vhost_migration_done(&net->dev, mac_addr);
}

bool vhost_net_virtqueue_pending(VHostNetState *net, int idx)
{
    return vhost_virtqueue_pending(&net->dev, idx);
}

void vhost_net_virtqueue_mask(VHostNetState *net, VirtIODevice *dev,
                              int idx, bool mask)
{
    vhost_virtqueue_mask(&net->dev, dev, idx, mask);
}

VHostNetState *get_vhost_net(NetClientState *nc)
{
    VHostNetState *vhost_net = 0;

    if (!nc) {
        return 0;
    }

    switch (nc->info->type) {
    case NET_CLIENT_DRIVER_TAP:
        vhost_net = tap_get_vhost_net(nc);
        break;
    case NET_CLIENT_DRIVER_VHOST_USER:
        vhost_net = vhost_user_get_vhost_net(nc);
        assert(vhost_net);
        break;
    default:
        break;
    }

    return vhost_net;
}

int vhost_set_vring_enable(NetClientState *nc, int enable)
{
    VHostNetState *net = get_vhost_net(nc);
    const VhostOps *vhost_ops = net->dev.vhost_ops;

    nc->vring_enable = enable;

    if (vhost_ops && vhost_ops->vhost_set_vring_enable) {
        return vhost_ops->vhost_set_vring_enable(&net->dev, enable);
    }

    return 0;
}

int vhost_net_set_mtu(struct vhost_net *net, uint16_t mtu)
{
    const VhostOps *vhost_ops = net->dev.vhost_ops;

    if (!vhost_ops->vhost_net_set_mtu) {
        return 0;
    }

    return vhost_ops->vhost_net_set_mtu(&net->dev, mtu);
}

#else
uint64_t vhost_net_get_max_queues(VHostNetState *net)
{
    return 1;
}

struct vhost_net *vhost_net_init(VhostNetOptions *options)
{
    error_report("vhost-net support is not compiled in");
    return NULL;
}

int vhost_net_start(VirtIODevice *dev,
                    NetClientState *ncs,
                    int total_queues)
{
    return -ENOSYS;
}
void vhost_net_stop(VirtIODevice *dev,
                    NetClientState *ncs,
                    int total_queues)
{
}

void vhost_net_cleanup(struct vhost_net *net)
{
}

uint64_t vhost_net_get_features(struct vhost_net *net, uint64_t features)
{
    return features;
}

void vhost_net_ack_features(struct vhost_net *net, uint64_t features)
{
}

uint64_t vhost_net_get_acked_features(VHostNetState *net)
{
    return 0;
}

bool vhost_net_virtqueue_pending(VHostNetState *net, int idx)
{
    return false;
}

void vhost_net_virtqueue_mask(VHostNetState *net, VirtIODevice *dev,
                              int idx, bool mask)
{
}

int vhost_net_notify_migration_done(struct vhost_net *net, char* mac_addr)
{
    return -1;
}

VHostNetState *get_vhost_net(NetClientState *nc)
{
    return 0;
}

int vhost_set_vring_enable(NetClientState *nc, int enable)
{
    return 0;
}

int vhost_net_set_mtu(struct vhost_net *net, uint16_t mtu)
{
    return 0;
}
#endif
