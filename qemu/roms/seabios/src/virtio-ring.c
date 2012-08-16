/* virtio-pci.c - virtio ring management
 *
 * (c) Copyright 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 *  some parts from Linux Virtio Ring
 *
 *  Copyright Rusty Russell IBM Corporation 2007
 *
 *  Adopted for Seabios: Gleb Natapov <gleb@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPLv3
 * See the COPYING file in the top-level directory.
 *
 *
 */

#include "virtio-ring.h"
#include "virtio-pci.h"
#include "biosvar.h" // GET_GLOBAL
#include "util.h" // dprintf

#define BUG() do {                                      \
        dprintf(1, "BUG: failure at %s:%d/%s()!\n",     \
                __FILE__, __LINE__, __func__);          \
                while(1);                               \
        } while (0)
#define BUG_ON(condition) do { if (condition) BUG(); } while (0)

/*
 * vring_more_used
 *
 * is there some used buffers ?
 *
 */

int vring_more_used(struct vring_virtqueue *vq)
{
    struct vring_used *used = GET_FLATPTR(vq->vring.used);
    int more = GET_FLATPTR(vq->last_used_idx) != GET_FLATPTR(used->idx);
    /* Make sure ring reads are done after idx read above. */
    smp_rmb();
    return more;
}

/*
 * vring_free
 *
 * put at the begin of the free list the current desc[head]
 */

void vring_detach(struct vring_virtqueue *vq, unsigned int head)
{
    struct vring *vr = &vq->vring;
    struct vring_desc *desc = GET_FLATPTR(vr->desc);
    unsigned int i;

    /* find end of given descriptor */

    i = head;
    while (GET_FLATPTR(desc[i].flags) & VRING_DESC_F_NEXT)
        i = GET_FLATPTR(desc[i].next);

    /* link it with free list and point to it */

    SET_FLATPTR(desc[i].next, GET_FLATPTR(vq->free_head));
    SET_FLATPTR(vq->free_head, head);
}

/*
 * vring_get_buf
 *
 * get a buffer from the used list
 *
 */

int vring_get_buf(struct vring_virtqueue *vq, unsigned int *len)
{
    struct vring *vr = &vq->vring;
    struct vring_used_elem *elem;
    struct vring_used *used = GET_FLATPTR(vq->vring.used);
    u32 id;
    int ret;

//    BUG_ON(!vring_more_used(vq));

    elem = &used->ring[GET_FLATPTR(vq->last_used_idx) % GET_FLATPTR(vr->num)];
    id = GET_FLATPTR(elem->id);
    if (len != NULL)
        *len = GET_FLATPTR(elem->len);

    ret = GET_FLATPTR(vq->vdata[id]);

    vring_detach(vq, id);

    SET_FLATPTR(vq->last_used_idx, GET_FLATPTR(vq->last_used_idx) + 1);

    return ret;
}

void vring_add_buf(struct vring_virtqueue *vq,
                   struct vring_list list[],
                   unsigned int out, unsigned int in,
                   int index, int num_added)
{
    struct vring *vr = &vq->vring;
    int i, av, head, prev;
    struct vring_desc *desc = GET_FLATPTR(vr->desc);
    struct vring_avail *avail = GET_FLATPTR(vr->avail);

    BUG_ON(out + in == 0);

    prev = 0;
    head = GET_FLATPTR(vq->free_head);
    for (i = head; out; i = GET_FLATPTR(desc[i].next), out--) {
        SET_FLATPTR(desc[i].flags, VRING_DESC_F_NEXT);
        SET_FLATPTR(desc[i].addr, (u64)virt_to_phys(list->addr));
        SET_FLATPTR(desc[i].len, list->length);
        prev = i;
        list++;
    }
    for ( ; in; i = GET_FLATPTR(desc[i].next), in--) {
        SET_FLATPTR(desc[i].flags, VRING_DESC_F_NEXT|VRING_DESC_F_WRITE);
        SET_FLATPTR(desc[i].addr, (u64)virt_to_phys(list->addr));
        SET_FLATPTR(desc[i].len, list->length);
        prev = i;
        list++;
    }
    SET_FLATPTR(desc[prev].flags,
                GET_FLATPTR(desc[prev].flags) & ~VRING_DESC_F_NEXT);

    SET_FLATPTR(vq->free_head, i);

    SET_FLATPTR(vq->vdata[head], index);

    av = (GET_FLATPTR(avail->idx) + num_added) % GET_FLATPTR(vr->num);
    SET_FLATPTR(avail->ring[av], head);
}

void vring_kick(unsigned int ioaddr, struct vring_virtqueue *vq, int num_added)
{
    struct vring *vr = &vq->vring;
    struct vring_avail *avail = GET_FLATPTR(vr->avail);

    /* Make sure idx update is done after ring write. */
    smp_wmb();
    SET_FLATPTR(avail->idx, GET_FLATPTR(avail->idx) + num_added);

    vp_notify(ioaddr, GET_FLATPTR(vq->queue_index));
}
