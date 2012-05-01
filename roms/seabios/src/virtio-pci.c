/* virtio-pci.c - pci interface for virtio interface
 *
 * (c) Copyright 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 * some parts from Linux Virtio PCI driver
 *
 *  Copyright IBM Corp. 2007
 *  Authors: Anthony Liguori  <aliguori@us.ibm.com>
 *
 *  Adopted for Seabios: Gleb Natapov <gleb@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPLv3
 * See the COPYING file in the top-level directory.
 */

#include "virtio-ring.h"
#include "virtio-pci.h"
#include "config.h" // CONFIG_DEBUG_LEVEL
#include "util.h" // dprintf

int vp_find_vq(unsigned int ioaddr, int queue_index,
               struct vring_virtqueue *vq)
{
   struct vring * vr = &vq->vring;
   u16 num;

   ASSERT32FLAT();
   /* select the queue */

   outw(queue_index, ioaddr + VIRTIO_PCI_QUEUE_SEL);

   /* check if the queue is available */

   num = inw(ioaddr + VIRTIO_PCI_QUEUE_NUM);
   if (!num) {
       dprintf(1, "ERROR: queue size is 0\n");
       return -1;
   }

   if (num > MAX_QUEUE_NUM) {
       dprintf(1, "ERROR: queue size %d > %d\n", num, MAX_QUEUE_NUM);
       return -1;
   }

   /* check if the queue is already active */

   if (inl(ioaddr + VIRTIO_PCI_QUEUE_PFN)) {
       dprintf(1, "ERROR: queue already active\n");
       return -1;
   }

   vq->queue_index = queue_index;

   /* initialize the queue */

   vring_init(vr, num, (unsigned char*)&vq->queue);

   /* activate the queue
    *
    * NOTE: vr->desc is initialized by vring_init()
    */

   outl((unsigned long)virt_to_phys(vr->desc) >> PAGE_SHIFT,
        ioaddr + VIRTIO_PCI_QUEUE_PFN);

   return num;
}
