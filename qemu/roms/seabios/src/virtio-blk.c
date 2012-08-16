// Virtio block boot support.
//
// Copyright (C) 2010 Red Hat Inc.
//
// Authors:
//  Gleb Natapov <gnatapov@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // dprintf
#include "pci.h" // foreachpci
#include "config.h" // CONFIG_*
#include "biosvar.h" // GET_GLOBAL
#include "pci_ids.h" // PCI_DEVICE_ID_VIRTIO_BLK
#include "pci_regs.h" // PCI_VENDOR_ID
#include "boot.h" // boot_add_hd
#include "virtio-pci.h"
#include "virtio-ring.h"
#include "virtio-blk.h"
#include "disk.h"

struct virtiodrive_s {
    struct drive_s drive;
    struct vring_virtqueue *vq;
    u16 ioaddr;
};

static int
virtio_blk_op(struct disk_op_s *op, int write)
{
    struct virtiodrive_s *vdrive_g =
        container_of(op->drive_g, struct virtiodrive_s, drive);
    struct vring_virtqueue *vq = GET_GLOBAL(vdrive_g->vq);
    struct virtio_blk_outhdr hdr = {
        .type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN,
        .ioprio = 0,
        .sector = op->lba,
    };
    u8 status = VIRTIO_BLK_S_UNSUPP;
    struct vring_list sg[] = {
        {
            .addr	= MAKE_FLATPTR(GET_SEG(SS), &hdr),
            .length	= sizeof(hdr),
        },
        {
            .addr	= op->buf_fl,
            .length	= GET_GLOBAL(vdrive_g->drive.blksize) * op->count,
        },
        {
            .addr	= MAKE_FLATPTR(GET_SEG(SS), &status),
            .length	= sizeof(status),
        },
    };

    /* Add to virtqueue and kick host */
    if (write)
        vring_add_buf(vq, sg, 2, 1, 0, 0);
    else
        vring_add_buf(vq, sg, 1, 2, 0, 0);
    vring_kick(GET_GLOBAL(vdrive_g->ioaddr), vq, 1);

    /* Wait for reply */
    while (!vring_more_used(vq))
        usleep(5);

    /* Reclaim virtqueue element */
    vring_get_buf(vq, NULL);

    /* Clear interrupt status register.  Avoid leaving interrupts stuck if
     * VRING_AVAIL_F_NO_INTERRUPT was ignored and interrupts were raised.
     */
    vp_get_isr(GET_GLOBAL(vdrive_g->ioaddr));

    return status == VIRTIO_BLK_S_OK ? DISK_RET_SUCCESS : DISK_RET_EBADTRACK;
}

int
process_virtio_op(struct disk_op_s *op)
{
    if (! CONFIG_VIRTIO_BLK || CONFIG_COREBOOT)
        return 0;
    switch (op->command) {
    case CMD_READ:
        return virtio_blk_op(op, 0);
    case CMD_WRITE:
        return virtio_blk_op(op, 1);
    case CMD_FORMAT:
    case CMD_RESET:
    case CMD_ISREADY:
    case CMD_VERIFY:
    case CMD_SEEK:
        return DISK_RET_SUCCESS;
    default:
        op->count = 0;
        return DISK_RET_EPARAM;
    }
}

static void
init_virtio_blk(struct pci_device *pci)
{
    u16 bdf = pci->bdf;
    dprintf(1, "found virtio-blk at %x:%x\n", pci_bdf_to_bus(bdf),
            pci_bdf_to_dev(bdf));
    struct virtiodrive_s *vdrive_g = malloc_fseg(sizeof(*vdrive_g));
    struct vring_virtqueue *vq = memalign_low(PAGE_SIZE, sizeof(*vq));
    if (!vdrive_g || !vq) {
        warn_noalloc();
        goto fail;
    }
    memset(vdrive_g, 0, sizeof(*vdrive_g));
    memset(vq, 0, sizeof(*vq));
    vdrive_g->drive.type = DTYPE_VIRTIO;
    vdrive_g->drive.cntl_id = bdf;
    vdrive_g->vq = vq;

    u16 ioaddr = pci_config_readl(bdf, PCI_BASE_ADDRESS_0) &
        PCI_BASE_ADDRESS_IO_MASK;

    vdrive_g->ioaddr = ioaddr;

    vp_reset(ioaddr);
    vp_set_status(ioaddr, VIRTIO_CONFIG_S_ACKNOWLEDGE |
                  VIRTIO_CONFIG_S_DRIVER );

    if (vp_find_vq(ioaddr, 0, vdrive_g->vq) < 0 ) {
        dprintf(1, "fail to find vq for virtio-blk %x:%x\n",
                pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf));
        goto fail;
    }

    struct virtio_blk_config cfg;
    vp_get(ioaddr, 0, &cfg, sizeof(cfg));

    u32 f = vp_get_features(ioaddr);
    vdrive_g->drive.blksize = (f & (1 << VIRTIO_BLK_F_BLK_SIZE)) ?
        cfg.blk_size : DISK_SECTOR_SIZE;

    vdrive_g->drive.sectors = cfg.capacity;
    dprintf(3, "virtio-blk %x:%x blksize=%d sectors=%u\n",
            pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf),
            vdrive_g->drive.blksize, (u32)vdrive_g->drive.sectors);

    if (vdrive_g->drive.blksize != DISK_SECTOR_SIZE) {
        dprintf(1, "virtio-blk %x:%x block size %d is unsupported\n",
                pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf),
                vdrive_g->drive.blksize);
        goto fail;
    }

    vdrive_g->drive.pchs.cylinders = cfg.cylinders;
    vdrive_g->drive.pchs.heads = cfg.heads;
    vdrive_g->drive.pchs.spt = cfg.sectors;
    char *desc = znprintf(MAXDESCSIZE, "Virtio disk PCI:%x:%x",
                          pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf));

    boot_add_hd(&vdrive_g->drive, desc, bootprio_find_pci_device(pci));

    vp_set_status(ioaddr, VIRTIO_CONFIG_S_ACKNOWLEDGE |
                  VIRTIO_CONFIG_S_DRIVER | VIRTIO_CONFIG_S_DRIVER_OK);
    return;

fail:
    free(vdrive_g);
    free(vq);
}

void
virtio_blk_setup(void)
{
    ASSERT32FLAT();
    if (! CONFIG_VIRTIO_BLK || CONFIG_COREBOOT)
        return;

    dprintf(3, "init virtio-blk\n");

    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->vendor != PCI_VENDOR_ID_REDHAT_QUMRANET
            || pci->device != PCI_DEVICE_ID_VIRTIO_BLK)
            continue;
        init_virtio_blk(pci);
    }
}
