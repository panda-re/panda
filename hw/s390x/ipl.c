/*
 * bootloader support
 *
 * Copyright IBM, Corp. 2012
 *
 * Authors:
 *  Christian Borntraeger <borntraeger@de.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at your
 * option) any later version.  See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "cpu.h"
#include "elf.h"
#include "hw/loader.h"
#include "hw/s390x/virtio-ccw.h"
#include "hw/s390x/css.h"
#include "ipl.h"
#include "qemu/error-report.h"

#define KERN_IMAGE_START                0x010000UL
#define KERN_PARM_AREA                  0x010480UL
#define INITRD_START                    0x800000UL
#define INITRD_PARM_START               0x010408UL
#define INITRD_PARM_SIZE                0x010410UL
#define PARMFILE_START                  0x001000UL
#define ZIPL_IMAGE_START                0x009000UL
#define IPL_PSW_MASK                    (PSW_MASK_32 | PSW_MASK_64)

static bool iplb_extended_needed(void *opaque)
{
    S390IPLState *ipl = S390_IPL(object_resolve_path(TYPE_S390_IPL, NULL));

    return ipl->iplbext_migration;
}

static const VMStateDescription vmstate_iplb_extended = {
    .name = "ipl/iplb_extended",
    .version_id = 0,
    .minimum_version_id = 0,
    .needed = iplb_extended_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8_ARRAY(reserved_ext, IplParameterBlock, 4096 - 200),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_iplb = {
    .name = "ipl/iplb",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8_ARRAY(reserved1, IplParameterBlock, 110),
        VMSTATE_UINT16(devno, IplParameterBlock),
        VMSTATE_UINT8_ARRAY(reserved2, IplParameterBlock, 88),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_iplb_extended,
        NULL
    }
};

static const VMStateDescription vmstate_ipl = {
    .name = "ipl",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64(compat_start_addr, S390IPLState),
        VMSTATE_UINT64(compat_bios_start_addr, S390IPLState),
        VMSTATE_STRUCT(iplb, S390IPLState, 0, vmstate_iplb, IplParameterBlock),
        VMSTATE_BOOL(iplb_valid, S390IPLState),
        VMSTATE_UINT8(cssid, S390IPLState),
        VMSTATE_UINT8(ssid, S390IPLState),
        VMSTATE_UINT16(devno, S390IPLState),
        VMSTATE_END_OF_LIST()
     }
};

static S390IPLState *get_ipl_device(void)
{
    return S390_IPL(object_resolve_path_type("", TYPE_S390_IPL, NULL));
}

static uint64_t bios_translate_addr(void *opaque, uint64_t srcaddr)
{
    uint64_t dstaddr = *(uint64_t *) opaque;
    /*
     * Assuming that our s390-ccw.img was linked for starting at address 0,
     * we can simply add the destination address for the final location
     */
    return srcaddr + dstaddr;
}

static void s390_ipl_realize(DeviceState *dev, Error **errp)
{
    S390IPLState *ipl = S390_IPL(dev);
    uint64_t pentry = KERN_IMAGE_START;
    int kernel_size;
    Error *err = NULL;

    int bios_size;
    char *bios_filename;

    /*
     * Always load the bios if it was enforced,
     * even if an external kernel has been defined.
     */
    if (!ipl->kernel || ipl->enforce_bios) {
        uint64_t fwbase = (MIN(ram_size, 0x80000000U) - 0x200000) & ~0xffffUL;

        if (bios_name == NULL) {
            bios_name = ipl->firmware;
        }

        bios_filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);
        if (bios_filename == NULL) {
            error_setg(&err, "could not find stage1 bootloader");
            goto error;
        }

        bios_size = load_elf(bios_filename, bios_translate_addr, &fwbase,
                             &ipl->bios_start_addr, NULL, NULL, 1,
                             EM_S390, 0, 0);
        if (bios_size > 0) {
            /* Adjust ELF start address to final location */
            ipl->bios_start_addr += fwbase;
        } else {
            /* Try to load non-ELF file */
            bios_size = load_image_targphys(bios_filename, ZIPL_IMAGE_START,
                                            4096);
            ipl->bios_start_addr = ZIPL_IMAGE_START;
        }
        g_free(bios_filename);

        if (bios_size == -1) {
            error_setg(&err, "could not load bootloader '%s'", bios_name);
            goto error;
        }

        /* default boot target is the bios */
        ipl->start_addr = ipl->bios_start_addr;
    }

    if (ipl->kernel) {
        kernel_size = load_elf(ipl->kernel, NULL, NULL, &pentry, NULL,
                               NULL, 1, EM_S390, 0, 0);
        if (kernel_size < 0) {
            kernel_size = load_image_targphys(ipl->kernel, 0, ram_size);
        }
        if (kernel_size < 0) {
            error_setg(&err, "could not load kernel '%s'", ipl->kernel);
            goto error;
        }
        /*
         * Is it a Linux kernel (starting at 0x10000)? If yes, we fill in the
         * kernel parameters here as well. Note: For old kernels (up to 3.2)
         * we can not rely on the ELF entry point - it was 0x800 (the SALIPL
         * loader) and it won't work. For this case we force it to 0x10000, too.
         */
        if (pentry == KERN_IMAGE_START || pentry == 0x800) {
            ipl->start_addr = KERN_IMAGE_START;
            /* Overwrite parameters in the kernel image, which are "rom" */
            strcpy(rom_ptr(KERN_PARM_AREA), ipl->cmdline);
        } else {
            ipl->start_addr = pentry;
        }

        if (ipl->initrd) {
            ram_addr_t initrd_offset;
            int initrd_size;

            initrd_offset = INITRD_START;
            while (kernel_size + 0x100000 > initrd_offset) {
                initrd_offset += 0x100000;
            }
            initrd_size = load_image_targphys(ipl->initrd, initrd_offset,
                                              ram_size - initrd_offset);
            if (initrd_size == -1) {
                error_setg(&err, "could not load initrd '%s'", ipl->initrd);
                goto error;
            }

            /*
             * we have to overwrite values in the kernel image,
             * which are "rom"
             */
            stq_p(rom_ptr(INITRD_PARM_START), initrd_offset);
            stq_p(rom_ptr(INITRD_PARM_SIZE), initrd_size);
        }
    }
    /*
     * Don't ever use the migrated values, they could come from a different
     * BIOS and therefore don't work. But still migrate the values, so
     * QEMUs relying on it don't break.
     */
    ipl->compat_start_addr = ipl->start_addr;
    ipl->compat_bios_start_addr = ipl->bios_start_addr;
    qemu_register_reset(qdev_reset_all_fn, dev);
error:
    error_propagate(errp, err);
}

static Property s390_ipl_properties[] = {
    DEFINE_PROP_STRING("kernel", S390IPLState, kernel),
    DEFINE_PROP_STRING("initrd", S390IPLState, initrd),
    DEFINE_PROP_STRING("cmdline", S390IPLState, cmdline),
    DEFINE_PROP_STRING("firmware", S390IPLState, firmware),
    DEFINE_PROP_STRING("netboot_fw", S390IPLState, netboot_fw),
    DEFINE_PROP_BOOL("enforce_bios", S390IPLState, enforce_bios, false),
    DEFINE_PROP_BOOL("iplbext_migration", S390IPLState, iplbext_migration,
                     true),
    DEFINE_PROP_END_OF_LIST(),
};

static bool s390_gen_initial_iplb(S390IPLState *ipl)
{
    DeviceState *dev_st;

    dev_st = get_boot_device(0);
    if (dev_st) {
        VirtioCcwDevice *virtio_ccw_dev = (VirtioCcwDevice *)
            object_dynamic_cast(OBJECT(qdev_get_parent_bus(dev_st)->parent),
                TYPE_VIRTIO_CCW_DEVICE);
        SCSIDevice *sd = (SCSIDevice *) object_dynamic_cast(OBJECT(dev_st),
                                                            TYPE_SCSI_DEVICE);
        VirtIONet *vn = (VirtIONet *) object_dynamic_cast(OBJECT(dev_st),
                                                          TYPE_VIRTIO_NET);

        if (vn) {
            ipl->netboot = true;
        }
        if (virtio_ccw_dev) {
            CcwDevice *ccw_dev = CCW_DEVICE(virtio_ccw_dev);

            ipl->iplb.len = cpu_to_be32(S390_IPLB_MIN_CCW_LEN);
            ipl->iplb.blk0_len =
                cpu_to_be32(S390_IPLB_MIN_CCW_LEN - S390_IPLB_HEADER_LEN);
            ipl->iplb.pbt = S390_IPL_TYPE_CCW;
            ipl->iplb.ccw.devno = cpu_to_be16(ccw_dev->sch->devno);
            ipl->iplb.ccw.ssid = ccw_dev->sch->ssid & 3;
            return true;
        } else if (sd) {
            SCSIBus *bus = scsi_bus_from_device(sd);
            VirtIOSCSI *vdev = container_of(bus, VirtIOSCSI, bus);
            VirtIOSCSICcw *scsi_ccw = container_of(vdev, VirtIOSCSICcw, vdev);
            CcwDevice *ccw_dev;

            ccw_dev = (CcwDevice *)object_dynamic_cast(OBJECT(scsi_ccw),
                                                       TYPE_CCW_DEVICE);
            if (!ccw_dev) {       /* It might be a PCI device instead */
                return false;
            }

            ipl->iplb.len = cpu_to_be32(S390_IPLB_MIN_QEMU_SCSI_LEN);
            ipl->iplb.blk0_len =
                cpu_to_be32(S390_IPLB_MIN_QEMU_SCSI_LEN - S390_IPLB_HEADER_LEN);
            ipl->iplb.pbt = S390_IPL_TYPE_QEMU_SCSI;
            ipl->iplb.scsi.lun = cpu_to_be32(sd->lun);
            ipl->iplb.scsi.target = cpu_to_be16(sd->id);
            ipl->iplb.scsi.channel = cpu_to_be16(sd->channel);
            ipl->iplb.scsi.devno = cpu_to_be16(ccw_dev->sch->devno);
            ipl->iplb.scsi.ssid = ccw_dev->sch->ssid & 3;
            return true;
        }
    }

    return false;
}

static int load_netboot_image(Error **errp)
{
    S390IPLState *ipl = get_ipl_device();
    char *netboot_filename;
    MemoryRegion *sysmem =  get_system_memory();
    MemoryRegion *mr = NULL;
    void *ram_ptr = NULL;
    int img_size = -1;

    mr = memory_region_find(sysmem, 0, 1).mr;
    if (!mr) {
        error_setg(errp, "Failed to find memory region at address 0");
        return -1;
    }

    ram_ptr = memory_region_get_ram_ptr(mr);
    if (!ram_ptr) {
        error_setg(errp, "No RAM found");
        goto unref_mr;
    }

    netboot_filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, ipl->netboot_fw);
    if (netboot_filename == NULL) {
        error_setg(errp, "Could not find network bootloader");
        goto unref_mr;
    }

    img_size = load_elf_ram(netboot_filename, NULL, NULL, &ipl->start_addr,
                            NULL, NULL, 1, EM_S390, 0, 0, NULL, false);

    if (img_size < 0) {
        img_size = load_image_size(netboot_filename, ram_ptr, ram_size);
        ipl->start_addr = KERN_IMAGE_START;
    }

    if (img_size < 0) {
        error_setg(errp, "Failed to load network bootloader");
    }

    g_free(netboot_filename);

unref_mr:
    memory_region_unref(mr);
    return img_size;
}

static bool is_virtio_net_device(IplParameterBlock *iplb)
{
    uint8_t cssid;
    uint8_t ssid;
    uint16_t devno;
    uint16_t schid;
    SubchDev *sch = NULL;

    if (iplb->pbt != S390_IPL_TYPE_CCW) {
        return false;
    }

    devno = be16_to_cpu(iplb->ccw.devno);
    ssid = iplb->ccw.ssid & 3;

    for (schid = 0; schid < MAX_SCHID; schid++) {
        for (cssid = 0; cssid < MAX_CSSID; cssid++) {
            sch = css_find_subch(1, cssid, ssid, schid);

            if (sch && sch->devno == devno) {
                return sch->id.cu_model == VIRTIO_ID_NET;
            }
        }
    }
    return false;
}

void s390_ipl_update_diag308(IplParameterBlock *iplb)
{
    S390IPLState *ipl = get_ipl_device();

    ipl->iplb = *iplb;
    ipl->iplb_valid = true;
    ipl->netboot = is_virtio_net_device(iplb);
}

IplParameterBlock *s390_ipl_get_iplb(void)
{
    S390IPLState *ipl = get_ipl_device();

    if (!ipl->iplb_valid) {
        return NULL;
    }
    return &ipl->iplb;
}

void s390_reipl_request(void)
{
    S390IPLState *ipl = get_ipl_device();

    ipl->reipl_requested = true;
    qemu_system_reset_request();
}

void s390_ipl_prepare_cpu(S390CPU *cpu)
{
    S390IPLState *ipl = get_ipl_device();
    Error *err = NULL;

    cpu->env.psw.addr = ipl->start_addr;
    cpu->env.psw.mask = IPL_PSW_MASK;

    if (!ipl->kernel || ipl->iplb_valid) {
        cpu->env.psw.addr = ipl->bios_start_addr;
        if (!ipl->iplb_valid) {
            ipl->iplb_valid = s390_gen_initial_iplb(ipl);
        }
    }
    if (ipl->netboot) {
        if (load_netboot_image(&err) < 0) {
            error_report_err(err);
            vm_stop(RUN_STATE_INTERNAL_ERROR);
        }
        ipl->iplb.ccw.netboot_start_addr = ipl->start_addr;
    }
}

static void s390_ipl_reset(DeviceState *dev)
{
    S390IPLState *ipl = S390_IPL(dev);

    if (!ipl->reipl_requested) {
        ipl->iplb_valid = false;
        memset(&ipl->iplb, 0, sizeof(IplParameterBlock));
    }
    ipl->reipl_requested = false;
}

static void s390_ipl_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = s390_ipl_realize;
    dc->props = s390_ipl_properties;
    dc->reset = s390_ipl_reset;
    dc->vmsd = &vmstate_ipl;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo s390_ipl_info = {
    .class_init = s390_ipl_class_init,
    .parent = TYPE_DEVICE,
    .name  = TYPE_S390_IPL,
    .instance_size  = sizeof(S390IPLState),
};

static void s390_ipl_register_types(void)
{
    type_register_static(&s390_ipl_info);
}

type_init(s390_ipl_register_types)
