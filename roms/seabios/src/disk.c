// 16bit code to access hard drives.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "disk.h" // floppy_13
#include "biosvar.h" // SET_BDA
#include "config.h" // CONFIG_*
#include "util.h" // debug_enter
#include "pic.h" // eoi_pic2
#include "bregs.h" // struct bregs
#include "pci.h" // pci_bdf_to_bus
#include "ata.h" // ATA_CB_DC


/****************************************************************
 * Helper functions
 ****************************************************************/

void
__disk_ret(struct bregs *regs, u32 linecode, const char *fname)
{
    u8 code = linecode;
    if (regs->dl < EXTSTART_HD)
        SET_BDA(floppy_last_status, code);
    else
        SET_BDA(disk_last_status, code);
    if (code)
        __set_code_invalid(regs, linecode, fname);
    else
        set_code_success(regs);
}

void
__disk_ret_unimplemented(struct bregs *regs, u32 linecode, const char *fname)
{
    u8 code = linecode;
    if (regs->dl < EXTSTART_HD)
        SET_BDA(floppy_last_status, code);
    else
        SET_BDA(disk_last_status, code);
    __set_code_unimplemented(regs, linecode, fname);
}

static void
__disk_stub(struct bregs *regs, int lineno, const char *fname)
{
    __warn_unimplemented(regs, lineno, fname);
    __disk_ret(regs, DISK_RET_SUCCESS | (lineno << 8), fname);
}

#define DISK_STUB(regs)                         \
    __disk_stub((regs), __LINE__, __func__)

// Get the cylinders/heads/sectors for the given drive.
static void
fillLCHS(struct drive_s *drive_g, u16 *nlc, u16 *nlh, u16 *nlspt)
{
    if (CONFIG_CDROM_EMU
        && drive_g == GLOBALFLAT2GLOBAL(GET_GLOBAL(cdemu_drive_gf))) {
        // Emulated drive - get info from ebda.  (It's not possible to
        // populate the geometry directly in the driveid because the
        // geometry is only known after the bios segment is made
        // read-only).
        u16 ebda_seg = get_ebda_seg();
        *nlc = GET_EBDA2(ebda_seg, cdemu.lchs.cylinders);
        *nlh = GET_EBDA2(ebda_seg, cdemu.lchs.heads);
        *nlspt = GET_EBDA2(ebda_seg, cdemu.lchs.spt);
        return;
    }
    *nlc = GET_GLOBAL(drive_g->lchs.cylinders);
    *nlh = GET_GLOBAL(drive_g->lchs.heads);
    *nlspt = GET_GLOBAL(drive_g->lchs.spt);
}

// Perform read/write/verify using old-style chs accesses
static void
basic_access(struct bregs *regs, struct drive_s *drive_g, u16 command)
{
    struct disk_op_s dop;
    dop.drive_g = drive_g;
    dop.command = command;

    u8 count = regs->al;
    u16 cylinder = regs->ch | ((((u16)regs->cl) << 2) & 0x300);
    u16 sector = regs->cl & 0x3f;
    u16 head = regs->dh;

    if (count > 128 || count == 0 || sector == 0) {
        warn_invalid(regs);
        disk_ret(regs, DISK_RET_EPARAM);
        return;
    }
    dop.count = count;

    u16 nlc, nlh, nlspt;
    fillLCHS(drive_g, &nlc, &nlh, &nlspt);

    // sanity check on cyl heads, sec
    if (cylinder >= nlc || head >= nlh || sector > nlspt) {
        warn_invalid(regs);
        disk_ret(regs, DISK_RET_EPARAM);
        return;
    }

    // translate lchs to lba
    dop.lba = (((((u32)cylinder * (u32)nlh) + (u32)head) * (u32)nlspt)
               + (u32)sector - 1);

    dop.buf_fl = MAKE_FLATPTR(regs->es, regs->bx);

    int status = send_disk_op(&dop);

    regs->al = dop.count;

    disk_ret(regs, status);
}

// Perform read/write/verify using new-style "int13ext" accesses.
static void
extended_access(struct bregs *regs, struct drive_s *drive_g, u16 command)
{
    struct disk_op_s dop;
    // Get lba and check.
    dop.lba = GET_INT13EXT(regs, lba);
    dop.command = command;
    dop.drive_g = drive_g;
    if (dop.lba >= GET_GLOBAL(drive_g->sectors)) {
        warn_invalid(regs);
        disk_ret(regs, DISK_RET_EPARAM);
        return;
    }

    dop.buf_fl = SEGOFF_TO_FLATPTR(GET_INT13EXT(regs, data));
    dop.count = GET_INT13EXT(regs, count);

    int status = send_disk_op(&dop);

    SET_INT13EXT(regs, count, dop.count);

    disk_ret(regs, status);
}


/****************************************************************
 * Hard Drive functions
 ****************************************************************/

// disk controller reset
static void
disk_1300(struct bregs *regs, struct drive_s *drive_g)
{
    struct disk_op_s dop;
    dop.drive_g = drive_g;
    dop.command = CMD_RESET;
    int status = send_disk_op(&dop);
    disk_ret(regs, status);
}

// read disk status
static void
disk_1301(struct bregs *regs, struct drive_s *drive_g)
{
    u8 v;
    if (regs->dl < EXTSTART_HD)
        // Floppy
        v = GET_BDA(floppy_last_status);
    else
        v = GET_BDA(disk_last_status);
    regs->ah = v;
    set_cf(regs, v);
    // XXX - clear disk_last_status?
}

// read disk sectors
static void
disk_1302(struct bregs *regs, struct drive_s *drive_g)
{
    basic_access(regs, drive_g, CMD_READ);
}

// write disk sectors
static void
disk_1303(struct bregs *regs, struct drive_s *drive_g)
{
    basic_access(regs, drive_g, CMD_WRITE);
}

// verify disk sectors
static void
disk_1304(struct bregs *regs, struct drive_s *drive_g)
{
    basic_access(regs, drive_g, CMD_VERIFY);
}

// format disk track
static void
disk_1305(struct bregs *regs, struct drive_s *drive_g)
{
    debug_stub(regs);

    u16 nlc, nlh, nlspt;
    fillLCHS(drive_g, &nlc, &nlh, &nlspt);

    u8 num_sectors = regs->al;
    u8 head        = regs->dh;

    if (head >= nlh || num_sectors == 0 || num_sectors > nlspt) {
        disk_ret(regs, DISK_RET_EPARAM);
        return;
    }

    struct disk_op_s dop;
    dop.drive_g = drive_g;
    dop.command = CMD_FORMAT;
    dop.lba = head;
    dop.count = num_sectors;
    dop.buf_fl = MAKE_FLATPTR(regs->es, regs->bx);
    int status = send_disk_op(&dop);
    disk_ret(regs, status);
}

// read disk drive parameters
static void
disk_1308(struct bregs *regs, struct drive_s *drive_g)
{
    u16 ebda_seg = get_ebda_seg();
    // Get logical geometry from table
    u16 nlc, nlh, nlspt;
    fillLCHS(drive_g, &nlc, &nlh, &nlspt);
    nlc--;
    nlh--;
    u8 count;
    if (regs->dl < EXTSTART_HD) {
        // Floppy
        count = GET_GLOBAL(FloppyCount);

        if (CONFIG_CDROM_EMU
            && drive_g == GLOBALFLAT2GLOBAL(GET_GLOBAL(cdemu_drive_gf)))
            regs->bx = GET_EBDA2(ebda_seg, cdemu.media) * 2;
        else
            regs->bx = GET_GLOBAL(drive_g->floppy_type);

        // set es & di to point to 11 byte diskette param table in ROM
        regs->es = SEG_BIOS;
        regs->di = (u32)&diskette_param_table2;
    } else if (regs->dl < EXTSTART_CD) {
        // Hard drive
        count = GET_BDA(hdcount);
        nlc--;  // last sector reserved
    } else {
        // Not supported on CDROM
        disk_ret(regs, DISK_RET_EPARAM);
        return;
    }

    if (CONFIG_CDROM_EMU && GET_EBDA2(ebda_seg, cdemu.active)) {
        u8 emudrive = GET_EBDA2(ebda_seg, cdemu.emulated_extdrive);
        if (((emudrive ^ regs->dl) & 0x80) == 0)
            // Note extra drive due to emulation.
            count++;
        if (regs->dl < EXTSTART_HD && count > 2)
            // Max of two floppy drives.
            count = 2;
    }

    regs->al = 0;
    regs->ch = nlc & 0xff;
    regs->cl = ((nlc >> 2) & 0xc0) | (nlspt & 0x3f);
    regs->dh = nlh;

    disk_ret(regs, DISK_RET_SUCCESS);
    regs->dl = count;
}

// initialize drive parameters
static void
disk_1309(struct bregs *regs, struct drive_s *drive_g)
{
    DISK_STUB(regs);
}

// seek to specified cylinder
static void
disk_130c(struct bregs *regs, struct drive_s *drive_g)
{
    DISK_STUB(regs);
}

// alternate disk reset
static void
disk_130d(struct bregs *regs, struct drive_s *drive_g)
{
    DISK_STUB(regs);
}

// check drive ready
static void
disk_1310(struct bregs *regs, struct drive_s *drive_g)
{
    // should look at 40:8E also???

    struct disk_op_s dop;
    dop.drive_g = drive_g;
    dop.command = CMD_ISREADY;
    int status = send_disk_op(&dop);
    disk_ret(regs, status);
}

// recalibrate
static void
disk_1311(struct bregs *regs, struct drive_s *drive_g)
{
    DISK_STUB(regs);
}

// controller internal diagnostic
static void
disk_1314(struct bregs *regs, struct drive_s *drive_g)
{
    DISK_STUB(regs);
}

// read disk drive size
static void
disk_1315(struct bregs *regs, struct drive_s *drive_g)
{
    disk_ret(regs, DISK_RET_SUCCESS);
    if (regs->dl < EXTSTART_HD || regs->dl >= EXTSTART_CD) {
        // Floppy or cdrom
        regs->ah = 1;
        return;
    }
    // Hard drive

    // Get logical geometry from table
    u16 nlc, nlh, nlspt;
    fillLCHS(drive_g, &nlc, &nlh, &nlspt);

    // Compute sector count seen by int13
    u32 lba = (u32)(nlc - 1) * (u32)nlh * (u32)nlspt;
    regs->cx = lba >> 16;
    regs->dx = lba & 0xffff;
    regs->ah = 3; // hard disk accessible
}

static void
disk_1316(struct bregs *regs, struct drive_s *drive_g)
{
    if (regs->dl >= EXTSTART_HD) {
        // Hard drive
        disk_ret(regs, DISK_RET_EPARAM);
        return;
    }
    disk_ret(regs, DISK_RET_ECHANGED);
}

// IBM/MS installation check
static void
disk_1341(struct bregs *regs, struct drive_s *drive_g)
{
    regs->bx = 0xaa55;  // install check
    regs->cx = 0x0007;  // ext disk access and edd, removable supported
    disk_ret(regs, DISK_RET_SUCCESS);
    regs->ah = 0x30;    // EDD 3.0
}

// IBM/MS extended read
static void
disk_1342(struct bregs *regs, struct drive_s *drive_g)
{
    extended_access(regs, drive_g, CMD_READ);
}

// IBM/MS extended write
static void
disk_1343(struct bregs *regs, struct drive_s *drive_g)
{
    extended_access(regs, drive_g, CMD_WRITE);
}

// IBM/MS verify
static void
disk_1344(struct bregs *regs, struct drive_s *drive_g)
{
    extended_access(regs, drive_g, CMD_VERIFY);
}

// lock
static void
disk_134500(struct bregs *regs, struct drive_s *drive_g)
{
    u16 ebda_seg = get_ebda_seg();
    int cdid = regs->dl - EXTSTART_CD;
    u8 locks = GET_EBDA2(ebda_seg, cdrom_locks[cdid]);
    if (locks == 0xff) {
        regs->al = 1;
        disk_ret(regs, DISK_RET_ETOOMANYLOCKS);
        return;
    }
    SET_EBDA2(ebda_seg, cdrom_locks[cdid], locks + 1);
    regs->al = 1;
    disk_ret(regs, DISK_RET_SUCCESS);
}

// unlock
static void
disk_134501(struct bregs *regs, struct drive_s *drive_g)
{
    u16 ebda_seg = get_ebda_seg();
    int cdid = regs->dl - EXTSTART_CD;
    u8 locks = GET_EBDA2(ebda_seg, cdrom_locks[cdid]);
    if (locks == 0x00) {
        regs->al = 0;
        disk_ret(regs, DISK_RET_ENOTLOCKED);
        return;
    }
    locks--;
    SET_EBDA2(ebda_seg, cdrom_locks[cdid], locks);
    regs->al = (locks ? 1 : 0);
    disk_ret(regs, DISK_RET_SUCCESS);
}

// status
static void
disk_134502(struct bregs *regs, struct drive_s *drive_g)
{
    int cdid = regs->dl - EXTSTART_CD;
    u8 locks = GET_EBDA(cdrom_locks[cdid]);
    regs->al = (locks ? 1 : 0);
    disk_ret(regs, DISK_RET_SUCCESS);
}

static void
disk_1345XX(struct bregs *regs, struct drive_s *drive_g)
{
    disk_ret_unimplemented(regs, DISK_RET_EPARAM);
}

// IBM/MS lock/unlock drive
static void
disk_1345(struct bregs *regs, struct drive_s *drive_g)
{
    if (regs->dl < EXTSTART_CD) {
        // Always success for HD
        disk_ret(regs, DISK_RET_SUCCESS);
        return;
    }

    switch (regs->al) {
    case 0x00: disk_134500(regs, drive_g); break;
    case 0x01: disk_134501(regs, drive_g); break;
    case 0x02: disk_134502(regs, drive_g); break;
    default:   disk_1345XX(regs, drive_g); break;
    }
}

// IBM/MS eject media
static void
disk_1346(struct bregs *regs, struct drive_s *drive_g)
{
    if (regs->dl < EXTSTART_CD) {
        // Volume Not Removable
        disk_ret(regs, DISK_RET_ENOTREMOVABLE);
        return;
    }

    int cdid = regs->dl - EXTSTART_CD;
    u8 locks = GET_EBDA(cdrom_locks[cdid]);
    if (locks != 0) {
        disk_ret(regs, DISK_RET_ELOCKED);
        return;
    }

    // FIXME should handle 0x31 no media in device
    // FIXME should handle 0xb5 valid request failed

    // Call removable media eject
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.ah = 0x52;
    br.dl = regs->dl;
    call16_int(0x15, &br);

    if (br.ah || br.flags & F_CF) {
        disk_ret(regs, DISK_RET_ELOCKED);
        return;
    }
    disk_ret(regs, DISK_RET_SUCCESS);
}

// IBM/MS extended seek
static void
disk_1347(struct bregs *regs, struct drive_s *drive_g)
{
    extended_access(regs, drive_g, CMD_SEEK);
}

// IBM/MS get drive parameters
static void
disk_1348(struct bregs *regs, struct drive_s *drive_g)
{
    u16 size = GET_INT13DPT(regs, size);
    u16 t13 = size == 74;

    // Buffer is too small
    if (size < 26) {
        disk_ret(regs, DISK_RET_EPARAM);
        return;
    }

    // EDD 1.x

    u8  type    = GET_GLOBAL(drive_g->type);
    u16 npc     = GET_GLOBAL(drive_g->pchs.cylinders);
    u16 nph     = GET_GLOBAL(drive_g->pchs.heads);
    u16 npspt   = GET_GLOBAL(drive_g->pchs.spt);
    u64 lba     = GET_GLOBAL(drive_g->sectors);
    u16 blksize = GET_GLOBAL(drive_g->blksize);

    dprintf(DEBUG_HDL_13, "disk_1348 size=%d t=%d chs=%d,%d,%d lba=%d bs=%d\n"
            , size, type, npc, nph, npspt, (u32)lba, blksize);

    SET_INT13DPT(regs, size, 26);
    if (type == DTYPE_ATAPI) {
        // 0x74 = removable, media change, lockable, max values
        SET_INT13DPT(regs, infos, 0x74);
        SET_INT13DPT(regs, cylinders, 0xffffffff);
        SET_INT13DPT(regs, heads, 0xffffffff);
        SET_INT13DPT(regs, spt, 0xffffffff);
        SET_INT13DPT(regs, sector_count, (u64)-1);
    } else {
        if (lba > (u64)npspt*nph*0x3fff) {
            SET_INT13DPT(regs, infos, 0x00); // geometry is invalid
            SET_INT13DPT(regs, cylinders, 0x3fff);
        } else {
            SET_INT13DPT(regs, infos, 0x02); // geometry is valid
            SET_INT13DPT(regs, cylinders, (u32)npc);
        }
        SET_INT13DPT(regs, heads, (u32)nph);
        SET_INT13DPT(regs, spt, (u32)npspt);
        SET_INT13DPT(regs, sector_count, lba);
    }
    SET_INT13DPT(regs, blksize, blksize);

    if (size < 30 ||
        (type != DTYPE_ATA && type != DTYPE_ATAPI && type != DTYPE_VIRTIO)) {
        disk_ret(regs, DISK_RET_SUCCESS);
        return;
    }

    // EDD 2.x

    int bdf;
    u16 iobase1 = 0;
    u64 device_path = 0;
    u8 channel = 0;
    SET_INT13DPT(regs, size, 30);
    if (type == DTYPE_ATA || type == DTYPE_ATAPI) {
        u16 ebda_seg = get_ebda_seg();

        SET_INT13DPT(regs, dpte_segment, ebda_seg);
        SET_INT13DPT(regs, dpte_offset
                     , offsetof(struct extended_bios_data_area_s, dpte));

        // Fill in dpte
        struct atadrive_s *adrive_g = container_of(
            drive_g, struct atadrive_s, drive);
        struct ata_channel_s *chan_gf = GET_GLOBAL(adrive_g->chan_gf);
        u8 slave = GET_GLOBAL(adrive_g->slave);
        u16 iobase2 = GET_GLOBALFLAT(chan_gf->iobase2);
        u8 irq = GET_GLOBALFLAT(chan_gf->irq);
        iobase1 = GET_GLOBALFLAT(chan_gf->iobase1);
        bdf = GET_GLOBALFLAT(chan_gf->pci_bdf);
        device_path = slave;
        channel = GET_GLOBALFLAT(chan_gf->chanid);

        u16 options = 0;
        if (type == DTYPE_ATA) {
            u8 translation = GET_GLOBAL(drive_g->translation);
            if (translation != TRANSLATION_NONE) {
                options |= 1<<3; // CHS translation
                if (translation == TRANSLATION_LBA)
                    options |= 1<<9;
                if (translation == TRANSLATION_RECHS)
                    options |= 3<<9;
            }
        } else {
            // ATAPI
            options |= 1<<5; // removable device
            options |= 1<<6; // atapi device
        }
        options |= 1<<4; // lba translation
        if (CONFIG_ATA_PIO32)
            options |= 1<<7;

        SET_EBDA2(ebda_seg, dpte.iobase1, iobase1);
        SET_EBDA2(ebda_seg, dpte.iobase2, iobase2 + ATA_CB_DC);
        SET_EBDA2(ebda_seg, dpte.prefix, ((slave ? ATA_CB_DH_DEV1 : ATA_CB_DH_DEV0)
                                          | ATA_CB_DH_LBA));
        SET_EBDA2(ebda_seg, dpte.unused, 0xcb);
        SET_EBDA2(ebda_seg, dpte.irq, irq);
        SET_EBDA2(ebda_seg, dpte.blkcount, 1);
        SET_EBDA2(ebda_seg, dpte.dma, 0);
        SET_EBDA2(ebda_seg, dpte.pio, 0);
        SET_EBDA2(ebda_seg, dpte.options, options);
        SET_EBDA2(ebda_seg, dpte.reserved, 0);
        SET_EBDA2(ebda_seg, dpte.revision, 0x11);

        u8 sum = checksum_far(
            ebda_seg, (void*)offsetof(struct extended_bios_data_area_s, dpte), 15);
        SET_EBDA2(ebda_seg, dpte.checksum, -sum);
    } else {
        SET_INT13DPT(regs, dpte_segment, 0);
        SET_INT13DPT(regs, dpte_offset, 0);
        bdf = GET_GLOBAL(drive_g->cntl_id);
    }

    if (size < 66) {
        disk_ret(regs, DISK_RET_SUCCESS);
        return;
    }

    // EDD 3.x
    SET_INT13DPT(regs, key, 0xbedd);
    SET_INT13DPT(regs, dpi_length, t13 ? 44 : 36);
    SET_INT13DPT(regs, reserved1, 0);
    SET_INT13DPT(regs, reserved2, 0);

    if (bdf != -1) {
        SET_INT13DPT(regs, host_bus[0], 'P');
        SET_INT13DPT(regs, host_bus[1], 'C');
        SET_INT13DPT(regs, host_bus[2], 'I');
        SET_INT13DPT(regs, host_bus[3], ' ');

        u32 path = (pci_bdf_to_bus(bdf) | (pci_bdf_to_dev(bdf) << 8)
                    | (pci_bdf_to_fn(bdf) << 16));
        if (t13)
            path |= channel << 24;

        SET_INT13DPT(regs, iface_path, path);
    } else {
        // ISA
        SET_INT13DPT(regs, host_bus[0], 'I');
        SET_INT13DPT(regs, host_bus[1], 'S');
        SET_INT13DPT(regs, host_bus[2], 'A');
        SET_INT13DPT(regs, host_bus[3], ' ');

        SET_INT13DPT(regs, iface_path, iobase1);
    }

    if (type != DTYPE_VIRTIO) {
        SET_INT13DPT(regs, iface_type[0], 'A');
        SET_INT13DPT(regs, iface_type[1], 'T');
        SET_INT13DPT(regs, iface_type[2], 'A');
        SET_INT13DPT(regs, iface_type[3], ' ');
    } else {
        SET_INT13DPT(regs, iface_type[0], 'S');
        SET_INT13DPT(regs, iface_type[1], 'C');
        SET_INT13DPT(regs, iface_type[2], 'S');
        SET_INT13DPT(regs, iface_type[3], 'I');
    }
    SET_INT13DPT(regs, iface_type[4], ' ');
    SET_INT13DPT(regs, iface_type[5], ' ');
    SET_INT13DPT(regs, iface_type[6], ' ');
    SET_INT13DPT(regs, iface_type[7], ' ');

    if (t13) {
        SET_INT13DPT(regs, t13.device_path[0], device_path);
        SET_INT13DPT(regs, t13.device_path[1], 0);

        SET_INT13DPT(regs, t13.checksum
                     , -checksum_far(regs->ds, (void*)(regs->si+30), 43));
    } else {
        SET_INT13DPT(regs, phoenix.device_path, device_path);

        SET_INT13DPT(regs, phoenix.checksum
                     , -checksum_far(regs->ds, (void*)(regs->si+30), 35));
    }

    disk_ret(regs, DISK_RET_SUCCESS);
}

// IBM/MS extended media change
static void
disk_1349(struct bregs *regs, struct drive_s *drive_g)
{
    if (regs->dl < EXTSTART_CD) {
        // Always success for HD
        disk_ret(regs, DISK_RET_SUCCESS);
        return;
    }
    set_invalid(regs);
    // always send changed ??
    regs->ah = DISK_RET_ECHANGED;
}

static void
disk_134e01(struct bregs *regs, struct drive_s *drive_g)
{
    disk_ret(regs, DISK_RET_SUCCESS);
}

static void
disk_134e03(struct bregs *regs, struct drive_s *drive_g)
{
    disk_ret(regs, DISK_RET_SUCCESS);
}

static void
disk_134e04(struct bregs *regs, struct drive_s *drive_g)
{
    disk_ret(regs, DISK_RET_SUCCESS);
}

static void
disk_134e06(struct bregs *regs, struct drive_s *drive_g)
{
    disk_ret(regs, DISK_RET_SUCCESS);
}

static void
disk_134eXX(struct bregs *regs, struct drive_s *drive_g)
{
    disk_ret(regs, DISK_RET_EPARAM);
}

// IBM/MS set hardware configuration
static void
disk_134e(struct bregs *regs, struct drive_s *drive_g)
{
    switch (regs->al) {
    case 0x01: disk_134e01(regs, drive_g); break;
    case 0x03: disk_134e03(regs, drive_g); break;
    case 0x04: disk_134e04(regs, drive_g); break;
    case 0x06: disk_134e06(regs, drive_g); break;
    default:   disk_134eXX(regs, drive_g); break;
    }
}

static void
disk_13XX(struct bregs *regs, struct drive_s *drive_g)
{
    disk_ret_unimplemented(regs, DISK_RET_EPARAM);
}

static void
disk_13(struct bregs *regs, struct drive_s *drive_g)
{
    //debug_stub(regs);

    // clear completion flag
    SET_BDA(disk_interrupt_flag, 0);

    switch (regs->ah) {
    case 0x00: disk_1300(regs, drive_g); break;
    case 0x01: disk_1301(regs, drive_g); break;
    case 0x02: disk_1302(regs, drive_g); break;
    case 0x03: disk_1303(regs, drive_g); break;
    case 0x04: disk_1304(regs, drive_g); break;
    case 0x05: disk_1305(regs, drive_g); break;
    case 0x08: disk_1308(regs, drive_g); break;
    case 0x09: disk_1309(regs, drive_g); break;
    case 0x0c: disk_130c(regs, drive_g); break;
    case 0x0d: disk_130d(regs, drive_g); break;
    case 0x10: disk_1310(regs, drive_g); break;
    case 0x11: disk_1311(regs, drive_g); break;
    case 0x14: disk_1314(regs, drive_g); break;
    case 0x15: disk_1315(regs, drive_g); break;
    case 0x16: disk_1316(regs, drive_g); break;
    case 0x41: disk_1341(regs, drive_g); break;
    case 0x42: disk_1342(regs, drive_g); break;
    case 0x43: disk_1343(regs, drive_g); break;
    case 0x44: disk_1344(regs, drive_g); break;
    case 0x45: disk_1345(regs, drive_g); break;
    case 0x46: disk_1346(regs, drive_g); break;
    case 0x47: disk_1347(regs, drive_g); break;
    case 0x48: disk_1348(regs, drive_g); break;
    case 0x49: disk_1349(regs, drive_g); break;
    case 0x4e: disk_134e(regs, drive_g); break;
    default:   disk_13XX(regs, drive_g); break;
    }
}

static void
floppy_13(struct bregs *regs, struct drive_s *drive_g)
{
    // Only limited commands are supported on floppies.
    switch (regs->ah) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x08:
    case 0x15:
    case 0x16:
        disk_13(regs, drive_g);
        break;
    default:   disk_13XX(regs, drive_g); break;
    }
}


/****************************************************************
 * Entry points
 ****************************************************************/

static void
handle_legacy_disk(struct bregs *regs, u8 extdrive)
{
    if (! CONFIG_DRIVES) {
        // XXX - support handle_1301 anyway?
        disk_ret(regs, DISK_RET_EPARAM);
        return;
    }

    if (extdrive < EXTSTART_HD) {
        struct drive_s *drive_g = getDrive(EXTTYPE_FLOPPY, extdrive);
        if (!drive_g)
            goto fail;
        floppy_13(regs, drive_g);
        return;
    }

    struct drive_s *drive_g;
    if (extdrive >= EXTSTART_CD)
        drive_g = getDrive(EXTTYPE_CD, extdrive - EXTSTART_CD);
    else
        drive_g = getDrive(EXTTYPE_HD, extdrive - EXTSTART_HD);
    if (!drive_g)
        goto fail;
    disk_13(regs, drive_g);
    return;

fail:
    // XXX - support 1301/1308/1315 anyway?
    disk_ret(regs, DISK_RET_EPARAM);
}

void VISIBLE16
handle_40(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_40);
    handle_legacy_disk(regs, regs->dl);
}

// INT 13h Fixed Disk Services Entry Point
void VISIBLE16
handle_13(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_13);
    u8 extdrive = regs->dl;

    if (CONFIG_CDROM_EMU) {
        if (regs->ah == 0x4b) {
            cdemu_134b(regs);
            return;
        }
        u16 ebda_seg = get_ebda_seg();
        if (GET_EBDA2(ebda_seg, cdemu.active)) {
            u8 emudrive = GET_EBDA2(ebda_seg, cdemu.emulated_extdrive);
            if (extdrive == emudrive) {
                // Access to an emulated drive.
                struct drive_s *cdemu_g;
                cdemu_g = GLOBALFLAT2GLOBAL(GET_GLOBAL(cdemu_drive_gf));
                if (regs->ah > 0x16) {
                    // Only old-style commands supported.
                    disk_13XX(regs, cdemu_g);
                    return;
                }
                disk_13(regs, cdemu_g);
                return;
            }
            if (extdrive < EXTSTART_CD && ((emudrive ^ extdrive) & 0x80) == 0)
                // Adjust id to make room for emulated drive.
                extdrive--;
        }
    }
    handle_legacy_disk(regs, extdrive);
}

// record completion in BIOS task complete flag
void VISIBLE16
handle_76(void)
{
    debug_isr(DEBUG_ISR_76);
    SET_BDA(disk_interrupt_flag, 0xff);
    eoi_pic2();
}

// Old Fixed Disk Parameter Table (newer tables are in the ebda).
struct fdpt_s OldFDPT VAR16FIXED(0xe401);
