// Support for booting from cdroms (the "El Torito" spec).
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "disk.h" // cdrom_13
#include "util.h" // memset
#include "bregs.h" // struct bregs
#include "biosvar.h" // GET_EBDA
#include "ata.h" // ATA_CMD_REQUEST_SENSE
#include "blockcmd.h" // CDB_CMD_REQUEST_SENSE


/****************************************************************
 * CD emulation
 ****************************************************************/

struct drive_s *cdemu_drive_gf VAR16VISIBLE;

static int
cdemu_read(struct disk_op_s *op)
{
    u16 ebda_seg = get_ebda_seg();
    struct drive_s *drive_g;
    drive_g = GLOBALFLAT2GLOBAL(GET_EBDA2(ebda_seg, cdemu.emulated_drive_gf));
    struct disk_op_s dop;
    dop.drive_g = drive_g;
    dop.command = op->command;
    dop.lba = GET_EBDA2(ebda_seg, cdemu.ilba) + op->lba / 4;

    int count = op->count;
    op->count = 0;
    u8 *cdbuf_fl = GET_GLOBAL(bounce_buf_fl);

    if (op->lba & 3) {
        // Partial read of first block.
        dop.count = 1;
        dop.buf_fl = cdbuf_fl;
        int ret = process_op(&dop);
        if (ret)
            return ret;
        u8 thiscount = 4 - (op->lba & 3);
        if (thiscount > count)
            thiscount = count;
        count -= thiscount;
        memcpy_fl(op->buf_fl, cdbuf_fl + (op->lba & 3) * 512, thiscount * 512);
        op->buf_fl += thiscount * 512;
        op->count += thiscount;
        dop.lba++;
    }

    if (count > 3) {
        // Read n number of regular blocks.
        dop.count = count / 4;
        dop.buf_fl = op->buf_fl;
        int ret = process_op(&dop);
        op->count += dop.count * 4;
        if (ret)
            return ret;
        u8 thiscount = count & ~3;
        count &= 3;
        op->buf_fl += thiscount * 512;
        dop.lba += thiscount / 4;
    }

    if (count) {
        // Partial read on last block.
        dop.count = 1;
        dop.buf_fl = cdbuf_fl;
        int ret = process_op(&dop);
        if (ret)
            return ret;
        u8 thiscount = count;
        memcpy_fl(op->buf_fl, cdbuf_fl, thiscount * 512);
        op->count += thiscount;
    }

    return DISK_RET_SUCCESS;
}

int
process_cdemu_op(struct disk_op_s *op)
{
    if (!CONFIG_CDROM_EMU)
        return 0;

    switch (op->command) {
    case CMD_READ:
        return cdemu_read(op);
    case CMD_WRITE:
    case CMD_FORMAT:
        return DISK_RET_EWRITEPROTECT;
    case CMD_VERIFY:
    case CMD_RESET:
    case CMD_SEEK:
    case CMD_ISREADY:
        return DISK_RET_SUCCESS;
    default:
        op->count = 0;
        return DISK_RET_EPARAM;
    }
}

void
cdemu_setup(void)
{
    if (!CONFIG_CDROM_EMU)
        return;
    if (!CDCount)
        return;
    if (bounce_buf_init() < 0)
        return;

    struct drive_s *drive_g = malloc_fseg(sizeof(*drive_g));
    if (!drive_g) {
        warn_noalloc();
        free(drive_g);
        return;
    }
    cdemu_drive_gf = drive_g;
    memset(drive_g, 0, sizeof(*drive_g));
    drive_g->type = DTYPE_CDEMU;
    drive_g->blksize = DISK_SECTOR_SIZE;
    drive_g->sectors = (u64)-1;
}

struct eltorito_s {
    u8 size;
    u8 media;
    u8 emulated_drive;
    u8 controller_index;
    u32 ilba;
    u16 device_spec;
    u16 buffer_segment;
    u16 load_segment;
    u16 sector_count;
    u8 cylinders;
    u8 sectors;
    u8 heads;
};

#define SET_INT13ET(regs,var,val)                                      \
    SET_FARVAR((regs)->ds, ((struct eltorito_s*)((regs)->si+0))->var, (val))

// ElTorito - Terminate disk emu
void
cdemu_134b(struct bregs *regs)
{
    // FIXME ElTorito Hardcoded
    u16 ebda_seg = get_ebda_seg();
    SET_INT13ET(regs, size, 0x13);
    SET_INT13ET(regs, media, GET_EBDA2(ebda_seg, cdemu.media));
    SET_INT13ET(regs, emulated_drive
                , GET_EBDA2(ebda_seg, cdemu.emulated_extdrive));
    struct drive_s *drive_gf = GET_EBDA2(ebda_seg, cdemu.emulated_drive_gf);
    u8 cntl_id = 0;
    if (drive_gf)
        cntl_id = GET_GLOBALFLAT(drive_gf->cntl_id);
    SET_INT13ET(regs, controller_index, cntl_id / 2);
    SET_INT13ET(regs, device_spec, cntl_id % 2);
    SET_INT13ET(regs, ilba, GET_EBDA2(ebda_seg, cdemu.ilba));
    SET_INT13ET(regs, buffer_segment, GET_EBDA2(ebda_seg, cdemu.buffer_segment));
    SET_INT13ET(regs, load_segment, GET_EBDA2(ebda_seg, cdemu.load_segment));
    SET_INT13ET(regs, sector_count, GET_EBDA2(ebda_seg, cdemu.sector_count));
    SET_INT13ET(regs, cylinders, GET_EBDA2(ebda_seg, cdemu.lchs.cylinders));
    SET_INT13ET(regs, sectors, GET_EBDA2(ebda_seg, cdemu.lchs.spt));
    SET_INT13ET(regs, heads, GET_EBDA2(ebda_seg, cdemu.lchs.heads));

    // If we have to terminate emulation
    if (regs->al == 0x00) {
        // FIXME ElTorito Various. Should be handled accordingly to spec
        SET_EBDA2(ebda_seg, cdemu.active, 0x00); // bye bye

        // XXX - update floppy/hd count.
    }

    disk_ret(regs, DISK_RET_SUCCESS);
}


/****************************************************************
 * CD booting
 ****************************************************************/

static int
atapi_is_ready(struct disk_op_s *op)
{
    dprintf(6, "atapi_is_ready (drive=%p)\n", op->drive_g);

    /* Retry READ CAPACITY for 5 seconds unless MEDIUM NOT PRESENT is
     * reported by the device.  If the device reports "IN PROGRESS",
     * 30 seconds is added. */
    struct cdbres_read_capacity info;
    int in_progress = 0;
    u64 end = calc_future_tsc(5000);
    for (;;) {
        if (check_tsc(end)) {
            dprintf(1, "read capacity failed\n");
            return -1;
        }

        int ret = cdb_read_capacity(op, &info);
        if (!ret)
            // Success
            break;

        struct cdbres_request_sense sense;
        ret = cdb_get_sense(op, &sense);
        if (ret)
            // Error - retry.
            continue;

        // Sense succeeded.
        if (sense.asc == 0x3a) { /* MEDIUM NOT PRESENT */
            dprintf(1, "Device reports MEDIUM NOT PRESENT\n");
            return -1;
        }

        if (sense.asc == 0x04 && sense.ascq == 0x01 && !in_progress) {
            /* IN PROGRESS OF BECOMING READY */
            printf("Waiting for device to detect medium... ");
            /* Allow 30 seconds more */
            end = calc_future_tsc(30000);
            in_progress = 1;
        }
    }

    u32 blksize = ntohl(info.blksize), sectors = ntohl(info.sectors);
    if (blksize != GET_GLOBAL(op->drive_g->blksize)) {
        printf("Unsupported sector size %u\n", blksize);
        return -1;
    }

    dprintf(6, "sectors=%u\n", sectors);
    printf("%dMB medium detected\n", sectors>>(20-11));
    return 0;
}

int
cdrom_boot(struct drive_s *drive_g)
{
    struct disk_op_s dop;
    int cdid = getDriveId(EXTTYPE_CD, drive_g);
    memset(&dop, 0, sizeof(dop));
    dop.drive_g = drive_g;
    if (!dop.drive_g || cdid < 0)
        return 1;

    int ret = atapi_is_ready(&dop);
    if (ret)
        dprintf(1, "atapi_is_ready returned %d\n", ret);

    // Read the Boot Record Volume Descriptor
    u8 buffer[2048];
    dop.lba = 0x11;
    dop.count = 1;
    dop.buf_fl = MAKE_FLATPTR(GET_SEG(SS), buffer);
    ret = cdb_read(&dop);
    if (ret)
        return 3;

    // Validity checks
    if (buffer[0])
        return 4;
    if (strcmp((char*)&buffer[1], "CD001\001EL TORITO SPECIFICATION") != 0)
        return 5;

    // ok, now we calculate the Boot catalog address
    u32 lba = *(u32*)&buffer[0x47];

    // And we read the Boot Catalog
    dop.lba = lba;
    dop.count = 1;
    ret = cdb_read(&dop);
    if (ret)
        return 7;

    // Validation entry
    if (buffer[0x00] != 0x01)
        return 8;   // Header
    if (buffer[0x01] != 0x00)
        return 9;   // Platform
    if (buffer[0x1E] != 0x55)
        return 10;  // key 1
    if (buffer[0x1F] != 0xAA)
        return 10;  // key 2

    // Initial/Default Entry
    if (buffer[0x20] != 0x88)
        return 11; // Bootable

    u16 ebda_seg = get_ebda_seg();
    u8 media = buffer[0x21];
    SET_EBDA2(ebda_seg, cdemu.media, media);

    SET_EBDA2(ebda_seg, cdemu.emulated_drive_gf, dop.drive_g);

    u16 boot_segment = *(u16*)&buffer[0x22];
    if (!boot_segment)
        boot_segment = 0x07C0;
    SET_EBDA2(ebda_seg, cdemu.load_segment, boot_segment);
    SET_EBDA2(ebda_seg, cdemu.buffer_segment, 0x0000);

    u16 nbsectors = *(u16*)&buffer[0x26];
    SET_EBDA2(ebda_seg, cdemu.sector_count, nbsectors);

    lba = *(u32*)&buffer[0x28];
    SET_EBDA2(ebda_seg, cdemu.ilba, lba);

    // And we read the image in memory
    dop.lba = lba;
    dop.count = DIV_ROUND_UP(nbsectors, 4);
    dop.buf_fl = MAKE_FLATPTR(boot_segment, 0);
    ret = cdb_read(&dop);
    if (ret)
        return 12;

    if (media == 0) {
        // No emulation requested - return success.
        SET_EBDA2(ebda_seg, cdemu.emulated_extdrive, EXTSTART_CD + cdid);
        return 0;
    }

    // Emulation of a floppy/harddisk requested
    if (! CONFIG_CDROM_EMU || !cdemu_drive_gf)
        return 13;

    // Set emulated drive id and increase bios installed hardware
    // number of devices
    if (media < 4) {
        // Floppy emulation
        SET_EBDA2(ebda_seg, cdemu.emulated_extdrive, 0x00);
        // XXX - get and set actual floppy count.
        SETBITS_BDA(equipment_list_flags, 0x41);

        switch (media) {
        case 0x01:  // 1.2M floppy
            SET_EBDA2(ebda_seg, cdemu.lchs.spt, 15);
            SET_EBDA2(ebda_seg, cdemu.lchs.cylinders, 80);
            SET_EBDA2(ebda_seg, cdemu.lchs.heads, 2);
            break;
        case 0x02:  // 1.44M floppy
            SET_EBDA2(ebda_seg, cdemu.lchs.spt, 18);
            SET_EBDA2(ebda_seg, cdemu.lchs.cylinders, 80);
            SET_EBDA2(ebda_seg, cdemu.lchs.heads, 2);
            break;
        case 0x03:  // 2.88M floppy
            SET_EBDA2(ebda_seg, cdemu.lchs.spt, 36);
            SET_EBDA2(ebda_seg, cdemu.lchs.cylinders, 80);
            SET_EBDA2(ebda_seg, cdemu.lchs.heads, 2);
            break;
        }
    } else {
        // Harddrive emulation
        SET_EBDA2(ebda_seg, cdemu.emulated_extdrive, 0x80);
        SET_BDA(hdcount, GET_BDA(hdcount) + 1);

        // Peak at partition table to get chs.
        struct mbr_s *mbr = (void*)0;
        u8 sptcyl = GET_FARVAR(boot_segment, mbr->partitions[0].last.sptcyl);
        u8 cyllow = GET_FARVAR(boot_segment, mbr->partitions[0].last.cyllow);
        u8 heads = GET_FARVAR(boot_segment, mbr->partitions[0].last.heads);

        SET_EBDA2(ebda_seg, cdemu.lchs.spt, sptcyl & 0x3f);
        SET_EBDA2(ebda_seg, cdemu.lchs.cylinders
                  , ((sptcyl<<2)&0x300) + cyllow + 1);
        SET_EBDA2(ebda_seg, cdemu.lchs.heads, heads + 1);
    }

    // everything is ok, so from now on, the emulation is active
    SET_EBDA2(ebda_seg, cdemu.active, 0x01);
    dprintf(6, "cdemu media=%d\n", media);

    return 0;
}
