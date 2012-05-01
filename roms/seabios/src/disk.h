// Definitions for X86 bios disks.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.
#ifndef __DISK_H
#define __DISK_H

#include "types.h" // u8
#include "config.h" // CONFIG_*
#include "farptr.h" // struct segoff_s

#define DISK_RET_SUCCESS       0x00
#define DISK_RET_EPARAM        0x01
#define DISK_RET_EADDRNOTFOUND 0x02
#define DISK_RET_EWRITEPROTECT 0x03
#define DISK_RET_ECHANGED      0x06
#define DISK_RET_EBOUNDARY     0x09
#define DISK_RET_EBADTRACK     0x0c
#define DISK_RET_ECONTROLLER   0x20
#define DISK_RET_ETIMEOUT      0x80
#define DISK_RET_ENOTLOCKED    0xb0
#define DISK_RET_ELOCKED       0xb1
#define DISK_RET_ENOTREMOVABLE 0xb2
#define DISK_RET_ETOOMANYLOCKS 0xb4
#define DISK_RET_EMEDIA        0xC0
#define DISK_RET_ENOTREADY     0xAA


/****************************************************************
 * Interface structs
 ****************************************************************/

// Bios disk structures.
struct int13ext_s {
    u8  size;
    u8  reserved;
    u16 count;
    struct segoff_s data;
    u64 lba;
} PACKED;

#define GET_INT13EXT(regs,var)                                          \
    GET_FARVAR((regs)->ds, ((struct int13ext_s*)((regs)->si+0))->var)
#define SET_INT13EXT(regs,var,val)                                      \
    SET_FARVAR((regs)->ds, ((struct int13ext_s*)((regs)->si+0))->var, (val))

// Disk Physical Table definition
struct int13dpt_s {
    u16 size;
    u16 infos;
    u32 cylinders;
    u32 heads;
    u32 spt;
    u64 sector_count;
    u16 blksize;
    u16 dpte_offset;
    u16 dpte_segment;
    u16 key;
    u8  dpi_length;
    u8  reserved1;
    u16 reserved2;
    u8  host_bus[4];
    u8  iface_type[8];
    u64 iface_path;
    union {
        struct {
            u64 device_path;
            u8  reserved3;
            u8  checksum;
        } phoenix;
        struct {
            u64 device_path[2];
            u8  reserved3;
            u8  checksum;
        } t13;
    };
} PACKED;

#define GET_INT13DPT(regs,var)                                          \
    GET_FARVAR((regs)->ds, ((struct int13dpt_s*)((regs)->si+0))->var)
#define SET_INT13DPT(regs,var,val)                                      \
    SET_FARVAR((regs)->ds, ((struct int13dpt_s*)((regs)->si+0))->var, (val))

// Floppy "Disk Base Table"
struct floppy_dbt_s {
    u8 specify1;
    u8 specify2;
    u8 shutoff_ticks;
    u8 bps_code;
    u8 sectors;
    u8 interblock_len;
    u8 data_len;
    u8 gap_len;
    u8 fill_byte;
    u8 settle_time;
    u8 startup_time;
} PACKED;

struct floppy_ext_dbt_s {
    struct floppy_dbt_s dbt;
    // Extra fields
    u8 max_track;
    u8 data_rate;
    u8 drive_type;
} PACKED;

// Helper function for setting up a return code.
struct bregs;
void __disk_ret(struct bregs *regs, u32 linecode, const char *fname);
#define disk_ret(regs, code) \
    __disk_ret((regs), (code) | (__LINE__ << 8), __func__)
void __disk_ret_unimplemented(struct bregs *regs, u32 linecode
                              , const char *fname);
#define disk_ret_unimplemented(regs, code) \
    __disk_ret_unimplemented((regs), (code) | (__LINE__ << 8), __func__)


/****************************************************************
 * Master boot record
 ****************************************************************/

struct packed_chs_s {
    u8 heads;
    u8 sptcyl;
    u8 cyllow;
};

struct partition_s {
    u8 status;
    struct packed_chs_s first;
    u8 type;
    struct packed_chs_s last;
    u32 lba;
    u32 count;
} PACKED;

struct mbr_s {
    u8 code[440];
    // 0x01b8
    u32 diskseg;
    // 0x01bc
    u16 null;
    // 0x01be
    struct partition_s partitions[4];
    // 0x01fe
    u16 signature;
} PACKED;

#define MBR_SIGNATURE 0xaa55


/****************************************************************
 * Disk command request
 ****************************************************************/

struct disk_op_s {
    u64 lba;
    void *buf_fl;
    struct drive_s *drive_g;
    u16 count;
    u8 command;
};

#define CMD_RESET   0x00
#define CMD_READ    0x02
#define CMD_WRITE   0x03
#define CMD_VERIFY  0x04
#define CMD_FORMAT  0x05
#define CMD_SEEK    0x07
#define CMD_ISREADY 0x10


/****************************************************************
 * Global storage
 ****************************************************************/

struct chs_s {
    u16 heads;      // # heads
    u16 cylinders;  // # cylinders
    u16 spt;        // # sectors / track
};

struct drive_s {
    u8 type;            // Driver type (DTYPE_*)
    u8 floppy_type;     // Type of floppy (only for floppy drives).
    struct chs_s lchs;  // Logical CHS
    u64 sectors;        // Total sectors count
    u32 cntl_id;        // Unique id for a given driver type.
    u8 removable;       // Is media removable (currently unused)

    // Info for EDD calls
    u8 translation;     // type of translation
    u16 blksize;        // block size
    struct chs_s pchs;  // Physical CHS
};

#define DISK_SECTOR_SIZE  512
#define CDROM_SECTOR_SIZE 2048

#define DTYPE_NONE     0x00
#define DTYPE_FLOPPY   0x01
#define DTYPE_ATA      0x02
#define DTYPE_ATAPI    0x03
#define DTYPE_RAMDISK  0x04
#define DTYPE_CDEMU    0x05
#define DTYPE_USB      0x06
#define DTYPE_VIRTIO   0x07
#define DTYPE_AHCI     0x08

#define MAXDESCSIZE 80

#define TRANSLATION_NONE  0
#define TRANSLATION_LBA   1
#define TRANSLATION_LARGE 2
#define TRANSLATION_RECHS 3

#define EXTTYPE_FLOPPY 0
#define EXTTYPE_HD 1
#define EXTTYPE_CD 2

#define EXTSTART_HD 0x80
#define EXTSTART_CD 0xE0


/****************************************************************
 * Function defs
 ****************************************************************/

// block.c
extern u8 FloppyCount, CDCount;
extern u8 *bounce_buf_fl;
struct drive_s *getDrive(u8 exttype, u8 extdriveoffset);
int getDriveId(u8 exttype, struct drive_s *drive_g);
void map_floppy_drive(struct drive_s *drive_g);
void map_hd_drive(struct drive_s *drive_g);
void map_cd_drive(struct drive_s *drive_g);
int process_op(struct disk_op_s *op);
int send_disk_op(struct disk_op_s *op);
int bounce_buf_init(void);

// floppy.c
extern struct floppy_ext_dbt_s diskette_param_table2;
void floppy_setup(void);
struct drive_s *init_floppy(int floppyid, int ftype);
int find_floppy_type(u32 size);
int process_floppy_op(struct disk_op_s *op);
void floppy_tick(void);

// cdrom.c
extern struct drive_s *cdemu_drive_gf;
int process_cdemu_op(struct disk_op_s *op);
void cdemu_setup(void);
void cdemu_134b(struct bregs *regs);
int cdrom_boot(struct drive_s *drive_g);

// ramdisk.c
void ramdisk_setup(void);
int process_ramdisk_op(struct disk_op_s *op);

#endif // disk.h
