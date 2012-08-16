// Variable layouts of bios.
//
// Copyright (C) 2008-2010  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.
#ifndef __BIOSVAR_H
#define __BIOSVAR_H

#include "types.h" // u8
#include "farptr.h" // GET_FARVAR
#include "config.h" // CONFIG_*
#include "disk.h" // struct chs_s


/****************************************************************
 * Interupt vector table
 ****************************************************************/

struct rmode_IVT {
    struct segoff_s ivec[256];
};

#define GET_IVT(vector)                                         \
    GET_FARVAR(SEG_IVT, ((struct rmode_IVT *)0)->ivec[vector])
#define SET_IVT(vector, segoff)                                         \
    SET_FARVAR(SEG_IVT, ((struct rmode_IVT *)0)->ivec[vector], segoff)

#define FUNC16(func) ({                                 \
        ASSERT32FLAT();                                 \
        extern void func (void);                        \
        SEGOFF(SEG_BIOS, (u32)func - BUILD_BIOS_ADDR);  \
    })


/****************************************************************
 * Bios Data Area (BDA)
 ****************************************************************/

struct bios_data_area_s {
    // 40:00
    u16 port_com[4];
    u16 port_lpt[3];
    u16 ebda_seg;
    // 40:10
    u16 equipment_list_flags;
    u8 pad1;
    u16 mem_size_kb;
    u8 pad2;
    u8 ps2_ctrl_flag;
    u8 kbd_flag0;
    u8 kbd_flag1;
    u8 alt_keypad;
    u16 kbd_buf_head;
    u16 kbd_buf_tail;
    // 40:1e
    u8 kbd_buf[32];
    u8 floppy_recalibration_status;
    u8 floppy_motor_status;
    // 40:40
    u8 floppy_motor_counter;
    u8 floppy_last_status;
    u8 floppy_return_status[7];
    u8 video_mode;
    u16 video_cols;
    u16 video_pagesize;
    u16 video_pagestart;
    // 40:50
    u16 cursor_pos[8];
    // 40:60
    u16 cursor_type;
    u8 video_page;
    u16 crtc_address;
    u8 video_msr;
    u8 video_pal;
    struct segoff_s jump;
    u8 other_6b;
    u32 timer_counter;
    // 40:70
    u8 timer_rollover;
    u8 break_flag;
    u16 soft_reset_flag;
    u8 disk_last_status;
    u8 hdcount;
    u8 disk_control_byte;
    u8 port_disk;
    u8 lpt_timeout[4];
    u8 com_timeout[4];
    // 40:80
    u16 kbd_buf_start_offset;
    u16 kbd_buf_end_offset;
    u8 video_rows;
    u16 char_height;
    u8 video_ctl;
    u8 video_switches;
    u8 modeset_ctl;
    u8 dcc_index;
    u8 floppy_last_data_rate;
    u8 disk_status_controller;
    u8 disk_error_controller;
    u8 disk_interrupt_flag;
    u8 floppy_harddisk_info;
    // 40:90
    u8 floppy_media_state[4];
    u8 floppy_track[2];
    u8 kbd_flag2;
    u8 kbd_led;
    struct segoff_s user_wait_complete_flag;
    u32 user_wait_timeout;
    // 40:A0
    u8 rtc_wait_flag;
    u8 other_a1[7];
    struct segoff_s video_savetable;
    u8 other_ac[4];
    // 40:B0
    u8 other_b0[10];
    u16 vbe_mode;
} PACKED;

// BDA floppy_recalibration_status bitdefs
#define FRS_TIMEOUT (1<<7)

// BDA rtc_wait_flag bitdefs
#define RWS_WAIT_PENDING (1<<0)
#define RWS_WAIT_ELAPSED (1<<7)

// BDA floppy_media_state bitdefs
#define FMS_DRIVE_STATE_MASK        (0x07)
#define FMS_MEDIA_DRIVE_ESTABLISHED (1<<4)
#define FMS_DOUBLE_STEPPING         (1<<5)
#define FMS_DATA_RATE_MASK          (0xc0)

// Accessor functions
#define GET_BDA(var) \
    GET_FARVAR(SEG_BDA, ((struct bios_data_area_s *)0)->var)
#define SET_BDA(var, val) \
    SET_FARVAR(SEG_BDA, ((struct bios_data_area_s *)0)->var, (val))
#define CLEARBITS_BDA(var, val) do {                                    \
        typeof(((struct bios_data_area_s *)0)->var) __val = GET_BDA(var); \
        SET_BDA(var, (__val & ~(val)));                                 \
    } while (0)
#define SETBITS_BDA(var, val) do {                                      \
        typeof(((struct bios_data_area_s *)0)->var) __val = GET_BDA(var); \
        SET_BDA(var, (__val | (val)));                                  \
    } while (0)


/****************************************************************
 * Extended Bios Data Area (EBDA)
 ****************************************************************/

// DPTE definition
struct dpte_s {
    u16 iobase1;
    u16 iobase2;
    u8  prefix;
    u8  unused;
    u8  irq;
    u8  blkcount;
    u8  dma;
    u8  pio;
    u16 options;
    u16 reserved;
    u8  revision;
    u8  checksum;
};

// ElTorito Device Emulation data
struct cdemu_s {
    struct drive_s *emulated_drive_gf;
    u32 ilba;
    u16 buffer_segment;
    u16 load_segment;
    u16 sector_count;
    u8  active;
    u8  media;
    u8  emulated_extdrive;

    // Virtual device
    struct chs_s lchs;
};

struct fdpt_s {
    u16 cylinders;
    u8 heads;
    u8 a0h_signature;
    u8 phys_sectors;
    u16 precompensation;
    u8 reserved;
    u8 drive_control_byte;
    u16 phys_cylinders;
    u8 phys_heads;
    u16 landing_zone;
    u8 sectors;
    u8 checksum;
} PACKED;

struct usbkeyinfo {
    union {
        struct {
            u8 modifiers;
            u8 repeatcount;
            u8 keys[6];
        };
        u64 data;
    };
};

struct extended_bios_data_area_s {
    u8 size;
    u8 reserved1[0x21];
    struct segoff_s far_call_pointer;
    u8 mouse_flag1;
    u8 mouse_flag2;
    u8 mouse_data[0x08];
    // 0x30
    u8 other1[0x0d];

    // 0x3d
    struct fdpt_s fdpt[2];

    // 0x5d
    u8 other2[0xC4];

    // 0x121 - Begin custom storage.
    u8 ps2ctr;
    struct usbkeyinfo usbkey_last;

    int RTCusers;

    // El Torito Emulation data
    struct cdemu_s cdemu;

    // Buffer for disk DPTE table
    struct dpte_s dpte;

    // Locks for removable devices
    u8 cdrom_locks[CONFIG_MAX_EXTDRIVE];

    u16 boot_sequence;

    // Stack space available for code that needs it.
    u8 extra_stack[512] __aligned(8);
} PACKED;

// The initial size and location of EBDA
#define EBDA_SIZE_START \
    DIV_ROUND_UP(sizeof(struct extended_bios_data_area_s), 1024)
#define EBDA_SEGMENT_START \
    FLATPTR_TO_SEG(BUILD_LOWRAM_END - EBDA_SIZE_START*1024)

// Accessor functions
static inline u16 get_ebda_seg(void) {
    return GET_BDA(ebda_seg);
}
static inline struct extended_bios_data_area_s *
get_ebda_ptr(void)
{
    ASSERT32FLAT();
    return MAKE_FLATPTR(get_ebda_seg(), 0);
}
#define GET_EBDA2(eseg, var)                                            \
    GET_FARVAR(eseg, ((struct extended_bios_data_area_s *)0)->var)
#define SET_EBDA2(eseg, var, val)                                       \
    SET_FARVAR(eseg, ((struct extended_bios_data_area_s *)0)->var, (val))
#define GET_EBDA(var)                           \
    GET_EBDA2(get_ebda_seg(), var)
#define SET_EBDA(var, val)                      \
    SET_EBDA2(get_ebda_seg(), var, (val))

#define EBDA_OFFSET_TOP_STACK                                   \
    offsetof(struct extended_bios_data_area_s, extra_stack[     \
                 FIELD_SIZEOF(struct extended_bios_data_area_s  \
                              , extra_stack)])


/****************************************************************
 * Global variables
 ****************************************************************/

#if MODE16 == 0 && MODESEGMENT == 1
// In 32bit segmented mode %cs may not be readable and the code may be
// relocated.  The entry code sets up %gs with a readable segment and
// the code offset can be determined by get_global_offset().
#define GLOBAL_SEGREG GS
static inline u32 __attribute_const get_global_offset(void) {
    u32 ret;
    asm("  calll 1f\n"
        "1:popl %0\n"
        "  subl $1b, %0"
        : "=r"(ret));
    return ret;
}
#else
#define GLOBAL_SEGREG CS
static inline u32 __attribute_const get_global_offset(void) {
    return 0;
}
#endif
static inline u16 get_global_seg(void) {
    return GET_SEG(GLOBAL_SEGREG);
}
#define GET_GLOBAL(var)                                                 \
    GET_VAR(GLOBAL_SEGREG, *(typeof(&(var)))((void*)&(var)              \
                                             + get_global_offset()))
#define SET_GLOBAL(var, val) do {               \
        ASSERT32FLAT();                         \
        (var) = (val);                          \
    } while (0)
#if MODESEGMENT
#define GLOBALFLAT2GLOBAL(var) ((typeof(var))((void*)(var) - BUILD_BIOS_ADDR))
#else
#define GLOBALFLAT2GLOBAL(var) (var)
#endif
// Access a "flat" pointer known to point to the f-segment.
#define GET_GLOBALFLAT(var) GET_GLOBAL(*GLOBALFLAT2GLOBAL(&(var)))


/****************************************************************
 * Bios Config Table
 ****************************************************************/

struct bios_config_table_s {
    u16 size;
    u8 model;
    u8 submodel;
    u8 biosrev;
    u8 feature1, feature2, feature3, feature4, feature5;
} PACKED;

extern struct bios_config_table_s BIOS_CONFIG_TABLE __aligned(1);

#endif // __BIOSVAR_H
