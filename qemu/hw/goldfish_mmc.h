/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
#if !defined(GOLDFISH_MMC_H)
#define GOLDFISH_MMC_H

/* Uses ancient version of QEMU's SD card header and infrastructure */
// begin old sd.h
/*
 *  include/linux/mmc/sd.h
 *
 *  Copyright (C) 2005-2007 Pierre Ossman, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#ifndef MMC_SD_H
#define MMC_SD_H

/* SD commands                           type  argument     response */
  /* class 0 */
/* This is basically the same command as for MMC with some quirks. */
#define SD_SEND_RELATIVE_ADDR     3   /* bcr                     R6  */
#define SD_SEND_IF_COND           8   /* bcr  [11:0] See below   R7  */

  /* class 10 */
#define SD_SWITCH                 6   /* adtc [31:0] See below   R1  */

  /* Application commands */
#define SD_APP_SET_BUS_WIDTH      6   /* ac   [1:0] bus width    R1  */
#define SD_APP_SEND_NUM_WR_BLKS  22   /* adtc                    R1  */
#define SD_APP_OP_COND           41   /* bcr  [31:0] OCR         R3  */
#define SD_APP_SEND_SCR          51   /* adtc                    R1  */

/*
 * SD_SWITCH argument format:
 *
 *      [31] Check (0) or switch (1)
 *      [30:24] Reserved (0)
 *      [23:20] Function group 6
 *      [19:16] Function group 5
 *      [15:12] Function group 4
 *      [11:8] Function group 3
 *      [7:4] Function group 2
 *      [3:0] Function group 1
 */

/*
 * SD_SEND_IF_COND argument format:
 *
 *      [31:12] Reserved (0)
 *      [11:8] Host Voltage Supply Flags
 *      [7:0] Check Pattern (0xAA)
 */

/*
 * SCR field definitions
 */

#define SCR_SPEC_VER_0          0       /* Implements system specification 1.0 - 1.01 */
#define SCR_SPEC_VER_1          1       /* Implements system specification 1.10 */
#define SCR_SPEC_VER_2          2       /* Implements system specification 2.00 */

/*
 * SD bus widths
 */
#define SD_BUS_WIDTH_1          0
#define SD_BUS_WIDTH_4          2

/*
 * SD_SWITCH mode
 */
#define SD_SWITCH_CHECK         0
#define SD_SWITCH_SET           1

/*
 * SD_SWITCH function groups
 */
#define SD_SWITCH_GRP_ACCESS    0

/*
 * SD_SWITCH access modes
 */
#define SD_SWITCH_ACCESS_DEF    0
#define SD_SWITCH_ACCESS_HS     1

#endif
//end of old sd.h


// Definitions from goldfish_mmc.c that we need for PANDA plugins
// for IO read/write analysis

enum {
    /* status register */
    MMC_INT_STATUS          = 0x00,
    /* set this to enable IRQ */
    MMC_INT_ENABLE          = 0x04,
    /* set this to specify buffer address */
    MMC_SET_BUFFER          = 0x08,

    /* MMC command number */
    MMC_CMD                 = 0x0C,

    /* MMC argument */
    MMC_ARG                 = 0x10,

    /* MMC response (or R2 bits 0 - 31) */
    MMC_RESP_0              = 0x14,

    /* MMC R2 response bits 32 - 63 */
    MMC_RESP_1              = 0x18,

    /* MMC R2 response bits 64 - 95 */
    MMC_RESP_2              = 0x1C,

    /* MMC R2 response bits 96 - 127 */
    MMC_RESP_3              = 0x20,

    MMC_BLOCK_LENGTH        = 0x24,
    MMC_BLOCK_COUNT         = 0x28,

    /* MMC state flags */
    MMC_STATE               = 0x2C,

    /* MMC_INT_STATUS bits */

    MMC_STAT_END_OF_CMD     = 1U << 0,
    MMC_STAT_END_OF_DATA    = 1U << 1,
    MMC_STAT_STATE_CHANGE   = 1U << 2,

    /* MMC_STATE bits */
    MMC_STATE_INSERTED     = 1U << 0,
    MMC_STATE_READ_ONLY     = 1U << 1,
};


typedef struct GoldfishMmcDevice {
    GoldfishDevice dev;
    BlockDriverState *bs;
    // pointer to our buffer
    uint32_t buffer_address;
    // offsets for read and write operations
    uint32_t read_offset, write_offset;
    // buffer status flags
    uint32_t int_status;
    // irq enable mask for int_status
    uint32_t int_enable;

    // MMC command argument
    uint32_t arg;
    uint32_t resp[4];

    uint32_t block_length;
    uint32_t block_count;
    int is_SDHC;

    uint8_t* buf;
    char* path;
} GoldfishMmcDevice;

#endif
