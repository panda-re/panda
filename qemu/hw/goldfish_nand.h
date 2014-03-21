/* Copyright (C) 2007-2008 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#ifndef NAND_DEVICE_H
#define NAND_DEVICE_H

#define MAX_NAND_DEVS 5

void nand_dev_init(uint32_t base);
//void nand_add_dev(const char *arg);
void parse_nand_limits(char*  limits);

typedef struct {
    uint64_t     limit;
    uint64_t     counter;
    int          pid;
    int          signal;
} nand_threshold;

extern nand_threshold   android_nand_read_threshold;
extern nand_threshold   android_nand_write_threshold;

#define ANDROID_QCOW

/* Information on a single device/nand image used by the emulator
 */
typedef struct {
    char*      devname;      /* name for this device (not null-terminated, use len below) */
    size_t     devname_len;
    uint8_t*   data;         /* buffer for read/write actions to underlying image */
#if defined(ANDROID_QCOW)
    BlockDriverState *bdrv; /* back nand w/qcow */
#else
    int        fd;
#endif
    uint32_t   flags;
    uint32_t   page_size;
    uint32_t   extra_size;
    uint32_t   erase_size;   /* size of the data buffer mentioned above */
    uint64_t   max_size;     /* Capacity limit for the image. The actual underlying
                              * file may be smaller. */
} nand_dev;


/* The controller is the single access point for all NAND images currently
 * attached to the system.
 */
typedef struct GoldfishNandDevice {
    GoldfishDevice qdev;
    char *system_path;
    char *system_init_path;
    uint64_t system_size;

    char *user_data_path;
    char *user_data_init_path;
    uint64_t user_data_size;
    
    char *cache_path;
    uint64_t cache_size;
    uint32_t base;

    // register state
    uint32_t dev;            /* offset in nand_devs for the device that is
                              * currently being accessed */
    uint32_t addr_low;
    uint32_t addr_high;
    uint32_t transfer_size;
    uint32_t data;
    uint32_t batch_addr_low;
    uint32_t batch_addr_high;
    uint32_t result;
    uint32_t nand_dev_count;
    nand_dev nand_devs[MAX_NAND_DEVS];
} GoldfishNandDevice;

#endif
