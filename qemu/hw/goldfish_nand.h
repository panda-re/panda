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

void nand_dev_init(uint32_t base);
void nand_add_dev(const char *arg);
void parse_nand_limits(char*  limits);

typedef struct {
    uint64_t     limit;
    uint64_t     counter;
    int          pid;
    int          signal;
} nand_threshold;

extern nand_threshold   android_nand_read_threshold;
extern nand_threshold   android_nand_write_threshold;

#endif
