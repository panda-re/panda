/*
 * Copyright (C) 2010 VMware, Inc.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _SNPNET_H
#define _SNPNET_H

/** @file
 *
 * EFI Simple Network Protocol network device driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

struct snp_device;

extern int snpnet_probe ( struct snp_device *snpdev );
extern void snpnet_remove ( struct snp_device *snpdev );

#endif /* _SNPNET_H */
