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
#ifndef _android_gps_h
#define _android_gps_h

#include "qemu-common.h"

/* this is the internal character driver used to communicate with the
 * emulated GPS unit. see qemu_chr_open() in vl.c */
extern CharDriverState*  android_gps_cs;

extern void  android_gps_send_nmea( const char*  sentence );

#endif /* _android_gps_h */
