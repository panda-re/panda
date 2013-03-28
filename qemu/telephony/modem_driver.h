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
#ifndef _modem_driver_h
#define _modem_driver_h

#include "android_modem.h"
#include "qemu-common.h"

/** in telephony/modem_driver.c */
/* this is the internal character driver used to communicate with the
 * emulated GSM modem. see qemu_chr_open() in vl.c */
extern CharDriverState*  android_modem_cs;

/* the emulated GSM modem itself */
extern AModem  android_modem;

/* must be called before the VM runs if there is a modem to emulate */
extern void   android_modem_init( int  base_port );

#endif /* _modem_driver_h */
