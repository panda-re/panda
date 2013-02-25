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
#ifndef _CHARPIPE_H
#define _CHARPIPE_H

#include "qemu-common.h"

/* open two connected character drivers that can be used to communicate by internal
 * QEMU components. For Android, this is used to connect an emulated serial port
 * with the android modem
 */
extern int  qemu_chr_open_charpipe( CharDriverState* *pfirst, CharDriverState* *psecond );

/* create a buffering character driver for a given endpoint. The result will buffer
 * anything that is sent to it but cannot be sent to the endpoint immediately.
 * On the other hand, if the endpoint calls can_read() or read(), these calls
 * are passed immediately to the can_read() or read() handlers of the result.
 */
extern CharDriverState*  qemu_chr_open_buffer( CharDriverState*  endpoint );

/* must be called from the main event loop to poll all charpipes */
extern void charpipe_poll( void );

#endif /* _CHARPIPE_H */
