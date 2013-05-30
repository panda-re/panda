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
#include "android/gps.h"
#include "android/utils/debug.h"
#include "qemu-char.h"

CharDriverState*   android_gps_cs;

#define  D(...)  VERBOSE_PRINT(gps,__VA_ARGS__)

void
android_gps_send_nmea( const char*  sentence )
{
    if (sentence == NULL)
        return;

    D("sending '%s'", sentence);

    if (android_gps_cs == NULL) {
        D("missing GPS channel, ignored");
        return;
    }

    qemu_chr_fe_write( android_gps_cs, (const void*)sentence, strlen(sentence) );
    qemu_chr_fe_write( android_gps_cs, (const void*)"\n", 1 );
}


