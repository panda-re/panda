/* Copyright (C) 2010 The Android Open Source Project
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

#include <stdio.h>
#include "android/utils/debug.h"
#include "android/keycode-array.h"
//#include "user-events.h"

void
android_keycodes_add_key_event( AKeycodeBuffer* keycodes,
                                unsigned       code,
                                unsigned       down )
{
    if (code != 0 && keycodes->keycode_count < MAX_KEYCODES) {
        keycodes->keycodes[(int)keycodes->keycode_count++] =
                ( (code & 0x1ff) | (down ? 0x200 : 0) );
    }
}

void
android_keycodes_flush(AKeycodeBuffer* keycodes)
{
    if (keycodes->keycode_count > 0) {
        if (VERBOSE_CHECK(keys)) {
            int  nn;
            printf(">> KEY" );
            for (nn = 0; nn < keycodes->keycode_count; nn++) {
                int  code = keycodes->keycodes[nn];
                printf(" [0x%03x,%s]", (code & 0x1ff), (code & 0x200) ? "down" : " up " );
            }
            printf( "\n" );
        }
        //user_event_keycodes(keycodes->keycodes, keycodes->keycode_count);
        keycodes->keycode_count = 0;
    }
}
