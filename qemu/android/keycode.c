/* Copyright (C) 2009 The Android Open Source Project
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
#include "android/keycode.h"

AndroidKeyCode
android_keycode_rotate( AndroidKeyCode  code, int  rotation )
{
    static const AndroidKeyCode  wheel[4] = { kKeyCodeDpadUp,
                                              kKeyCodeDpadRight,
                                              kKeyCodeDpadDown,
                                              kKeyCodeDpadLeft };

    int  index;

    for (index = 0; index < 4; index++) {
        if (code == wheel[index]) {
            index = (index + rotation) & 3;
            code  = wheel[index];
            break;
        }
    }
    return code;
}

