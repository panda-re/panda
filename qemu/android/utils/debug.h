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
#ifndef _ANDROID_UTILS_DEBUG_H
#define _ANDROID_UTILS_DEBUG_H

#include <stdarg.h>

#define  VERBOSE_TAG_LIST    \
    _VERBOSE_TAG(init,         "emulator initialization")  \
    _VERBOSE_TAG(console,      "control console")  \
    _VERBOSE_TAG(modem,        "emulated GSM modem")  \
    _VERBOSE_TAG(radio,        "emulated GSM AT Command channel") \
    _VERBOSE_TAG(keys,         "key bindings & presses") \
    _VERBOSE_TAG(slirp,        "internal router/firewall") \
    _VERBOSE_TAG(timezone,     "host timezone detection" ) \
    _VERBOSE_TAG(socket,       "network sockets") \
    _VERBOSE_TAG(proxy,        "network proxy support") \
    _VERBOSE_TAG(audio,        "audio sub-system") \
    _VERBOSE_TAG(audioin,      "audio input backend") \
    _VERBOSE_TAG(audioout,     "audio output backend") \
    _VERBOSE_TAG(surface,      "video surface support") \
    _VERBOSE_TAG(qemud,        "qemud multiplexer daemon") \
    _VERBOSE_TAG(gps,          "emulated GPS") \
    _VERBOSE_TAG(nand_limits,  "nand/flash read/write thresholding") \
    _VERBOSE_TAG(hw_control,   "emulated power/flashlight/led/vibrator") \
    _VERBOSE_TAG(avd_config,   "android virtual device configuration") \
    _VERBOSE_TAG(sensors,      "emulated sensors") \
    _VERBOSE_TAG(memcheck,     "memory checker") \
    _VERBOSE_TAG(adbserver,    "ADB server") \
    _VERBOSE_TAG(adbclient,    "ADB client") \
    _VERBOSE_TAG(adb,          "ADB") \

#define  _VERBOSE_TAG(x,y)  VERBOSE_##x,
typedef enum {
    VERBOSE_TAG_LIST
    VERBOSE_MAX  /* do not remove */
} VerboseTag;
#undef  _VERBOSE_TAG

/* defined in android_main.c */
extern unsigned long  android_verbose;

#define  VERBOSE_ENABLE(tag)    \
    android_verbose |= (1 << VERBOSE_##tag)

#define  VERBOSE_DISABLE(tag)   \
    android_verbose &= (1 << VERBOSE_##tag)

#define  VERBOSE_CHECK(tag)    \
    ((android_verbose & (1 << VERBOSE_##tag)) != 0)

#define  VERBOSE_CHECK_ANY()    \
    (android_verbose != 0)

#define  VERBOSE_PRINT(tag,...)  \
    do { if (VERBOSE_CHECK(tag)) dprint(__VA_ARGS__); } while (0)

/** DEBUG TRACE SUPPORT
 **
 ** debug messages can be sent by calling these function
 **
 ** 'dprint' prints the message, then appends a '\n\
 ** 'dprintn' simply prints the message as is
 ** 'dprintnv' allows you to use a va_list argument
 ** 'dwarning' prints a warning message, then appends a '\n'
 ** 'derror' prints a severe error message, then appends a '\n'
 */

extern void   dprint( const char*  format, ... );
extern void   dprintn( const char*  format, ... );
extern void   dprintnv( const char*  format, va_list  args );
extern void   dwarning( const char*  format, ... );
extern void   derror( const char*  format, ... );

/** STDOUT/STDERR REDIRECTION
 **
 ** allows you to shut temporarily shutdown stdout/stderr
 ** this is useful to get rid of debug messages from ALSA and esd
 ** on Linux.
 **/

extern void  stdio_disable( void );
extern void  stdio_enable( void );

/* */

#endif /* _ANDROID_UTILS_DEBUG_H */
