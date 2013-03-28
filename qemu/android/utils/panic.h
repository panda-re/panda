/* Copyright (C) 2008 The Android Open Source Project
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
#ifndef ANDROID_UTILS_PANIC_H
#define ANDROID_UTILS_PANIC_H

#include <stdarg.h>

/* Print formatted panic message and halts the process */
void __attribute__((noreturn)) android_panic ( const char*  fmt, ... );

/* Variant of android_vpanic which take va_list formating arguments */
void __attribute__((noreturn)) android_vpanic( const char*  fmt, va_list  args );

/* Convenience macro */
#define  APANIC(...)    android_panic(__VA_ARGS__)

typedef void (*APanicHandlerFunc)(const char*, va_list) __attribute__((noreturn));

#ifdef ACONFIG_UNIT_TEST
/* Register a new panic handler. This should only be used for unit-testing */
void android_panic_registerHandler( APanicHandlerFunc  handler );
#endif /* ACONFIG_UNIT_TEST */

#endif /* ANDROID_UTILS_PANIC_H */
