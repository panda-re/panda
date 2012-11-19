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
#include "android/utils/panic.h"
#include <stdio.h>
#include <stdlib.h>

static void __attribute__((noreturn))
_android_panic_defaultHandler( const char*  fmt, va_list  args )
{
    fprintf(stderr, "PANIC: ");
    vfprintf(stderr, fmt, args);
    exit(1);
}

static APanicHandlerFunc  _panicHandler = _android_panic_defaultHandler;

void android_panic( const char*  fmt, ... )
{
    va_list  args;
    va_start(args, fmt);
    android_vpanic(fmt, args);
    va_end(args);
}

/* Variant of android_vpanic which take va_list formating arguments */
void android_vpanic( const char*  fmt, va_list  args )
{
    _panicHandler(fmt, args);
}

void android_panic_registerHandler( APanicHandlerFunc  handler )
{
    if (handler == NULL)
        android_panic("Passing NULL to %s", __FUNCTION__);

    _panicHandler = handler;
}
