/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Common defines for all Dalvik code.
 */
#ifndef _DALVIK_COMMON
#define _DALVIK_COMMON

/*******************************************************************************
 * LIST OF CHANGES
 * 1. Fixed this redefinition warning when integrated with QEMU @ 43
 * 2. Changed to not define __BYTE_ORDER if it is already defined by QEMU @ 135
 * 3. Removed include of utils/log.h @ 167
 */
#ifndef LOG_TAG
# define LOG_TAG "dalvikvm"
#endif

#include <stdio.h>
#include <assert.h>

#if !defined(NDEBUG) && defined(WITH_DALVIK_ASSERT)
# undef assert
# define assert(x) \
    ((x) ? ((void)0) : (LOGE("ASSERT FAILED (%s:%d): %s\n", \
        __FILE__, __LINE__, #x), *(int*)39=39, 0) )
#endif

//LOK: Fixed this redefinition warning when integrated with QEMU
#ifndef MIN
#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x,y) (((x) > (y)) ? (x) : (y))
#endif

#define LIKELY(exp) (__builtin_expect((exp) != 0, true))
#define UNLIKELY(exp) (__builtin_expect((exp) != 0, false))

/*
 * If "very verbose" logging is enabled, make it equivalent to LOGV.
 * Otherwise, make it disappear.
 *
 * Define this above the #include "Dalvik.h" to enable for only a
 * single file.
 */
/* #define VERY_VERBOSE_LOG */
#if defined(VERY_VERBOSE_LOG)
# define LOGVV      LOGV
# define IF_LOGVV() IF_LOGV()
#else
# define LOGVV(...) ((void)0)
# define IF_LOGVV() if (false)
#endif


/*
 * These match the definitions in the VM specification.
 */
#ifdef HAVE_STDINT_H
# include <stdint.h>    /* C99 */
typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;
#else
typedef unsigned char       u1;
typedef unsigned short      u2;
typedef unsigned int        u4;
typedef unsigned long long  u8;
typedef signed char         s1;
typedef signed short        s2;
typedef signed int          s4;
typedef signed long long    s8;
#endif

/*
 * Storage for primitive types and object references.
 *
 * Some parts of the code (notably object field access) assume that values
 * are "left aligned", i.e. given "JValue jv", "jv.i" and "*((s4*)&jv)"
 * yield the same result.  This seems to be guaranteed by gcc on big- and
 * little-endian systems.
 */
typedef union JValue {
    u1      z;
    s1      b;
    u2      c;
    s2      s;
    s4      i;
    s8      j;
    float   f;
    double  d;
    void*   l;
} JValue;

/*
 * The <stdbool.h> definition uses _Bool, a type known to the compiler.
 */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>   /* C99 */
#else
# ifndef __bool_true_false_are_defined
typedef enum { false=0, true=!false } bool;
# define __bool_true_false_are_defined 1
# endif
#endif

#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))


#if defined(HAVE_ENDIAN_H)
# include <endian.h>
#else /*not HAVE_ENDIAN_H*/
# define __BIG_ENDIAN 4321
# define __LITTLE_ENDIAN 1234
//LOK Changed to not define __BYTE_ORDER if it is already defined by QEMU
#ifndef __BYTE_ORDER
# if defined(HAVE_LITTLE_ENDIAN)
#  define __BYTE_ORDER __LITTLE_ENDIAN
# else
#  define __BYTE_ORDER __BIG_ENDIAN
# endif
#endif
#endif /*not HAVE_ENDIAN_H*/



#if 0
/*
 * Pretend we have the Android logging macros.  These are replaced by the
 * Android logging implementation.
 */
#define ANDROID_LOG_DEBUG 3
#define LOGV(...)    LOG_PRI(2, 0, __VA_ARGS__)
#define LOGD(...)    LOG_PRI(3, 0, __VA_ARGS__)
#define LOGI(...)    LOG_PRI(4, 0, __VA_ARGS__)
#define LOGW(...)    LOG_PRI(5, 0, __VA_ARGS__)
#define LOGE(...)    LOG_PRI(6, 0, __VA_ARGS__)
#define MIN_LOG_LEVEL   2

#define LOG_PRI(priority, tag, ...) do {                            \
        if (priority >= MIN_LOG_LEVEL) {                            \
            dvmFprintf(stdout, "%s:%-4d ", __FILE__, __LINE__);     \
            dvmFprintf(stdout, __VA_ARGS__);                        \
        }                                                           \
    } while(0)
#else
//LOK - Removed this reference
//# include "utils/Log.h"
#endif

#endif /*_DALVIK_COMMON*/
