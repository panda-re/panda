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
#include "android/utils/system.h"
#include <stdlib.h>
#include <stdio.h>
#ifdef ACONFIG_USE_ASSERT
#include "android/utils/assert.h"
#endif
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>  /* for Sleep */
#else
#  include <unistd.h>  /* for usleep */
#endif

void*
android_alloc( size_t  size )
{
    void*   block;

    if (size == 0)
        return NULL;

    block = malloc(size);
    if (block != NULL)
        return block;

    fprintf(stderr, "PANIC: not enough memory\n");
    exit(1);
    return NULL;
}

void*
android_alloc0( size_t  size )
{
    void*   block;

    if (size == 0)
        return NULL;

    block = calloc(1, size);
    if (block != NULL)
        return block;

    fprintf(stderr, "PANIC: not enough memory\n");
    exit(1);
    return NULL;
}

void*
android_realloc( void*  block, size_t  size )
{
    void*   block2;

    if (size == 0) {
        free(block);
        return NULL;
    }
    block2 = realloc(block, size);
    if (block2 != NULL)
        return block2;

    fprintf(stderr, "PANIC: not enough memory to reallocate %zu bytes\n", size);
    exit(1);
    return NULL;
}

void
android_free( void*  block )
{
    if (block)
        free(block);
}

void*
_android_array_alloc( size_t  itemSize, size_t  count )
{
#ifdef ACONFIG_USE_ASSERT
    size_t  maxSize;

    if (itemSize == 0)
        AASSERT_FAIL("item size is 0\n");

    maxSize = (~(size_t)0) / itemSize;
    if (count > maxSize)
        AASSERT_FAIL("allocation too large (%d > %d)\n", count, maxSize);
#endif
    return android_alloc(itemSize * count);
}

void*
_android_array_alloc0( size_t  itemSize, size_t  count )
{
    void*  block = _android_array_alloc(itemSize, count);
    memset(block, 0, itemSize*count);
    return block;
}

void*
_android_array_realloc( void* block, size_t  itemSize, size_t  count )
{
#ifdef ACONFIG_USE_ASSERT
    size_t  maxSize;

    if (itemSize == 0)
        AASSERT_FAIL("item size is 0\n");

    maxSize = (~(size_t)0) / itemSize;
    if (count > maxSize)
        AASSERT_FAIL("reallocation of %d-bytes array too large (%d > %d)\n",
                     itemSize, count, maxSize);
#endif
    return android_realloc(block, itemSize*count);
}

char*
android_strdup( const char*  str )
{
    int    len;
    char*  copy;

    if (str == NULL)
        return NULL;

    len  = strlen(str);
    copy = malloc(len+1);
    memcpy(copy, str, len);
    copy[len] = 0;

    return copy;
}

#ifdef _WIN32
char*
win32_strsep(char**  pline, const char*  delim)
{
    char*  line = *pline;
    char*  p    = line;

    if (p == NULL)
        return NULL;

    for (;;) {
        int          c = *p++;
        const char*  q = delim;

        if (c == 0) {
            p = NULL;
            break;
        }

        while (*q) {
            if (*q == c) {
                p[-1] = 0;
                goto Exit;
            }
            q++;
        }
    }
Exit:
    *pline = p;
    return line;
}
#endif


void
disable_sigalrm( signal_state_t  *state )
{
#ifdef _WIN32
    (void)state;
#else
    sigset_t  set;

    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    pthread_sigmask (SIG_BLOCK, &set, &state->old);
#endif
}

void
restore_sigalrm( signal_state_t  *state )
{
#ifdef _WIN32
    (void)state;
#else
    pthread_sigmask (SIG_SETMASK, &state->old, NULL);
#endif
}

void
sleep_ms( int  timeout_ms )
{
#ifdef _WIN32
    if (timeout_ms <= 0)
        return;

    Sleep( timeout_ms );
#else
    if (timeout_ms <= 0)
        return;

    BEGIN_NOSIGALRM
    usleep( timeout_ms*1000 );
    END_NOSIGALRM
#endif
}
