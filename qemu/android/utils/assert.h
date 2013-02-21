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
#ifndef ANDROID_UTILS_ASSERT_H
#define ANDROID_UTILS_ASSERT_H

#include <stdarg.h>

/* These are always defined, so you can write your own macros that
 * call them, independently of the value of ACONFIG_USE_ASSERT
 */

/* Used internally by the macros to register the current source location */
void  _android_assert_loc(const char*  fileName,
                          long         fileLineno,
                          const char*  functionName);

/* Call this after _android_assert_loc() to dump an assertion failed message
 * just before panicking, i.e. abort the current program
 */
void __attribute__((noreturn)) android_assert_fail(const char*  messageFmt, ...);

/* See _android_assert_loc() */
#define  _ANDROID_ASSERT_LOC()  \
    _android_assert_loc(__FILE__,__LINE__,__FUNCTION__)

/* Report an assertion failure then panic. Arguments are formatted string */
#define  _ANDROID_ASSERT_FAIL(...) \
    android_assert_fail(__VA_ARGS__)

/* Report an unreachable code */
#define  _ANDROID_ASSERT_UNREACHED(...)   \
    do { \
        _ANDROID_ASSERT_LOC(); \
        android_assert_fail(__VA_ARGS__); \
    } while (0);

/* Check that 'cond' is true, and report an assertion failure otherwise */
#define  _ANDROID_ASSERT(cond,...)  \
    do { \
        if (!(cond)) { \
            _ANDROID_ASSERT_LOC(); \
            android_assert_fail(__VA_ARGS__); \
        } \
    } while (0)

/* Check that 'cond' is boolean true (i.e. not 0), and report an assertion
 * failure otherwise. */
#define  _ANDROID_ASSERT_BOOL(cond_,expected_)    \
    do { \
        int  cond_result_   = !!(cond_); \
        int  cond_expected_ = !!(expected_); \
        if (cond_result_ != cond_expected_) { \
            _ANDROID_ASSERT_LOC(); \
            android_assert_fail("%s is %s instead of %s\n",\
               #cond_, \
               cond_result_ ? "TRUE" : "FALSE", \
               cond_expected_ ? "TRUE" : "FALSE" ); \
        } \
    } while (0)

/* Assert that a given expression is of a given integer value */
#define  _ANDROID_ASSERT_INT(cond_,expected_)  \
    do { \
        int  cond_result_ = (cond_); \
        int  cond_expected_ = (expected_); \
        if (cond_result_ != cond_expected_) { \
            _ANDROID_ASSERT_LOC(); \
            android_assert_fail("%s is %d instead of %d\n", \
                                #cond_ , cond_result_, cond_expected_); \
        } \
    } while (0)

#define  _ANDROID_ASSERT_INT_OP(cond_,expected_,op_) \
    do { \
        int  cond_result_ = (cond_); \
        int  cond_expected_ = (expected_); \
        if (!(cond_result_ _op cond_expected_)) { \
            _ANDROID_ASSERT_LOC(); \
            android_assert_fail("%s is %d and should be %s %d\n", \
                                #cond_ , cond_result_, #op_, cond_expected_); \
        } \
    } while (0)

#  define  _ANDROID_ASSERT_PTR(cond_,expected_)  \
    do { \
        void*  cond_result_ = (cond_); \
        void*  cond_expected_ = (void*)(expected_); \
        if (cond_result_ != cond_expected_) { \
            _ANDROID_ASSERT_LOC(); \
            android_assert_fail("%s is %p instead of %p\n", \
                                #cond_ , cond_result_, cond_expected_); \
        } \
    } while (0)

#  define  _ANDROID_NEVER_NULL(ptr_)  \
    do { \
        void*  never_ptr_ = (ptr_); \
        if (never_ptr_ == NULL) { \
            _ANDROID_ASSERT_LOC(); \
            android_assert_fail("%s is NULL\n", #ptr_); \
        } \
    } while (0)



#ifdef ACONFIG_USE_ASSERT

#  define  AASSERT_LOC()   _ANDROID_ASSERT_LOC()
#  define  AASSERT_FAIL(...) _ANDROID_ASSERT_FAIL(__VA_ARGS__)

/* Assert we never reach some code point */
#  define  AASSERT_UNREACHED(...)   _ANDROID_ASSERT_UNREACHED(__VA_ARGS__)


/* Generic assertion, must be followed by formatted string parameters */
#  define  AASSERT(cond,...)  _ANDROID_ASSERT(cond,__VA_ARGS__)

/* Assert a condition evaluates to a given boolean */
#  define  AASSERT_BOOL(cond_,expected_)   _ANDROID_ASSERT_BOOL(cond_,expected_)

/* Assert a condition evaluates to a given integer */
#  define  AASSERT_INT(cond_,expected_)  _ANDROID_ASSERT_INT(cond_,expected_)

#  define  AASSERT_INT_LT(cond_,expected_)  _ANDROID_ASSERT_INT_OP(cond_,expected_,< )
#  define  AASSERT_INT_LTE(cond_,expected_) _ANDROID_ASSERT_INT_OP(cond_,expected_,<= )
#  define  AASSERT_INT_GT(cond_,expected_)  _ANDROID_ASSERT_INT_OP(cond_,expected_,> )
#  define  AASSERT_INT_GTE(cond_,expected_) _ANDROID_ASSERT_INT_OP(cond_,expected_,>= )
#  define  AASSERT_INT_EQ(cond_,expected_)  _ANDROID_ASSERT_INT_OP(cond_,expected_,==)
#  define  AASSERT_INT_NEQ(cond_,expected_) _ANDROID_ASSERT_INT_OP(cond_,expected_,!=)

#  define  AASSERT_PTR(cond_,expected_)  _ANDROID_ASSERT_PTR(cond_,expected_)

#  define  ANEVER_NULL(ptr_)   _ANDROID_NEVER_NULL(ptr_)

#else /* !ACONFIG_USE_ASSERT */

#  define AASSERT_LOC()              ((void)0)
#  define  AASSERT_FAIL(...)        ((void)0)
#  define  AASSERT_UNREACHED(...)   ((void)0)

/* for side-effects */
#  define  AASSERT(cond,...)             ((void)(cond), (void)0)
#  define  AASSERT_BOOL(cond,val)        ((void)(cond), (void)0)
#  define  AASSERT_INT(cond,val)         AASSERT_BOOL(cond,val)
#  define  AASSERT_PTR(cond,val)         AASSERT_BOOL(cond,val)
#  define  ANEVER_NULL(ptr)              ((void)(ptr), (void)0)

#endif /* !ACONFIG_USE_ASSERT */

#  define  AASSERT_TRUE(cond_)   AASSERT_BOOL(cond_,1)
#  define  AASSERT_FALSE(cond_)  AASSERT_BOOL(cond_,0)


/* this can be used to redirect the assertion log to something
 * other than stderr. Note that android_assert_fail also calls
 * android_vpanic.
 */
typedef void (*AAssertLogFunc)( const char*  fmt, va_list  args );
void  android_assert_registerLog( AAssertLogFunc  logger );

#endif /* ANDROID_UTILS_ASSERT_H */
