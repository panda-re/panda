/* Copyright (C) 2007-2009 The Android Open Source Project
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
#ifndef _ANDROID_UTILS_PATH_H
#define _ANDROID_UTILS_PATH_H

#include <android/utils/system.h>
#include <stdint.h>  /* for uint64_t */

/** MISC FILE AND DIRECTORY HANDLING
 **/

/* O_BINARY is required in the MS C library to avoid opening file
 * in text mode (the default, ahhhhh)
 */
#if !defined(_WIN32) && !defined(O_BINARY)
#  define  O_BINARY  0
#endif

/* define  PATH_SEP as a string containing the directory separateor */
#ifdef _WIN32
#  define  PATH_SEP   "\\"
#  define  PATH_SEP_C '\\'
#else
#  define  PATH_SEP   "/"
#  define  PATH_SEP_C '/'
#endif

/* get MAX_PATH, note that PATH_MAX is set to 260 on Windows for
 * stupid backwards-compatibility reason, though any 32-bit version
 * of the OS handles much much longer paths
 */
#ifdef _WIN32
#  undef   MAX_PATH
#  define  MAX_PATH    1024
#  undef   PATH_MAX
#  define  PATH_MAX    MAX_PATH
#else
#  include <limits.h>
#  define  MAX_PATH    PATH_MAX
#endif

/* checks that a given file exists */
//extern bool  path_exists( const char*  path );

/* checks that a path points to a regular file */
//extern bool  path_is_regular( const char*  path );

/* checks that a path points to a directory */
//extern bool  path_is_dir( const char*  path );

/* checks that a path is absolute or not */
//extern ABool  path_is_absolute( const char*  path );

/* checks that one can read/write a given (regular) file */
//extern bool  path_can_read( const char*  path );
//extern bool  path_can_write( const char*  path );

/* checks that one can execute a given file */
//extern bool  path_can_exec( const char* path );

/* try to make a directory */
//extern APosixStatus   path_mkdir( const char*  path, int  mode );

/* ensure that a given directory exists, create it if not,
   0 on success, -1 on error */
//extern APosixStatus   path_mkdir_if_needed( const char*  path, int  mode );

/* return the size of a given file in '*psize'. returns 0 on
 * success, -1 on failure (error code in errno) */
//extern APosixStatus   path_get_size( const char*  path, uint64_t  *psize );

/*  path_parent() can be used to return the n-level parent of a given directory
 *  this understands . and .. when encountered in the input path.
 *
 *  the returned string must be freed by the caller.
 */
extern char*  path_parent( const char*  path, int  levels );

/* split a path into a (dirname,basename) pair. the result strings must be freed
 * by the caller. Return 0 on success, or -1 on error. Error conditions include
 * the following:
 *   - 'path' is empty
 *   - 'path' is "/" or degenerate cases like "////"
 *   - basename is "." or ".."
 *
 * if there is no directory separator in path, *dirname will be set to "."
 * if the path is of type "/foo", then *dirname will be set to "/"
 *
 * pdirname can be NULL if you don't want the directory name
 * pbasename can be NULL if you don't want the base name
 */
extern int    path_split( const char*  path, char* *pdirname, char* *pbasename );

/* a convenience function to retrieve the directory name as returned by
 * path_split(). Returns NULL if path_split() returns an error.
 * the result string must be freed by the caller
 */
extern char*  path_dirname( const char*  path );

/* a convenience function to retrieve the base name as returned by
 * path_split(). Returns NULL if path_split() returns an error.
 * the result must be freed by the caller.
 */
extern char*  path_basename( const char*  path );

/* look for a given executable in the system path and return its full path.
 * Returns NULL if not found. Note that on Windows this doesn't not append
 * an .exe prefix, or other magical thing like Cygwin usually does.
 */
extern char*  path_search_exec( const char* filename );

/** OTHER FILE UTILITIES
 **
 **  path_empty_file() creates an empty file at a given path location.
 **  if the file already exists, it is truncated without warning
 **
 **  path_copy_file() copies one file into another.
 **
 **  unlink_file() is equivalent to unlink() on Unix, on Windows,
 **  it will handle the case where _unlink() fails because the file is
 **  read-only by trying to change its access rights then calling _unlink()
 **  again.
 **
 **  these functions return 0 on success, and -1 on error
 **
 **  load_text_file() reads a file into a heap-allocated memory block,
 **  and appends a 0 to it. the caller must free it
 **/

/* creates an empty file at a given location. If the file already
 * exists, it is truncated without warning. returns 0 on success,
 * or -1 on failure.
 */
//extern APosixStatus   path_empty_file( const char*  path );

/* copies on file into another one. 0 on success, -1 on failure
 * (error code in errno). Does not work on directories */
//extern APosixStatus   path_copy_file( const char*  dest, const char*  source );

/* unlink/delete a given file. Note that on Win32, this will
 * fail if the program has an opened handle to the file
 */
//extern APosixStatus   path_delete_file( const char*  path );

/* try to load a given file into a heap-allocated block.
 * if 'pSize' is not NULL, this will set the file's size in '*pSize'
 * note that this actually zero-terminates the file for convenience.
 * In case of failure, NULL is returned and the error code is in errno
 */
extern void*          path_load_file( const char*  path, size_t  *pSize );

/* */

#endif /* _ANDROID_UTILS_PATH_H */
