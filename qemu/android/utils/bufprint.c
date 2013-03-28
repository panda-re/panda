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

#include "android/utils/bufprint.h"
#include "android/utils/path.h"
#include "android/utils/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include "windows.h"
#  include "shlobj.h"
#else
#  include <unistd.h>
#  include <sys/stat.h>
#endif

#define  D(...)  VERBOSE_PRINT(init,__VA_ARGS__)


/** USEFUL STRING BUFFER FUNCTIONS
 **/

char*
vbufprint( char*        buffer,
           char*        buffer_end,
           const char*  fmt,
           va_list      args )
{
    int  len = vsnprintf( buffer, buffer_end - buffer, fmt, args );
    if (len < 0 || buffer+len >= buffer_end) {
        if (buffer < buffer_end)
            buffer_end[-1] = 0;
        return buffer_end;
    }
    return buffer + len;
}

char*
bufprint(char*  buffer, char*  end, const char*  fmt, ... )
{
    va_list  args;
    char*    result;

    va_start(args, fmt);
    result = vbufprint(buffer, end, fmt, args);
    va_end(args);
    return  result;
}

/** USEFUL DIRECTORY SUPPORT
 **
 **  bufprint_app_dir() returns the directory where the emulator binary is located
 **
 **  get_android_home() returns a user-specific directory where the emulator will
 **  store its writable data (e.g. config files, profiles, etc...).
 **  on Unix, this is $HOME/.android, on Windows, this is something like
 **  "%USERPROFILE%/Local Settings/AppData/Android" on XP, and something different
 **  on Vista.
 **
 **  both functions return a string that must be freed by the caller
 **/

#ifdef __linux__
char*
bufprint_app_dir(char*  buff, char*  end)
{
    char   path[1024];
    int    len;
    char*  x;

    len = readlink("/proc/self/exe", path, sizeof(path));
    if (len <= 0 || len >= (int)sizeof(path)) goto Fail;
    path[len] = 0;

    x = strrchr(path, '/');
    if (x == 0) goto Fail;
    *x = 0;

    return bufprint(buff, end, "%s", path);
Fail:
    fprintf(stderr,"cannot locate application directory\n");
    exit(1);
    return end;
}

#elif defined(__APPLE__)
/* the following hack is needed in order to build with XCode 3.1
 * don't ask me why, but it seems that there were changes in the
 * GCC compiler that we don't have in our pre-compiled version
 */
#ifndef __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
#define __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ MAC_OS_X_VERSION_10_4
#endif
#import <Carbon/Carbon.h>
#include <unistd.h>

char*
bufprint_app_dir(char*  buff, char*  end)
{
    ProcessSerialNumber psn;
    CFDictionaryRef     dict;
    CFStringRef         value;
    char                s[PATH_MAX];
    char*               x;

    GetCurrentProcess(&psn);
    dict  = ProcessInformationCopyDictionary(&psn, 0xffffffff);
    value = (CFStringRef)CFDictionaryGetValue(dict,
                                             CFSTR("CFBundleExecutable"));
    CFStringGetCString(value, s, PATH_MAX - 1, kCFStringEncodingUTF8);
    x = strrchr(s, '/');
    if (x == 0) goto fail;
    *x = 0;

    return bufprint(buff, end, "%s", s);
fail:
    fprintf(stderr,"cannot locate application directory\n");
    exit(1);
    return end;
}
#elif defined _WIN32
char*
bufprint_app_dir(char*  buff, char*  end)
{
    char   appDir[MAX_PATH];
	int    len;
	char*  sep;

    len = GetModuleFileName( 0, appDir, sizeof(appDir)-1 );
	if (len == 0) {
		fprintf(stderr, "PANIC CITY!!\n");
		exit(1);
	}
	if (len >= (int)sizeof(appDir)) {
		len = sizeof(appDir)-1;
	    appDir[len] = 0;
    }

	sep = strrchr(appDir, '\\');
	if (sep)
	  *sep = 0;

    return bufprint(buff, end, "%s", appDir);
}
#else
char*
bufprint_app_dir(char*  buff, char*  end)
{
    return bufprint(buff, end, ".");
}
#endif

#define  _ANDROID_PATH   ".android"

char*
bufprint_config_path(char*  buff, char*  end)
{
#ifdef _WIN32
    const char*  home = getenv("ANDROID_SDK_HOME");
    if (home != NULL) {
        return bufprint(buff, end, "%s\\%s", home, _ANDROID_PATH );
    } else {
        char  path[MAX_PATH];

        SHGetFolderPath( NULL, CSIDL_PROFILE,
                         NULL, 0, path);

        return bufprint(buff, end, "%s\\%s", path, _ANDROID_PATH );
    }
#else
    const char*  home = getenv("ANDROID_SDK_HOME");
    if (home == NULL)
        home = getenv("HOME");
    if (home == NULL)
        home = "/tmp";
    return bufprint(buff, end, "%s/%s", home, _ANDROID_PATH );
#endif
}

char*
bufprint_config_file(char*  buff, char*  end, const char*  suffix)
{
    char*   p;
    p = bufprint_config_path(buff, end);
    p = bufprint(p, end, PATH_SEP "%s", suffix);
    return p;
}

char*
bufprint_temp_dir(char*  buff, char*  end)
{
#ifdef _WIN32
    char   path[MAX_PATH];
    DWORD  retval;

    retval = GetTempPath( sizeof(path), path );
    if (retval > sizeof(path) || retval == 0) {
        D( "can't locate TEMP directory" );
        strncpy(path, "C:\\Temp", sizeof(path) );
    }
    strncat( path, "\\AndroidEmulator", sizeof(path)-1 );
    path_mkdir(path, 0744);

    return  bufprint(buff, end, "%s", path);
#else
    char path[MAX_PATH];
    const char*  tmppath = getenv("ANDROID_TMP");
    if (!tmppath) {
        const char* user = getenv("USER");
        if (user == NULL || user[0] == '\0')
            user = "unknown";

        snprintf(path, sizeof path, "/tmp/android-%s", user);
        tmppath = path;
    }
    mkdir(tmppath, 0744);
    return  bufprint(buff, end, "%s", tmppath );
#endif
}

char*
bufprint_temp_file(char*  buff, char*  end, const char*  suffix)
{
    char*  p;
    p = bufprint_temp_dir(buff, end);
    p = bufprint(p, end, PATH_SEP "%s", suffix);
    return p;
}

