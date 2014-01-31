/* Copyright (C) 2006-2010 The Android Open Source Project
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

#include "libslirp.h"
#include "qemu-common.h"
#include "sysemu.h"
#include "telephony/modem_driver.h"
//#include "proxy_http.h"
#include "sockets.h"

#include "android/android.h"
//#include "android/globals.h"
#include "android/hw-sensors.h"
#include "android/utils/debug.h"
//#include "android/utils/path.h"
#include "android/utils/system.h"
#include "android/utils/bufprint.h"
#include "android/adb-server.h"
#include "android/adb-qemud.h"

#define  D(...)  do {  if (VERBOSE_CHECK(init)) dprint(__VA_ARGS__); } while (0)

#ifdef ANDROID_SDK_TOOLS_REVISION
#  define  VERSION_STRING  STRINGIFY(ANDROID_SDK_TOOLS_REVISION)".0"
#else
#  define  VERSION_STRING  "standalone"
#endif

extern int  control_console_start( int  port );  /* in control.c */

/* Contains arguments for -android-ports option. */
char* android_op_ports = NULL;
/* Contains arguments for -android-port option. */
char* android_op_port = NULL;
/* Contains arguments for -android-report-console option. */
char* android_op_report_console = NULL;
/* Contains arguments for -http-proxy option. */
char* op_http_proxy = NULL;
/* Base port for the emulated system. */
int    android_base_port;

/* Strings describing the host system's OpenGL implementation */
//char android_gl_vendor[ANDROID_GLSTRING_BUF_SIZE];
//char android_gl_renderer[ANDROID_GLSTRING_BUF_SIZE];
//char android_gl_version[ANDROID_GLSTRING_BUF_SIZE];

/*** APPLICATION DIRECTORY
 *** Where are we ?
 ***/

/*const char*  get_app_dir(void)
{
    char  buffer[1024];
    char* p   = buffer;
    char* end = p + sizeof(buffer);
    p = bufprint_app_dir(p, end);
    if (p >= end)
        return NULL;

    return strdup(buffer);
}*/

enum {
    REPORT_CONSOLE_SERVER = (1 << 0),
    REPORT_CONSOLE_MAX    = (1 << 1)
};

static int
get_report_console_options( char*  end, int  *maxtries )
{
    int    flags = 0;

    if (end == NULL || *end == 0)
        return 0;

    if (end[0] != ',') {
        derror( "socket port/path can be followed by [,<option>]+ only\n");
        exit(3);
    }
    end += 1;
    while (*end) {
        char*  p = strchr(end, ',');
        if (p == NULL)
            p = end + strlen(end);

        if (memcmp( end, "server", p-end ) == 0)
            flags |= REPORT_CONSOLE_SERVER;
        else if (memcmp( end, "max=", 4) == 0) {
            end  += 4;
            *maxtries = strtol( end, NULL, 10 );
            flags |= REPORT_CONSOLE_MAX;
        } else {
            derror( "socket port/path can be followed by [,server][,max=<count>] only\n");
            exit(3);
        }

        end = p;
        if (*end)
            end += 1;
    }
    return flags;
}

static void
report_console( const char*  proto_port, int  console_port )
{
    int   s = -1, s2;
    int   maxtries = 10;
    int   flags = 0;
    signal_state_t  sigstate;

    disable_sigalrm( &sigstate );

    if ( !strncmp( proto_port, "tcp:", 4) ) {
        char*  end;
        long   port = strtol(proto_port + 4, &end, 10);

        flags = get_report_console_options( end, &maxtries );

        if (flags & REPORT_CONSOLE_SERVER) {
            s = socket_loopback_server( port, SOCKET_STREAM );
            if (s < 0) {
                fprintf(stderr, "could not create server socket on TCP:%ld: %s\n",
                        port, errno_str);
                exit(3);
            }
        } else {
            for ( ; maxtries > 0; maxtries-- ) {
                D("trying to find console-report client on tcp:%d", port);
                s = socket_loopback_client( port, SOCKET_STREAM );
                if (s >= 0)
                    break;

                sleep_ms(1000);
            }
            if (s < 0) {
                fprintf(stderr, "could not connect to server on TCP:%ld: %s\n",
                        port, errno_str);
                exit(3);
            }
        }
    } else if ( !strncmp( proto_port, "unix:", 5) ) {
#ifdef _WIN32
        fprintf(stderr, "sorry, the unix: protocol is not supported on Win32\n");
        exit(3);
#else
        char*  path = strdup(proto_port+5);
        char*  end  = strchr(path, ',');
        if (end != NULL) {
            flags = get_report_console_options( end, &maxtries );
            *end  = 0;
        }
        if (flags & REPORT_CONSOLE_SERVER) {
            s = socket_unix_server( path, SOCKET_STREAM );
            if (s < 0) {
                fprintf(stderr, "could not bind unix socket on '%s': %s\n",
                        proto_port+5, errno_str);
                exit(3);
            }
        } else {
            for ( ; maxtries > 0; maxtries-- ) {
                s = socket_unix_client( path, SOCKET_STREAM );
                if (s >= 0)
                    break;

                sleep_ms(1000);
            }
            if (s < 0) {
                fprintf(stderr, "could not connect to unix socket on '%s': %s\n",
                        path, errno_str);
                exit(3);
            }
        }
        free(path);
#endif
    } else {
        fprintf(stderr, "-report-console must be followed by a 'tcp:<port>' or 'unix:<path>'\n");
        exit(3);
    }

    if (flags & REPORT_CONSOLE_SERVER) {
        int  tries = 3;
        D( "waiting for console-reporting client" );
        do {
            s2 = socket_accept(s, NULL);
        } while (s2 < 0 && --tries > 0);

        if (s2 < 0) {
            fprintf(stderr, "could not accept console-reporting client connection: %s\n",
                   errno_str);
            exit(3);
        }

        socket_close(s);
        s = s2;
    }

    /* simply send the console port in text */
    {
        char  temp[12];
        snprintf( temp, sizeof(temp), "%d", console_port );

        if (socket_send(s, temp, strlen(temp)) < 0) {
            fprintf(stderr, "could not send console number report: %d: %s\n",
                    errno, errno_str );
            exit(3);
        }
        socket_close(s);
    }
    D( "console port number sent to remote. resuming boot" );

    restore_sigalrm (&sigstate);
}

//jeh: copied from slirp/misc.c
inline int
inet_strtoip(const char*  str, uint32_t  *ip)
{
    int  comp[4];
    
    if (sscanf(str, "%d.%d.%d.%d", &comp[0], &comp[1], &comp[2], &comp[3]) != 4)
        return -1;
    
    if ((unsigned)comp[0] >= 256 ||
        (unsigned)comp[1] >= 256 ||
        (unsigned)comp[2] >= 256 ||
        (unsigned)comp[3] >= 256)
        return -1;
    
    *ip = (uint32_t)((comp[0] << 24) | (comp[1] << 16) |
    (comp[2] << 8)  |  comp[3]);
    return 0;
}


/* this function is called from qemu_main() once all arguments have been parsed
 * it should be used to setup any Android-specific items in the emulation before the
 * main loop runs
 */
void  android_emulation_setup( void )
{
    int   tries     = 16;
    int   base_port = 5554;
    int   adb_host_port = 5037; // adb's default
    int   success   = 0;
    int   s;
    uint32_t  guest_ip;

    inet_strtoip("10.0.2.15", &guest_ip);

    {


        for ( ; tries > 0; tries--, base_port += 2 ) {

            /* setup first redirection for ADB, the Android Debug Bridge */
            {
	        // Don't try to connect to 5555, let the QEMU port forwarding do it
                if (0)//adb_server_init(base_port+1))
                    continue;
                android_adb_service_init();
            }

            /* setup second redirection for the emulator console */
            if ( control_console_start( base_port ) < 0 ) {
                D("control console failed");
            }

            D( "control console listening on port %d, ADB on port %d", base_port, base_port+1 );
            success = 1;
            break;
        }

        if (!success) {
            fprintf(stderr, "it seems too many emulator instances are running on this machine. Aborting\n" );
            exit(1);
        }
    }

    android_modem_init( base_port );

    /* Save base port. */
    android_base_port = base_port;

   /* send a simple message to the ADB host server to tell it we just started.
    * it should be listening on port 5037. if we can't reach it, don't bother
    */
    do
    {
        SockAddress  addr;
        char         tmp[32];

        s = socket_create_inet( SOCKET_STREAM );
        if (s < 0) {
            D("can't create socket to talk to the ADB server");
            break;
        }

        sock_address_init_inet( &addr, SOCK_ADDRESS_INET_LOOPBACK, adb_host_port );
        if (socket_connect( s, &addr ) < 0) {
            D("can't connect to ADB server: %s", errno_str );
            break;
        }

        sprintf(tmp,"0012host:emulator:%d",base_port+1);
        socket_send(s, tmp, 18+4);
        D("sent '%s' to ADB server", tmp);
    }
    while (0);

    if (s >= 0)
        socket_close(s);

    /* initialize sensors, this must be done here due to timer issues */
    android_hw_sensors_init();
   
}


