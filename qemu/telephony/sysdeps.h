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
#ifndef __sysdeps_h__
#define __sysdeps_h__

/* system-dependent platform abstraction used by the emulated GSM modem
 */

/* to be called before anything else */

extern void  sys_main_init( void );

/** callbacks
 **/
typedef void  (*SysCallback)( void*  opaque );

/** events
 **/
enum {
    SYS_EVENT_READ  = 0x01,
    SYS_EVENT_WRITE = 0x02,
    SYS_EVENT_ERROR = 0x04,
    SYS_EVENT_ALL   = 0x07
};

/** channels
 **/
typedef struct SysChannelRec_*  SysChannel;

typedef void (*SysChannelCallback)( void*  opaque, int  event_flags );

/* XXX: TODO: channel creation functions */
extern SysChannel  sys_channel_create_tcp_server( int port );
extern SysChannel  sys_channel_create_tcp_handler( SysChannel  server_channel );
extern SysChannel  sys_channel_create_tcp_client( const char*  hostname, int  port );
extern int         sys_channel_set_non_block( SysChannel  channel );

extern  void   sys_channel_on( SysChannel          channel,
                               int                 event_flags,
                               SysChannelCallback  event_callback,
                               void*               event_opaqe );

extern  int   sys_channel_read( SysChannel  channel, void*  buffer, int  size );

extern  int   sys_channel_write( SysChannel  channel, const void*  buffer, int  size );

extern  void  sys_channel_close( SysChannel  channel );


/** time measurement
 **/
typedef long long   SysTime;

extern SysTime   sys_time_now( void );

/** timers
 **/
typedef struct SysTimerRec_*    SysTimer;

extern SysTimer   sys_timer_create( void );
extern void       sys_timer_set( SysTimer  timer, SysTime  when, SysCallback   callback, void*  opaque );
extern void       sys_timer_unset( SysTimer  timer );
extern void       sys_timer_destroy( SysTimer  timer );

extern long long  sys_time_ms( void );

/** main loop (may return immediately on some platform)
 **/
extern int   sys_main_loop( void );

#endif /* __sysdeps_h__ */
