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
#include "remote_call.h"
#include "android/utils/bufprint.h"
#include "android/utils/debug.h"
#include "sysdeps.h"
#include "gsm.h"
#include "android/android.h"
#include "sockets.h"
#include <stdlib.h>

#define  DEBUG  1

#if 1
#  define  D_ACTIVE  VERBOSE_CHECK(modem)
#else
#  define  D_ACTIVE  DEBUG
#endif

#if 1
#  define  S_ACTIVE  VERBOSE_CHECK(socket)
#else
#  define  S_ACTIVE  DEBUG
#endif

#if DEBUG
#  include <stdio.h>
#  define  D(...)   do { if (D_ACTIVE) fprintf( stderr, __VA_ARGS__ ); } while (0)
#  define  S(...)   do { if (S_ACTIVE) fprintf( stderr, __VA_ARGS__ ); } while (0)
#else
#  define  D(...)   ((void)0)
#  define  S(...)   ((void)0)
#endif

/** By convention, remote numbers are the console ports, i.e. 5554, 5556, etc...
 **/
#define  REMOTE_NUMBER_BASE       5554
#define  REMOTE_NUMBER_MAX        16
#define  REMOTE_NUMBER_MAX_CHARS  4
#define  REMOTE_CONSOLE_PORT      5554

int
remote_number_from_port( int  port )
{
    if (port & 1)  /* must be even */
        return -1;

    port = (port - REMOTE_CONSOLE_PORT) >> 1;
    if ((unsigned)port >= REMOTE_NUMBER_MAX)
        return -1;

    return REMOTE_NUMBER_BASE + port*2;
}

int
remote_number_to_port( int  number )
{
    if (number & 1)  /* must be even */
        return -1;

    number = (number - REMOTE_NUMBER_BASE) >> 1;
    if ((unsigned)number >= REMOTE_NUMBER_MAX)
        return -1;

    return REMOTE_CONSOLE_PORT + number*2;
}

int
remote_number_string_to_port( const char*  number )
{
    char*  end;
    long   num;
    const char*  temp = number;
    int    len;

    len = strlen(number);
    if (len > 0 && number[len-1] == ';')
        len--;
    if (len == 11 && !memcmp(number, PHONE_PREFIX, 7))
        temp += 7;
    num = strtol( temp, &end, 10 );

    if (end == NULL || *end || (int)num != num )
        return -1;

    return remote_number_to_port( (int)num );
}

/** REMOTE CALL OBJECTS
 **/

typedef struct RemoteCallRec {
    struct RemoteCallRec*   next;
    struct RemoteCallRec**  pref;
    RemoteCallType          type;
    int                     to_port;
    int                     from_port;
    SysChannel              channel;
    RemoteResultFunc        result_func;
    void*                   result_opaque;

    char                    quitting;

    /* the output buffer */
    char*                   buff;
    int                     buff_pos;
    int                     buff_len;
    int                     buff_size;
    char                    buff0[32];

} RemoteCallRec, *RemoteCall;

static void
remote_call_done( RemoteCall  call )
{
    call->pref[0] = call->next;
    call->next    = NULL;
    call->pref    = &call->next;

    if (call->buff && call->buff != call->buff0) {
        free(call->buff);
        call->buff      = call->buff0;
        call->buff_size = (int) sizeof(call->buff0);
    }

    if ( call->channel ) {
        sys_channel_close( call->channel );
        call->channel = NULL;
    }

    call->buff_pos = 0;
    call->buff_len = 0;
}


static void
remote_call_free( RemoteCall  call )
{
    if (call) {
        remote_call_done( call );
        free(call);
    }
}


static void  remote_call_event( void*  opaque, int  events );  /* forward */

static RemoteCall
remote_call_alloc( RemoteCallType  type, int  to_port, int  from_port )
{
    RemoteCall  rcall    = calloc( sizeof(*rcall), 1 );
    int         from_num = remote_number_from_port(from_port);

    if (rcall != NULL) {
        char  *p, *end;

        rcall->pref      = &rcall->next;
        rcall->type      = type;
        rcall->to_port   = to_port;
        rcall->from_port = from_port;
        rcall->buff      = rcall->buff0;
        rcall->buff_size = sizeof(rcall->buff0);
        rcall->buff_pos  = 0;

        p   = rcall->buff;
        end = p + rcall->buff_size;

        switch (type) {
            case REMOTE_CALL_DIAL:
                p = bufprint(p, end, "gsm call " PHONE_PREFIX "%d\n", from_num );
                break;

            case REMOTE_CALL_BUSY:
                p = bufprint(p, end, "gsm busy " PHONE_PREFIX "%d\n", from_num);
                break;

            case REMOTE_CALL_HOLD:
                p = bufprint(p, end, "gsm hold " PHONE_PREFIX "%d\n", from_num);
                break;

            case REMOTE_CALL_ACCEPT:
                p = bufprint(p, end, "gsm accept " PHONE_PREFIX "%d\n", from_num);
                break;

            case REMOTE_CALL_HANGUP:
                p = bufprint(p, end, "gsm cancel " PHONE_PREFIX "%d\n", from_num );
                break;

            default:
                ;
        }
        if (p >= end) {
            D("%s: buffer too short\n", __FUNCTION__ );
            remote_call_free(rcall);
            return NULL;
        }

        rcall->buff_len = p - rcall->buff;

        rcall->channel = sys_channel_create_tcp_client( "localhost", to_port );
        if (rcall->channel == NULL) {
            D("%s: could not create channel to port %d\n", __FUNCTION__, to_port);
            remote_call_free(rcall);
            return NULL;
        }

        sys_channel_on( rcall->channel, SYS_EVENT_WRITE, remote_call_event, rcall );
    }
    return  rcall;
}


static int
remote_call_set_sms_pdu( RemoteCall  call,
                         SmsPDU      pdu )
{
    char  *p, *end;
    int    msg2len;

    msg2len = 32 + smspdu_to_hex( pdu, NULL, 0 );
    if (msg2len > call->buff_size) {
        char*  old_buff = call->buff == call->buff0 ? NULL : call->buff;
        char*  new_buff = realloc( old_buff, msg2len );
        if (new_buff == NULL) {
            D("%s: not enough memory to alloc %d bytes", __FUNCTION__, msg2len);
            return -1;
        }
        call->buff      = new_buff;
        call->buff_size = msg2len;
    }

    p   = call->buff;
    end = p + call->buff_size;

    p  = bufprint(p, end, "sms pdu ");
    p += smspdu_to_hex( pdu, p, end-p );
    *p++ = '\n';
    *p = 0;

    call->buff_len = p - call->buff;
    call->buff_pos = 0;
    return 0;
}


static void
remote_call_add( RemoteCall   call,
                 RemoteCall  *plist )
{
    RemoteCall  first = *plist;

    call->next = first;
    call->pref = plist;

    if (first)
        first->pref = &call->next;
}

static void
remote_call_event( void*  opaque, int  events )
{
    RemoteCall  call = opaque;

    S("%s: called for call (%d,%d), events=%02x\n", __FUNCTION__,
       call->from_port, call->to_port, events);

    if (events & SYS_EVENT_READ) {
        /* simply drain the channel */
        char  temp[32];
        int  n = sys_channel_read( call->channel, temp, sizeof(temp) );
        if (n <= 0) {
            /* remote emulator probably quitted */
            //S("%s: emulator %d quitted with %d: %s\n", __FUNCTION__, call->to_port, errno, errno_str);
            remote_call_free( call );
            return;
        }
    }

    if (events & SYS_EVENT_WRITE) {
        int  n;

        if (S_ACTIVE) {
            int  nn;
            S("%s: call (%d,%d) sending %d bytes '", __FUNCTION__,
            call->from_port, call->to_port, call->buff_len - call->buff_pos );
            for (nn = call->buff_pos; nn < call->buff_len; nn++) {
                int  c = call->buff[nn];
                if (c < 32) {
                    if (c == '\n')
                        S("\\n");
                    else if (c == '\t')
                        S("\\t");
                    else if (c == '\r')
                        S("\\r");
                    else
                        S("\\x%02x", c);
                } else
                    S("%c", c);
            }
            S("'\n");
        }

        n = sys_channel_write( call->channel,
                               call->buff + call->buff_pos,
                               call->buff_len - call->buff_pos );
        if (n <= 0) {
            /* remote emulator probably quitted */
            S("%s: emulator %d quitted unexpectedly with error %d: %s\n",
                    __FUNCTION__, call->to_port, errno, errno_str);
            if (call->result_func)
                call->result_func( call->result_opaque, 0 );
            remote_call_free( call );
            return;
        }
        call->buff_pos += n;

        if (call->buff_pos >= call->buff_len) {
            /* cool, we sent everything */
            S("%s: finished sending data to %d\n", __FUNCTION__, call->to_port);
            if (!call->quitting) {
                    call->quitting = 1;
                    sprintf( call->buff, "quit\n" );
                    call->buff_len = strlen(call->buff);
                    call->buff_pos = 0;
            } else {
                call->quitting = 0;
                if (call->result_func)
                    call->result_func( call->result_opaque, 1 );

                sys_channel_on( call->channel, SYS_EVENT_READ, remote_call_event, call );
            }
        }
    }
}

static RemoteCall  _the_remote_calls;

#if 0
static int
remote_from_number( const char*  from )
{
    char*  end;
    long   num = strtol( from, &end, 10 );

    if (end == NULL || *end)
        return -1;

    if ((unsigned)(num - REMOTE_NUMBER_BASE) >= REMOTE_NUMBER_MAX)
        return -1;

    return (int) num;
}
#endif

static RemoteCall
remote_call_generic( RemoteCallType  type, const char*  to_number, int  from_port )
{
    int         to_port = remote_number_string_to_port(to_number);
    RemoteCall  call;

    if ( remote_number_from_port(from_port) < 0 ) {
        D("%s: from_port value %d is not valid", __FUNCTION__, from_port);
        return NULL;
    }
    if ( to_port < 0 ) {
        D("%s: phone number '%s' is not decimal or remote", __FUNCTION__, to_number);
        return NULL;
    }
    if (to_port == from_port) {
        D("%s: trying to call self\n", __FUNCTION__);
        return NULL;
    }
    call = remote_call_alloc( type, to_port, from_port );
    if (call == NULL) {
        return NULL;
    }
    remote_call_add( call, &_the_remote_calls );
    D("%s: adding new call from port %d to port %d\n", __FUNCTION__, from_port, to_port);
    return call;
}


int
remote_call_dial( const char*       number,
                  int               from,
                  RemoteResultFunc  result_func,
                  void*             result_opaque )
{
    RemoteCall   call = remote_call_generic( REMOTE_CALL_DIAL, number, from );

    if (call != NULL) {
        call->result_func   = result_func;
        call->result_opaque = result_opaque;
    }
    return call ? 0 : -1;
}


void
remote_call_other( const char*  to_number, int  from_port, RemoteCallType  type )
{
    remote_call_generic( type, to_number, from_port );
}

/* call this function to send a SMS to a remote emulator */
int
remote_call_sms( const char*   number,
                 int           from,
                 SmsPDU        pdu )
{
    RemoteCall   call = remote_call_generic( REMOTE_CALL_SMS, number, from );

    if (call == NULL)
        return -1;

    if (call != NULL) {
        if ( remote_call_set_sms_pdu( call, pdu ) < 0 ) {
            remote_call_free(call);
            return -1;
        }
    }
    return call ? 0 : -1;
}


void
remote_call_cancel( const char*  to_number, int  from_port )
{
    remote_call_generic( REMOTE_CALL_HANGUP, to_number, from_port );
}
