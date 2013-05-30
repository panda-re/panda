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

/* this file implements the support of the new 'hardware control'
 * qemud communication channel, which is used by libs/hardware on
 * the system image to communicate with the emulator program for
 * emulating the following:
 *
 *   - power management
 *   - led(s) brightness
 *   - vibrator
 *   - flashlight
 */
#include "android/hw-control.h"
#include "cbuffer.h"
#include "android/hw-qemud.h"
//#include "android/globals.h"
#include "android/utils/misc.h"
#include "android/utils/debug.h"
#include "qemu-char.h"
#include <stdio.h>
#include <string.h>

#define  D(...)  VERBOSE_PRINT(hw_control,__VA_ARGS__)

/* define T_ACTIVE to 1 to debug transport communications */
#define  T_ACTIVE  0

#if T_ACTIVE
#define  T(...)  VERBOSE_PRINT(hw_control,__VA_ARGS__)
#else
#define  T(...)   ((void)0)
#endif

typedef struct {
    void*                  client;
    AndroidHwControlFuncs  client_funcs;
    QemudService*          service;
} HwControl;

/* handle query */
static void  hw_control_do_query( HwControl*  h, uint8_t*  query, int  querylen );

/* called when a qemud client sends a command */
static void
_hw_control_qemud_client_recv( void*         opaque,
                               uint8_t*      msg,
                               int           msglen,
                               QemudClient*  client )
{
    hw_control_do_query(opaque, msg, msglen);
}

/* called when a qemud client connects to the service */
static QemudClient*
_hw_control_qemud_connect( void*  opaque,
                           QemudService*  service,
                           int  channel,
                           const char* client_param )
{
    QemudClient*  client;

    client = qemud_client_new( service, channel, client_param,
                               opaque,
                               _hw_control_qemud_client_recv,
                               NULL, NULL, NULL );

    qemud_client_set_framing(client, 1);
    return client;
}


static uint8_t*
if_starts_with( uint8_t*  buf, int buflen, const char*  prefix )
{
    int  prefixlen = strlen(prefix);

    if (buflen < prefixlen || memcmp(buf, prefix, prefixlen))
        return NULL;

    return (uint8_t*)buf + prefixlen;
}


static void
hw_control_do_query( HwControl*  h,
                     uint8_t*    query,
                     int         querylen )
{
    uint8_t*   q;

    T("%s: query %4d '%.*s'", __FUNCTION__, querylen, querylen, query );

    q = if_starts_with( query, querylen, "power:light:brightness:" );
    if (q != NULL) {
        if (h->client_funcs.light_brightness){// && android_hw->hw_lcd_backlight) {
            char*  qq = strchr((const char*)q, ':');
            int    value;
            if (qq == NULL) {
                D("%s: badly formatted", __FUNCTION__ );
                return;
            }
            *qq++ = 0;
            value = atoi(qq);
            h->client_funcs.light_brightness( h->client, (char*)q, value );
        }
        return;
    }
}


static void
hw_control_init( HwControl*                    control,
                 void*                         client,
                 const AndroidHwControlFuncs*  client_funcs )
{
    control->client       = client;
    control->client_funcs = client_funcs[0];
    control->service      = qemud_service_register( "hw-control", 0,
                                                    control,
                                                    _hw_control_qemud_connect,
                                                    NULL, NULL);
}

const AndroidHwControlFuncs  defaultControls = {
    NULL,
};

static HwControl   hwstate[1];

void
android_hw_control_init( void )
{
    hw_control_init(hwstate, NULL, &defaultControls);
    D("%s: hw-control qemud handler initialized", __FUNCTION__);
}

void
android_hw_control_set( void*  opaque, const AndroidHwControlFuncs*  funcs )
{
    hwstate->client       = opaque;
    hwstate->client_funcs = funcs[0];
}

