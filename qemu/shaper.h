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
#ifndef _SLIRP_SHAPER_H_
#define _SLIRP_SHAPER_H_

#include <stddef.h>

/* a NetShaper object is used to limit the throughput of data packets
 * at a fixed rate expressed in bits/seconds
 */
typedef struct NetShaperRec_*  NetShaper;
typedef void (*NetShaperSendFunc)( void*  data, size_t  size, void*  opaque);

NetShaper   netshaper_create  ( int                do_copy,
                                NetShaperSendFunc  send_func );

void        netshaper_set_rate(NetShaper  shaper, double  rate );

void        netshaper_send( NetShaper  shaper, void* data, size_t  size );

void        netshaper_send_aux( NetShaper  shaper, void* data, size_t  size, void*  opaque );

int         netshaper_can_send( NetShaper  shaper );

void        netshaper_destroy (NetShaper   shaper);

/* a NetDelay object is used to simulate network connection latencies */
typedef struct NetDelayRec_*  NetDelay;

NetDelay   netdelay_create( NetShaperSendFunc  send_func );
void       netdelay_set_latency( NetDelay  delay, int  min_ms, int  max_ms );
void       netdelay_send( NetDelay  delay, const void*  data, size_t  size );
void       netdelay_send_aux( NetDelay  delay, const void*  data, size_t  size, void*  opaque );
void       netdelay_destroy( NetDelay  delay );

/** in vl.c */
/* network traffic shaper and delayer */
extern NetShaper   slirp_shaper_in;
extern NetShaper   slirp_shaper_out;
extern NetDelay    slirp_delay_in;

#endif /* _SLIRP_SHAPER_H_ */
