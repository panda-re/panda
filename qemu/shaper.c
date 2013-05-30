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
#include "shaper.h"
#include "qemu-common.h"
#include "qemu-timer.h"
#include <stdlib.h>

#define  SHAPER_CLOCK        rt_clock
#define  SHAPER_CLOCK_UNIT   1000.

static int
_packet_is_internal( const uint8_t*  data, size_t  size )
{
    const uint8_t*  end = data + size;

    /* must have room for Mac + IP header */
    if (data + 40 > end)
        return 0;

    if (data[12] != 0x08 || data[13] != 0x00 )
        return 0;

    /* must have valid IP header */
    data += 14;
    if ((data[0] >> 4) != 4 || (data[0] & 15) < 5)
        return 0;

    /* internal if both source and dest addresses are in 10.x.x.x */
    return ( data[12] == 10 && data[16] == 10);
}

/* here's how we implement network shaping. we want to limit the network
 * rate to a given constant MAX_RATE expressed as bits/second. this means
 * that it takes 1/MAX_RATE seconds to send a single bit, and count*8/MAX_RATE
 * seconds to send 'count' bytes.
 *
 * we're going to implement a scheme where, when we send a packet of
 * 'count' bytes, no other packet will go through in the same direction for
 * at least 'count*8/MAX_RATE' seconds. any successive packet that is "sent"
 * in this interval is placed in a queue, associated to a timer
 *
 * there are different (queue/timer/rate) values for the input and output
 * direction of the user vlan.
 */
typedef struct QueuedPacketRec_ {
    int64_t                    expiration;
    struct QueuedPacketRec_*   next;
    size_t                     size;
    void*                      opaque;
    void*                      data;
} QueuedPacketRec, *QueuedPacket;


static QueuedPacket
queued_packet_create( const void*   data,
                      size_t        size,
                      void*         opaque,
                      int           do_copy )
{
    QueuedPacket   packet;
    size_t         packet_size = sizeof(*packet);

    if (do_copy)
        packet_size += size;

    packet = g_malloc(packet_size);
    packet->next       = NULL;
    packet->expiration = 0;
    packet->size       = (size_t)size;
    packet->opaque     = opaque;

    if (do_copy) {
        packet->data = (void*)(packet+1);
        memcpy( (char*)packet->data, (char*)data, packet->size );
    } else {
        packet->data = (void*)data;
    }
    return packet;
}

static void
queued_packet_free( QueuedPacket  packet )
{
    if (packet) {
        g_free( packet );
    }
}

typedef struct NetShaperRec_ {
    QueuedPacket   packets;   /* list of queued packets, ordered by expiration date */
    int            num_packets;
    int            active;    /* is this shaper active ? */
    int64_t        block_until;
    double         max_rate;  /* max rate expressed in bytes/second */
    double         inv_rate;  /* inverse of max rate                */
    QEMUTimer*     timer;     /* QEMU timer */

    int                do_copy;
    NetShaperSendFunc  send_func;

} NetShaperRec;


void
netshaper_destroy( NetShaper  shaper )
{
    if (shaper) {
        shaper->active = 0;

        while (shaper->packets) {
            QueuedPacket  packet = shaper->packets;
            shaper->packets = packet->next;
            packet->next    = NULL;
            queued_packet_free(packet);
        }

        qemu_del_timer(shaper->timer);
        qemu_free_timer(shaper->timer);
        shaper->timer = NULL;
        g_free(shaper);
    }
}

/* this function is called when the shaper's timer expires */
static void
netshaper_expires( NetShaper  shaper )
{
    QueuedPacket  packet;

    while ((packet = shaper->packets) != NULL) {
        int64_t   now = qemu_get_clock_ms( SHAPER_CLOCK );

       if (packet->expiration > now)
           break;

       shaper->packets = packet->next;
       shaper->send_func( packet->data, packet->size, packet->opaque );
       queued_packet_free(packet);
       shaper->num_packets--;
   }

   /* reprogram timer if needed */
   if (shaper->packets) {
       shaper->block_until = shaper->packets->expiration;
       qemu_mod_timer( shaper->timer, shaper->block_until );
   } else {
       shaper->block_until = -1;
   }
}


NetShaper
netshaper_create( int                do_copy,
                  NetShaperSendFunc  send_func )
{
    NetShaper  shaper = g_malloc(sizeof(*shaper));

    shaper->active = 0;
    shaper->packets = NULL;
    shaper->num_packets = 0;
    shaper->timer   = qemu_new_timer_ms( SHAPER_CLOCK,
                                         (QEMUTimerCB*) netshaper_expires,
                                         shaper );
    shaper->send_func = send_func;
    shaper->max_rate  = 1e6;
    shaper->inv_rate  = 0.;

    shaper->block_until = -1; /* magic value, means to not block */

    return shaper;
}

void
netshaper_set_rate( NetShaper  shaper,
                    double     rate )
{
    /* send all current packets when changing the rate */
    while (shaper->packets) {
        QueuedPacket  packet = shaper->packets;
        shaper->packets = packet->next;
        shaper->send_func(packet->data, packet->size, packet->opaque);
        g_free(packet);
        shaper->num_packets = 0;
    }

    shaper->max_rate = rate;
    if (rate > 1.) {
        shaper->inv_rate = (8.*SHAPER_CLOCK_UNIT)/rate;  /* qemu_get_clock returns time in ms */
        shaper->active   = 1;                            /* for the real-time clock           */
    } else {
        shaper->active = 0;
    }

    shaper->block_until = -1;
}

void
netshaper_send_aux( NetShaper  shaper,
                    void*      data,
                    size_t     size,
                    void*      opaque )
{
    int64_t   now;

    if (!shaper->active || _packet_is_internal(data, size)) {
        shaper->send_func( data, size, opaque );
        return;
    }

    now = qemu_get_clock_ms( SHAPER_CLOCK );
    if (now >= shaper->block_until) {
        shaper->send_func( data, size, opaque );
        shaper->block_until = now + size*shaper->inv_rate;
        //fprintf(stderr, "NETSHAPER: block for %.2fms\n", (shaper->block_until - now)*1.0 );
        return;
    }

    /* create new packet, add it to the queue */
    {
        QueuedPacket   packet;

        packet = queued_packet_create( data, size, opaque, shaper->do_copy );

        packet->expiration = shaper->block_until;

        {
            QueuedPacket  *pnode, node;

            pnode = &shaper->packets;
            for (;;) {
                node = *pnode;
                if (node == NULL || node->expiration > packet->expiration )
                    break;
                pnode = &node->next;
            }
            packet->next = *pnode;
            *pnode       = packet;

            if (packet == shaper->packets)
                qemu_mod_timer( shaper->timer, packet->expiration );
        }
        shaper->num_packets += 1;
    }
    shaper->block_until += size*shaper->inv_rate;
    //fprintf(stderr, "NETSHAPER: block2 for %.2fms\n", (shaper->block_until - now)*1.0 );
}

void
netshaper_send( NetShaper  shaper,
                void*      data,
                size_t     size )
{
    netshaper_send_aux(shaper, data, size, NULL);
}


int
netshaper_can_send( NetShaper  shaper )
{
    int64_t  now;

    if (!shaper->active || shaper->block_until < 0)
        return 1;

    if (shaper->packets)
        return 0;

    now = qemu_get_clock_ms( SHAPER_CLOCK );
    return (now >= shaper->block_until);
}






/* this type is used to model a session connection/state
 * if session->packet is != NULL, then the connection is delayed
 */
typedef struct SessionRec_ {
    int64_t               expiration;
    struct SessionRec_*   next;
    unsigned              src_ip;
    unsigned              dst_ip;
    unsigned short        src_port;
    unsigned short        dst_port;
    uint8_t               protocol;
    QueuedPacket          packet;

} SessionRec, *Session;

#define  _PROTOCOL_TCP   6
#define  _PROTOCOL_UDP   17



static void
session_free( Session  session )
{
    if (session) {
        if (session->packet) {
            queued_packet_free(session->packet);
            session->packet = NULL;
        }
        g_free( session );
    }
}


#if 0  /* useful for debugging */
static const char*
session_to_string( Session  session )
{
    static char  temp[256];
    const char*  format = (session->protocol == _PROTOCOL_TCP) ? "TCP" : "UDP";
    sprintf( temp, "%s[%d.%d.%d.%d:%d / %d.%d.%d.%d:%d]", format,
             (session->src_ip >> 24) & 255, (session->src_ip >> 16) & 255,
             (session->src_ip >> 8) & 255, (session->src_ip) & 255, session->src_port,
             (session->dst_ip >> 24) & 255, (session->dst_ip >> 16) & 255,
             (session->dst_ip >> 8) & 255, (session->dst_ip) & 255, session->dst_port);

    return temp;
}
#endif

/* returns TRUE if this corresponds to a SYN packet */
int
_packet_SYN_flags( const void*  _data, size_t   size, Session  info )
{
    const uint8_t*  data = (const uint8_t*)_data;
    const uint8_t*  end  = data + size;

    /* enough room for a Ethernet MAC packet ? */
    if (data + 14 > end - 4)
        return 0;

    /* is it an IP packet ? */
    if (data[12] != 0x8 || data[13] != 0)
        return 0;

    data += 14;
    end  -= 4;

    if (data + 20 > end)
        return 0;

    /* IP version must be 4, and the header length in words at least 5 */
    if ((data[0] & 0xF) < 5 || (data[0] >> 4) != 4)
        return 0;

    /* time-to-live must be > 0 */
    if (data[8] == 0)
        return 0;

    /* must be TCP or UDP packet */
    if (data[9] != _PROTOCOL_TCP && data[9] != _PROTOCOL_UDP)
        return 0;

    info->protocol = data[9];
    info->src_ip   = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
    info->dst_ip   = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];

    data += 4*(data[0] & 15);
    if (data + 20 > end)
        return 0;

    info->src_port = (unsigned short)((data[0] << 8) | data[1]);
    info->dst_port = (unsigned short)((data[2] << 8) | data[3]);

    return (data[13] & 0x1f);
}


typedef struct NetDelayRec_
{
    Session     sessions;
    int         num_sessions;
    QEMUTimer*  timer;
    int         active;
    int         min_ms;
    int         max_ms;

    NetShaperSendFunc  send_func;

} NetDelayRec;


static Session*
netdelay_lookup_session( NetDelay  delay, Session  info )
{
    Session*  pnode = &delay->sessions;
    Session   node;

    for (;;) {
        node = *pnode;
        if (node == NULL)
            break;

        if (node->src_ip == info->src_ip &&
            node->dst_ip == info->dst_ip &&
            node->src_port == info->src_port &&
            node->dst_port == info->dst_port &&
            node->protocol == info->protocol )
            break;

        pnode = &node->next;
    }
    return pnode;
}



/* called by the delay's timer on expiration */
static void
netdelay_expires( NetDelay  delay )
{
    Session  session;
    int64_t  now = qemu_get_clock_ms( SHAPER_CLOCK );
    int      rearm = 0;
    int64_t  rearm_time = 0;

    for (session = delay->sessions; session != NULL; session = session->next)
    {
        QueuedPacket  packet = session->packet;

        if (packet == NULL)
            continue;

        if (session->expiration <= now) {
            /* send the SYN packet now */
                    //fprintf(stderr, "NetDelay:RST: sending creation for %s\n", session_to_string(session) );
            delay->send_func( packet->data, packet->size, packet->opaque );
            session->packet = NULL;
            queued_packet_free( packet );
        } else {
            if (!rearm) {
                rearm      = 1;
                rearm_time = session->expiration;
            }
            else if ( session->expiration < rearm_time )
                rearm_time = session->expiration;
        }
    }

    if (rearm)
        qemu_mod_timer( delay->timer, rearm_time );
}


NetDelay
netdelay_create( NetShaperSendFunc  send_func )
{
    NetDelay  delay = g_malloc(sizeof(*delay));

    delay->sessions     = NULL;
    delay->num_sessions = 0;
    delay->timer        = qemu_new_timer_ms( SHAPER_CLOCK,
                                             (QEMUTimerCB*) netdelay_expires,
                                             delay );
    delay->active = 0;
    delay->min_ms = 0;
    delay->max_ms = 0;

    delay->send_func = send_func;

    return delay;
}


void
netdelay_set_latency( NetDelay  delay, int  min_ms, int  max_ms )
{
    /* when changing the latency, accept all sessions */
    while (delay->sessions) {
        Session  session = delay->sessions;
        delay->sessions = session->next;
        session->next = NULL;
        if (session->packet) {
            QueuedPacket  packet = session->packet;
            delay->send_func( packet->data, packet->size, packet->opaque );
        }
        session_free(session);
        delay->num_sessions--;
    }

    delay->min_ms = min_ms;
    delay->max_ms = max_ms;
    delay->active = (min_ms <= max_ms) && min_ms > 0;
}

void
netdelay_send( NetDelay  delay, const void*  data, size_t  size )
{
    netdelay_send_aux(delay, data, size, NULL);
}


void
netdelay_send_aux( NetDelay  delay, const void*  data, size_t  size, void* opaque )
{
    if (delay->active && !_packet_is_internal(data, size)) {
        SessionRec  info[1];
        int         flags;

        flags = _packet_SYN_flags( data, size, info );
        if ((flags & 0x05) != 0)
        {  /* FIN or RST: drop connection */
            Session*  lookup  = netdelay_lookup_session( delay, info );
            Session   session = *lookup;
            if (session != NULL) {
                //fprintf(stderr, "NetDelay:RST: dropping %s\n", session_to_string(info) );

                *lookup = session->next;
                session_free( session );
                delay->num_sessions -= 1;
            }
        }
        else if ((flags & 0x12) == 0x02)
        {
            /* SYN: create connection */
            Session*  lookup  = netdelay_lookup_session( delay, info );
            Session   session = *lookup;

            if (session != NULL) {
                if (session->packet != NULL) {
                   /* this is a SYN re-transmission, since we didn't
                    * send the original SYN packet yet, just eat this one
                    */
                    //fprintf(stderr, "NetDelay:RST: swallow SYN re-send for %s\n", session_to_string(info) );
                    return;
                }
            } else {
                /* establish a new session slightly in the future */
                int   latency = delay->min_ms;
                int   range   = delay->max_ms - delay->min_ms;

                 if (range > 0)
                    latency += rand() % range;

                    //fprintf(stderr, "NetDelay:RST: delay creation for %s\n", session_to_string(info) );
                session = g_malloc( sizeof(*session) );

                session->next        = delay->sessions;
                delay->sessions      = session;
                delay->num_sessions += 1;

                session->expiration = qemu_get_clock_ms( SHAPER_CLOCK ) + latency;

                session->src_ip   = info->src_ip;
                session->dst_ip   = info->dst_ip;
                session->src_port = info->src_port;
                session->dst_port = info->dst_port;
                session->protocol = info->protocol;

                session->packet = queued_packet_create( data, size, opaque, 1 );

                netdelay_expires(delay);
                return;
            }
        }
    }

    delay->send_func( (void*)data, size, opaque );
}


void
netdelay_destroy( NetDelay  delay )
{
    if (delay) {
        while (delay->sessions) {
            Session  session = delay->sessions;
            delay->sessions = session->next;
            session_free(session);
            delay->num_sessions -= 1;
        }
        delay->active = 0;
        g_free( delay );
    }
}

