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
#ifndef _android_qemud_h
#define _android_qemud_h

#include "qemu-common.h"

/* Support for the qemud-based 'services' in the emulator.
 * Please read docs/ANDROID-QEMUD.TXT to understand what this is about.
 */

/* initialize the qemud support code in the emulator
 */

extern void  android_qemud_init( void );

/* return the character driver state object that needs to be connected to the
 * emulated serial port where all multiplexed channels go through.
 */
extern CharDriverState*  android_qemud_get_cs( void );

/* returns in '*pcs' a CharDriverState object that will be connected to
 * a single client in the emulated system for a given named service.
 *
 * this is only used to connect GPS and GSM service clients to the
 * implementation that requires a CharDriverState object for legacy
 * reasons.
 *
 * returns 0 on success, or -1 in case of error
 */
extern int  android_qemud_get_channel( const char*  name, CharDriverState* *pcs );

/* set an explicit CharDriverState object for a given qemud communication channel. this
 * is used to attach the channel to an external char driver device (e.g. one
 * created with "-serial <device>") directly.
 *
 * returns 0 on success, -1 on error
 */
extern int  android_qemud_set_channel( const char*  name, CharDriverState*  peer_cs );

/* list of known qemud channel names */
#define  ANDROID_QEMUD_GSM      "gsm"
#define  ANDROID_QEMUD_GPS      "gps"
#define  ANDROID_QEMUD_CONTROL  "control"
#define  ANDROID_QEMUD_SENSORS  "sensors"

/* A QemudService service is used to connect one or more clients to
 * a given emulator facility. Only one client can be connected at any
 * given time, but the connection can be closed periodically.
 */

typedef struct QemudClient   QemudClient;
typedef struct QemudService  QemudService;


/* A function that will be called when the client running in the emulated
 * system has closed its connection to qemud.
 */
typedef void (*QemudClientClose)( void*  opaque );

/* A function that will be called when the client sends a message to the
 * service through qemud.
 */
typedef void (*QemudClientRecv) ( void*  opaque, uint8_t*  msg, int  msglen, QemudClient*  client );

/* A function that will be called when the state of the client should be
 * saved to a snapshot.
 */
typedef void (*QemudClientSave) ( QEMUFile*  f, QemudClient*  client, void*  opaque );

/* A function that will be called when the state of the client should be
 * restored from a snapshot.
 */
typedef int (*QemudClientLoad) ( QEMUFile*  f, QemudClient*  client, void*  opaque );

/* Register a new client for a given service.
 * 'clie_opaque' will be sent as the first argument to 'clie_recv' and 'clie_close'
 * 'clie_recv' and 'clie_close' are both optional and may be NULL.
 *
 * You should typically use this function within a QemudServiceConnect callback
 * (see below).
 */
extern QemudClient*  qemud_client_new( QemudService*      service,
                                        int               channel_id,
                                        const char*       client_param,
                                        void*             clie_opaque,
                                        QemudClientRecv   clie_recv,
                                        QemudClientClose  clie_close,
                                        QemudClientSave   clie_save,
                                        QemudClientLoad   clie_load );

/* Enable framing on a given client channel.
 */
extern void           qemud_client_set_framing( QemudClient*  client, int  enabled );

/* Send a message to a given qemud client
 */
extern void   qemud_client_send ( QemudClient*  client, const uint8_t*  msg, int  msglen );

/* Force-close the connection to a given qemud client.
 */
extern void   qemud_client_close( QemudClient*  client );


/* A function that will be called each time a new client in the emulated
 * system tries to connect to a given qemud service. This should typically
 * call qemud_client_new() to register a new client.
 */
typedef QemudClient*  (*QemudServiceConnect)( void*   opaque,
                                              QemudService*  service,
                                              int  channel,
                                              const char* client_param );

/* A function that will be called when the state of the service should be
 * saved to a snapshot.
 */
typedef void (*QemudServiceSave) ( QEMUFile*  f, QemudService*  service, void*  opaque );

/* A function that will be called when the state of the service should be
 * restored from a snapshot.
 */
typedef int (*QemudServiceLoad) ( QEMUFile*  f, QemudService*  service, void*  opaque );

/* Register a new qemud service.
 * 'serv_opaque' is the first parameter to 'serv_connect'
 */
extern QemudService*  qemud_service_register( const char*          serviceName,
                                              int                  max_clients,
                                              void*                serv_opaque,
                                              QemudServiceConnect  serv_connect,
                                              QemudServiceSave     serv_save,
                                              QemudServiceLoad     serv_load);

/* Sends a message to all clients of a given service.
 */
extern void           qemud_service_broadcast( QemudService*   sv,
                                               const uint8_t*  msg,
                                               int             msglen );

#endif /* _android_qemud_h */
