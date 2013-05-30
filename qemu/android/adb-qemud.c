/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "qemu-common.h"
//#include "android/globals.h"  /* for android_hw */
#include "android/hw-qemud.h"
#include "android/utils/misc.h"
#include "android/utils/system.h"
#include "android/utils/debug.h"
#include "android/adb-server.h"
#include "android/adb-qemud.h"

#define  E(...)    derror(__VA_ARGS__)
#define  W(...)    dwarning(__VA_ARGS__)
#define  D(...)    VERBOSE_PRINT(adbclient,__VA_ARGS__)
#define  DD(...)   VERBOSE_PRINT(adb,__VA_ARGS__)
#define  D_ACTIVE  VERBOSE_CHECK(adbclient)
#define  DD_ACTIVE VERBOSE_CHECK(adb)
#define  QB(b, s)  quote_bytes((const char*)b, (s < 32) ? s : 32)

#define SERVICE_NAME        "adb"
#define DEBUG_SERVICE_NAME  "adb-debug"
/* Maximum length of the message that can be received from the guest. */
#define ADB_MAX_MSG_LEN     8
/* Enumerates ADB client state values. */
typedef enum AdbClientState {
    /* Waiting on a connection from ADB host. */
    ADBC_STATE_WAIT_ON_HOST,
    /* ADB host is connected. Waiting on the transport initialization completion
     * in the guest. */
    ADBC_STATE_HOST_CONNECTED,
    /* Connection between ADB host and ADB guest is fully established. */
    ADBC_STATE_CONNECTED,
    /* ADB host has been disconnected. */
    ADBC_STATE_HOST_DISCONNECTED,
    /* ADB guest has been disconnected. */
    ADBC_STATE_GUEST_DISCONNECTED,
} AdbClientState;

/* ADB client descriptor. */
typedef struct AdbClient AdbClient;
struct AdbClient {
    /* Opaque pointer returned from adb_server_register_guest API. */
    void*           opaque;
    /* QEMUD client pipe for this client. */
    QemudClient*    qemud_client;
    /* Connection state. */
    AdbClientState  state;
    /* Buffer, collecting accept / stop messages from client. */
    char            msg_buffer[ADB_MAX_MSG_LEN];
    /* Current position in message buffer. */
    int             msg_cur;
};

/* ADB debugging client descriptor. */
typedef struct AdbDbgClient AdbDbgClient;
struct AdbDbgClient {
    /* QEMUD client pipe for this client. */
    QemudClient*    qemud_client;
};

/********************************************************************************
 *                      ADB host communication.
 *******************************************************************************/

/* A callback that is invoked when the host is connected.
 * Param:
 *  opaque - AdbClient instance.
 *  connection - An opaque pointer that identifies connection with the ADB host.
 */
static void
_adb_on_host_connected(void* opaque, void* connection)
{
    AdbClient* const adb_client = (AdbClient*)opaque;

    if (adb_client->state == ADBC_STATE_WAIT_ON_HOST) {
        D("ADB client %p(o=%p) is connected to the host %p",
          adb_client, adb_client->opaque, connection);

        /* Bump the state up. */
         adb_client->state = ADBC_STATE_HOST_CONNECTED;

        /* Notify the ADB guest that host has been  connected.This will unblock
         * the guest from a 'read', then guest will register the transport, and
         * will send 'setart' request, indicating that it is ready to receive
         * data from the host. */
        qemud_client_send(adb_client->qemud_client, (const uint8_t*)"ok", 2);
    } else {
        D("Unexpected ADB host connection while state is %d", adb_client->state);
    }
}

/* A callback that is invoked when the host gets disconnected.
 * Param:
 *  opaque - AdbClient instance.
 *  connection - An opaque pointer that identifies connection with the ADB host.
 */
static void
_adb_on_host_disconnect(void* opaque, void* connection)
{
    AdbClient* const adb_client = (AdbClient*)opaque;

    D("ADB client %p(o=%p) is disconnected from the host %p",
      adb_client, adb_client->opaque, connection);
    adb_client->state = ADBC_STATE_HOST_DISCONNECTED;
}

/* A callback that is invoked when the host sends data.
 * Param:
 *  opaque - AdbClient instance.
 *  connection - An opaque pointer that identifies connection with the ADB host.
 *  buff, size - Buffer containing the host data.
 */
static void
_adb_on_host_data(void* opaque, void* connection, const void* buff, int size)
{
    AdbClient* const adb_client = (AdbClient*)opaque;
    D("ADB client %p(o=%p) received from the host %p %d bytes in %s",
      adb_client, adb_client->opaque, connection, size, QB(buff, size));

    if (adb_client->state == ADBC_STATE_CONNECTED) {
        /* Dispatch data down to the guest. */
        qemud_client_send(adb_client->qemud_client, (const uint8_t*)buff, size);
    } else {
        D("Unexpected data from ADB host %p while client %p(o=%p) is in state %d",
          connection, adb_client, adb_client->opaque, adb_client->state);
    }
}

/* ADB guest API required for adb_server_register_guest */
static AdbGuestRoutines _adb_client_routines = {
    /* A callback that is invoked when the host is connected. */
    _adb_on_host_connected,
    /* A callback that is invoked when the host gets disconnected. */
    _adb_on_host_disconnect,
    /* A callback that is invoked when the host sends data. */
    _adb_on_host_data,
};

/********************************************************************************
 *                      ADB guest communication.
 *******************************************************************************/

/* Allocates AdbClient instance. */
static AdbClient*
_adb_client_new(void)
{
    AdbClient* adb_client;

    ANEW0(adb_client);

    return adb_client;
}

/* Frees AdbClient instance, allocated with _adb_client_new */
static void
_adb_client_free(AdbClient* adb_client)
{
    if (adb_client != NULL) {
        free(adb_client);
    }
}

/* A callback that is invoked when ADB guest sends data to the service.
 * Param:
 *  opaque - AdbClient instance.
 *  msg, msglen - Message received from the ADB guest.
 *  client - adb QEMUD client.
 */
static void
_adb_client_recv(void* opaque, uint8_t* msg, int msglen, QemudClient* client)
{
    AdbClient* const adb_client = (AdbClient*)opaque;

    D("ADB client %p(o=%p) received from guest %d bytes in %s",
      adb_client, adb_client->opaque, msglen, QB(msg, msglen));

    if (adb_client->state == ADBC_STATE_CONNECTED) {
        /* Connection is fully established. Dispatch the message to the host. */
        adb_server_on_guest_message(adb_client->opaque, msg, msglen);
        return;
    }

    /*
     * At this point we expect either "accept", or "start" messages. Depending
     * on the state of the pipe (although small) these messages could be broken
     * into pieces. So, simply checking msg for "accept", or "start" may not
     * work. Lets collect them first in internal buffer, and then will see.
     */

    /* Make sure tha message doesn't overflow the buffer. */
    if ((msglen + adb_client->msg_cur) > sizeof(adb_client->msg_buffer)) {
        D("Unexpected message in ADB client.");
        adb_client->msg_cur = 0;
        return;
    }
    /* Append to current message. */
    memcpy(adb_client->msg_buffer + adb_client->msg_cur, msg, msglen);
    adb_client->msg_cur += msglen;

    /* Properly dispatch the message, depending on the client state. */
    switch (adb_client->state) {
        case ADBC_STATE_WAIT_ON_HOST:
            /* At this state the only message that is allowed is 'accept' */
            if (adb_client->msg_cur == 6 &&
                !memcmp(adb_client->msg_buffer, "accept", 6)) {
                adb_client->msg_cur = 0;
                /* Register ADB guest connection with the ADB server. */
                adb_client->opaque =
                    adb_server_register_guest(adb_client, &_adb_client_routines);
                if (adb_client->opaque == NULL) {
                    D("Unable to register ADB guest with the ADB server.");
                    /* KO the guest. */
                    qemud_client_send(adb_client->qemud_client,
                                      (const uint8_t*)"ko", 2);
                }
            } else {
                D("Unexpected guest request while waiting on ADB host to connect.");
            }
            break;

        case ADBC_STATE_HOST_CONNECTED:
            /* At this state the only message that is allowed is 'start' */
            if (adb_client->msg_cur &&
                !memcmp(adb_client->msg_buffer, "start", 5)) {
                adb_client->msg_cur = 0;
                adb_client->state = ADBC_STATE_CONNECTED;
                adb_server_complete_connection(adb_client->opaque);
            } else {
                D("Unexpected request while waiting on connection to start.");
            }
            break;

        default:
            D("Unexpected ADB guest request '%s' while client state is %d.",
              QB(msg, msglen), adb_client->state);
            break;
    }
}

/* A callback that is invoked when ADB guest disconnects from the service. */
static void
_adb_client_close(void* opaque)
{
    AdbClient* const adb_client = (AdbClient*)opaque;

    D("ADB client %p(o=%p) is disconnected from the guest.",
      adb_client, adb_client->opaque);
    adb_client->state = ADBC_STATE_GUEST_DISCONNECTED;
    if (adb_client->opaque != NULL) {
        /* Close connection with the host. */
        adb_server_on_guest_closed(adb_client->opaque);
    }
    _adb_client_free(adb_client);
}

/* A callback that is invoked when ADB daemon running inside the guest connects
 * to the service.
 * Client parameters are ignored here. Typically they contain the ADB port number
 * which is always 5555 for the device / emulated system.
 */
static QemudClient*
_adb_service_connect(void*          opaque,
                     QemudService*  serv,
                     int            channel,
                     const char*    client_param)
{
    /* Create new QEMUD client for the connection with ADB daemon. */
    AdbClient* const adb_client = _adb_client_new();

    D("Connecting ADB guest: '%s'", client_param ? client_param : "<null>");
    adb_client->qemud_client =
        qemud_client_new(serv, channel, client_param, adb_client,
                         _adb_client_recv, _adb_client_close, NULL, NULL);
    if (adb_client->qemud_client == NULL) {
        D("Unable to create QEMUD client for ADB guest.");
        _adb_client_free(adb_client);
        return NULL;
    }

    return adb_client->qemud_client;
}

/********************************************************************************
 *                      Debugging ADB guest communication.
 *******************************************************************************/

/* Allocates AdbDbgClient instance. */
static AdbDbgClient*
_adb_dbg_client_new(void)
{
    AdbDbgClient* adb_dbg_client;

    ANEW0(adb_dbg_client);

    return adb_dbg_client;
}

/* Frees AdbDbgClient instance, allocated with _adb_dbg_client_new */
static void
_adb_dbg_client_free(AdbDbgClient* adb_dbg_client)
{
    if (adb_dbg_client != NULL) {
        free(adb_dbg_client);
    }
}

/* A callback that is invoked when ADB debugging guest sends data to the service.
 * Param:
 *  opaque - AdbDbgClient instance.
 *  msg, msglen - Message received from the ADB guest.
 *  client - adb-debug QEMUD client.
 */
static void
_adb_dbg_client_recv(void* opaque, uint8_t* msg, int msglen, QemudClient* client)
{
    if (DD_ACTIVE) {
        fprintf(stderr, "ADB: %s", (const char*)msg);
    }
}

/* A callback that is invoked when ADB debugging guest disconnects from the
 * service. */
static void
_adb_dbg_client_close(void* opaque)
{
    AdbDbgClient* const adb_dbg_client = (AdbDbgClient*)opaque;

    DD("ADB debugging client %p is disconnected from the guest.", adb_dbg_client);
    _adb_dbg_client_free(adb_dbg_client);
}

/* A callback that is invoked when ADB daemon running inside the guest connects
 * to the debugging service.
 * Client parameters are ignored here.
 */
static QemudClient*
_adb_debug_service_connect(void*          opaque,
                           QemudService*  serv,
                           int            channel,
                           const char*    client_param)
{
    /* Create new QEMUD client for the connection with ADB debugger. */
    AdbDbgClient* const adb_dbg_client = _adb_dbg_client_new();

    DD("Connecting ADB debugging guest: '%s'",
       client_param ? client_param : "<null>");
    adb_dbg_client->qemud_client =
        qemud_client_new(serv, channel, client_param, adb_dbg_client,
                         _adb_dbg_client_recv, _adb_dbg_client_close, NULL, NULL);
    if (adb_dbg_client->qemud_client == NULL) {
        DD("Unable to create QEMUD client for ADB debugging guest.");
        _adb_dbg_client_free(adb_dbg_client);
        return NULL;
    }

    return adb_dbg_client->qemud_client;
}

/********************************************************************************
 *                      ADB service API.
 *******************************************************************************/

void
android_adb_service_init(void)
{
static int _inited = 0;

    if (!adb_server_is_initialized()) {
        return;
    }

    if (!_inited) {
        /* Register main ADB service. */
        QemudService*  serv = qemud_service_register(SERVICE_NAME, 0, NULL,
                                                     _adb_service_connect,
                                                     NULL, NULL);
        if (serv == NULL) {
            derror("%s: Could not register '%s' service",
                   __FUNCTION__, SERVICE_NAME);
            return;
        }
        D("%s: Registered '%s' qemud service", __FUNCTION__, SERVICE_NAME);

        /* Register debugging ADB service. */
        serv = qemud_service_register(DEBUG_SERVICE_NAME, 0, NULL,
                                      _adb_debug_service_connect, NULL, NULL);
        if (serv != NULL) {
            DD("Registered '%s' qemud service", DEBUG_SERVICE_NAME);
        } else {
            dwarning("%s: Could not register '%s' service",
                   __FUNCTION__, DEBUG_SERVICE_NAME);
        }
    }
}
