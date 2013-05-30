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
#include "sockets.h"
#include "iolooper.h"
#include "android/async-utils.h"
#include "android/utils/debug.h"
#include "android/utils/list.h"
#include "android/utils/misc.h"
#include "android/adb-server.h"

#define  E(...)    derror(__VA_ARGS__)
#define  W(...)    dwarning(__VA_ARGS__)
#define  D(...)    VERBOSE_PRINT(adbserver,__VA_ARGS__)

#define  D_ACTIVE  VERBOSE_CHECK(adbserver)
#define  QB(b, s)  quote_bytes((const char*)b, (s < 32) ? s : 32)

typedef struct AdbServer    AdbServer;
typedef struct AdbHost      AdbHost;
typedef struct AdbGuest     AdbGuest;

/* ADB guest connection descriptor. */
struct AdbGuest {
    /* Entry in the list of pending or connected ADB guests.
     * NOTE: This must be the first entry in the descriptor! */
    ACList              list_entry;
    /* Opaque pointer associated with the guest. */
    void*               opaque;
    /* ADB server for this guest. */
    AdbServer*          adb_srv;
    /* ADB host connected with this ADB guest. */
    AdbHost*            adb_host;
    /* Callback routines for the ADB guest. */
    AdbGuestRoutines*   callbacks;
    /* ADB guest connection status. If 0 indicates that ADB guest is not yet
     * ready to receive data from the host. */
    int                 is_connected;
};

/* ADB host connection descriptor. */
struct AdbHost {
    /* Entry in the list of pending or connected ADB hosts.
     * NOTE: This must be the first entry in the descriptor! */
    ACList      list_entry;
    /* ADB server for this host. */
    AdbServer*  adb_srv;
    /* ADB socket connected with the host. */
    int         host_so;
    /* I/O port for asynchronous I/O on the host socket. */
    LoopIo      io[1];
    /* ADB guest connected with this ADB host. */
    AdbGuest*   adb_guest;
    /* Pending data to send to the guest when it is fully connected. */
    uint8_t*    pending_data;
    /* Size of the pending data buffer. */
    int         pending_data_size;
    /* Contains data that are pending to be sent to the host. */
    uint8_t*    pending_send_buffer;
    /* Number of bytes that are pending to be sent to the host. */
    int         pending_send_data_size;
    /* Size of the pending_send_buffer */
    int         pending_send_buffer_size;
};

/* ADB server descriptor. */
struct AdbServer {
    /* ADB socket address. */
    SockAddress socket_address;
    /* Looper for async I/O on ADB server socket. */
    Looper*     looper;
    /* I/O port for asynchronous I/O on ADB server socket. */
    LoopIo      io[1];
    /* ADB port. */
    int         port;
    /* Server socket. */
    int         so;
    /* List of connected ADB hosts. */
    ACList      adb_hosts;
    /* List of connected ADB guests. */
    ACList      adb_guests;
    /* List of ADB hosts pending connection with ADB guest. */
    ACList      pending_hosts;
    /* List of ADB guests pending connection with ADB host. */
    ACList      pending_guests;
};

/* One and only one ADB server instance. */
static AdbServer    _adb_server;
/* ADB server initialization flag. */
static int          _adb_server_initialized = 0;

/********************************************************************************
 *                             ADB host API
 *******************************************************************************/

/* Creates and initializes a new AdbHost instance. */
static AdbHost*
_adb_host_new(AdbServer* adb_srv)
{
    AdbHost* adb_host;

    ANEW0(adb_host);
    alist_init(&adb_host->list_entry);
    adb_host->adb_srv = adb_srv;
    adb_host->host_so = -1;

    return adb_host;
}

/* Frees AdbHost instance created with _adb_host_new routine. */
static void
_adb_host_free(AdbHost* adb_host)
{
    if (adb_host != NULL) {
        /* At this point it must not be listed anywhere. */
        assert(alist_is_empty(&adb_host->list_entry));

        /* Close the host socket. */
        if (adb_host->host_so >= 0) {
            loopIo_done(adb_host->io);
            socket_close(adb_host->host_so);
        }

        /* Free pending data buffers. */
        if (adb_host->pending_data != NULL) {
            free(adb_host->pending_data);
        }
        if (adb_host->pending_send_buffer != NULL) {
            free(adb_host->pending_send_buffer);
        }

        AFREE(adb_host);
    }
}

static void
_adb_host_append_message(AdbHost* adb_host, const void* msg, int msglen)
{
    printf("Append %d bytes to ADB host buffer.\n", msglen);

    /* Make sure that buffer can contain the appending data. */
    if (adb_host->pending_send_buffer == NULL) {
        adb_host->pending_send_buffer = (uint8_t*)malloc(msglen);
        adb_host->pending_send_buffer_size = msglen;
    } else if ((adb_host->pending_send_data_size + msglen) >
               adb_host->pending_send_buffer_size) {
        adb_host->pending_send_buffer =
            (uint8_t*)realloc(adb_host->pending_send_buffer,
                              adb_host->pending_send_data_size + msglen);
        adb_host->pending_send_buffer_size =
            adb_host->pending_send_data_size + msglen;
    }

    if (adb_host->pending_send_buffer == NULL) {
        D("Unable to allocate %d bytes for pending ADB host data.",
          adb_host->pending_send_data_size + msglen);
        adb_host->pending_send_buffer_size = adb_host->pending_send_data_size = 0;
        loopIo_dontWantWrite(adb_host->io);
        return;
    }

    memcpy(adb_host->pending_send_buffer + adb_host->pending_send_data_size,
           msg, msglen);
    loopIo_wantWrite(adb_host->io);
}

/* Connects ADB host with ADB guest. */
static void
_adb_connect(AdbHost* adb_host, AdbGuest* adb_guest)
{
    D("Connecting ADB host %p(so=%d) with ADB guest %p(o=%p)",
      adb_host, adb_host->host_so, adb_guest, adb_guest->opaque);

    adb_guest->adb_host = adb_host;
    adb_host->adb_guest = adb_guest;
    adb_guest->callbacks->on_connected(adb_guest->opaque, adb_guest);
}

/* Callback invoked when ADB host socket gets disconnected. */
static void
_on_adb_host_disconnected(AdbHost* adb_host)
{
    AdbGuest* const adb_guest = adb_host->adb_guest;

    /* Notify the ADB guest that the host got disconnected. */
    if (adb_guest != NULL) {
        D("Disconnecting ADB host %p(so=%d) from ADB guest %p(o=%p)",
          adb_host, adb_host->host_so, adb_guest, adb_guest->opaque);
        adb_host->adb_guest = NULL;
        adb_guest->callbacks->on_disconnect(adb_guest->opaque, adb_guest);
        adb_guest->adb_host = NULL;
    } else {
        D("Disconnecting ADB host %p(so=%d)", adb_host, adb_host->host_so);
    }

    /* Destroy the host. */
    alist_remove(&adb_host->list_entry);
    _adb_host_free(adb_host);

    /* Remove the guest from the list. */
    if (adb_guest != NULL) {
        alist_remove(&adb_guest->list_entry);
    }
}

/* Read I/O callback on ADB host socket. */
static void
_on_adb_host_read(AdbHost* adb_host)
{
    char buff[4096];

    /* Read data from the socket. */
    const int size = socket_recv(adb_host->host_so, buff, sizeof(buff));
    if (size < 0) {
        D("Error while reading from ADB host %p(so=%d). Error: %s",
          adb_host, adb_host->host_so, strerror(errno));
    } else if (size == 0) {
        /* This is a "disconnect" condition. */
        _on_adb_host_disconnected(adb_host);
    } else {
        D("%s %d bytes received from ADB host %p(so=%d): %s",
           adb_host->adb_guest ? "Transfer" : "Pend", size, adb_host,
           adb_host->host_so, QB(buff, size));

        /* Lets see if there is an ADB guest associated with this host, and it
         * is ready to receive host data. */
        AdbGuest* const adb_guest = adb_host->adb_guest;
        if (adb_guest != NULL && adb_guest->is_connected) {
            /* Channel the data through... */
            adb_guest->callbacks->on_read(adb_guest->opaque, adb_guest, buff, size);
        } else {
            /* Pend the data for the upcoming guest connection. */
            if (adb_host->pending_data == NULL) {
                adb_host->pending_data = malloc(size);
            } else {
                adb_host->pending_data = realloc(adb_host->pending_data,
                                                 adb_host->pending_data_size + size);
            }
            if (adb_host->pending_data != NULL) {
                memcpy(adb_host->pending_data + adb_host->pending_data_size,
                       buff, size);
                adb_host->pending_data_size += size;
            } else {
                D("Unable to (re)allocate %d bytes for pending ADB host data",
                  adb_host->pending_data_size + size);
            }
        }
    }
}

/* Write I/O callback on ADB host socket. */
static void
_on_adb_host_write(AdbHost* adb_host)
{
    while (adb_host->pending_send_data_size && adb_host->pending_send_buffer != NULL) {
        const int sent = socket_send(adb_host->host_so,
                                     adb_host->pending_send_buffer,
                                     adb_host->pending_send_data_size);
        if (sent < 0) {
            if (errno == EWOULDBLOCK) {
                /* Try again later. */
                return;
            } else {
                D("Unable to send pending data to the ADB host: %s",
                   strerror(errno));
                free(adb_host->pending_send_buffer);
                adb_host->pending_send_buffer = NULL;
                adb_host->pending_send_buffer_size = 0;
                adb_host->pending_send_data_size = 0;
                break;
            }
        } else if (sent == 0) {
            /* Disconnect condition. */
            free(adb_host->pending_send_buffer);
            adb_host->pending_send_buffer = NULL;
            adb_host->pending_send_buffer_size = 0;
            adb_host->pending_send_data_size = 0;
            _on_adb_host_disconnected(adb_host);
            break;
        } else if (sent == adb_host->pending_send_data_size) {
            free(adb_host->pending_send_buffer);
            adb_host->pending_send_buffer = NULL;
            adb_host->pending_send_buffer_size = 0;
            adb_host->pending_send_data_size = 0;
        } else {
            adb_host->pending_send_data_size -= sent;
            memmove(adb_host->pending_send_buffer,
                    adb_host->pending_send_buffer + sent,
                    adb_host->pending_send_data_size);
            return;
        }
    }

    loopIo_dontWantWrite(adb_host->io);
}

/* I/O callback on ADB host socket. */
static void
_on_adb_host_io(void* opaque, int fd, unsigned events)
{
    AdbHost* const adb_host = (AdbHost*)opaque;
    assert(fd == adb_host->host_so);

    /* Dispatch I/O to read / write handlers. */
    if ((events & LOOP_IO_READ) != 0) {
        _on_adb_host_read(adb_host);
    }
    if ((events & LOOP_IO_WRITE) != 0) {
        _on_adb_host_write(adb_host);
    }
}

/********************************************************************************
 *                            ADB guest API
 *******************************************************************************/

/* Creates and initializes a new AdbGuest instance. */
static AdbGuest*
_adb_guest_new(AdbServer* adb_srv)
{
    AdbGuest* adb_guest;

    ANEW0(adb_guest);
    alist_init(&adb_guest->list_entry);
    adb_guest->adb_srv = adb_srv;

    return adb_guest;
}

/* Frees AdbGuest instance created with _adb_guest_new routine. */
static void
_adb_guest_free(AdbGuest* adb_guest)
{
    if (adb_guest != NULL) {
        /* At this poin the guest must not be in any of the lists. */
        assert(alist_is_empty(&adb_guest->list_entry));
        AFREE(adb_guest);
    }
}

/********************************************************************************
 *                            ADB server internals
 *******************************************************************************/

/* I/O callback on ADB server socket. */
static void
_on_server_socket_io(void* opaque, int fd, unsigned events)
{
    AdbHost* adb_host;
    AdbGuest* adb_guest;
    AdbServer* adb_srv = (AdbServer*)opaque;
    assert(adb_srv->so == fd);

    /* Since this is a server socket, we only expect a connection I/O here. */
    if ((events & LOOP_IO_READ) == 0) {
        D("Unexpected write I/O on ADB server socket");
        return;
    }

    /* Create AdbHost instance for the new host connection. */
    adb_host = _adb_host_new(adb_srv);

    /* Accept the connection. */
    adb_host->host_so = socket_accept(fd, &adb_srv->socket_address);
    if (adb_host->host_so < 0) {
        D("Unable to accept ADB connection: %s", strerror(errno));
        _adb_host_free(adb_host);
        return;
    }

    /* Prepare for I/O on the host connection socket. */
    loopIo_init(adb_host->io, adb_srv->looper, adb_host->host_so,
                _on_adb_host_io, adb_host);

    /* Lets see if there is an ADB guest waiting for a host connection. */
    adb_guest = (AdbGuest*)alist_remove_head(&adb_srv->pending_guests);
    if (adb_guest != NULL) {
        /* Tie up ADB host with the ADB guest. */
        alist_insert_tail(&adb_srv->adb_guests, &adb_guest->list_entry);
        alist_insert_tail(&adb_srv->adb_hosts, &adb_host->list_entry);
        _adb_connect(adb_host, adb_guest);
    } else {
        /* Pend this connection. */
        D("Pend ADB host %p(so=%d)", adb_host, adb_host->host_so);
        alist_insert_tail(&adb_srv->pending_hosts, &adb_host->list_entry);
    }

    /* Enable I/O on the host socket. */
    loopIo_wantRead(adb_host->io);
}

/********************************************************************************
 *                            ADB server API
 *******************************************************************************/
int
adb_server_init(int port)
{
    if (!_adb_server_initialized) {
        /* Initialize the descriptor. */
        memset(&_adb_server, 0, sizeof(_adb_server));
        alist_init(&_adb_server.adb_hosts);
        alist_init(&_adb_server.adb_guests);
        alist_init(&_adb_server.pending_hosts);
        alist_init(&_adb_server.pending_guests);
        _adb_server.port = port;

        /* Create looper for an async I/O on the server. */
        _adb_server.looper = looper_newCore();
        if (_adb_server.looper == NULL) {
            E("Unable to create I/O looper for ADB server");
            return -1;
        }

        /* Create loopback server socket for the ADB port. */
        sock_address_init_inet(&_adb_server.socket_address,
                               SOCK_ADDRESS_INET_LOOPBACK, port);
        _adb_server.so = socket_loopback_server(port, SOCKET_STREAM);
        if (_adb_server.so < 0) {
            E("Unable to create ADB server socket: %s", strerror(errno));
            return -1;
        }

        /* Prepare server socket for I/O */
        socket_set_nonblock(_adb_server.so);
        loopIo_init(_adb_server.io, _adb_server.looper, _adb_server.so,
                    _on_server_socket_io, &_adb_server);
        loopIo_wantRead(_adb_server.io);

        D("ADB server has been initialized for port %d. Socket: %d",
          port, _adb_server.so);

        _adb_server_initialized = 1;
    }

    return 0;
}

int
adb_server_is_initialized(void)
{
    return _adb_server_initialized;
}

void*
adb_server_register_guest(void* opaque, AdbGuestRoutines* callbacks)
{
    if (_adb_server_initialized) {
        AdbHost* adb_host;

        /* Create and initialize ADB guest descriptor. */
        AdbGuest* const adb_guest = _adb_guest_new(&_adb_server);
        adb_guest->opaque = opaque;
        adb_guest->callbacks = callbacks;

        /* Lets see if there is a pending ADB host for the new guest. */
        adb_host = (AdbHost*)alist_remove_head(&_adb_server.pending_hosts);
        if (adb_host != NULL) {
            /* Tie up ADB host with the ADB guest. */
            alist_insert_tail(&_adb_server.adb_guests, &adb_guest->list_entry);
            alist_insert_tail(&_adb_server.adb_hosts, &adb_host->list_entry);
            _adb_connect(adb_host, adb_guest);
        } else {
            /* Host is not available. Pend this guest. */
            D("Pend ADB guest %p(o=%p)", adb_guest, adb_guest->opaque);
            alist_insert_tail(&_adb_server.pending_guests, &adb_guest->list_entry);
        }

        return adb_guest;
    } else {
        D("%s is called on an uninitialized ADB server.", __FUNCTION__);
        return NULL;
    }
}

void
adb_server_complete_connection(void* opaque)
{
    AdbGuest* const adb_guest = (AdbGuest*)opaque;
    AdbHost* const adb_host = adb_guest->adb_host;

    /* Mark the guest as fully connected and ready for the host data. */
    adb_guest->is_connected = 1;

    /* Lets see if there is a host data pending transmission to the guest. */
    if (adb_host->pending_data != NULL && adb_host->pending_data_size != 0) {
        /* Send the pending data to the guest. */
        D("Pushing %d bytes of the pending ADB host data.",
          adb_host->pending_data_size);
        adb_guest->callbacks->on_read(adb_guest->opaque, adb_guest,
                                      adb_host->pending_data,
                                      adb_host->pending_data_size);
        free(adb_host->pending_data);
        adb_host->pending_data = NULL;
        adb_host->pending_data_size = 0;
    }
}

void
adb_server_on_guest_message(void* opaque, const uint8_t* msg, int msglen)
{
    AdbGuest* const adb_guest = (AdbGuest*)opaque;
    AdbHost* const adb_host = adb_guest->adb_host;

    if (adb_host != NULL) {
        D("Sending %d bytes to the ADB host: %s", msglen, QB(msg, msglen));

        /* Lets see if we can send the data immediatelly... */
        if (adb_host->pending_send_buffer == NULL) {
            /* There are no data that are pending to be sent to the host. Do the
             * direct send. */
            const int sent = socket_send(adb_host->host_so, msg, msglen);
            if (sent < 0) {
                if (errno == EWOULDBLOCK) {
                } else {
                    D("Unable to send data to ADB host: %s", strerror(errno));
                }
            } else if (sent == 0) {
                /* Disconnect condition. */
                _on_adb_host_disconnected(adb_host);
            } else if (sent < msglen) {
                /* Couldn't send everything. Schedule write via I/O callback. */
                _adb_host_append_message(adb_host, msg + sent, msglen - sent);
            }
        } else {
            /* There are data that are pending to be sent to the host. We need
             * to append new data to the end of the pending data buffer. */
            _adb_host_append_message(adb_host, msg, msglen);
        }
    } else {
        D("ADB host is disconneted and can't accept %d bytes in %s",
          msglen, QB(msg, msglen));
    }
}

void
adb_server_on_guest_closed(void* opaque)
{
    AdbGuest* const adb_guest = (AdbGuest*)opaque;
    AdbHost* const adb_host = adb_guest->adb_host;

    /* Remove the guest from the list */
    if (!alist_is_empty(&adb_guest->list_entry)) {
        alist_remove(&adb_guest->list_entry);
    }

    /* Disassociate the host. */
    if (adb_host != NULL) {
        if (!alist_is_empty(&adb_host->list_entry)) {
            alist_remove(&adb_host->list_entry);
        }
        _adb_host_free(adb_host);
    }
    _adb_guest_free(adb_guest);
}
