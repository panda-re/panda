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

#ifndef ANDROID_ADB_SERVER_H_
#define ANDROID_ADB_SERVER_H_

/*
 * Encapsulates a socket server that is bound to ADB port, and bridges ADB host
 * connections and data to ADB daemon running inside the guest.
 */

/* Callback to be invoked wheh host ADB gets connected with the guest ADB.
 * Param:
 *  opaque - An opaque pointer associated with the guest. This pointer contains
 *      the 'opaque' parameter that was passed to the adb_server_register_guest
 *      routine.
 *  connection - An opaque pointer defining the connection between the host and
 *      the guest ADBs. This pointer must be used for further operations on the
 *      host <-> guest connection.
 */
typedef void (*adbguest_connect)(void* opaque, void* connection);

/* Callback to be invoked wheh the host ADB sends data to the guest ADB.
 * Param:
 *  opaque - An opaque pointer associated with the guest. This pointer contains
 *      the 'opaque' parameter that was passed to the adb_server_register_guest
 *      routine.
 *  connection - An opaque pointer defining the connection between the host and
 *      the guest ADB. This pointer must be used for further operations on the
 *      host <-> guest connection.
 *  buff, size - Buffer that has ben sent by the host.
 */
typedef void (*adbguest_read)(void* opaque,
                              void* connection,
                              const void* buff,
                              int size);

/* Callback to be invoked wheh the host ADB gets disconnected.
 * Param:
 *  opaque - An opaque pointer associated with the guest. This pointer contains
 *      the 'opaque' parameter that was passed to the adb_server_register_guest
 *      routine.
 *  connection - An opaque pointer defining the connection between the host and
 *      the guest ADB. This pointer must be used for further operations on the
 *      host <-> guest connection.
 */
typedef void (*adbguest_disconnect)(void* opaque, void* connection);

/* Defines a set of callbacks for a guest ADB. */
typedef struct AdbGuestRoutines AdbGuestRoutines;
struct AdbGuestRoutines {
    /* Callback to invoke when ADB host is connected. */
    adbguest_connect     on_connected;
    /* Callback to invoke when ADB host is disconnected. */
    adbguest_disconnect  on_disconnect;
    /* Callback to invoke when ADB host sends data. */
    adbguest_read        on_read;
};

/* Initializes ADB server.
 * Param:
 *  port - socket port that is assigned for communication with the ADB host. This
 *      is 'base port' + 1.
 * Return:
 *  0 on success, or != 0 on failure.
 */
extern int adb_server_init(int port);

/* Checks if ADB server has been initialized. */
extern int adb_server_is_initialized(void);

/* Registers ADB guest with the ADB server.
 * There can be two cases here, as far as connection with the host is concerned:
 *  - There is no host connection to immediately associate the guest with. In
 *    this case the guest will be registered as "pending connection", and routine
 *    will return.
 *  - There is a pending host connection to associate with the new guest. In this
 *    case the association will be made in this routine, and 'adbguest_connect'
 *    callback will be called before this routine returns.
 * Param:
 *  opaque Opaque pointer associated with the guest. This pointer will be passed
 *      back to thee guest API in callback routines.
 *  callbacks Contains callback routines for the registering guest.
 * Return:
 *  An opaque pointer associated with the ADB guest on success, or NULL on
 *  failure. The pointer returned from this routine must be passed into ADB
 *  server API called from the guest.
 */
extern void* adb_server_register_guest(void* opaque, AdbGuestRoutines* callbacks);

/* Completes connection with the guest.
 * This routine is called by the guest when it receives a 'start' request from
 * ADB guest. This request tells the system that ADB daemon running inside the
 * guest is ready to receive data.
 * Param:
 *  opaque - An opaque pointer returned from adb_server_register_guest.
 */
extern void adb_server_complete_connection(void* opaque);

/* Handles data received from the guest.
 * Param:
 *  opaque - An opaque pointer returned from adb_server_register_guest.
 * data, size - Data buffer received from the guest.
 */
extern void adb_server_on_guest_message(void* opaque,
                                        const uint8_t* data,
                                        int size);

/* Notifies the ADB server that the guest has closed its connection.
 * Param:
 *  opaque - An opaque pointer returned from adb_server_register_guest.
 */
extern void adb_server_on_guest_closed(void* opaque);

#endif  /* ANDROID_ADB_SERVER_H_ */
