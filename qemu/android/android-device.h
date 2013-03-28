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

#ifndef ANDROID_ANDROID_DEVICE_H_
#define ANDROID_ANDROID_DEVICE_H_

/*
 * Encapsulates an exchange protocol between the emulator, and an Android device
 * that is connected to the host via USB. The communication is established over
 * a TCP port forwarding, enabled by ADB (always use 'adb -d forward ...' variant
 * of this command, so ADB will know to enable port forwarding on the connected
 * device, and not on the emulator's guest system).
 *
 * Exchange protocol contains two channel:
 *
 * - Query channel.
 * - Event channel.
 *
 * Both channels are implemented on top of TCP sockets that are connected to the
 * same port.
 *
 * I QUERY CHANNEL.
 * Query channel is intended to send queries to and receive responses from the
 * connected device. It is implemented on top of iolooper_xxx API (see iolooper.h)
 * because it must work outside of the main event loop. This is required to enable
 * proper initialization of components (such as sensors) that must be set up
 * before emulator enters the main loop.
 *
 * II EVENT CHANNEL.
 * Event channel is intended to listen on events sent from the device, and
 * asynchronously report them back to the client of this API by invoking an event
 * callback that was registered by the client. Event channel is implemented on
 * top of asyncXxx API (see android/async-utils.*). Note that using of asyncXxx
 * API limits the use of event channel to the time after the emulator has entered
 * its main event loop. The only exception is if event channel is connected from
 * android_device_connect_sync API, in which case iolooper_xxx API is used to
 * establish the connection. However, even in this case listening for events will
 * not be available until after the emulator enters its event loop, since event
 * listening always uses asyncXxx API.
 *
 * III. ESTABLISHING CONNECTION.
 * ADB port forwarding requires that the server socket is to be run on the device,
 * while emulator must use a client socket for communication. Thus, it's the
 * emulator that initiates the connection.
 *
 * There are two ways how emulator can initiate the connection:
 *
 * - Synchronous connection.
 * - Asynchronous connection.
 *
 * III.I SYNCHROUNOUS CONNECTION.
 * Synchronous connection is initiated via android_device_connect_sync API, and
 * completes synchronously.
 *
 * This API should be used when connection with the device is required at the time
 * of the call. For instance, when initializing sensor emulation, connection with
 * the device is required to properly set up the emulator before the guest system
 * starts, and before emulator enters its main event loop.
 *
 * III.II ASYNCHRONOUS CONNECTION.
 * Asynchronous connection is initiated via android_device_connect_async API. The
 * main difference with the synchronous connection is that this API will not fail
 * if connection is not immediately available. If connection is not available at
 * the time of the call, the API will schedule a retry (based on a timer), and
 * will continue reprying untill connection becomes available, or until an error
 * occurs that prevent further retries.
 *
 * This API should be used when ... Well, whenever appropriate. For instance,
 * sensor emulation will use this API to restore lost connection with the device.
 *
 * NOTE: Asynchronous connection will complete no sooner than the emulator enters
 * its main loop.
 *
 * IV EXCHANGE PROTOCOL.
 * Obviously, there must be some application running on the device, that implements
 * a socket server listening on the forwarded TCP port, and accepting the clients.
 *
 * IV.I Query vs. event channel.
 * The exchange protocol assumes, that when a channel is connected, it will
 * identify itself by sending a string containing channel type. Only after such
 * identification has been made the channel becomes available for use.
 *
 * IV.II Message format.
 * All data that is transferred in both directions over both channels are zero-
 * terminated strings.
 */

#include "qemu-common.h"
#include "android/async-utils.h"
#include "android/utils/debug.h"

/* TCP port reserved for sensor emulation. */
#define AD_SENSOR_PORT  1968

/* Definis infinite timeout. */
#define AD_INFINITE_WAIT    -1

/* Enumerates results of asynchronous data transfer.
 */
typedef enum ATResult {
    /* Data transfer has been completed. */
    ATR_SUCCESS,
    /* Socket got disconnected while data transfer has been in progress. */
    ATR_DISCONNECT,
    /* An I/O error has occured. 'errno' contains error value. */
    ATR_IO_ERROR,
} ATResult;

/* Android device descriptor. */
typedef struct AndroidDevice AndroidDevice;

/********************************************************************************
 *                       Callback declarations
 *******************************************************************************/

/* Callback routine that is invoked when android device is connected, or failed
 * to connect. As discussed above, this callback is called when both, query and
 * event channels have been connected. This callback is used only for asynchronous
 * connections.
 * Param:
 *  opaque - Opaque pointer that was passed to android_device_init API.
 *  ad - Androd device descriptor for the connection.
 *  failure - Zero indicates that connection with the device has been successfuly
 *      established. Non-zero vaule passed in this parameter indicates a failure,
 *      and contains 'errno'-reason for failure.
 */
typedef void (*device_connected_cb)(void* opaque, AndroidDevice* ad, int failure);

/* Callback routine that is invoked on an event received in the event channel.
 * NOTE: It's important to check 'errno' in this callback. If 'errno' is set to
 * ENOMEM, this signals that buffer passed to android_device_listen was too small
 * to contain the entire event message.
 * Param:
 *  opaque - Opaque pointer that was passed to android_device_init API.
 *  ad - Androd device descriptor for the connection.
 *  msg - Event message (a zero-terminated string) received from the device.
 *  msgsize - Event message size (including zero-terminator).
 */
typedef void (*event_cb)(void* opaque, AndroidDevice* ad, char* msg, int msgsize);

/* Callback routine that is invoked when an I/O failure occurs on a channel.
 * Note that this callback will not be invoked on connection failures.
 * Param:
 *  opaque - Opaque pointer that was passed to android_device_init API.
 *  ad - Android device instance
 *  failure - Contains 'errno' indicating the reason for failure.
 */
typedef void (*io_failure_cb)(void* opaque, AndroidDevice* ad, int failure);

/* Callback routine that is invoked when an asynchronous data send has been
 * completed.
 * Param:
 *  opaque - An opaque pointer associated with the data.
 *  res - Result of data transfer.
 *  data, size - Transferred data buffer.
 *  sent - Number of sent bytes.
 */
typedef void (*async_send_cb)(void* opaque,
                              ATResult res,
                              void* data,
                              int size,
                              int sent);

/********************************************************************************
 *                       Android Device API.
 *******************************************************************************/

/* Initializes android device descriptor.
 * Param:
 *  opaque - An opaque pointer to associate with the descriptor. This pointer
 *      will be passed to all callbacks (see above) that were invoked by the
 *      initializing android device instance.
 *  port - TCP port to use for connection.
 *  on_io_failure - Callback to invoke when an I/O failure occurs on a channel
 *      used by the initializing android device instance. Can be NULL.
 * Return:
 *  Initialized android device descriptor on success, or NULL on failure.
 */
extern AndroidDevice* android_device_init(void* opaque,
                                          int port,
                                          io_failure_cb on_io_failure);

/* Disconnects and destroys android device descriptor.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *      Note that memory allocated for this descriptor will be freed in this
 *      routine.
 */
extern void android_device_destroy(AndroidDevice* ad);

/* Synchronously connects to the device. See notes above for more details.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *  to - Milliseconds to wait for connection to be established.
 * Return:
 *  Zero on success, or non-zero value on failure with 'errno' properly set.
 */
extern int android_device_connect_sync(AndroidDevice* ad, int to);

/* Asynchronously connects to the device. See notes above for more details.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *  on_connected - Callback to invoke when connection is completed (i,e, both,
 *      event, and query channels have been connected). This parameter can be
 *      NULL. Note that connection errors will be also reported through this
 *      callback. Also note that this callback will be invoked even if this
 *      routine returns with a failure.
 * Return:
 *  Zero on success, or non-zero value on failure with 'errno' properly set.
 */
extern int android_device_connect_async(AndroidDevice* ad,
                                        device_connected_cb on_connected);

/* Disconnects from the android device.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 */
extern void android_device_disconnect(AndroidDevice* ad);

/* Queries the device via query channel.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *  query - Zero-terminated query string.
 *  buff, buffsize - Buffer where to receive the response to the query.
 *  to - Milliseconds to wait for the entire query to complete.
 * Return:
 *  Zero on success, or non-zero value on failure with 'errno' properly set:
 *      - 0 Indicates that the server has failed the query.
 *      - Anything else indicates an I/O error.
 */
extern int android_device_query(AndroidDevice* ad,
                                const char* query,
                                char* buff,
                                size_t buffsize,
                                int to);

/* Starts a query that may require more than one buffer transfer.
 * This routine allows to initiate a query that may require more than one call to
 * send_data, or may have a format that differs from the usual (a zero-terminated
 * string). For instance, sending a BLOB data should use this routine to start a
 * a query, then use android_device_send_query_data to transfer the data, and
 * then call android_device_complete_query to obtain the response.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *  query - Zero-terminated query string.
 *  to - Milliseconds to wait for the entire query to complete.
 * Return:
 *  Zero on success, or non-zero value on failure with 'errno' properly set:
 *      - 0 Indicates that the server has failed the query.
 *      - Anything else indicates an I/O error.
 */
extern int android_device_start_query(AndroidDevice* ad,
                                      const char* query,
                                      int to);

/* Sends data block for a query started with android_device_start_query
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *  data, size - Data to transfer.
 * Return:
 *  Number of bytes transferred on success, or -1 on failure with errno
 *  containing the reason for failure.
 */
extern int android_device_send_query_data(AndroidDevice* ad,
                                          const void* data,
                                          int size);

/* Completes a query started with android_device_start_query, and receives the
 * query response.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *  buff, buffsize - Buffer where to receive the response to the query.
 * Return:
 *  Zero on success, or non-zero value on failure with 'errno' properly set.
 */
extern int android_device_complete_query(AndroidDevice* ad, char* buff, size_t buffsize);

/* Start listening on the event channel.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *  buff, buffsize - Buffer where to receive the event message.
 *  on_event - Callback to invoke on event. Note that this callback will be
 *      invoked even if this routine returns with a failure.
 * Return:
 *  Zero on success, or non-zero value on failure with 'errno' properly set.
 */
extern int android_device_listen(AndroidDevice* ad,
                                 char* buff,
                                 int buffsize,
                                 event_cb on_event);

/* Asynchronously sends data to the android device.
 * Param:
 *  ad - Android device descriptor, returned from android_device_init API.
 *  data, size - Buffer containing data to send.
 *  free_on_close - A boolean flag indicating whether the data buffer should be
 *      freed upon data transfer completion.
 *  cb - Callback to invoke when data transfer is completed.
 *  opaque - An opaque pointer to pass to the transfer completion callback.
 */
extern int android_device_send_async(AndroidDevice* ad,
                                     void* data,
                                     int size,
                                     int free_on_close,
                                     async_send_cb cb,
                                     void* opaque);

#endif  /* ANDROID_ANDROID_DEVICE_H_ */
