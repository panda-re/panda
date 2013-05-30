/*
 * Copyright (C) 2010 The Android Open Source Project
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
#ifndef ANDROID_ASYNC_UTILS_H
#define ANDROID_ASYNC_UTILS_H

#include "android/looper.h"
#include "sockets.h"

/* A set of useful data types to perform asynchronous operations.
 *
 * IMPORTANT NOTE:
 *    In case of network disconnection, read() and write() just return 0
 *    the first time they are called. As a convenience, these functions
 *    will return ASYNC_ERROR and set 'errno' to ECONNRESET instead.
 */
typedef enum {
    ASYNC_COMPLETE = 0,   /* asynchronous operation completed */
    ASYNC_ERROR,          /* an error occurred, look at errno */
    ASYNC_NEED_MORE       /* more data is needed, try again later */
} AsyncStatus;

/**************************************************************************
 **************************************************************************
 *****
 *****  A S Y N C   R E A D E R
 *****
 *****/

/* An AsyncReader makes it easier to read a given number of bytes into
 * a target buffer asynchronously. Usage is the following:
 *
 * 1/ setup the reader with asyncReader_init(ar, buffer, buffsize,io);
 * 2/ call asyncReader_read(ar, io), where 'io' is a LoopIo whenever
 *    you can receive data, i.e. just after the init() or in your
 *    own callback.
 */
typedef struct {
    uint8_t*  buffer;
    size_t    buffsize;
    size_t    pos;
    LoopIo*   io;
} AsyncReader;

/* Setup an ASyncReader, by giving the address of the read buffer,
 * and the number of bytes we want to read.
 *
 * This also calls loopIo_wantRead(io) for you.
 */
void asyncReader_init(AsyncReader* ar,
                      void*        buffer,
                      size_t       buffsize,
                      LoopIo*      io);

/* Try to read data from 'io' and return the state of the read operation.
 *
 * Returns:
 *    ASYNC_COMPLETE: If the read operation was complete. This will also
 *                    call loopIo_dontWantRead(io) for you.
 *
 *    ASYNC_ERROR: If an error occured (see errno). The error will be
 *                 ECONNRESET in case of disconnection.
 *
 *    ASYNC_NEED_MORE: If there was not enough incoming data to complete
 *                     the read (or if 'events' doesn't contain LOOP_IO_READ).
 */
AsyncStatus  asyncReader_read(AsyncReader*  ar);

/**************************************************************************
 **************************************************************************
 *****
 *****  A S Y N C   W R I T E R
 *****
 *****/

/* An AsyncWriter is the counterpart of an AsyncReader, but for writing
 * data to a file descriptor asynchronously.
 */
typedef struct {
    const uint8_t* buffer;
    size_t         buffsize;
    size_t         pos;
    LoopIo*        io;
} AsyncWriter;

/* Setup an ASyncWriter, by giving the address of the write buffer,
 * and the number of bytes we want to write.
 *
 * This also calls loopIo_wantWrite(io) for you.
 */
void asyncWriter_init(AsyncWriter*  aw,
                      const void*   buffer,
                      size_t        buffsize,
                      LoopIo*       io);

/* Try to write data to 'io' and return the state of the write operation.
 *
 * Returns:
 *    ASYNC_COMPLETE: If the write operation was complete. This will also
 *                    call loopIo_dontWantWrite(io) for you.
 *
 *    ASYNC_ERROR: If an error occured (see errno). The error will be
 *                 ECONNRESET in case of disconnection.
 *
 *    ASYNC_NEED_MORE: If not all bytes could be sent yet (or if 'events'
 *                     doesn't contain LOOP_IO_WRITE).
 */
AsyncStatus asyncWriter_write(AsyncWriter* aw);


/**************************************************************************
 **************************************************************************
 *****
 *****  A S Y N C   L I N E   R E A D E R
 *****
 *****/

/* An AsyncLineReader allows you to read one line of text asynchronously.
 * The biggest difference with AsyncReader is that you don't know the line
 * size in advance, so the object will read data byte-by-byte until it
 * encounters a '\n'.
 */
typedef struct {
    uint8_t*  buffer;
    size_t    buffsize;
    size_t    pos;
    LoopIo*   io;
    char      eol;
} AsyncLineReader;

/* Setup an AsyncLineReader to read at most 'buffsize' characters (bytes)
 * into 'buffer'. The reader will stop when it finds a '\n' which will be
 * part of the buffer by default.
 *
 * NOTE: buffsize must be > 0. If not, asyncLineReader_getLine will return
 *       ASYNC_ERROR with errno == ENOMEM.
 *
 *        buffsize must also sufficiently big to hold the final '\n'.
 *
 * Also calls loopIo_wantRead(io) for you.
 */
void asyncLineReader_init(AsyncLineReader* alr,
                          void*            buffer,
                          size_t           buffsize,
                          LoopIo*          io);

/* Sets line terminator character for the reader.
 * By default, asyncLineReader_init will set EOL to be '\n'. Sometimes it's more
 * convenient to have '\0' as line terminator, so "line" reader easily becomes
 * a "string" reader.
 */
AINLINED void
asyncLineReader_setEOL(AsyncLineReader* alr, char eol)
{
    alr->eol = eol;
}

/* Try to read line characters from 'io'.
 * Returns:
 *    ASYNC_COMPLETE: An end-of-line was detected, call asyncLineReader_getLine
 *                    to extract the line content.
 *
 *    ASYNC_ERROR: An error occured. Note that in case of disconnection,
 *                 errno will be set to ECONNRESET, but you should be able
 *                 to call asyncLineReader_getLine to read the partial line
 *                 that was read.
 *
 *                 In case of overflow, errno will be set to ENOMEM.
 *
 *    ASYNC_NEED_MORE: If there was not enough incoming data (or events
 *                     does not contain LOOP_IO_READ).
 */
AsyncStatus asyncLineReader_read(AsyncLineReader* alr);

/* Return a pointer to the NON-ZERO-TERMINATED line characters, if any.
 * If 'pLength" is not NULL, the function sets '*pLength' to the length
 * in bytes of the line.
 *
 * Returns:
 *    NULL if 'buffsize' was initially 0, otherwise, a pointer to 'buffer'
 *    as passed in asyncLineReader_setup().
 *
 *    NOTE: The data is *not* zero terminated, but its last character
 *           should be '\n' unless an error occured.
 */
const char* asyncLineReader_getLineRaw(AsyncLineReader* alr, int *pLength);

/* Return a pointer to the ZERO-TERMINATED line, with final '\n' or '\r\n'
 * stripped. This will be NULL in case of error though.
 */
const char* asyncLineReader_getLine(AsyncLineReader* alr);

/**************************************************************************
 **************************************************************************
 *****
 *****  A S Y N C   C O N N E C T O R
 *****
 *****/

/* Asynchronous connection to a socket
 */
typedef struct {
    int     error;
    int     state;
    LoopIo* io;
} AsyncConnector;

AsyncStatus
asyncConnector_init(AsyncConnector*    ac,
                    const SockAddress* address,
                    LoopIo*            io);

AsyncStatus
asyncConnector_run(AsyncConnector* ac);

/* Stops connection in progress.
 * Return:
 *  0 if connection in progress has been stopped, or -1 if no connection has been
 *  in progress.
 */
int
asyncConnector_stop(AsyncConnector* ac);

#endif /* ANDROID_ASYNC_UTILS_H */
