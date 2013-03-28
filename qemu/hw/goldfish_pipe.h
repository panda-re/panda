/* Copyright (C) 2011 The Android Open Source Project
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
#ifndef _HW_GOLDFISH_PIPE_H
#define _HW_GOLDFISH_PIPE_H

#include <stdint.h>
#include "hw/hw.h"

/* TECHNICAL NOTE:
 *
 * A goldfish pipe is a very fast communication channel between the guest
 * system and the emulator program.
 *
 * To open a new pipe to the emulator, a guest client will do the following:
 *
 *     fd = open("/dev/qemu_pipe", O_RDWR);
 *     char  invite[64];
 *     snprintf(invite, sizeof invite, "%s", pipeName);
 *     ret = write(fd, invite, strlen(invite));
 *
 *     if (ret < 0) {
 *         // something bad happened, see errno
 *     }
 *
 *     now read()/write() to communicate with <pipeName> service in the
 *     emulator.
 *
 * This header provides the interface used by pipe services in the emulator
 * to receive new client connection and deal with them.
 *
 *
 * 1/ Call goldfish_pipe_add_type() to register a new pipe service by name.
 *    This must provide a pointer to a series of functions that will be called
 *    during normal pipe operations.
 *
 * 2/ When a client connects to the service, the 'init' callback will be called
 *    to create a new service-specific client identifier (which must returned
 *    by the function).
 *
 * 3/ Call goldfish_pipe_close() to force the closure of a given pipe.
 *
 * 4/ Call goldfish_pipe_signal() to signal a change of state to the pipe.
 *
 */

/* Buffer descriptor for sendBuffers() and recvBuffers() callbacks */
typedef struct GoldfishPipeBuffer {
    uint8_t*  data;
    size_t    size;
} GoldfishPipeBuffer;

/* Pipe handler funcs */
typedef struct {
    /* Create new client connection, 'hwpipe' must be passed to other
     * goldfish_pipe_xxx functions, while the returned value will be passed
     * to other callbacks (e.g. close). 'pipeOpaque' is the value passed
     * to goldfish_pipe_add_type() when registering a given pipe service.
     */
    void*        (*init)( void* hwpipe, void* pipeOpaque, const char* args );

    /* Called when the guest kernel has finally closed a pipe connection.
     * This is the only place where you can release/free the client connection.
     * You should never invoke this callback directly. Call goldfish_pipe_close()
     * instead.
     */
    void         (*close)( void* pipe );

    /* Called when the guest is write()-ing to the pipe. Should return the
     * number of bytes transfered, 0 for EOF status, or a negative error
     * value otherwise, including PIPE_ERROR_AGAIN to indicate that the
     * emulator is not ready to receive data yet.
     */
    int          (*sendBuffers)( void* pipe, const GoldfishPipeBuffer*  buffers, int numBuffers );

    /* Same as sendBuffers when the guest is read()-ing from the pipe. */
    int          (*recvBuffers)( void* pipe, GoldfishPipeBuffer* buffers, int numBuffers );

    /* Called when guest wants to poll the read/write status for the pipe.
     * Should return a combination of PIPE_POLL_XXX flags.
     */
    unsigned     (*poll)( void* pipe );

    /* Called to signal that the guest wants to be woken when the set of
     * PIPE_WAKE_XXX bit-flags in 'flags' occur. When the condition occurs,
     * then the pipe implementation shall call goldfish_pipe_wake().
     */
    void         (*wakeOn)( void* opaque, int flags );

    /* Called to save the pipe's state to a QEMUFile, i.e. when saving
     * snapshots. This can be NULL to indicate that no state can be saved.
     * In this case, when the pipe is loaded, the emulator will automatically
     * force-close so the next operation the guest performs on it will return
     * a PIPE_ERROR_IO error code.
     */
    void         (*save)( void* pipe, QEMUFile* file );

    /* Called to load the sate of a pipe from a QEMUFile. This will always
     * correspond to the state of the pipe as saved by a previous call to
     * the 'save' method. Can be NULL to indicate that the pipe state cannot
     * be loaded. In this case, the emulator will automatically force-close
     * it.
     *
     * In case of success, this returns 0, and the new pipe object is returned
     * in '*ppipe'. In case of errno code is returned to indicate a failure.
     * 'hwpipe' and 'pipeOpaque' are the same arguments than those passed
     * to 'init'.
     */
    void*        (*load)( void* hwpipe, void* pipeOpaque, const char* args, QEMUFile* file);
} GoldfishPipeFuncs;

/* Register a new pipe handler type. 'pipeOpaque' is passed directly
 * to 'init() when a new pipe is connected to.
 */
extern void  goldfish_pipe_add_type(const char*               pipeName,
                                     void*                     pipeOpaque,
                                     const GoldfishPipeFuncs*  pipeFuncs );

/* This tells the guest system that we want to close the pipe and that
 * further attempts to read or write to it will fail. This will not
 * necessarily call the 'close' callback immediately though.
 *
 * This will also wake-up any blocked guest threads waiting for i/o.
 */
extern void goldfish_pipe_close( void* hwpipe );

/* Signal that the pipe can be woken up. 'flags' must be a combination of
 * PIPE_WAKE_READ and PIPE_WAKE_WRITE.
 */
extern void goldfish_pipe_wake( void* hwpipe, unsigned flags );

/* The following definitions must match those under:
 *
 *    $KERNEL/drivers/misc/qemupipe/qemu_pipe.c
 *
 * Where $KERNEL points to the android-goldfish-2.6.xx branch on:
 *
 *     android.git.kernel.org/kernel/qemu.git.
 */

/* pipe device registers */
#define PIPE_REG_COMMAND            0x00  /* write: value = command */
#define PIPE_REG_STATUS             0x04  /* read */
#define PIPE_REG_CHANNEL            0x08  /* read/write: channel id */
#define PIPE_REG_SIZE               0x0c  /* read/write: buffer size */
#define PIPE_REG_ADDRESS            0x10  /* write: physical address */
#define PIPE_REG_WAKES              0x14  /* read: wake flags */
/* read/write: parameter buffer address */
#define PIPE_REG_PARAMS_ADDR_LOW     0x18
#define PIPE_REG_PARAMS_ADDR_HIGH    0x1c
/* write: access with paremeter buffer */
#define PIPE_REG_ACCESS_PARAMS       0x20

/* list of commands for PIPE_REG_COMMAND */
#define PIPE_CMD_OPEN               1  /* open new channel */
#define PIPE_CMD_CLOSE              2  /* close channel (from guest) */
#define PIPE_CMD_POLL               3  /* poll read/write status */

/* List of bitflags returned in status of CMD_POLL command */
#define PIPE_POLL_IN   (1 << 0)
#define PIPE_POLL_OUT  (1 << 1)
#define PIPE_POLL_HUP  (1 << 2)

/* The following commands are related to write operations */
#define PIPE_CMD_WRITE_BUFFER       4  /* send a user buffer to the emulator */
#define PIPE_CMD_WAKE_ON_WRITE      5  /* tell the emulator to wake us when writing is possible */

/* The following commands are related to read operations, they must be
 * listed in the same order than the corresponding write ones, since we
 * will use (CMD_READ_BUFFER - CMD_WRITE_BUFFER) as a special offset
 * in qemu_pipe_read_write() below.
 */
#define PIPE_CMD_READ_BUFFER        6  /* receive a page-contained buffer from the emulator */
#define PIPE_CMD_WAKE_ON_READ       7  /* tell the emulator to wake us when reading is possible */

/* Possible status values used to signal errors - see qemu_pipe_error_convert */
#define PIPE_ERROR_INVAL       -1
#define PIPE_ERROR_AGAIN       -2
#define PIPE_ERROR_NOMEM       -3
#define PIPE_ERROR_IO          -4

/* Bit-flags used to signal events from the emulator */
#define PIPE_WAKE_CLOSED       (1 << 0)  /* emulator closed pipe */
#define PIPE_WAKE_READ         (1 << 1)  /* pipe can now be read from */
#define PIPE_WAKE_WRITE        (1 << 2)  /* pipe can now be written to */

void pipe_dev_init(void);

struct access_params{
    uint32_t channel;
    uint32_t size;
    uint32_t address;
    uint32_t cmd;
    uint32_t result;
    /* reserved for future extension */
    uint32_t flags;
};

#endif /* _HW_GOLDFISH_PIPE_H */
