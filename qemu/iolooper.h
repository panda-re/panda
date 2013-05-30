#ifndef IOLOOPER_H
#define IOLOOPER_H

#include <stdint.h>

/* An IOLooper is an abstraction for select() */

typedef struct IoLooper  IoLooper;

IoLooper*  iolooper_new(void);
void       iolooper_free( IoLooper*  iol );
void       iolooper_reset( IoLooper*  iol );

void       iolooper_add_read( IoLooper*  iol, int  fd );
void       iolooper_add_write( IoLooper*  iol, int  fd );
void       iolooper_del_read( IoLooper*  iol, int  fd );
void       iolooper_del_write( IoLooper*  iol, int  fd );

enum {
    IOLOOPER_READ = (1<<0),
    IOLOOPER_WRITE = (1<<1),
};
void       iolooper_modify( IoLooper*  iol, int fd, int oldflags, int newflags);

int        iolooper_poll( IoLooper*  iol );
/* Wrapper around select()
 * Return:
 *  > 0 in case an I/O has occurred, or < 0 on error, or 0 on timeout with
 *  errno set to ETIMEDOUT.
 */
int        iolooper_wait( IoLooper*  iol, int64_t  duration );

int        iolooper_is_read( IoLooper*  iol, int  fd );
int        iolooper_is_write( IoLooper*  iol, int  fd );
/* Returns 1 if this IoLooper has one or more file descriptor to interact with */
int        iolooper_has_operations( IoLooper*  iol );
/* Gets current time in milliseconds.
 * Return:
 *  Number of milliseconds corresponded to the current time on success, or -1
 *  on failure.
 */
int64_t    iolooper_now(void);
/* Waits for an I/O to occur before specific absolute time.
 * This routine should be used (instead of iolooper_wait) in cases when multiple
 * sequential I/O should be completed within given time interval. For instance,
 * consider the scenario, when "server" does two sequential writes, and "client"
 * now has to read data transferred with these two distinct writes. It might be
 * wasteful to do two reads, each with the same (large) timeout. Instead, it
 * would be better to assign a deadline for both reads before the first read,
 * and call iolooper_wait_absoulte with the same deadline value:
 *  int64_t deadline = iolooper_now() + TIMEOUT;
 *  if (iolooper_wait_absoulte(iol, deadline)) {
 *      // Process first buffer.
 *      (iolooper_wait_absoulte(iol, deadline)) {
 *          // Process second read
 *      }
 *  }
 * Param:
 *  iol IoLooper instance for an I/O.
 *  deadline Deadline (absoulte time in milliseconds) before which an I/O should
 *      occur.
 * Return:
 *  Number of I/O descriptors set in iol, if an I/O has occurred, 0 if no I/O
 *  occurred before the deadline, or -1 on error.
 */
int iolooper_wait_absolute(IoLooper* iol, int64_t deadline);

#endif /* IOLOOPER_H */
