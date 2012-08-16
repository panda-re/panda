#ifndef _IPXE_PROCESS_H
#define _IPXE_PROCESS_H

/** @file
 *
 * Processes
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/list.h>
#include <ipxe/refcnt.h>
#include <ipxe/tables.h>

/** A process */
struct process {
	/** List of processes */
	struct list_head list;
	/**
	 * Single-step the process
	 *
	 * This method should execute a single step of the process.
	 * Returning from this method is isomorphic to yielding the
	 * CPU to another process.
	 */
	void ( * step ) ( struct process *process );
	/** Reference counter
	 *
	 * If this interface is not part of a reference-counted
	 * object, this field may be NULL.
	 */
	struct refcnt *refcnt;
};

extern void process_add ( struct process *process );
extern void process_del ( struct process *process );
extern void step ( void );

/**
 * Initialise process without adding to process list
 *
 * @v process		Process
 * @v step		Process' step() method
 */
static inline __attribute__ (( always_inline )) void
process_init_stopped ( struct process *process,
		       void ( * step ) ( struct process *process ),
		       struct refcnt *refcnt ) {
	INIT_LIST_HEAD ( &process->list );
	process->step = step;
	process->refcnt = refcnt;
}

/**
 * Initialise process and add to process list
 *
 * @v process		Process
 * @v step		Process' step() method
 */
static inline __attribute__ (( always_inline )) void
process_init ( struct process *process,
	       void ( * step ) ( struct process *process ),
	       struct refcnt *refcnt ) {
	process_init_stopped ( process, step, refcnt );
	process_add ( process );
}

/**
 * Check if process is running
 *
 * @v process		Process
 * @ret running		Process is running
 */
static inline __attribute__ (( always_inline )) int
process_running ( struct process *process ) {
	return ( ! list_empty ( &process->list ) );
}

/** Permanent process table */
#define PERMANENT_PROCESSES __table ( struct process, "processes" )

/**
 * Declare a permanent process
 *
 * Permanent processes will be automatically added to the process list
 * at initialisation time.
 */
#define __permanent_process __table_entry ( PERMANENT_PROCESSES, 01 )

#endif /* _IPXE_PROCESS_H */
