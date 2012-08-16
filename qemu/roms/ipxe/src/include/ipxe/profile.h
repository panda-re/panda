#ifndef _IPXE_PROFILE_H
#define _IPXE_PROFILE_H

/** @file
 *
 * Profiling
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>

/**
 * A data structure for storing profiling information
 */
union profiler {
	/** Timestamp (in CPU-specific "ticks") */
	uint64_t timestamp;
	/** Registers returned by rdtsc.
	 *
	 * This part should really be architecture-specific code.
	 */
	struct {
		uint32_t eax;
		uint32_t edx;
	} rdtsc;
};

/**
 * Static per-object profiler, for use with simple_profile()
 */
static union profiler simple_profiler;

/**
 * Perform profiling
 *
 * @v profiler		Profiler data structure
 * @ret delta		Elapsed ticks since last call to profile().
 *
 * Call profile() both before and after the code you wish to measure.
 * The "after" call will return the measurement.  For example:
 *
 * @code
 *
 *     profile ( &profiler );
 *     ... do something here ...
 *     printf ( "It took %ld ticks to execute\n", profile ( &profiler ) );
 *
 * @endcode
 */
static inline __attribute__ (( always_inline )) unsigned long
profile ( union profiler *profiler ) {
	uint64_t last_timestamp = profiler->timestamp;

	__asm__ __volatile__ ( "rdtsc" :
			       "=a" ( profiler->rdtsc.eax ),
			       "=d" ( profiler->rdtsc.edx ) );
	return ( profiler->timestamp - last_timestamp );
}

/**
 * Perform profiling
 *
 * @ret delta		Elapsed ticks since last call to profile().
 *
 * When you only need one profiler, you can avoid the hassle of
 * creating your own @c profiler data structure by using
 * simple_profile() instead.
 *
 * simple_profile() is equivalent to profile(&simple_profiler), where
 * @c simple_profiler is a @c profiler data structure that is static
 * to each object which includes @c profile.h.
 */
static inline __attribute__ (( always_inline )) unsigned long
simple_profile ( void ) {
	return profile ( &simple_profiler );
}

#endif /* _IPXE_PROFILE_H */
