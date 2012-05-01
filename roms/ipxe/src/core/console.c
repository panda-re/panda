#include "stddef.h"
#include <ipxe/console.h>
#include <ipxe/process.h>
#include <ipxe/nap.h>

/** @file */

FILE_LICENCE ( GPL2_OR_LATER );

/**
 * Write a single character to each console device.
 *
 * @v character		Character to be written
 * @ret None		-
 * @err None		-
 *
 * The character is written out to all enabled console devices, using
 * each device's console_driver::putchar() method.
 *
 */
void putchar ( int character ) {
	struct console_driver *console;

	/* Automatic LF -> CR,LF translation */
	if ( character == '\n' )
		putchar ( '\r' );

	for_each_table_entry ( console, CONSOLES ) {
		if ( ( ! console->disabled ) && console->putchar )
			console->putchar ( character );
	}
}

/**
 * Check to see if any input is available on any console.
 *
 * @v None		-
 * @ret console		Console device that has input available, if any.
 * @ret NULL		No console device has input available.
 * @err None		-
 *
 * All enabled console devices are checked once for available input
 * using each device's console_driver::iskey() method.  The first
 * console device that has available input will be returned, if any.
 *
 */
static struct console_driver * has_input ( void ) {
	struct console_driver *console;

	for_each_table_entry ( console, CONSOLES ) {
		if ( ( ! console->disabled ) && console->iskey ) {
			if ( console->iskey () )
				return console;
		}
	}
	return NULL;
}

/**
 * Read a single character from any console.
 *
 * @v None		-
 * @ret character	Character read from a console.
 * @err None		-
 *
 * A character will be read from the first enabled console device that
 * has input available using that console's console_driver::getchar()
 * method.  If no console has input available to be read, this method
 * will block.  To perform a non-blocking read, use something like
 *
 * @code
 *
 *   int key = iskey() ? getchar() : -1;
 *
 * @endcode
 *
 * The character read will not be echoed back to any console.
 *
 */
int getchar ( void ) {
	struct console_driver *console;
	int character;

	while ( 1 ) {
		console = has_input();
		if ( console && console->getchar ) {
			character = console->getchar ();
			break;
		}

		/* Doze for a while (until the next interrupt).  This works
		 * fine, because the keyboard is interrupt-driven, and the
		 * timer interrupt (approx. every 50msec) takes care of the
		 * serial port, which is read by polling.  This reduces the
		 * power dissipation of a modern CPU considerably, and also
		 * makes Etherboot waiting for user interaction waste a lot
		 * less CPU time in a VMware session.
		 */
		cpu_nap();

		/* Keep processing background tasks while we wait for
		 * input.
		 */
		step();
	}

	/* CR -> LF translation */
	if ( character == '\r' )
		character = '\n';

	return character;
}

/** Check for available input on any console.
 *
 * @v None		-
 * @ret True		Input is available on a console
 * @ret False		Input is not available on any console
 * @err None		-
 *
 * All enabled console devices are checked once for available input
 * using each device's console_driver::iskey() method.  If any console
 * device has input available, this call will return True.  If this
 * call returns True, you can then safely call getchar() without
 * blocking.
 *
 */
int iskey ( void ) {
	return has_input() ? 1 : 0;
}
