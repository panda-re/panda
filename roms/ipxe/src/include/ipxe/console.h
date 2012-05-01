#ifndef _IPXE_CONSOLE_H
#define _IPXE_CONSOLE_H

#include <ipxe/tables.h>

/** @file
 *
 * User interaction.
 *
 * Various console devices can be selected via the build options
 * CONSOLE_FIRMWARE, CONSOLE_SERIAL etc.  The console functions
 * putchar(), getchar() and iskey() delegate to the individual console
 * drivers.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

/**
 * A console driver
 *
 * Defines the functions that implement a particular console type.
 * Must be made part of the console drivers table by using
 * #__console_driver.
 *
 * @note Consoles that cannot be used before their initialisation
 * function has completed should set #disabled=1 initially.  This
 * allows other console devices to still be used to print out early
 * debugging messages.
 *
 */
struct console_driver {
	/** Console is disabled.
	 *
	 * The console's putchar(), getchar() and iskey() methods will
	 * not be called while #disabled==1.  Typically the console's
	 * initialisation functions will set #disabled=0 upon
	 * completion.
	 *
	 */
	int disabled;

	/** Write a character to the console.
	 *
	 * @v character		Character to be written
	 * @ret None		-
	 * @err None		-
	 *
	 */
	void ( *putchar ) ( int character );

	/** Read a character from the console.
	 *
	 * @v None		-
	 * @ret character	Character read
	 * @err None		-
	 *
	 * If no character is available to be read, this method will
	 * block.  The character read should not be echoed back to the
	 * console.
	 *
	 */
	int ( *getchar ) ( void );

	/** Check for available input.
	 *
	 * @v None		-
	 * @ret True		Input is available
	 * @ret False		Input is not available
	 * @err None		-
	 *
	 * This should return True if a subsequent call to getchar()
	 * will not block.
	 *
	 */
	int ( *iskey ) ( void );
};

/** Console driver table */
#define CONSOLES __table ( struct console_driver, "consoles" )

/**
 * Mark a <tt> struct console_driver </tt> as being part of the
 * console drivers table.
 *
 * Use as e.g.
 *
 * @code
 *
 *   struct console_driver my_console __console_driver = {
 *      .putchar = my_putchar,
 *	.getchar = my_getchar,
 *	.iskey = my_iskey,
 *   };
 *
 * @endcode
 *
 */
#define __console_driver __table_entry ( CONSOLES, 01 )

/* Function prototypes */

extern void putchar ( int character );
extern int getchar ( void );
extern int iskey ( void );
extern int getkey ( unsigned long timeout );

#endif /* _IPXE_CONSOLE_H */
