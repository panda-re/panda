#ifndef CONFIG_CONSOLE_H
#define CONFIG_CONSOLE_H

/** @file
 *
 * Console configuration
 *
 * These options specify the console types that Etherboot will use for
 * interaction with the user.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <config/defaults.h>

//#define	CONSOLE_PCBIOS		/* Default BIOS console */
//#define	CONSOLE_SERIAL		/* Serial port */
//#define	CONSOLE_DIRECT_VGA	/* Direct access to VGA card */
//#define	CONSOLE_BTEXT		/* Who knows what this does? */
//#define	CONSOLE_PC_KBD		/* Direct access to PC keyboard */
//#define	CONSOLE_SYSLOG		/* Syslog console */

#define	KEYBOARD_MAP	us

#include <config/local/console.h>

#endif /* CONFIG_CONSOLE_H */
