#include <ipxe/init.h>
#include <ipxe/serial.h>
#include <ipxe/console.h>

/** @file
 *
 * Serial console
 *
 */

struct console_driver serial_console __console_driver;

static void serial_console_init ( void ) {
	/* Serial driver initialization should already be done,
	 * time to enable the serial console. */
	serial_console.disabled = 0;
}

struct console_driver serial_console __console_driver = {
	.putchar = serial_putc,
	.getchar = serial_getc,
	.iskey = serial_ischar,
	.disabled = 1,
};

/**
 * Serial console initialisation function
 */
struct init_fn serial_console_init_fn __init_fn ( INIT_CONSOLE ) = {
	.initialise = serial_console_init,
};
