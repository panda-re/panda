/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * Syslog protocol
 *
 */

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/tcpip.h>
#include <ipxe/dhcp.h>
#include <ipxe/settings.h>
#include <ipxe/console.h>
#include <ipxe/ansiesc.h>
#include <ipxe/syslog.h>

/** The syslog server */
static struct sockaddr_tcpip logserver = {
	.st_port = htons ( SYSLOG_PORT ),
};

/** Syslog UDP interface operations */
static struct interface_operation syslogger_operations[] = {};

/** Syslog UDP interface descriptor */
static struct interface_descriptor syslogger_desc =
	INTF_DESC_PURE ( syslogger_operations );

/** The syslog UDP interface */
static struct interface syslogger = INTF_INIT ( syslogger_desc );

/******************************************************************************
 *
 * Console driver
 *
 ******************************************************************************
 */

/** Syslog line buffer */
static char syslog_buffer[SYSLOG_BUFSIZE];

/** Index into syslog line buffer */
static unsigned int syslog_idx;

/** Syslog recursion marker */
static int syslog_entered;

/** Syslog ANSI escape sequence handlers */
static struct ansiesc_handler syslog_ansiesc_handlers[] = {
	{ 0, NULL }
};

/** Syslog ANSI escape sequence context */
static struct ansiesc_context syslog_ansiesc_ctx = {
	.handlers = syslog_ansiesc_handlers,
};

/**
 * Print a character to syslog console
 *
 * @v character		Character to be printed
 */
static void syslog_putchar ( int character ) {
	int rc;

	/* Do nothing if we have no log server */
	if ( ! logserver.st_family )
		return;

	/* Ignore if we are already mid-logging */
	if ( syslog_entered )
		return;

	/* Strip ANSI escape sequences */
	character = ansiesc_process ( &syslog_ansiesc_ctx, character );
	if ( character < 0 )
		return;

	/* Ignore carriage return */
	if ( character == '\r' )
		return;

	/* Treat newline as a terminator */
	if ( character == '\n' )
		character = 0;

	/* Add character to buffer */
	syslog_buffer[syslog_idx++] = character;

	/* Do nothing more unless we reach end-of-line (or end-of-buffer) */
	if ( ( character != 0 ) &&
	     ( syslog_idx < ( sizeof ( syslog_buffer ) - 1 /* NUL */ ) ) ) {
		return;
	}

	/* Reset to start of buffer */
	syslog_idx = 0;

	/* Guard against re-entry */
	syslog_entered = 1;

	/* Send log message */
	if ( ( rc = xfer_printf ( &syslogger, "<%d>ipxe: %s",
				  SYSLOG_PRIORITY ( SYSLOG_FACILITY,
						    SYSLOG_SEVERITY ),
				  syslog_buffer ) ) != 0 ) {
		DBG ( "SYSLOG could not send log message: %s\n",
		      strerror ( rc ) );
	}

	/* Clear re-entry flag */
	syslog_entered = 0;
}

/** Syslog console driver */
struct console_driver syslog_console __console_driver = {
	.putchar = syslog_putchar,
};

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/** Syslog server setting */
struct setting syslog_setting __setting ( SETTING_MISC ) = {
	.name = "syslog",
	.description = "Syslog server",
	.tag = DHCP_LOG_SERVERS,
	.type = &setting_type_ipv4,
};

/**
 * Apply syslog settings
 *
 * @ret rc		Return status code
 */
static int apply_syslog_settings ( void ) {
	struct sockaddr_in *sin_logserver =
		( struct sockaddr_in * ) &logserver;
	struct in_addr old_addr;
	int len;
	int rc;

	/* Fetch log server */
	old_addr.s_addr = sin_logserver->sin_addr.s_addr;
	logserver.st_family = 0;
	if ( ( len = fetch_ipv4_setting ( NULL, &syslog_setting,
					  &sin_logserver->sin_addr ) ) >= 0 ) {
		sin_logserver->sin_family = AF_INET;
	}

	/* Do nothing unless log server has changed */
	if ( sin_logserver->sin_addr.s_addr == old_addr.s_addr )
		return 0;

	/* Reset syslog connection */
	intf_restart ( &syslogger, 0 );

	/* Do nothing unless we have a log server */
	if ( ! logserver.st_family ) {
		DBG ( "SYSLOG has no log server\n" );
		return 0;
	}

	/* Connect to log server */
	if ( ( rc = xfer_open_socket ( &syslogger, SOCK_DGRAM,
				       ( ( struct sockaddr * ) &logserver ),
				       NULL ) ) != 0 ) {
		DBG ( "SYSLOG cannot connect to log server: %s\n",
		      strerror ( rc ) );
		return rc;
	}
	DBG ( "SYSLOG using log server %s\n",
	      inet_ntoa ( sin_logserver->sin_addr ) );

	return 0;
}

/** Syslog settings applicator */
struct settings_applicator syslog_applicator __settings_applicator = {
	.apply = apply_syslog_settings,
};
