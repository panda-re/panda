/**************************************************************************
iPXE -  Network Bootstrap Program

Literature dealing with the network protocols:
	ARP - RFC826
	RARP - RFC903
	UDP - RFC768
	BOOTP - RFC951, RFC2132 (vendor extensions)
	DHCP - RFC2131, RFC2132 (options)
	TFTP - RFC1350, RFC2347 (options), RFC2348 (blocksize), RFC2349 (tsize)
	RPC - RFC1831, RFC1832 (XDR), RFC1833 (rpcbind/portmapper)

**************************************************************************/

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdio.h>
#include <stdlib.h>
#include <ipxe/init.h>
#include <ipxe/features.h>
#include <ipxe/shell.h>
#include <ipxe/image.h>
#include <ipxe/keys.h>
#include <usr/prompt.h>
#include <usr/autoboot.h>
#include <config/general.h>

#define NORMAL	"\033[0m"
#define BOLD	"\033[1m"
#define CYAN	"\033[36m"

/** The "scriptlet" setting */
struct setting scriptlet_setting __setting ( SETTING_MISC ) = {
	.name = "scriptlet",
	.description = "Boot scriptlet",
	.tag = DHCP_EB_SCRIPTLET,
	.type = &setting_type_string,
};

/**
 * Prompt for shell entry
 *
 * @ret	enter_shell		User wants to enter shell
 */
static int shell_banner ( void ) {

	/* Skip prompt if timeout is zero */
	if ( BANNER_TIMEOUT <= 0 )
		return 0;

	return ( prompt ( "\nPress Ctrl-B for the iPXE command line...",
			  ( BANNER_TIMEOUT * 100 ), CTRL_B ) == 0 );
}

/**
 * Main entry point
 *
 * @ret rc		Return status code
 */
__asmcall int main ( void ) {
	struct feature *feature;
	struct image *image;
	char *scriptlet;

	/* Some devices take an unreasonably long time to initialise */
	printf ( PRODUCT_SHORT_NAME " initialising devices..." );
	initialise();
	startup();
	printf ( "ok\n" );

	/*
	 * Print welcome banner
	 *
	 *
	 * If you wish to brand this build of iPXE, please do so by
	 * defining the string PRODUCT_NAME in config/general.h.
	 *
	 * While nothing in the GPL prevents you from removing all
	 * references to iPXE or http://ipxe.org, we prefer you not to
	 * do so.
	 *
	 */
	printf ( NORMAL "\n\n" PRODUCT_NAME "\n" BOLD "iPXE " VERSION
		 NORMAL " -- Open Source Network Boot Firmware -- "
		 CYAN "http://ipxe.org" NORMAL "\n"
		 "Features:" );
	for_each_table_entry ( feature, FEATURES )
		printf ( " %s", feature->name );
	printf ( "\n" );

	/* Boot system */
	if ( ( image = first_image() ) != NULL ) {
		/* We have an embedded image; execute it */
		image_exec ( image );
	} else if ( shell_banner() ) {
		/* User wants shell; just give them a shell */
		shell();
	} else {
		fetch_string_setting_copy ( NULL, &scriptlet_setting,
					    &scriptlet );
		if ( scriptlet ) {
			/* User has defined a scriptlet; execute it */
			system ( scriptlet );
			free ( scriptlet );
		} else {
			/* Try booting.  If booting fails, offer the
			 * user another chance to enter the shell.
			 */
			autoboot();
			if ( shell_banner() )
				shell();
		}
	}

	shutdown_exit();

	return 0;
}
