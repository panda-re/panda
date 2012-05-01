/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/netdevice.h>
#include <ipxe/dhcp.h>
#include <ipxe/settings.h>
#include <ipxe/image.h>
#include <ipxe/sanboot.h>
#include <ipxe/uri.h>
#include <ipxe/open.h>
#include <ipxe/init.h>
#include <usr/ifmgmt.h>
#include <usr/route.h>
#include <usr/dhcpmgmt.h>
#include <usr/imgmgmt.h>
#include <usr/autoboot.h>

/** @file
 *
 * Automatic booting
 *
 */

/* Disambiguate the various error causes */
#define ENOENT_BOOT __einfo_error ( EINFO_ENOENT_BOOT )
#define EINFO_ENOENT_BOOT \
	__einfo_uniqify ( EINFO_ENOENT, 0x01, "Nothing to boot" )

/**
 * Perform PXE menu boot when PXE stack is not available
 */
__weak int pxe_menu_boot ( struct net_device *netdev __unused ) {
	return -ENOTSUP;
}

/**
 * Identify the boot network device
 *
 * @ret netdev		Boot network device
 */
static struct net_device * find_boot_netdev ( void ) {
	return NULL;
}

/**
 * Parse next-server and filename into a URI
 *
 * @v next_server	Next-server address
 * @v filename		Filename
 * @ret uri		URI, or NULL on failure
 */
static struct uri * parse_next_server_and_filename ( struct in_addr next_server,
						     const char *filename ) {
	char buf[ 23 /* "tftp://xxx.xxx.xxx.xxx/" */ + strlen ( filename )
		  + 1 /* NUL */ ];
	struct uri *uri;

	/* Parse filename */
	uri = parse_uri ( filename );
	if ( ! uri )
		return NULL;

	/* Construct a tftp:// URI for the filename, if applicable.
	 * We can't just rely on the current working URI, because the
	 * relative URI resolution will remove the distinction between
	 * filenames with and without initial slashes, which is
	 * significant for TFTP.
	 */
	if ( next_server.s_addr && filename[0] && ! uri_is_absolute ( uri ) ) {
		uri_put ( uri );
		snprintf ( buf, sizeof ( buf ), "tftp://%s/%s",
			   inet_ntoa ( next_server ), filename );
		uri = parse_uri ( buf );
		if ( ! uri )
			return NULL;
	}

	return uri;
}

/** The "keep-san" setting */
struct setting keep_san_setting __setting ( SETTING_SANBOOT_EXTRA ) = {
	.name = "keep-san",
	.description = "Preserve SAN connection",
	.tag = DHCP_EB_KEEP_SAN,
	.type = &setting_type_int8,
};

/** The "skip-san-boot" setting */
struct setting skip_san_boot_setting __setting ( SETTING_SANBOOT_EXTRA ) = {
	.name = "skip-san-boot",
	.description = "Do not boot from SAN device",
	.tag = DHCP_EB_SKIP_SAN_BOOT,
	.type = &setting_type_int8,
};

/**
 * Boot from filename and root-path URIs
 *
 * @v filename		Filename
 * @v root_path		Root path
 * @ret rc		Return status code
 */
int uriboot ( struct uri *filename, struct uri *root_path ) {
	int drive;
	int rc;

	/* Treat empty URIs as absent */
	if ( filename && ( ! uri_has_path ( filename ) ) )
		filename = NULL;
	if ( root_path && ( ! uri_is_absolute ( root_path ) ) )
		root_path = NULL;

	/* If we have both a filename and a root path, ignore an
	 * unsupported URI scheme in the root path, since it may
	 * represent an NFS root.
	 */
	if ( filename && root_path &&
	     ( xfer_uri_opener ( root_path->scheme ) == NULL ) ) {
		printf ( "Ignoring unsupported root path\n" );
		root_path = NULL;
	}

	/* Check that we have something to boot */
	if ( ! ( filename || root_path ) ) {
		rc = -ENOENT_BOOT;
		printf ( "Nothing to boot: %s\n", strerror ( rc ) );
		goto err_no_boot;
	}

	/* Hook SAN device, if applicable */
	if ( root_path ) {
		drive = san_hook ( root_path, 0 );
		if ( drive < 0 ) {
			rc = drive;
			printf ( "Could not open SAN device: %s\n",
				 strerror ( rc ) );
			goto err_san_hook;
		}
		printf ( "Registered as SAN device %#02x\n", drive );
	} else {
		drive = -ENODEV;
	}

	/* Describe SAN device, if applicable */
	if ( ( drive >= 0 ) && ( ( rc = san_describe ( drive ) ) != 0 ) ) {
		printf ( "Could not describe SAN device %#02x: %s\n",
			 drive, strerror ( rc ) );
		goto err_san_describe;
	}

	/* Allow a root-path-only boot with skip-san enabled to succeed */
	rc = 0;

	/* Attempt filename boot if applicable */
	if ( filename ) {
		if ( ( rc = imgdownload ( filename, NULL, NULL,
					  register_and_boot_image ) ) != 0 ) {
			printf ( "\nCould not chain image: %s\n",
				 strerror ( rc ) );
			/* Fall through to (possibly) attempt a SAN boot
			 * as a fallback.  If no SAN boot is attempted,
			 * our status will become the return status.
			 */
		} else {
			/* Always print an extra newline, because we
			 * don't know where the NBP may have left the
			 * cursor.
			 */
			printf ( "\n" );
		}
	}

	/* Attempt SAN boot if applicable */
	if ( root_path ) {
		if ( fetch_intz_setting ( NULL, &skip_san_boot_setting) == 0 ) {
			printf ( "Booting from SAN device %#02x\n", drive );
			rc = san_boot ( drive );
			printf ( "Boot from SAN device %#02x failed: %s\n",
				 drive, strerror ( rc ) );
		} else {
			printf ( "Skipping boot from SAN device %#02x\n",
				 drive );
			/* Avoid overwriting a possible failure status
			 * from a filename boot.
			 */
		}
	}

 err_san_describe:
	/* Unhook SAN device, if applicable */
	if ( drive >= 0 ) {
		if ( fetch_intz_setting ( NULL, &keep_san_setting ) == 0 ) {
			printf ( "Unregistering SAN device %#02x\n", drive );
			san_unhook ( drive );
		} else {
			printf ( "Preserving connection to SAN device %#02x\n",
				 drive );
		}
	}
 err_san_hook:
 err_no_boot:
	return rc;
}

/**
 * Close all open net devices
 *
 * Called before a fresh boot attempt in order to free up memory.  We
 * don't just close the device immediately after the boot fails,
 * because there may still be TCP connections in the process of
 * closing.
 */
static void close_all_netdevs ( void ) {
	struct net_device *netdev;

	for_each_netdev ( netdev ) {
		ifclose ( netdev );
	}
}

/**
 * Fetch next-server and filename settings into a URI
 *
 * @v settings		Settings block
 * @ret uri		URI, or NULL on failure
 */
struct uri * fetch_next_server_and_filename ( struct settings *settings ) {
	struct in_addr next_server;
	char buf[256];
	char *filename;
	struct uri *uri;

	/* Fetch next-server setting */
	fetch_ipv4_setting ( settings, &next_server_setting, &next_server );
	if ( next_server.s_addr )
		printf ( "Next server: %s\n", inet_ntoa ( next_server ) );

	/* Fetch filename setting */
	fetch_string_setting ( settings, &filename_setting,
			       buf, sizeof ( buf ) );
	if ( buf[0] )
		printf ( "Filename: %s\n", buf );

	/* Expand filename setting */
	filename = expand_settings ( buf );
	if ( ! filename )
		return NULL;

	/* Parse next server and filename */
	uri = parse_next_server_and_filename ( next_server, filename );

	free ( filename );
	return uri;
}

/**
 * Fetch root-path setting into a URI
 *
 * @v settings		Settings block
 * @ret uri		URI, or NULL on failure
 */
static struct uri * fetch_root_path ( struct settings *settings ) {
	char buf[256];
	char *root_path;
	struct uri *uri;

	/* Fetch root-path setting */
	fetch_string_setting ( settings, &root_path_setting,
			       buf, sizeof ( buf ) );
	if ( buf[0] )
		printf ( "Root path: %s\n", buf );

	/* Expand filename setting */
	root_path = expand_settings ( buf );
	if ( ! root_path )
		return NULL;

	/* Parse root path */
	uri = parse_uri ( root_path );

	free ( root_path );
	return uri;
}

/**
 * Check whether or not we have a usable PXE menu
 *
 * @ret have_menu	A usable PXE menu is present
 */
static int have_pxe_menu ( void ) {
	struct setting vendor_class_id_setting
		= { .tag = DHCP_VENDOR_CLASS_ID };
	struct setting pxe_discovery_control_setting
		= { .tag = DHCP_PXE_DISCOVERY_CONTROL };
	struct setting pxe_boot_menu_setting
		= { .tag = DHCP_PXE_BOOT_MENU };
	char buf[256];
	unsigned int pxe_discovery_control;

	fetch_string_setting ( NULL, &vendor_class_id_setting,
			       buf, sizeof ( buf ) );
	pxe_discovery_control =
		fetch_uintz_setting ( NULL, &pxe_discovery_control_setting );

	return ( ( strcmp ( buf, "PXEClient" ) == 0 ) &&
		 setting_exists ( NULL, &pxe_boot_menu_setting ) &&
		 ( ! ( ( pxe_discovery_control & PXEBS_SKIP ) &&
		       setting_exists ( NULL, &filename_setting ) ) ) );
}

/**
 * Boot from a network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
int netboot ( struct net_device *netdev ) {
	struct uri *filename;
	struct uri *root_path;
	int rc;

	/* Close all other network devices */
	close_all_netdevs();

	/* Open device and display device status */
	if ( ( rc = ifopen ( netdev ) ) != 0 )
		goto err_ifopen;
	ifstat ( netdev );

	/* Configure device via DHCP */
	if ( ( rc = dhcp ( netdev ) ) != 0 )
		goto err_dhcp;
	route();

	/* Try PXE menu boot, if applicable */
	if ( have_pxe_menu() ) {
		printf ( "Booting from PXE menu\n" );
		rc = pxe_menu_boot ( netdev );
		goto err_pxe_menu_boot;
	}

	/* Fetch next server, filename and root path */
	filename = fetch_next_server_and_filename ( NULL );
	if ( ! filename )
		goto err_filename;
	root_path = fetch_root_path ( NULL );
	if ( ! root_path )
		goto err_root_path;

	/* Boot using next server, filename and root path */
	if ( ( rc = uriboot ( filename, root_path ) ) != 0 )
		goto err_uriboot;

 err_uriboot:
	uri_put ( root_path );
 err_root_path:
	uri_put ( filename );
 err_filename:
 err_pxe_menu_boot:
 err_dhcp:
 err_ifopen:
	return rc;
}

/**
 * Boot the system
 */
int autoboot ( void ) {
	struct net_device *boot_netdev;
	struct net_device *netdev;
	int rc = -ENODEV;

	/* If we have an identifable boot device, try that first */
	if ( ( boot_netdev = find_boot_netdev() ) )
		rc = netboot ( boot_netdev );

	/* If that fails, try booting from any of the other devices */
	for_each_netdev ( netdev ) {
		if ( netdev == boot_netdev )
			continue;
		rc = netboot ( netdev );
	}

	printf ( "No more network devices\n" );
	return rc;
}
