#ifndef _USR_AUTOBOOT_H
#define _USR_AUTOBOOT_H

/** @file
 *
 * Automatic booting
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/in.h>
struct net_device;
struct uri;
struct settings;

extern int uriboot ( struct uri *filename, struct uri *root_path );
extern struct uri *
fetch_next_server_and_filename ( struct settings *settings );
extern int netboot ( struct net_device *netdev );
extern int autoboot ( void );

extern int pxe_menu_boot ( struct net_device *netdev );

#endif /* _USR_AUTOBOOT_H */
