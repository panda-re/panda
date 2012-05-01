#ifndef _USR_DHCPMGMT_H
#define _USR_DHCPMGMT_H

/** @file
 *
 * DHCP management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

struct net_device;

extern int dhcp ( struct net_device *netdev );
extern int pxebs ( struct net_device *netdev, unsigned int pxe_type );

#endif /* _USR_DHCPMGMT_H */
