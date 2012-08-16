#ifndef _USR_IFMGMT_H
#define _USR_IFMGMT_H

/** @file
 *
 * Network interface management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

struct net_device;

extern int ifopen ( struct net_device *netdev );
extern void ifclose ( struct net_device *netdev );
extern void ifstat ( struct net_device *netdev );
extern int iflinkwait ( struct net_device *netdev, unsigned int max_wait_ms );

#endif /* _USR_IFMGMT_H */
