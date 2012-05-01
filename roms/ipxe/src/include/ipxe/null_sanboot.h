#ifndef _IPXE_NULL_SANBOOT_H
#define _IPXE_NULL_SANBOOT_H

/** @file
 *
 * Standard do-nothing sanboot interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#ifdef SANBOOT_NULL
#define SANBOOT_PREFIX_null
#else
#define SANBOOT_PREFIX_null __null_
#endif

#endif /* _IPXE_NULL_SANBOOT_H */
