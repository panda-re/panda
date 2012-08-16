#ifndef _IPXE_BIOS_SANBOOT_H
#define _IPXE_BIOS_SANBOOT_H

/** @file
 *
 * Standard PC-BIOS sanboot interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#ifdef SANBOOT_PCBIOS
#define SANBOOT_PREFIX_pcbios
#else
#define SANBOOT_PREFIX_pcbios __pcbios_
#endif

#endif /* _IPXE_BIOS_SANBOOT_H */
