#ifndef _IPXE_UUID_H
#define _IPXE_UUID_H

/** @file
 *
 * Universally unique IDs
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>

/** A universally unique ID */
union uuid {
	/** Canonical form (00000000-0000-0000-0000-000000000000) */
	struct {
		/** 8 hex digits, big-endian */
		uint32_t a;
		/** 2 hex digits, big-endian */
		uint16_t b;
		/** 2 hex digits, big-endian */
		uint16_t c;
		/** 2 hex digits, big-endian */
		uint16_t d;
		/** 12 hex digits, big-endian */
		uint8_t e[6];
	} canonical;
	uint8_t raw[16];
};

extern char * uuid_ntoa ( union uuid *uuid );

#endif /* _IPXE_UUID_H */
