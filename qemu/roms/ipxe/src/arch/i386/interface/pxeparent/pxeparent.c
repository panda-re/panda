/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <ipxe/dhcp.h>
#include <pxeparent.h>
#include <pxe_api.h>
#include <pxe_types.h>
#include <pxe.h>

/** @file
 *
 * Call interface to parent PXE stack
 *
 */

/**
 * Name PXE API call
 *
 * @v function		API call number
 * @ret name		API call name
 */
static inline __attribute__ (( always_inline )) const char *
pxeparent_function_name ( unsigned int function ) {
	switch ( function ) {
	case PXENV_START_UNDI:
		return "PXENV_START_UNDI";
	case PXENV_STOP_UNDI:
		return "PXENV_STOP_UNDI";
	case PXENV_UNDI_STARTUP:
		return "PXENV_UNDI_STARTUP";
	case PXENV_UNDI_CLEANUP:
		return "PXENV_UNDI_CLEANUP";
	case PXENV_UNDI_INITIALIZE:
		return "PXENV_UNDI_INITIALIZE";
	case PXENV_UNDI_RESET_ADAPTER:
		return "PXENV_UNDI_RESET_ADAPTER";
	case PXENV_UNDI_SHUTDOWN:
		return "PXENV_UNDI_SHUTDOWN";
	case PXENV_UNDI_OPEN:
		return "PXENV_UNDI_OPEN";
	case PXENV_UNDI_CLOSE:
		return "PXENV_UNDI_CLOSE";
	case PXENV_UNDI_TRANSMIT:
		return "PXENV_UNDI_TRANSMIT";
	case PXENV_UNDI_SET_MCAST_ADDRESS:
		return "PXENV_UNDI_SET_MCAST_ADDRESS";
	case PXENV_UNDI_SET_STATION_ADDRESS:
		return "PXENV_UNDI_SET_STATION_ADDRESS";
	case PXENV_UNDI_SET_PACKET_FILTER:
		return "PXENV_UNDI_SET_PACKET_FILTER";
	case PXENV_UNDI_GET_INFORMATION:
		return "PXENV_UNDI_GET_INFORMATION";
	case PXENV_UNDI_GET_STATISTICS:
		return "PXENV_UNDI_GET_STATISTICS";
	case PXENV_UNDI_CLEAR_STATISTICS:
		return "PXENV_UNDI_CLEAR_STATISTICS";
	case PXENV_UNDI_INITIATE_DIAGS:
		return "PXENV_UNDI_INITIATE_DIAGS";
	case PXENV_UNDI_FORCE_INTERRUPT:
		return "PXENV_UNDI_FORCE_INTERRUPT";
	case PXENV_UNDI_GET_MCAST_ADDRESS:
		return "PXENV_UNDI_GET_MCAST_ADDRESS";
	case PXENV_UNDI_GET_NIC_TYPE:
		return "PXENV_UNDI_GET_NIC_TYPE";
	case PXENV_UNDI_GET_IFACE_INFO:
		return "PXENV_UNDI_GET_IFACE_INFO";
	/*
	 * Duplicate case value; this is a bug in the PXE specification.
	 *
	 *	case PXENV_UNDI_GET_STATE:
	 *		return "PXENV_UNDI_GET_STATE";
	 */
	case PXENV_UNDI_ISR:
		return "PXENV_UNDI_ISR";
	case PXENV_GET_CACHED_INFO:
		return "PXENV_GET_CACHED_INFO";
	default:
		return "UNKNOWN API CALL";
	}
}

/**
 * PXE parent parameter block
 *
 * Used as the paramter block for all parent PXE API calls.  Resides in base
 * memory.
 */
static union u_PXENV_ANY __bss16 ( pxeparent_params );
#define pxeparent_params __use_data16 ( pxeparent_params )

/** PXE parent entry point
 *
 * Used as the indirection vector for all parent PXE API calls.  Resides in
 * base memory.
 */
SEGOFF16_t __bss16 ( pxeparent_entry_point );
#define pxeparent_entry_point __use_data16 ( pxeparent_entry_point )

/**
 * Issue parent PXE API call
 *
 * @v entry		Parent PXE stack entry point
 * @v function		API call number
 * @v params		PXE parameter block
 * @v params_len	Length of PXE parameter block
 * @ret rc		Return status code
 */
int pxeparent_call ( SEGOFF16_t entry, unsigned int function,
		     void *params, size_t params_len ) {
	PXENV_EXIT_t exit;
	int discard_b, discard_D;
	int rc;

	/* Copy parameter block and entry point */
	assert ( params_len <= sizeof ( pxeparent_params ) );
	memcpy ( &pxeparent_params, params, params_len );
	memcpy ( &pxeparent_entry_point, &entry, sizeof ( entry ) );

	/* Call real-mode entry point.  This calling convention will
	 * work with both the !PXE and the PXENV+ entry points.
	 */
	__asm__ __volatile__ ( REAL_CODE ( "pushw %%es\n\t"
					   "pushw %%di\n\t"
					   "pushw %%bx\n\t"
					   "lcall *pxeparent_entry_point\n\t"
					   "addw $6, %%sp\n\t" )
			       : "=a" ( exit ), "=b" ( discard_b ),
			         "=D" ( discard_D )
			       : "b" ( function ),
			         "D" ( __from_data16 ( &pxeparent_params ) )
			       : "ecx", "edx", "esi", "ebp" );

	/* Determine return status code based on PXENV_EXIT and
	 * PXENV_STATUS
	 */
	if ( exit == PXENV_EXIT_SUCCESS ) {
		rc = 0;
	} else {
		rc = -pxeparent_params.Status;
		/* Paranoia; don't return success for the combination
		 * of PXENV_EXIT_FAILURE but PXENV_STATUS_SUCCESS
		 */
		if ( rc == 0 )
			rc = -EIO;
	}

	/* If anything goes wrong, print as much debug information as
	 * it's possible to give.
	 */
	if ( rc != 0 ) {
		SEGOFF16_t rm_params = {
			.segment = rm_ds,
			.offset = __from_data16 ( &pxeparent_params ),
		};

		DBG ( "PXEPARENT %s failed: %s\n",
		       pxeparent_function_name ( function ), strerror ( rc ) );
		DBG ( "PXEPARENT parameters at %04x:%04x length "
		       "%#02zx, entry point at %04x:%04x\n",
		       rm_params.segment, rm_params.offset, params_len,
		       pxeparent_entry_point.segment,
		       pxeparent_entry_point.offset );
		DBG ( "PXEPARENT parameters provided:\n" );
		DBG_HDA ( rm_params, params, params_len );
		DBG ( "PXEPARENT parameters returned:\n" );
		DBG_HDA ( rm_params, &pxeparent_params, params_len );
	}

	/* Copy parameter block back */
	memcpy ( params, &pxeparent_params, params_len );

	return rc;
}

