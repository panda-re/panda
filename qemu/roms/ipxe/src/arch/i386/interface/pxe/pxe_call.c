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

#include <ipxe/uaccess.h>
#include <ipxe/init.h>
#include <setjmp.h>
#include <registers.h>
#include <biosint.h>
#include <pxe.h>
#include <pxe_call.h>

/** @file
 *
 * PXE API entry point
 */

/** Vector for chaining INT 1A */
extern struct segoff __text16 ( pxe_int_1a_vector );
#define pxe_int_1a_vector __use_text16 ( pxe_int_1a_vector )

/** INT 1A handler */
extern void pxe_int_1a ( void );

/** INT 1A hooked flag */
static int int_1a_hooked = 0;

/** A function pointer to hold any PXE API call
 *
 * Used by pxe_api_call() to avoid large swathes of duplicated code.
 */
union pxenv_call {
	PXENV_EXIT_t ( * any ) ( union u_PXENV_ANY * );
	PXENV_EXIT_t ( * unknown ) ( struct s_PXENV_UNKNOWN * );
	PXENV_EXIT_t ( * unload_stack ) ( struct s_PXENV_UNLOAD_STACK * );
	PXENV_EXIT_t ( * get_cached_info )
			( struct s_PXENV_GET_CACHED_INFO * );
	PXENV_EXIT_t ( * restart_tftp ) ( struct s_PXENV_TFTP_READ_FILE * );
	PXENV_EXIT_t ( * start_undi ) ( struct s_PXENV_START_UNDI * );
	PXENV_EXIT_t ( * stop_undi ) ( struct s_PXENV_STOP_UNDI * );
	PXENV_EXIT_t ( * start_base ) ( struct s_PXENV_START_BASE * );
	PXENV_EXIT_t ( * stop_base ) ( struct s_PXENV_STOP_BASE * );
	PXENV_EXIT_t ( * tftp_open ) ( struct s_PXENV_TFTP_OPEN * );
	PXENV_EXIT_t ( * tftp_close ) ( struct s_PXENV_TFTP_CLOSE * );
	PXENV_EXIT_t ( * tftp_read ) ( struct s_PXENV_TFTP_READ * );
	PXENV_EXIT_t ( * tftp_read_file ) ( struct s_PXENV_TFTP_READ_FILE * );
	PXENV_EXIT_t ( * tftp_get_fsize ) ( struct s_PXENV_TFTP_GET_FSIZE * );
	PXENV_EXIT_t ( * udp_open ) ( struct s_PXENV_UDP_OPEN * );
	PXENV_EXIT_t ( * udp_close ) ( struct s_PXENV_UDP_CLOSE * );
	PXENV_EXIT_t ( * udp_write ) ( struct s_PXENV_UDP_WRITE * );
	PXENV_EXIT_t ( * udp_read ) ( struct s_PXENV_UDP_READ * );
	PXENV_EXIT_t ( * undi_startup ) ( struct s_PXENV_UNDI_STARTUP * );
	PXENV_EXIT_t ( * undi_cleanup ) ( struct s_PXENV_UNDI_CLEANUP * );
	PXENV_EXIT_t ( * undi_initialize )
			( struct s_PXENV_UNDI_INITIALIZE * );
	PXENV_EXIT_t ( * undi_reset_adapter ) ( struct s_PXENV_UNDI_RESET * );
	PXENV_EXIT_t ( * undi_shutdown ) ( struct s_PXENV_UNDI_SHUTDOWN * );
	PXENV_EXIT_t ( * undi_open ) ( struct s_PXENV_UNDI_OPEN * );
	PXENV_EXIT_t ( * undi_close ) ( struct s_PXENV_UNDI_CLOSE * );
	PXENV_EXIT_t ( * undi_transmit ) ( struct s_PXENV_UNDI_TRANSMIT * );
	PXENV_EXIT_t ( * undi_set_mcast_address )
			( struct s_PXENV_UNDI_SET_MCAST_ADDRESS * );
	PXENV_EXIT_t ( * undi_set_station_address )
			( struct s_PXENV_UNDI_SET_STATION_ADDRESS * );
	PXENV_EXIT_t ( * undi_set_packet_filter )
			( struct s_PXENV_UNDI_SET_PACKET_FILTER * );
	PXENV_EXIT_t ( * undi_get_information )
			( struct s_PXENV_UNDI_GET_INFORMATION * );
	PXENV_EXIT_t ( * undi_get_statistics )
			( struct s_PXENV_UNDI_GET_STATISTICS * );
	PXENV_EXIT_t ( * undi_clear_statistics )
			( struct s_PXENV_UNDI_CLEAR_STATISTICS * );
	PXENV_EXIT_t ( * undi_initiate_diags )
			( struct s_PXENV_UNDI_INITIATE_DIAGS * );
	PXENV_EXIT_t ( * undi_force_interrupt )
			( struct s_PXENV_UNDI_FORCE_INTERRUPT * );
	PXENV_EXIT_t ( * undi_get_mcast_address )
			( struct s_PXENV_UNDI_GET_MCAST_ADDRESS * );
	PXENV_EXIT_t ( * undi_get_nic_type )
			( struct s_PXENV_UNDI_GET_NIC_TYPE * );
	PXENV_EXIT_t ( * undi_get_iface_info )
			( struct s_PXENV_UNDI_GET_IFACE_INFO * );
	PXENV_EXIT_t ( * undi_get_state ) ( struct s_PXENV_UNDI_GET_STATE * );
	PXENV_EXIT_t ( * undi_isr ) ( struct s_PXENV_UNDI_ISR * );
	PXENV_EXIT_t ( * file_open ) ( struct s_PXENV_FILE_OPEN * );
	PXENV_EXIT_t ( * file_close ) ( struct s_PXENV_FILE_CLOSE * );
	PXENV_EXIT_t ( * file_select ) ( struct s_PXENV_FILE_SELECT * );
	PXENV_EXIT_t ( * file_read ) ( struct s_PXENV_FILE_READ * );
	PXENV_EXIT_t ( * get_file_size ) ( struct s_PXENV_GET_FILE_SIZE * );
	PXENV_EXIT_t ( * file_exec ) ( struct s_PXENV_FILE_EXEC * );
	PXENV_EXIT_t ( * file_api_check ) ( struct s_PXENV_FILE_API_CHECK * );
	PXENV_EXIT_t ( * file_exit_hook ) ( struct s_PXENV_FILE_EXIT_HOOK * );
};

/**
 * Handle an unknown PXE API call
 *
 * @v pxenv_unknown 			Pointer to a struct s_PXENV_UNKNOWN
 * @ret #PXENV_EXIT_FAILURE		Always
 * @err #PXENV_STATUS_UNSUPPORTED	Always
 */
static PXENV_EXIT_t pxenv_unknown ( struct s_PXENV_UNKNOWN *pxenv_unknown ) {
	pxenv_unknown->Status = PXENV_STATUS_UNSUPPORTED;
	return PXENV_EXIT_FAILURE;
}

/**
 * Dispatch PXE API call
 *
 * @v bx		PXE opcode
 * @v es:di		Address of PXE parameter block
 * @ret ax		PXE exit code
 */
__asmcall void pxe_api_call ( struct i386_all_regs *ix86 ) {
	int opcode = ix86->regs.bx;
	userptr_t parameters = real_to_user ( ix86->segs.es, ix86->regs.di );
	size_t param_len;
	union u_PXENV_ANY pxenv_any;
	union pxenv_call pxenv_call;
	PXENV_EXIT_t ret;

	switch ( opcode ) {
	case PXENV_UNLOAD_STACK:
		pxenv_call.unload_stack = pxenv_unload_stack;
		param_len = sizeof ( pxenv_any.unload_stack );
		break;
	case PXENV_GET_CACHED_INFO:
		pxenv_call.get_cached_info = pxenv_get_cached_info;
		param_len = sizeof ( pxenv_any.get_cached_info );
		break;
	case PXENV_RESTART_TFTP:
		pxenv_call.restart_tftp = pxenv_restart_tftp;
		param_len = sizeof ( pxenv_any.restart_tftp );
		break;
	case PXENV_START_UNDI:
		pxenv_call.start_undi = pxenv_start_undi;
		param_len = sizeof ( pxenv_any.start_undi );
		break;
	case PXENV_STOP_UNDI:
		pxenv_call.stop_undi = pxenv_stop_undi;
		param_len = sizeof ( pxenv_any.stop_undi );
		break;
	case PXENV_START_BASE:
		pxenv_call.start_base = pxenv_start_base;
		param_len = sizeof ( pxenv_any.start_base );
		break;
	case PXENV_STOP_BASE:
		pxenv_call.stop_base = pxenv_stop_base;
		param_len = sizeof ( pxenv_any.stop_base );
		break;
	case PXENV_TFTP_OPEN:
		pxenv_call.tftp_open = pxenv_tftp_open;
		param_len = sizeof ( pxenv_any.tftp_open );
		break;
	case PXENV_TFTP_CLOSE:
		pxenv_call.tftp_close = pxenv_tftp_close;
		param_len = sizeof ( pxenv_any.tftp_close );
		break;
	case PXENV_TFTP_READ:
		pxenv_call.tftp_read = pxenv_tftp_read;
		param_len = sizeof ( pxenv_any.tftp_read );
		break;
	case PXENV_TFTP_READ_FILE:
		pxenv_call.tftp_read_file = pxenv_tftp_read_file;
		param_len = sizeof ( pxenv_any.tftp_read_file );
		break;
	case PXENV_TFTP_GET_FSIZE:
		pxenv_call.tftp_get_fsize = pxenv_tftp_get_fsize;
		param_len = sizeof ( pxenv_any.tftp_get_fsize );
		break;
	case PXENV_UDP_OPEN:
		pxenv_call.udp_open = pxenv_udp_open;
		param_len = sizeof ( pxenv_any.udp_open );
		break;
	case PXENV_UDP_CLOSE:
		pxenv_call.udp_close = pxenv_udp_close;
		param_len = sizeof ( pxenv_any.udp_close );
		break;
	case PXENV_UDP_WRITE:
		pxenv_call.udp_write = pxenv_udp_write;
		param_len = sizeof ( pxenv_any.udp_write );
		break;
	case PXENV_UDP_READ:
		pxenv_call.udp_read = pxenv_udp_read;
		param_len = sizeof ( pxenv_any.udp_read );
		break;
	case PXENV_UNDI_STARTUP:
		pxenv_call.undi_startup = pxenv_undi_startup;
		param_len = sizeof ( pxenv_any.undi_startup );
		break;
	case PXENV_UNDI_CLEANUP:
		pxenv_call.undi_cleanup = pxenv_undi_cleanup;
		param_len = sizeof ( pxenv_any.undi_cleanup );
		break;
	case PXENV_UNDI_INITIALIZE:
		pxenv_call.undi_initialize = pxenv_undi_initialize;
		param_len = sizeof ( pxenv_any.undi_initialize );
		break;
	case PXENV_UNDI_RESET_ADAPTER:
		pxenv_call.undi_reset_adapter = pxenv_undi_reset_adapter;
		param_len = sizeof ( pxenv_any.undi_reset_adapter );
		break;
	case PXENV_UNDI_SHUTDOWN:
		pxenv_call.undi_shutdown = pxenv_undi_shutdown;
		param_len = sizeof ( pxenv_any.undi_shutdown );
		break;
	case PXENV_UNDI_OPEN:
		pxenv_call.undi_open = pxenv_undi_open;
		param_len = sizeof ( pxenv_any.undi_open );
		break;
	case PXENV_UNDI_CLOSE:
		pxenv_call.undi_close = pxenv_undi_close;
		param_len = sizeof ( pxenv_any.undi_close );
		break;
	case PXENV_UNDI_TRANSMIT:
		pxenv_call.undi_transmit = pxenv_undi_transmit;
		param_len = sizeof ( pxenv_any.undi_transmit );
		break;
	case PXENV_UNDI_SET_MCAST_ADDRESS:
		pxenv_call.undi_set_mcast_address =
			pxenv_undi_set_mcast_address;
		param_len = sizeof ( pxenv_any.undi_set_mcast_address );
		break;
	case PXENV_UNDI_SET_STATION_ADDRESS:
		pxenv_call.undi_set_station_address =
			pxenv_undi_set_station_address;
		param_len = sizeof ( pxenv_any.undi_set_station_address );
		break;
	case PXENV_UNDI_SET_PACKET_FILTER:
		pxenv_call.undi_set_packet_filter =
			pxenv_undi_set_packet_filter;
		param_len = sizeof ( pxenv_any.undi_set_packet_filter );
		break;
	case PXENV_UNDI_GET_INFORMATION:
		pxenv_call.undi_get_information = pxenv_undi_get_information;
		param_len = sizeof ( pxenv_any.undi_get_information );
		break;
	case PXENV_UNDI_GET_STATISTICS:
		pxenv_call.undi_get_statistics = pxenv_undi_get_statistics;
		param_len = sizeof ( pxenv_any.undi_get_statistics );
		break;
	case PXENV_UNDI_CLEAR_STATISTICS:
		pxenv_call.undi_clear_statistics = pxenv_undi_clear_statistics;
		param_len = sizeof ( pxenv_any.undi_clear_statistics );
		break;
	case PXENV_UNDI_INITIATE_DIAGS:
		pxenv_call.undi_initiate_diags = pxenv_undi_initiate_diags;
		param_len = sizeof ( pxenv_any.undi_initiate_diags );
		break;
	case PXENV_UNDI_FORCE_INTERRUPT:
		pxenv_call.undi_force_interrupt = pxenv_undi_force_interrupt;
		param_len = sizeof ( pxenv_any.undi_force_interrupt );
		break;
	case PXENV_UNDI_GET_MCAST_ADDRESS:
		pxenv_call.undi_get_mcast_address =
			pxenv_undi_get_mcast_address;
		param_len = sizeof ( pxenv_any.undi_get_mcast_address );
		break;
	case PXENV_UNDI_GET_NIC_TYPE:
		pxenv_call.undi_get_nic_type = pxenv_undi_get_nic_type;
		param_len = sizeof ( pxenv_any.undi_get_nic_type );
		break;
	case PXENV_UNDI_GET_IFACE_INFO:
		pxenv_call.undi_get_iface_info = pxenv_undi_get_iface_info;
		param_len = sizeof ( pxenv_any.undi_get_iface_info );
		break;
	case PXENV_UNDI_ISR:
		pxenv_call.undi_isr = pxenv_undi_isr;
		param_len = sizeof ( pxenv_any.undi_isr );
		break;
	case PXENV_FILE_OPEN:
		pxenv_call.file_open = pxenv_file_open;
		param_len = sizeof ( pxenv_any.file_open );
		break;
	case PXENV_FILE_CLOSE:
		pxenv_call.file_close = pxenv_file_close;
		param_len = sizeof ( pxenv_any.file_close );
		break;
	case PXENV_FILE_SELECT:
		pxenv_call.file_select = pxenv_file_select;
		param_len = sizeof ( pxenv_any.file_select );
		break;
	case PXENV_FILE_READ:
		pxenv_call.file_read = pxenv_file_read;
		param_len = sizeof ( pxenv_any.file_read );
		break;
	case PXENV_GET_FILE_SIZE:
		pxenv_call.get_file_size = pxenv_get_file_size;
		param_len = sizeof ( pxenv_any.get_file_size );
		break;
	case PXENV_FILE_EXEC:
		pxenv_call.file_exec = pxenv_file_exec;
		param_len = sizeof ( pxenv_any.file_exec );
		break;
	case PXENV_FILE_API_CHECK:
		pxenv_call.file_api_check = pxenv_file_api_check;
		param_len = sizeof ( pxenv_any.file_api_check );
		break;
	case PXENV_FILE_EXIT_HOOK:
		pxenv_call.file_exit_hook = pxenv_file_exit_hook;
		param_len = sizeof ( pxenv_any.file_exit_hook );
		break;
	default:
		DBG ( "PXENV_UNKNOWN_%hx", opcode );
		pxenv_call.unknown = pxenv_unknown;
		param_len = sizeof ( pxenv_any.unknown );
		break;
	}

	/* Copy parameter block from caller */
	copy_from_user ( &pxenv_any, parameters, 0, param_len );

	/* Set default status in case child routine fails to do so */
	pxenv_any.Status = PXENV_STATUS_FAILURE;

	/* Hand off to relevant API routine */
	DBG ( "[" );
	ret = pxenv_call.any ( &pxenv_any );
	if ( pxenv_any.Status != PXENV_STATUS_SUCCESS ) {
		DBG ( " %02x", pxenv_any.Status );
	}
	if ( ret != PXENV_EXIT_SUCCESS ) {
		DBG ( ret == PXENV_EXIT_FAILURE ? " err" : " ??" );
	}
	DBG ( "]" );
	
	/* Copy modified parameter block back to caller and return */
	copy_to_user ( parameters, 0, &pxenv_any, param_len );
	ix86->regs.ax = ret;
}

/**
 * Dispatch weak PXE API call with PXE stack available
 *
 * @v ix86		Registers for PXE call
 * @ret present		Zero (PXE stack present)
 */
int pxe_api_call_weak ( struct i386_all_regs *ix86 )
{
	pxe_api_call ( ix86 );
	return 0;
}

/**
 * Dispatch PXE loader call
 *
 * @v es:di		Address of PXE parameter block
 * @ret ax		PXE exit code
 */
__asmcall void pxe_loader_call ( struct i386_all_regs *ix86 ) {
	userptr_t uparams = real_to_user ( ix86->segs.es, ix86->regs.di );
	struct s_UNDI_LOADER params;
	PXENV_EXIT_t ret;

	/* Copy parameter block from caller */
	copy_from_user ( &params, uparams, 0, sizeof ( params ) );

	/* Fill in ROM segment address */
	ppxe.UNDIROMID.segment = ix86->segs.ds;

	/* Set default status in case child routine fails to do so */
	params.Status = PXENV_STATUS_FAILURE;

	/* Call UNDI loader */
	ret = undi_loader ( &params );

	/* Copy modified parameter block back to caller and return */
	copy_to_user ( uparams, 0, &params, sizeof ( params ) );
	ix86->regs.ax = ret;
}

/**
 * Calculate byte checksum as used by PXE
 *
 * @v data		Data
 * @v size		Length of data
 * @ret sum		Checksum
 */
static uint8_t pxe_checksum ( void *data, size_t size ) {
	uint8_t *bytes = data;
	uint8_t sum = 0;

	while ( size-- ) {
		sum += *bytes++;
	}
	return sum;
}

/**
 * Initialise !PXE and PXENV+ structures
 *
 */
static void pxe_init_structures ( void ) {
	uint32_t rm_cs_phys = ( rm_cs << 4 );
	uint32_t rm_ds_phys = ( rm_ds << 4 );

	/* Fill in missing segment fields */
	ppxe.EntryPointSP.segment = rm_cs;
	ppxe.EntryPointESP.segment = rm_cs;
	ppxe.Stack.segment_address = rm_ds;
	ppxe.Stack.Physical_address = rm_ds_phys;
	ppxe.UNDIData.segment_address = rm_ds;
	ppxe.UNDIData.Physical_address = rm_ds_phys;
	ppxe.UNDICode.segment_address = rm_cs;
	ppxe.UNDICode.Physical_address = rm_cs_phys;
	ppxe.UNDICodeWrite.segment_address = rm_cs;
	ppxe.UNDICodeWrite.Physical_address = rm_cs_phys;
	pxenv.RMEntry.segment = rm_cs;
	pxenv.StackSeg = rm_ds;
	pxenv.UNDIDataSeg = rm_ds;
	pxenv.UNDICodeSeg = rm_cs;
	pxenv.PXEPtr.segment = rm_cs;

	/* Update checksums */
	ppxe.StructCksum -= pxe_checksum ( &ppxe, sizeof ( ppxe ) );
	pxenv.Checksum -= pxe_checksum ( &pxenv, sizeof ( pxenv ) );
}

/** PXE structure initialiser */
struct init_fn pxe_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = pxe_init_structures,
};

/**
 * Activate PXE stack
 *
 * @v netdev		Net device to use as PXE net device
 */
void pxe_activate ( struct net_device *netdev ) {

	/* Ensure INT 1A is hooked */
	if ( ! int_1a_hooked ) {
		hook_bios_interrupt ( 0x1a, ( unsigned int ) pxe_int_1a,
				      &pxe_int_1a_vector );
		devices_get();
		int_1a_hooked = 1;
	}

	/* Set PXE network device */
	pxe_set_netdev ( netdev );
}

/**
 * Deactivate PXE stack
 *
 * @ret rc		Return status code
 */
int pxe_deactivate ( void ) {
	int rc;

	/* Clear PXE network device */
	pxe_set_netdev ( NULL );

	/* Ensure INT 1A is unhooked, if possible */
	if ( int_1a_hooked ) {
		if ( ( rc = unhook_bios_interrupt ( 0x1a,
						    (unsigned int) pxe_int_1a,
						    &pxe_int_1a_vector ))!= 0){
			DBG ( "Could not unhook INT 1A: %s\n",
			      strerror ( rc ) );
			return rc;
		}
		devices_put();
		int_1a_hooked = 0;
	}

	return 0;
}

/** Jump buffer for PXENV_RESTART_TFTP */
rmjmp_buf pxe_restart_nbp;

/**
 * Start PXE NBP at 0000:7c00
 *
 * @ret rc		Return status code
 */
int pxe_start_nbp ( void ) {
	int jmp;
	int discard_b, discard_c, discard_d, discard_D;
	uint16_t rc;

	/* Allow restarting NBP via PXENV_RESTART_TFTP */
	jmp = rmsetjmp ( pxe_restart_nbp );
	if ( jmp )
		DBG ( "Restarting NBP (%x)\n", jmp );

	/* Far call to PXE NBP */
	__asm__ __volatile__ ( REAL_CODE ( "movw %%cx, %%es\n\t"
					   "pushw %%es\n\t"
					   "pushw %%di\n\t"
					   "sti\n\t"
					   "lcall $0, $0x7c00\n\t"
					   "addw $4, %%sp\n\t" )
			       : "=a" ( rc ), "=b" ( discard_b ),
				 "=c" ( discard_c ), "=d" ( discard_d ),
				 "=D" ( discard_D )
			       : "a" ( 0 ), "b" ( __from_text16 ( &pxenv ) ),
			         "c" ( rm_cs ),
			         "d" ( virt_to_phys ( &pxenv ) ),
				 "D" ( __from_text16 ( &ppxe ) )
			       : "esi", "ebp", "memory" );

	return rc;
}
