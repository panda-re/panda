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

#include <string.h>
#include <pxe.h>
#include <realmode.h>
#include <pic8259.h>
#include <biosint.h>
#include <pnpbios.h>
#include <basemem_packet.h>
#include <ipxe/io.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <undi.h>
#include <undinet.h>
#include <pxeparent.h>


/** @file
 *
 * UNDI network device driver
 *
 */

/** An UNDI NIC */
struct undi_nic {
	/** Device supports IRQs */
	int irq_supported;
	/** Assigned IRQ number */
	unsigned int irq;
	/** Currently processing ISR */
	int isr_processing;
	/** Bug workarounds */
	int hacks;
};

/**
 * @defgroup undi_hacks UNDI workarounds
 * @{
 */

/** Work around Etherboot 5.4 bugs */
#define UNDI_HACK_EB54		0x0001

/** @} */

static void undinet_close ( struct net_device *netdev );

/** Address of UNDI entry point */
static SEGOFF16_t undinet_entry;

/*****************************************************************************
 *
 * UNDI interrupt service routine
 *
 *****************************************************************************
 */

/**
 * UNDI interrupt service routine
 *
 * The UNDI ISR increments a counter (@c trigger_count) and exits.
 */
extern void undiisr ( void );

/** IRQ number */
uint8_t __data16 ( undiisr_irq );
#define undiisr_irq __use_data16 ( undiisr_irq )

/** IRQ chain vector */
struct segoff __data16 ( undiisr_next_handler );
#define undiisr_next_handler __use_data16 ( undiisr_next_handler )

/** IRQ trigger count */
volatile uint8_t __data16 ( undiisr_trigger_count ) = 0;
#define undiisr_trigger_count __use_data16 ( undiisr_trigger_count )

/** Last observed trigger count */
static unsigned int last_trigger_count = 0;

/**
 * Hook UNDI interrupt service routine
 *
 * @v irq		IRQ number
 */
static void undinet_hook_isr ( unsigned int irq ) {

	assert ( irq <= IRQ_MAX );
	assert ( undiisr_irq == 0 );

	undiisr_irq = irq;
	hook_bios_interrupt ( IRQ_INT ( irq ),
			      ( ( unsigned int ) undiisr ),
			      &undiisr_next_handler );
}

/**
 * Unhook UNDI interrupt service routine
 *
 * @v irq		IRQ number
 */
static void undinet_unhook_isr ( unsigned int irq ) {

	assert ( irq <= IRQ_MAX );

	unhook_bios_interrupt ( IRQ_INT ( irq ),
				( ( unsigned int ) undiisr ),
				&undiisr_next_handler );
	undiisr_irq = 0;
}

/**
 * Test to see if UNDI ISR has been triggered
 *
 * @ret triggered	ISR has been triggered since last check
 */
static int undinet_isr_triggered ( void ) {
	unsigned int this_trigger_count;

	/* Read trigger_count.  Do this only once; it is volatile */
	this_trigger_count = undiisr_trigger_count;

	if ( this_trigger_count == last_trigger_count ) {
		/* Not triggered */
		return 0;
	} else {
		/* Triggered */
		last_trigger_count = this_trigger_count;
		return 1;
	}
}

/*****************************************************************************
 *
 * UNDI network device interface
 *
 *****************************************************************************
 */

/** UNDI transmit buffer descriptor */
static struct s_PXENV_UNDI_TBD __data16 ( undinet_tbd );
#define undinet_tbd __use_data16 ( undinet_tbd )

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int undinet_transmit ( struct net_device *netdev,
			      struct io_buffer *iobuf ) {
	struct s_PXENV_UNDI_TRANSMIT undi_transmit;
	size_t len = iob_len ( iobuf );
	int rc;

	/* Technically, we ought to make sure that the previous
	 * transmission has completed before we re-use the buffer.
	 * However, many PXE stacks (including at least some Intel PXE
	 * stacks and Etherboot 5.4) fail to generate TX completions.
	 * In practice this won't be a problem, since our TX datapath
	 * has a very low packet volume and we can get away with
	 * assuming that a TX will be complete by the time we want to
	 * transmit the next packet.
	 */

	/* Copy packet to UNDI I/O buffer */
	if ( len > sizeof ( basemem_packet ) )
		len = sizeof ( basemem_packet );
	memcpy ( &basemem_packet, iobuf->data, len );

	/* Create PXENV_UNDI_TRANSMIT data structure */
	memset ( &undi_transmit, 0, sizeof ( undi_transmit ) );
	undi_transmit.DestAddr.segment = rm_ds;
	undi_transmit.DestAddr.offset = __from_data16 ( &undinet_tbd );
	undi_transmit.TBD.segment = rm_ds;
	undi_transmit.TBD.offset = __from_data16 ( &undinet_tbd );

	/* Create PXENV_UNDI_TBD data structure */
	undinet_tbd.ImmedLength = len;
	undinet_tbd.Xmit.segment = rm_ds;
	undinet_tbd.Xmit.offset = __from_data16 ( basemem_packet );

	/* Issue PXE API call */
	if ( ( rc = pxeparent_call ( undinet_entry, PXENV_UNDI_TRANSMIT,
				     &undi_transmit,
				     sizeof ( undi_transmit ) ) ) != 0 )
		goto done;

	/* Free I/O buffer */
	netdev_tx_complete ( netdev, iobuf );

 done:
	return rc;
}

/** 
 * Poll for received packets
 *
 * @v netdev		Network device
 *
 * Fun, fun, fun.  UNDI drivers don't use polling; they use
 * interrupts.  We therefore cheat and pretend that an interrupt has
 * occurred every time undinet_poll() is called.  This isn't too much
 * of a hack; PCI devices share IRQs and so the first thing that a
 * proper ISR should do is call PXENV_UNDI_ISR to determine whether or
 * not the UNDI NIC generated the interrupt; there is no harm done by
 * spurious calls to PXENV_UNDI_ISR.  Similarly, we wouldn't be
 * handling them any more rapidly than the usual rate of
 * undinet_poll() being called even if we did implement a full ISR.
 * So it should work.  Ha!
 *
 * Addendum (21/10/03).  Some cards don't play nicely with this trick,
 * so instead of doing it the easy way we have to go to all the hassle
 * of installing a genuine interrupt service routine and dealing with
 * the wonderful 8259 Programmable Interrupt Controller.  Joy.
 *
 * Addendum (10/07/07).  When doing things such as iSCSI boot, in
 * which we have to co-operate with a running OS, we can't get away
 * with the "ISR-just-increments-a-counter-and-returns" trick at all,
 * because it involves tying up the PIC for far too long, and other
 * interrupt-dependent components (e.g. local disks) start breaking.
 * We therefore implement a "proper" ISR which calls PXENV_UNDI_ISR
 * from within interrupt context in order to deassert the device
 * interrupt, and sends EOI if applicable.
 */
static void undinet_poll ( struct net_device *netdev ) {
	struct undi_nic *undinic = netdev->priv;
	struct s_PXENV_UNDI_ISR undi_isr;
	struct io_buffer *iobuf = NULL;
	size_t len;
	size_t frag_len;
	size_t max_frag_len;
	int rc;

	if ( ! undinic->isr_processing ) {
		/* Allow interrupt to occur.  Do this even if
		 * interrupts are not known to be supported, since
		 * some cards erroneously report that they do not
		 * support interrupts.
		 */
		if ( ! undinet_isr_triggered() ) {
			/* Allow interrupt to occur */
			__asm__ __volatile__ ( REAL_CODE ( "sti\n\t"
							   "nop\n\t"
							   "nop\n\t"
							   "cli\n\t" ) : : );

			/* If interrupts are known to be supported,
			 * then do nothing on this poll; wait for the
			 * interrupt to be triggered.
			 */
			if ( undinic->irq_supported )
				return;
		}

		/* Start ISR processing */
		undinic->isr_processing = 1;
		undi_isr.FuncFlag = PXENV_UNDI_ISR_IN_PROCESS;
	} else {
		/* Continue ISR processing */
		undi_isr.FuncFlag = PXENV_UNDI_ISR_IN_GET_NEXT;
	}

	/* Run through the ISR loop */
	while ( 1 ) {
		if ( ( rc = pxeparent_call ( undinet_entry, PXENV_UNDI_ISR,
					     &undi_isr,
					     sizeof ( undi_isr ) ) ) != 0 )
			break;
		switch ( undi_isr.FuncFlag ) {
		case PXENV_UNDI_ISR_OUT_TRANSMIT:
			/* We don't care about transmit completions */
			break;
		case PXENV_UNDI_ISR_OUT_RECEIVE:
			/* Packet fragment received */
			len = undi_isr.FrameLength;
			frag_len = undi_isr.BufferLength;
			if ( ( len == 0 ) || ( len < frag_len ) ) {
				/* Don't laugh.  VMWare does it. */
				DBGC ( undinic, "UNDINIC %p reported insane "
				       "fragment (%zd of %zd bytes)\n",
				       undinic, frag_len, len );
				netdev_rx_err ( netdev, NULL, -EINVAL );
				break;
			}
			if ( ! iobuf )
				iobuf = alloc_iob ( len );
			if ( ! iobuf ) {
				DBGC ( undinic, "UNDINIC %p could not "
				       "allocate %zd bytes for RX buffer\n",
				       undinic, len );
				/* Fragment will be dropped */
				netdev_rx_err ( netdev, NULL, -ENOMEM );
				goto done;
			}
			max_frag_len = iob_tailroom ( iobuf );
			if ( frag_len > max_frag_len ) {
				DBGC ( undinic, "UNDINIC %p fragment too big "
				       "(%zd+%zd does not fit into %zd)\n",
				       undinic, iob_len ( iobuf ), frag_len,
				       ( iob_len ( iobuf ) + max_frag_len ) );
				frag_len = max_frag_len;
			}
			copy_from_real ( iob_put ( iobuf, frag_len ),
					 undi_isr.Frame.segment,
					 undi_isr.Frame.offset, frag_len );
			if ( iob_len ( iobuf ) == len ) {
				/* Whole packet received; deliver it */
				netdev_rx ( netdev, iob_disown ( iobuf ) );
				/* Etherboot 5.4 fails to return all packets
				 * under mild load; pretend it retriggered.
				 */
				if ( undinic->hacks & UNDI_HACK_EB54 )
					--last_trigger_count;
			}
			break;
		case PXENV_UNDI_ISR_OUT_DONE:
			/* Processing complete */
			undinic->isr_processing = 0;
			goto done;
		default:
			/* Should never happen.  VMWare does it routinely. */
			DBGC ( undinic, "UNDINIC %p ISR returned invalid "
			       "FuncFlag %04x\n", undinic, undi_isr.FuncFlag );
			undinic->isr_processing = 0;
			goto done;
		}
		undi_isr.FuncFlag = PXENV_UNDI_ISR_IN_GET_NEXT;
	}

 done:
	if ( iobuf ) {
		DBGC ( undinic, "UNDINIC %p returned incomplete packet "
		       "(%zd of %zd)\n", undinic, iob_len ( iobuf ),
		       ( iob_len ( iobuf ) + iob_tailroom ( iobuf ) ) );
		netdev_rx_err ( netdev, iobuf, -EINVAL );
	}
}

/**
 * Open NIC
 *
 * @v netdev		Net device
 * @ret rc		Return status code
 */
static int undinet_open ( struct net_device *netdev ) {
	struct undi_nic *undinic = netdev->priv;
	struct s_PXENV_UNDI_SET_STATION_ADDRESS undi_set_address;
	struct s_PXENV_UNDI_OPEN undi_open;
	int rc;

	/* Hook interrupt service routine and enable interrupt if applicable */
	if ( undinic->irq ) {
		undinet_hook_isr ( undinic->irq );
		enable_irq ( undinic->irq );
		send_eoi ( undinic->irq );
	}

	/* Set station address.  Required for some PXE stacks; will
	 * spuriously fail on others.  Ignore failures.  We only ever
	 * use it to set the MAC address to the card's permanent value
	 * anyway.
	 */
	memcpy ( undi_set_address.StationAddress, netdev->ll_addr,
		 sizeof ( undi_set_address.StationAddress ) );
	pxeparent_call ( undinet_entry, PXENV_UNDI_SET_STATION_ADDRESS,
			 &undi_set_address, sizeof ( undi_set_address ) );

	/* Open NIC.  We ask for promiscuous operation, since it's the
	 * only way to ask for all multicast addresses.  On any
	 * switched network, it shouldn't really make a difference to
	 * performance.
	 */
	memset ( &undi_open, 0, sizeof ( undi_open ) );
	undi_open.PktFilter = ( FLTR_DIRECTED | FLTR_BRDCST | FLTR_PRMSCS );
	if ( ( rc = pxeparent_call ( undinet_entry, PXENV_UNDI_OPEN,
				     &undi_open, sizeof ( undi_open ) ) ) != 0 )
		goto err;

	DBGC ( undinic, "UNDINIC %p opened\n", undinic );
	return 0;

 err:
	undinet_close ( netdev );
	return rc;
}

/**
 * Close NIC
 *
 * @v netdev		Net device
 */
static void undinet_close ( struct net_device *netdev ) {
	struct undi_nic *undinic = netdev->priv;
	struct s_PXENV_UNDI_ISR undi_isr;
	struct s_PXENV_UNDI_CLOSE undi_close;
	int rc;

	/* Ensure ISR has exited cleanly */
	while ( undinic->isr_processing ) {
		undi_isr.FuncFlag = PXENV_UNDI_ISR_IN_GET_NEXT;
		if ( ( rc = pxeparent_call ( undinet_entry, PXENV_UNDI_ISR,
					     &undi_isr,
					     sizeof ( undi_isr ) ) ) != 0 )
			break;
		switch ( undi_isr.FuncFlag ) {
		case PXENV_UNDI_ISR_OUT_TRANSMIT:
		case PXENV_UNDI_ISR_OUT_RECEIVE:
			/* Continue draining */
			break;
		default:
			/* Stop processing */
			undinic->isr_processing = 0;
			break;
		}
	}

	/* Close NIC */
	pxeparent_call ( undinet_entry, PXENV_UNDI_CLOSE,
			 &undi_close, sizeof ( undi_close ) );

	/* Disable interrupt and unhook ISR if applicable */
	if ( undinic->irq ) {
		disable_irq ( undinic->irq );
		undinet_unhook_isr ( undinic->irq );
	}

	DBGC ( undinic, "UNDINIC %p closed\n", undinic );
}

/**
 * Enable/disable interrupts
 *
 * @v netdev		Net device
 * @v enable		Interrupts should be enabled
 */
static void undinet_irq ( struct net_device *netdev, int enable ) {
	struct undi_nic *undinic = netdev->priv;

	/* Cannot support interrupts yet */
	DBGC ( undinic, "UNDINIC %p cannot %s interrupts\n",
	       undinic, ( enable ? "enable" : "disable" ) );
}

/** UNDI network device operations */
static struct net_device_operations undinet_operations = {
	.open		= undinet_open,
	.close		= undinet_close,
	.transmit	= undinet_transmit,
	.poll		= undinet_poll,
	.irq   		= undinet_irq,
};

/**
 * Probe UNDI device
 *
 * @v undi		UNDI device
 * @ret rc		Return status code
 */
int undinet_probe ( struct undi_device *undi ) {
	struct net_device *netdev;
	struct undi_nic *undinic;
	struct s_PXENV_START_UNDI start_undi;
	struct s_PXENV_UNDI_STARTUP undi_startup;
	struct s_PXENV_UNDI_INITIALIZE undi_initialize;
	struct s_PXENV_UNDI_GET_INFORMATION undi_info;
	struct s_PXENV_UNDI_GET_IFACE_INFO undi_iface;
	struct s_PXENV_UNDI_SHUTDOWN undi_shutdown;
	struct s_PXENV_UNDI_CLEANUP undi_cleanup;
	struct s_PXENV_STOP_UNDI stop_undi;
	int rc;

	/* Allocate net device */
	netdev = alloc_etherdev ( sizeof ( *undinic ) );
	if ( ! netdev )
		return -ENOMEM;
	netdev_init ( netdev, &undinet_operations );
	undinic = netdev->priv;
	undi_set_drvdata ( undi, netdev );
	netdev->dev = &undi->dev;
	memset ( undinic, 0, sizeof ( *undinic ) );
	undinet_entry = undi->entry;
	DBGC ( undinic, "UNDINIC %p using UNDI %p\n", undinic, undi );

	/* Hook in UNDI stack */
	if ( ! ( undi->flags & UNDI_FL_STARTED ) ) {
		memset ( &start_undi, 0, sizeof ( start_undi ) );
		start_undi.AX = undi->pci_busdevfn;
		start_undi.BX = undi->isapnp_csn;
		start_undi.DX = undi->isapnp_read_port;
		start_undi.ES = BIOS_SEG;
		start_undi.DI = find_pnp_bios();
		if ( ( rc = pxeparent_call ( undinet_entry, PXENV_START_UNDI,
					     &start_undi,
					     sizeof ( start_undi ) ) ) != 0 )
			goto err_start_undi;
	}
	undi->flags |= UNDI_FL_STARTED;

	/* Bring up UNDI stack */
	if ( ! ( undi->flags & UNDI_FL_INITIALIZED ) ) {
		memset ( &undi_startup, 0, sizeof ( undi_startup ) );
		if ( ( rc = pxeparent_call ( undinet_entry, PXENV_UNDI_STARTUP,
					     &undi_startup,
					     sizeof ( undi_startup ) ) ) != 0 )
			goto err_undi_startup;
		memset ( &undi_initialize, 0, sizeof ( undi_initialize ) );
		if ( ( rc = pxeparent_call ( undinet_entry,
					     PXENV_UNDI_INITIALIZE,
					     &undi_initialize,
					     sizeof ( undi_initialize ))) != 0 )
			goto err_undi_initialize;
	}
	undi->flags |= UNDI_FL_INITIALIZED;

	/* Get device information */
	memset ( &undi_info, 0, sizeof ( undi_info ) );
	if ( ( rc = pxeparent_call ( undinet_entry, PXENV_UNDI_GET_INFORMATION,
				     &undi_info, sizeof ( undi_info ) ) ) != 0 )
		goto err_undi_get_information;
	memcpy ( netdev->hw_addr, undi_info.PermNodeAddress, ETH_ALEN );
	undinic->irq = undi_info.IntNumber;
	if ( undinic->irq > IRQ_MAX ) {
		DBGC ( undinic, "UNDINIC %p has invalid IRQ %d\n",
		       undinic, undinic->irq );
		rc = -EINVAL;
		goto err_bad_irq;
	}
	DBGC ( undinic, "UNDINIC %p has MAC address %s and IRQ %d\n",
	       undinic, eth_ntoa ( netdev->hw_addr ), undinic->irq );

	/* Get interface information */
	memset ( &undi_iface, 0, sizeof ( undi_iface ) );
	if ( ( rc = pxeparent_call ( undinet_entry, PXENV_UNDI_GET_IFACE_INFO,
				     &undi_iface,
				     sizeof ( undi_iface ) ) ) != 0 )
		goto err_undi_get_iface_info;
	DBGC ( undinic, "UNDINIC %p has type %s, speed %d, flags %08x\n",
	       undinic, undi_iface.IfaceType, undi_iface.LinkSpeed,
	       undi_iface.ServiceFlags );
	if ( undi_iface.ServiceFlags & SUPPORTED_IRQ )
		undinic->irq_supported = 1;
	DBGC ( undinic, "UNDINIC %p using %s mode\n", undinic,
	       ( undinic->irq_supported ? "interrupt" : "polling" ) );
	if ( strncmp ( ( ( char * ) undi_iface.IfaceType ), "Etherboot",
		       sizeof ( undi_iface.IfaceType ) ) == 0 ) {
		DBGC ( undinic, "UNDINIC %p Etherboot 5.4 workaround enabled\n",
		       undinic );
		undinic->hacks |= UNDI_HACK_EB54;
	}

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	/* Mark as link up; we don't handle link state */
	netdev_link_up ( netdev );

	DBGC ( undinic, "UNDINIC %p added\n", undinic );
	return 0;

 err_register:
 err_undi_get_iface_info:
 err_bad_irq:
 err_undi_get_information:
 err_undi_initialize:
	/* Shut down UNDI stack */
	memset ( &undi_shutdown, 0, sizeof ( undi_shutdown ) );
	pxeparent_call ( undinet_entry, PXENV_UNDI_SHUTDOWN, &undi_shutdown,
			 sizeof ( undi_shutdown ) );
	memset ( &undi_cleanup, 0, sizeof ( undi_cleanup ) );
	pxeparent_call ( undinet_entry, PXENV_UNDI_CLEANUP, &undi_cleanup,
			 sizeof ( undi_cleanup ) );
	undi->flags &= ~UNDI_FL_INITIALIZED;
 err_undi_startup:
	/* Unhook UNDI stack */
	memset ( &stop_undi, 0, sizeof ( stop_undi ) );
	pxeparent_call ( undinet_entry, PXENV_STOP_UNDI, &stop_undi,
			 sizeof ( stop_undi ) );
	undi->flags &= ~UNDI_FL_STARTED;
 err_start_undi:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	undi_set_drvdata ( undi, NULL );
	return rc;
}

/**
 * Remove UNDI device
 *
 * @v undi		UNDI device
 */
void undinet_remove ( struct undi_device *undi ) {
	struct net_device *netdev = undi_get_drvdata ( undi );
	struct undi_nic *undinic = netdev->priv;
	struct s_PXENV_UNDI_SHUTDOWN undi_shutdown;
	struct s_PXENV_UNDI_CLEANUP undi_cleanup;
	struct s_PXENV_STOP_UNDI stop_undi;

	/* Unregister net device */
	unregister_netdev ( netdev );

	/* If we are preparing for an OS boot, or if we cannot exit
	 * via the PXE stack, then shut down the PXE stack.
	 */
	if ( ! ( undi->flags & UNDI_FL_KEEP_ALL ) ) {

		/* Shut down UNDI stack */
		memset ( &undi_shutdown, 0, sizeof ( undi_shutdown ) );
		pxeparent_call ( undinet_entry, PXENV_UNDI_SHUTDOWN,
				 &undi_shutdown, sizeof ( undi_shutdown ) );
		memset ( &undi_cleanup, 0, sizeof ( undi_cleanup ) );
		pxeparent_call ( undinet_entry, PXENV_UNDI_CLEANUP,
				 &undi_cleanup, sizeof ( undi_cleanup ) );
		undi->flags &= ~UNDI_FL_INITIALIZED;

		/* Unhook UNDI stack */
		memset ( &stop_undi, 0, sizeof ( stop_undi ) );
		pxeparent_call ( undinet_entry, PXENV_STOP_UNDI, &stop_undi,
				 sizeof ( stop_undi ) );
		undi->flags &= ~UNDI_FL_STARTED;
	}

	/* Clear entry point */
	memset ( &undinet_entry, 0, sizeof ( undinet_entry ) );

	/* Free network device */
	netdev_nullify ( netdev );
	netdev_put ( netdev );

	DBGC ( undinic, "UNDINIC %p removed\n", undinic );
}
