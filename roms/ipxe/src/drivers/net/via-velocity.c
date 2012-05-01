/**************************************************************************
*    via-velocity.c: Etherboot device driver for the VIA 6120 Gigabit
*    Changes for Etherboot port:
*       Copyright (c) 2006 by Timothy Legge <tlegge@rogers.com>
*
*    This program is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software
*    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
*    This driver is based on:
*         via-velocity.c: VIA Velocity VT6120, VT6122 Ethernet driver 
*             The changes are (c) Copyright 2004, Red Hat Inc. 
*                <alan@redhat.com>
*             Additional fixes and clean up: Francois Romieu
*
*     Original code:
*         Copyright (c) 1996, 2003 VIA Networking Technologies, Inc.
*         All rights reserved.
*             Author: Chuang Liang-Shing, AJ Jiang
* 
*    Linux Driver Version 2.6.15.4
* 
*    REVISION HISTORY:
*    ================
*
*    v1.0	03-06-2006	timlegge	Initial port of Linux driver
*    
*    Indent Options: indent -kr -i8
*************************************************************************/

FILE_LICENCE ( GPL2_OR_LATER );

#include "etherboot.h"
#include "nic.h"
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>

#include "via-velocity.h"

typedef int pci_power_t;

#define PCI_D0  ((int) 0)
#define PCI_D1  ((int) 1)
#define PCI_D2  ((int) 2)
#define PCI_D3hot       ((int) 3)
#define PCI_D3cold      ((int) 4)
#define PCI_POWER_ERROR ((int) -1)


/* Condensed operations for readability. */
#define virt_to_le32desc(addr)  cpu_to_le32(virt_to_bus(addr))
#define le32desc_to_virt(addr)  bus_to_virt(le32_to_cpu(addr))

//FIXME: Move to pci.c
int pci_set_power_state(struct pci_device *dev, int state);

/* FIXME: Move BASE to the private structure */
static u32 BASE;

/* NIC specific static variables go here */
#define VELOCITY_PARAM(N,D) \
        static const int N[MAX_UNITS]=OPTION_DEFAULT;
/*        MODULE_PARM(N, "1-" __MODULE_STRING(MAX_UNITS) "i");\
        MODULE_PARM_DESC(N, D); */

VELOCITY_PARAM(RxDescriptors, "Number of receive descriptors");
VELOCITY_PARAM(TxDescriptors, "Number of transmit descriptors");


#define VLAN_ID_MIN     0
#define VLAN_ID_MAX     4095
#define VLAN_ID_DEF     0
/* VID_setting[] is used for setting the VID of NIC.
   0: default VID.
   1-4094: other VIDs.
*/
VELOCITY_PARAM(VID_setting, "802.1Q VLAN ID");

#define RX_THRESH_MIN   0
#define RX_THRESH_MAX   3
#define RX_THRESH_DEF   0
/* rx_thresh[] is used for controlling the receive fifo threshold.
   0: indicate the rxfifo threshold is 128 bytes.
   1: indicate the rxfifo threshold is 512 bytes.
   2: indicate the rxfifo threshold is 1024 bytes.
   3: indicate the rxfifo threshold is store & forward.
*/
VELOCITY_PARAM(rx_thresh, "Receive fifo threshold");

#define DMA_LENGTH_MIN  0
#define DMA_LENGTH_MAX  7
#define DMA_LENGTH_DEF  0

/* DMA_length[] is used for controlling the DMA length
   0: 8 DWORDs
   1: 16 DWORDs
   2: 32 DWORDs
   3: 64 DWORDs
   4: 128 DWORDs
   5: 256 DWORDs
   6: SF(flush till emply)
   7: SF(flush till emply)
*/
VELOCITY_PARAM(DMA_length, "DMA length");

#define TAGGING_DEF     0
/* enable_tagging[] is used for enabling 802.1Q VID tagging.
   0: disable VID seeting(default).
   1: enable VID setting.
*/
VELOCITY_PARAM(enable_tagging, "Enable 802.1Q tagging");

#define IP_ALIG_DEF     0
/* IP_byte_align[] is used for IP header DWORD byte aligned
   0: indicate the IP header won't be DWORD byte aligned.(Default) .
   1: indicate the IP header will be DWORD byte aligned.
      In some enviroment, the IP header should be DWORD byte aligned,
      or the packet will be droped when we receive it. (eg: IPVS)
*/
VELOCITY_PARAM(IP_byte_align, "Enable IP header dword aligned");

#define TX_CSUM_DEF     1
/* txcsum_offload[] is used for setting the checksum offload ability of NIC.
   (We only support RX checksum offload now)
   0: disable csum_offload[checksum offload
   1: enable checksum offload. (Default)
*/
VELOCITY_PARAM(txcsum_offload, "Enable transmit packet checksum offload");

#define FLOW_CNTL_DEF   1
#define FLOW_CNTL_MIN   1
#define FLOW_CNTL_MAX   5

/* flow_control[] is used for setting the flow control ability of NIC.
   1: hardware deafult - AUTO (default). Use Hardware default value in ANAR.
   2: enable TX flow control.
   3: enable RX flow control.
   4: enable RX/TX flow control.
   5: disable
*/
VELOCITY_PARAM(flow_control, "Enable flow control ability");

#define MED_LNK_DEF 0
#define MED_LNK_MIN 0
#define MED_LNK_MAX 4
/* speed_duplex[] is used for setting the speed and duplex mode of NIC.
   0: indicate autonegotiation for both speed and duplex mode
   1: indicate 100Mbps half duplex mode
   2: indicate 100Mbps full duplex mode
   3: indicate 10Mbps half duplex mode
   4: indicate 10Mbps full duplex mode

   Note:
        if EEPROM have been set to the force mode, this option is ignored
            by driver.
*/
VELOCITY_PARAM(speed_duplex, "Setting the speed and duplex mode");

#define VAL_PKT_LEN_DEF     0
/* ValPktLen[] is used for setting the checksum offload ability of NIC.
   0: Receive frame with invalid layer 2 length (Default)
   1: Drop frame with invalid layer 2 length
*/
VELOCITY_PARAM(ValPktLen, "Receiving or Drop invalid 802.3 frame");

#define WOL_OPT_DEF     0
#define WOL_OPT_MIN     0
#define WOL_OPT_MAX     7
/* wol_opts[] is used for controlling wake on lan behavior.
   0: Wake up if recevied a magic packet. (Default)
   1: Wake up if link status is on/off.
   2: Wake up if recevied an arp packet.
   4: Wake up if recevied any unicast packet.
   Those value can be sumed up to support more than one option.
*/
VELOCITY_PARAM(wol_opts, "Wake On Lan options");

#define INT_WORKS_DEF   20
#define INT_WORKS_MIN   10
#define INT_WORKS_MAX   64

VELOCITY_PARAM(int_works, "Number of packets per interrupt services");

/* The descriptors for this card are required to be aligned on
64 byte boundaries.  As the align attribute does not guarantee alignment
greater than the alignment of the start address (which for Etherboot
is 16 bytes of alignment) it requires some extra steps.  Add 64 to the 
size of the array and the init_ring adjusts the alignment */

/* Define the TX Descriptor */
static u8 tx_ring[TX_DESC_DEF * sizeof(struct tx_desc) + 64];

/* Create a static buffer of size PKT_BUF_SZ for each TX Descriptor.  
All descriptors point to a part of this buffer */
static u8 txb[(TX_DESC_DEF * PKT_BUF_SZ) + 64];

/* Define the RX Descriptor */
static u8 rx_ring[RX_DESC_DEF * sizeof(struct rx_desc) + 64];

/* Create a static buffer of size PKT_BUF_SZ for each RX Descriptor
   All descriptors point to a part of this buffer */
static u8 rxb[(RX_DESC_DEF * PKT_BUF_SZ) + 64];

static void velocity_init_info(struct pci_device *pdev,
			       struct velocity_info *vptr,
			       struct velocity_info_tbl *info);
static int velocity_get_pci_info(struct velocity_info *,
				 struct pci_device *pdev);
static int velocity_open(struct nic *nic, struct pci_device *pci);

static int velocity_soft_reset(struct velocity_info *vptr);
static void velocity_init_cam_filter(struct velocity_info *vptr);
static void mii_init(struct velocity_info *vptr, u32 mii_status);
static u32 velocity_get_opt_media_mode(struct velocity_info *vptr);
static void velocity_print_link_status(struct velocity_info *vptr);
static void safe_disable_mii_autopoll(struct mac_regs *regs);
static void enable_flow_control_ability(struct velocity_info *vptr);
static void enable_mii_autopoll(struct mac_regs *regs);
static int velocity_mii_read(struct mac_regs *, u8 byIdx, u16 * pdata);
static int velocity_mii_write(struct mac_regs *, u8 byMiiAddr, u16 data);
static u32 mii_check_media_mode(struct mac_regs *regs);
static u32 check_connection_type(struct mac_regs *regs);
static int velocity_set_media_mode(struct velocity_info *vptr,
				   u32 mii_status);


/*
 *	Internal board variants. At the moment we have only one
 */

static struct velocity_info_tbl chip_info_table[] = {
	{CHIP_TYPE_VT6110,
	 "VIA Networking Velocity Family Gigabit Ethernet Adapter", 256, 1,
	 0x00FFFFFFUL},
	{0, NULL, 0, 0, 0}
};

/**
 *	velocity_set_int_opt	-	parser for integer options
 *	@opt: pointer to option value
 *	@val: value the user requested (or -1 for default)
 *	@min: lowest value allowed
 *	@max: highest value allowed
 *	@def: default value
 *	@name: property name
 *	@dev: device name
 *
 *	Set an integer property in the module options. This function does
 *	all the verification and checking as well as reporting so that
 *	we don't duplicate code for each option.
 */

static void velocity_set_int_opt(int *opt, int val, int min, int max,
				 int def, char *name, const char *devname)
{
	if (val == -1) {
		printf("%s: set value of parameter %s to %d\n",
		       devname, name, def);
		*opt = def;
	} else if (val < min || val > max) {
		printf
		    ("%s: the value of parameter %s is invalid, the valid range is (%d-%d)\n",
		     devname, name, min, max);
		*opt = def;
	} else {
		printf("%s: set value of parameter %s to %d\n",
		       devname, name, val);
		*opt = val;
	}
}

/**
 *	velocity_set_bool_opt	-	parser for boolean options
 *	@opt: pointer to option value
 *	@val: value the user requested (or -1 for default)
 *	@def: default value (yes/no)
 *	@flag: numeric value to set for true.
 *	@name: property name
 *	@dev: device name
 *
 *	Set a boolean property in the module options. This function does
 *	all the verification and checking as well as reporting so that
 *	we don't duplicate code for each option.
 */

static void velocity_set_bool_opt(u32 * opt, int val, int def, u32 flag,
				  char *name, const char *devname)
{
	(*opt) &= (~flag);
	if (val == -1) {
		printf("%s: set parameter %s to %s\n",
		       devname, name, def ? "TRUE" : "FALSE");
		*opt |= (def ? flag : 0);
	} else if (val < 0 || val > 1) {
		printf
		    ("%s: the value of parameter %s is invalid, the valid range is (0-1)\n",
		     devname, name);
		*opt |= (def ? flag : 0);
	} else {
		printf("%s: set parameter %s to %s\n",
		       devname, name, val ? "TRUE" : "FALSE");
		*opt |= (val ? flag : 0);
	}
}

/**
 *	velocity_get_options	-	set options on device
 *	@opts: option structure for the device
 *	@index: index of option to use in module options array
 *	@devname: device name
 *
 *	Turn the module and command options into a single structure
 *	for the current device
 */

static void velocity_get_options(struct velocity_opt *opts, int index,
				 const char *devname)
{

	/* FIXME Do the options need to be configurable */
	velocity_set_int_opt(&opts->rx_thresh, -1, RX_THRESH_MIN,
			     RX_THRESH_MAX, RX_THRESH_DEF, "rx_thresh",
			     devname);
	velocity_set_int_opt(&opts->DMA_length, DMA_length[index],
			     DMA_LENGTH_MIN, DMA_LENGTH_MAX,
			     DMA_LENGTH_DEF, "DMA_length", devname);
	velocity_set_int_opt(&opts->numrx, RxDescriptors[index],
			     RX_DESC_MIN, RX_DESC_MAX, RX_DESC_DEF,
			     "RxDescriptors", devname);
	velocity_set_int_opt(&opts->numtx, TxDescriptors[index],
			     TX_DESC_MIN, TX_DESC_MAX, TX_DESC_DEF,
			     "TxDescriptors", devname);
	velocity_set_int_opt(&opts->vid, VID_setting[index], VLAN_ID_MIN,
			     VLAN_ID_MAX, VLAN_ID_DEF, "VID_setting",
			     devname);
	velocity_set_bool_opt(&opts->flags, enable_tagging[index],
			      TAGGING_DEF, VELOCITY_FLAGS_TAGGING,
			      "enable_tagging", devname);
	velocity_set_bool_opt(&opts->flags, txcsum_offload[index],
			      TX_CSUM_DEF, VELOCITY_FLAGS_TX_CSUM,
			      "txcsum_offload", devname);
	velocity_set_int_opt(&opts->flow_cntl, flow_control[index],
			     FLOW_CNTL_MIN, FLOW_CNTL_MAX, FLOW_CNTL_DEF,
			     "flow_control", devname);
	velocity_set_bool_opt(&opts->flags, IP_byte_align[index],
			      IP_ALIG_DEF, VELOCITY_FLAGS_IP_ALIGN,
			      "IP_byte_align", devname);
	velocity_set_bool_opt(&opts->flags, ValPktLen[index],
			      VAL_PKT_LEN_DEF, VELOCITY_FLAGS_VAL_PKT_LEN,
			      "ValPktLen", devname);
	velocity_set_int_opt((void *) &opts->spd_dpx, speed_duplex[index],
			     MED_LNK_MIN, MED_LNK_MAX, MED_LNK_DEF,
			     "Media link mode", devname);
	velocity_set_int_opt((int *) &opts->wol_opts, wol_opts[index],
			     WOL_OPT_MIN, WOL_OPT_MAX, WOL_OPT_DEF,
			     "Wake On Lan options", devname);
	velocity_set_int_opt((int *) &opts->int_works, int_works[index],
			     INT_WORKS_MIN, INT_WORKS_MAX, INT_WORKS_DEF,
			     "Interrupt service works", devname);
	opts->numrx = (opts->numrx & ~3);
}

/**
 *	velocity_init_cam_filter	-	initialise CAM
 *	@vptr: velocity to program
 *
 *	Initialize the content addressable memory used for filters. Load
 *	appropriately according to the presence of VLAN
 */

static void velocity_init_cam_filter(struct velocity_info *vptr)
{
	struct mac_regs *regs = vptr->mac_regs;

	/* Turn on MCFG_PQEN, turn off MCFG_RTGOPT */
	WORD_REG_BITS_SET(MCFG_PQEN, MCFG_RTGOPT, &regs->MCFG);
	WORD_REG_BITS_ON(MCFG_VIDFR, &regs->MCFG);

	/* Disable all CAMs */
	memset(vptr->vCAMmask, 0, sizeof(u8) * 8);
	memset(vptr->mCAMmask, 0, sizeof(u8) * 8);
	mac_set_cam_mask(regs, vptr->vCAMmask, VELOCITY_VLAN_ID_CAM);
	mac_set_cam_mask(regs, vptr->mCAMmask, VELOCITY_MULTICAST_CAM);

	/* Enable first VCAM */
	if (vptr->flags & VELOCITY_FLAGS_TAGGING) {
		/* If Tagging option is enabled and VLAN ID is not zero, then
		   turn on MCFG_RTGOPT also */
		if (vptr->options.vid != 0)
			WORD_REG_BITS_ON(MCFG_RTGOPT, &regs->MCFG);

		mac_set_cam(regs, 0, (u8 *) & (vptr->options.vid),
			    VELOCITY_VLAN_ID_CAM);
		vptr->vCAMmask[0] |= 1;
		mac_set_cam_mask(regs, vptr->vCAMmask,
				 VELOCITY_VLAN_ID_CAM);
	} else {
		u16 temp = 0;
		mac_set_cam(regs, 0, (u8 *) & temp, VELOCITY_VLAN_ID_CAM);
		temp = 1;
		mac_set_cam_mask(regs, (u8 *) & temp,
				 VELOCITY_VLAN_ID_CAM);
	}
}

static inline void velocity_give_many_rx_descs(struct velocity_info *vptr)
{
	struct mac_regs *regs = vptr->mac_regs;
	int avail, dirty, unusable;

	/*
	 * RD number must be equal to 4X per hardware spec
	 * (programming guide rev 1.20, p.13)
	 */
	if (vptr->rd_filled < 4)
		return;

	wmb();

	unusable = vptr->rd_filled & 0x0003;
	dirty = vptr->rd_dirty - unusable;
	for (avail = vptr->rd_filled & 0xfffc; avail; avail--) {
		dirty = (dirty > 0) ? dirty - 1 : vptr->options.numrx - 1;
//              printf("return dirty: %d\n", dirty);
		vptr->rd_ring[dirty].rdesc0.owner = OWNED_BY_NIC;
	}

	writew(vptr->rd_filled & 0xfffc, &regs->RBRDU);
	vptr->rd_filled = unusable;
}

static int velocity_rx_refill(struct velocity_info *vptr)
{
	int dirty = vptr->rd_dirty, done = 0, ret = 0;

//      printf("rx_refill - rd_curr = %d, dirty = %d\n", vptr->rd_curr, dirty);
	do {
		struct rx_desc *rd = vptr->rd_ring + dirty;

		/* Fine for an all zero Rx desc at init time as well */
		if (rd->rdesc0.owner == OWNED_BY_NIC)
			break;
//              printf("rx_refill - after owner %d\n", dirty);

		rd->inten = 1;
		rd->pa_high = 0;
		rd->rdesc0.len = cpu_to_le32(vptr->rx_buf_sz);;

		done++;
		dirty = (dirty < vptr->options.numrx - 1) ? dirty + 1 : 0;
	} while (dirty != vptr->rd_curr);

	if (done) {
//              printf("\nGive Back Desc\n");
		vptr->rd_dirty = dirty;
		vptr->rd_filled += done;
		velocity_give_many_rx_descs(vptr);
	}

	return ret;
}

extern void hex_dump(const char *data, const unsigned int len);
/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static int velocity_poll(struct nic *nic, int retrieve)
{
	/* Work out whether or not there's an ethernet packet ready to
	 * read.  Return 0 if not.
	 */

	int rd_curr = vptr->rd_curr % RX_DESC_DEF;
	struct rx_desc *rd = &(vptr->rd_ring[rd_curr]);

	if (rd->rdesc0.owner == OWNED_BY_NIC)
		return 0;
	rmb();

	if ( ! retrieve ) return 1;

	/*
	 *      Don't drop CE or RL error frame although RXOK is off
	 */
	if ((rd->rdesc0.RSR & RSR_RXOK)
	    || (!(rd->rdesc0.RSR & RSR_RXOK)
		&& (rd->rdesc0.RSR & (RSR_CE | RSR_RL)))) {

		nic->packetlen = rd->rdesc0.len;
		// ptr->rxb + (rd_curr * PKT_BUF_SZ)
		memcpy(nic->packet, bus_to_virt(rd->pa_low),
		       nic->packetlen - 4);

		vptr->rd_curr++;
		vptr->rd_curr = vptr->rd_curr % RX_DESC_DEF;
		velocity_rx_refill(vptr);
		return 1;	/* Remove this line once this method is implemented */
	}
	return 0;
}

#define TX_TIMEOUT  (1000);
/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static void velocity_transmit(struct nic *nic, const char *dest,	/* Destination */
			      unsigned int type,	/* Type */
			      unsigned int size,	/* size */
			      const char *packet)
{				/* Packet */
	u16 nstype;
	u32 to;
	u8 *ptxb;
	unsigned int pktlen;
	struct tx_desc *td_ptr;

	int entry = vptr->td_curr % TX_DESC_DEF;
	td_ptr = &(vptr->td_rings[entry]);

	/* point to the current txb incase multiple tx_rings are used */
	ptxb = vptr->txb + (entry * PKT_BUF_SZ);
	memcpy(ptxb, dest, ETH_ALEN);	/* Destination */
	memcpy(ptxb + ETH_ALEN, nic->node_addr, ETH_ALEN);	/* Source */
	nstype = htons((u16) type);	/* Type */
	memcpy(ptxb + 2 * ETH_ALEN, (u8 *) & nstype, 2);	/* Type */
	memcpy(ptxb + ETH_HLEN, packet, size);

	td_ptr->tdesc1.TCPLS = TCPLS_NORMAL;
	td_ptr->tdesc1.TCR = TCR0_TIC;
	td_ptr->td_buf[0].queue = 0;

	size += ETH_HLEN;
	while (size < ETH_ZLEN)	/* pad to min length */
		ptxb[size++] = '\0';

	if (size < ETH_ZLEN) {
//              printf("Padd that packet\n");
		pktlen = ETH_ZLEN;
//                memcpy(ptxb, skb->data, skb->len);
		memset(ptxb + size, 0, ETH_ZLEN - size);

		vptr->td_rings[entry].tdesc0.pktsize = pktlen;
		vptr->td_rings[entry].td_buf[0].pa_low = virt_to_bus(ptxb);
		vptr->td_rings[entry].td_buf[0].pa_high &=
		    cpu_to_le32(0xffff0000UL);
		vptr->td_rings[entry].td_buf[0].bufsize =
		    vptr->td_rings[entry].tdesc0.pktsize;
		vptr->td_rings[entry].tdesc1.CMDZ = 2;
	} else {
//              printf("Correct size packet\n");
		td_ptr->tdesc0.pktsize = size;
		td_ptr->td_buf[0].pa_low = virt_to_bus(ptxb);
		td_ptr->td_buf[0].pa_high = 0;
		td_ptr->td_buf[0].bufsize = td_ptr->tdesc0.pktsize;
//                tdinfo->nskb_dma = 1;
		td_ptr->tdesc1.CMDZ = 2;
	}

	if (vptr->flags & VELOCITY_FLAGS_TAGGING) {
		td_ptr->tdesc1.pqinf.VID = (vptr->options.vid & 0xfff);
		td_ptr->tdesc1.pqinf.priority = 0;
		td_ptr->tdesc1.pqinf.CFI = 0;
		td_ptr->tdesc1.TCR |= TCR0_VETAG;
	}

	vptr->td_curr = (entry + 1);

	{

		int prev = entry - 1;

		if (prev < 0)
			prev = TX_DESC_DEF - 1;
		td_ptr->tdesc0.owner |= OWNED_BY_NIC;
		td_ptr = &(vptr->td_rings[prev]);
		td_ptr->td_buf[0].queue = 1;
		mac_tx_queue_wake(vptr->mac_regs, 0);

	}

	to = currticks() + TX_TIMEOUT;
	while ((td_ptr->tdesc0.owner & OWNED_BY_NIC) && (currticks() < to));	/* wait */

	if (currticks() >= to) {
		printf("TX Time Out");
	}

}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void velocity_disable(struct nic *nic __unused)
{
	/* put the card in its initial state */
	/* This function serves 3 purposes.
	 * This disables DMA and interrupts so we don't receive
	 *  unexpected packets or interrupts from the card after
	 *  etherboot has finished. 
	 * This frees resources so etherboot may use
	 *  this driver on another interface
	 * This allows etherboot to reinitialize the interface
	 *  if something is something goes wrong.
	 */
	struct mac_regs *regs = vptr->mac_regs;
	mac_disable_int(regs);
	writel(CR0_STOP, &regs->CR0Set);
	writew(0xFFFF, &regs->TDCSRClr);
	writeb(0xFF, &regs->RDCSRClr);
	safe_disable_mii_autopoll(regs);
	mac_clear_isr(regs);

	/* Power down the chip */
//      pci_set_power_state(vptr->pdev, PCI_D3hot);

	vptr->flags &= (~VELOCITY_FLAGS_OPENED);
}

/**************************************************************************
IRQ - handle interrupts
***************************************************************************/
static void velocity_irq(struct nic *nic __unused, irq_action_t action)
{
	/* This routine is somewhat optional.  Etherboot itself
	 * doesn't use interrupts, but they are required under some
	 * circumstances when we're acting as a PXE stack.
	 *
	 * If you don't implement this routine, the only effect will
	 * be that your driver cannot be used via Etherboot's UNDI
	 * API.  This won't affect programs that use only the UDP
	 * portion of the PXE API, such as pxelinux.
	 */

	switch (action) {
	case DISABLE:
	case ENABLE:
		/* Set receive interrupt enabled/disabled state */
		/*
		   outb ( action == ENABLE ? IntrMaskEnabled : IntrMaskDisabled,
		   nic->ioaddr + IntrMaskRegister );
		 */
		break;
	case FORCE:
		/* Force NIC to generate a receive interrupt */
		/*
		   outb ( ForceInterrupt, nic->ioaddr + IntrForceRegister );
		 */
		break;
	}
}

static struct nic_operations velocity_operations = {
	.connect	= dummy_connect,
	.poll		= velocity_poll,
	.transmit	= velocity_transmit,
	.irq		= velocity_irq,
};

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
***************************************************************************/
static int velocity_probe( struct nic *nic, struct pci_device *pci)
{
	int ret, i;
	struct mac_regs *regs;

	printf("via-velocity.c: Found %s Vendor=0x%hX Device=0x%hX\n",
	       pci->id->name, pci->vendor, pci->device);

	/* point to private storage */
	vptr = &vptx;
	info = chip_info_table;

	velocity_init_info(pci, vptr, info);

//FIXME: pci_enable_device(pci);
//FIXME: pci_set_power_state(pci, PCI_D0);

	ret = velocity_get_pci_info(vptr, pci);
	if (ret < 0) {
		printf("Failed to find PCI device.\n");
		return 0;
	}

	regs = ioremap(vptr->memaddr, vptr->io_size);
	if (regs == NULL) {
		printf("Unable to remap io\n");
		return 0;
	}

	vptr->mac_regs = regs;

	BASE = vptr->ioaddr;

	printf("Chip ID: %hX\n", vptr->chip_id);

	for (i = 0; i < 6; i++)
		nic->node_addr[i] = readb(&regs->PAR[i]);

	DBG ( "%s: %s at ioaddr %#hX\n", pci->id->name, eth_ntoa ( nic->node_addr ),
	      (unsigned int) BASE );

	velocity_get_options(&vptr->options, 0, pci->id->name);

	/* 
	 *      Mask out the options cannot be set to the chip
	 */
	vptr->options.flags &= 0x00FFFFFFUL;	//info->flags = 0x00FFFFFFUL;

	/*
	 *      Enable the chip specified capbilities
	 */

	vptr->flags =
	    vptr->options.
	    flags | (0x00FFFFFFUL /*info->flags */  & 0xFF000000UL);

	vptr->wol_opts = vptr->options.wol_opts;
	vptr->flags |= VELOCITY_FLAGS_WOL_ENABLED;

	vptr->phy_id = MII_GET_PHY_ID(vptr->mac_regs);

	if (vptr->flags & VELOCITY_FLAGS_TX_CSUM) {
		printf("features missing\n");
	}

	/* and leave the chip powered down */
// FIXME:       pci_set_power_state(pci, PCI_D3hot);

	check_connection_type(vptr->mac_regs);
	velocity_open(nic, pci);

	/* store NIC parameters */
	nic->nic_op = &velocity_operations;
	return 1;
}

//#define IORESOURCE_IO              0x00000100      /* Resource type */

/**
 *	velocity_init_info	-	init private data
 *	@pdev: PCI device
 *	@vptr: Velocity info
 *	@info: Board type
 *
 *	Set up the initial velocity_info struct for the device that has been
 *	discovered.
 */

static void velocity_init_info(struct pci_device *pdev,
			       struct velocity_info *vptr,
			       struct velocity_info_tbl *info)
{
	memset(vptr, 0, sizeof(struct velocity_info));

	vptr->pdev = pdev;
	vptr->chip_id = info->chip_id;
	vptr->io_size = info->io_size;
	vptr->num_txq = info->txqueue;
	vptr->multicast_limit = MCAM_SIZE;

	printf
	    ("chip_id: 0x%hX, io_size: %d, num_txq %d, multicast_limit: %d\n",
	     vptr->chip_id, (unsigned int) vptr->io_size, vptr->num_txq,
	     vptr->multicast_limit);
	printf("Name: %s\n", info->name);

//      spin_lock_init(&vptr->lock);
//      INIT_LIST_HEAD(&vptr->list);
}

/**
 *	velocity_get_pci_info	-	retrieve PCI info for device
 *	@vptr: velocity device
 *	@pdev: PCI device it matches
 *
 *	Retrieve the PCI configuration space data that interests us from
 *	the kernel PCI layer
 */

#define IORESOURCE_IO   0x00000100	/* Resource type */
#define IORESOURCE_PREFETCH        0x00001000	/* No side effects */

#define IORESOURCE_MEM             0x00000200
#define BAR_0           0
#define BAR_1           1
#define BAR_5           5
#define  PCI_BASE_ADDRESS_SPACE 0x01	/* 0 = memory, 1 = I/O */
#define  PCI_BASE_ADDRESS_SPACE_IO 0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY 0x00
#define  PCI_BASE_ADDRESS_MEM_TYPE_MASK 0x06
#define  PCI_BASE_ADDRESS_MEM_TYPE_32   0x00	/* 32 bit address */
#define  PCI_BASE_ADDRESS_MEM_TYPE_1M   0x02	/* Below 1M [obsolete] */
#define  PCI_BASE_ADDRESS_MEM_TYPE_64   0x04	/* 64 bit address */
#define  PCI_BASE_ADDRESS_MEM_PREFETCH  0x08	/* prefetchable? */
//#define  PCI_BASE_ADDRESS_MEM_MASK      (~0x0fUL)
// #define  PCI_BASE_ADDRESS_IO_MASK       (~0x03UL)

unsigned long pci_resource_flags(struct pci_device *pdev, unsigned int bar)
{
	uint32_t l, sz;
	unsigned long flags = 0;

	pci_read_config_dword(pdev, bar, &l);
	pci_write_config_dword(pdev, bar, ~0);
	pci_read_config_dword(pdev, bar, &sz);
	pci_write_config_dword(pdev, bar, l);

	if (!sz || sz == 0xffffffff)
		printf("Weird size\n");
	if (l == 0xffffffff)
		l = 0;
	if ((l & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_MEMORY) {
		/*    sz = pci_size(l, sz, PCI_BASE_ADDRESS_MEM_MASK);
		   if (!sz)
		   continue;
		   res->start = l & PCI_BASE_ADDRESS_MEM_MASK;
		 */ flags |= l & ~PCI_BASE_ADDRESS_MEM_MASK;
		printf("Memory Resource\n");
	} else {
		//            sz = pci_size(l, sz, PCI_BASE_ADDRESS_IO_MASK & 0xffff);
		///         if (!sz)
		///              continue;
//              res->start = l & PCI_BASE_ADDRESS_IO_MASK;
		flags |= l & ~PCI_BASE_ADDRESS_IO_MASK;
		printf("I/O Resource\n");
	}
	if (flags & PCI_BASE_ADDRESS_SPACE_IO) {
		printf("Why is it here\n");
		flags |= IORESOURCE_IO;
	} else {
		printf("here\n");
//flags &= ~IORESOURCE_IO;
	}


	if (flags & PCI_BASE_ADDRESS_MEM_PREFETCH)
		flags |= IORESOURCE_MEM | IORESOURCE_PREFETCH;


	return flags;
}
static int velocity_get_pci_info(struct velocity_info *vptr,
				 struct pci_device *pdev)
{
	if (pci_read_config_byte(pdev, PCI_REVISION_ID, &vptr->rev_id) < 0) {
		printf("DEBUG: pci_read_config_byte failed\n");
		return -1;
	}

	adjust_pci_device(pdev);

	vptr->ioaddr = pci_bar_start(pdev, PCI_BASE_ADDRESS_0);
	vptr->memaddr = pci_bar_start(pdev, PCI_BASE_ADDRESS_1);

	printf("Looking for I/O Resource - Found:");
	if (!
	    (pci_resource_flags(pdev, PCI_BASE_ADDRESS_0) & IORESOURCE_IO))
	{
		printf
		    ("DEBUG: region #0 is not an I/O resource, aborting.\n");
		return -1;
	}

	printf("Looking for Memory Resource - Found:");
	if ((pci_resource_flags(pdev, PCI_BASE_ADDRESS_1) & IORESOURCE_IO)) {
		printf("DEBUG: region #1 is an I/O resource, aborting.\n");
		return -1;
	}

	if (pci_bar_size(pdev, PCI_BASE_ADDRESS_1) < 256) {
		printf("DEBUG: region #1 is too small.\n");
		return -1;
	}
	vptr->pdev = pdev;

	return 0;
}

/**
 *	velocity_print_link_status	-	link status reporting
 *	@vptr: velocity to report on
 *
 *	Turn the link status of the velocity card into a kernel log
 *	description of the new link state, detailing speed and duplex
 *	status
 */

static void velocity_print_link_status(struct velocity_info *vptr)
{

	if (vptr->mii_status & VELOCITY_LINK_FAIL) {
		printf("failed to detect cable link\n");
	} else if (vptr->options.spd_dpx == SPD_DPX_AUTO) {
		printf("Link autonegation");

		if (vptr->mii_status & VELOCITY_SPEED_1000)
			printf(" speed 1000M bps");
		else if (vptr->mii_status & VELOCITY_SPEED_100)
			printf(" speed 100M bps");
		else
			printf(" speed 10M bps");

		if (vptr->mii_status & VELOCITY_DUPLEX_FULL)
			printf(" full duplex\n");
		else
			printf(" half duplex\n");
	} else {
		printf("Link forced");
		switch (vptr->options.spd_dpx) {
		case SPD_DPX_100_HALF:
			printf(" speed 100M bps half duplex\n");
			break;
		case SPD_DPX_100_FULL:
			printf(" speed 100M bps full duplex\n");
			break;
		case SPD_DPX_10_HALF:
			printf(" speed 10M bps half duplex\n");
			break;
		case SPD_DPX_10_FULL:
			printf(" speed 10M bps full duplex\n");
			break;
		default:
			break;
		}
	}
}

/**
 *	velocity_rx_reset	-	handle a receive reset
 *	@vptr: velocity we are resetting
 *
 *	Reset the ownership and status for the receive ring side.
 *	Hand all the receive queue to the NIC.
 */

static void velocity_rx_reset(struct velocity_info *vptr)
{

	struct mac_regs *regs = vptr->mac_regs;
	int i;

//ptr->rd_dirty = vptr->rd_filled = vptr->rd_curr = 0;

	/*
	 *      Init state, all RD entries belong to the NIC
	 */
	for (i = 0; i < vptr->options.numrx; ++i)
		vptr->rd_ring[i].rdesc0.owner = OWNED_BY_NIC;

	writew(RX_DESC_DEF, &regs->RBRDU);
	writel(virt_to_le32desc(vptr->rd_ring), &regs->RDBaseLo);
	writew(0, &regs->RDIdx);
	writew(RX_DESC_DEF - 1, &regs->RDCSize);
}

/**
 *	velocity_init_registers	-	initialise MAC registers
 *	@vptr: velocity to init
 *	@type: type of initialisation (hot or cold)
 *
 *	Initialise the MAC on a reset or on first set up on the
 *	hardware.
 */

static void velocity_init_registers(struct nic *nic,
				    struct velocity_info *vptr,
				    enum velocity_init_type type)
{
	struct mac_regs *regs = vptr->mac_regs;
	int i, mii_status;

	mac_wol_reset(regs);

	switch (type) {
	case VELOCITY_INIT_RESET:
	case VELOCITY_INIT_WOL:

//netif_stop_queue(vptr->dev);

		/*
		 *      Reset RX to prevent RX pointer not on the 4X location
		 */
		velocity_rx_reset(vptr);
		mac_rx_queue_run(regs);
		mac_rx_queue_wake(regs);

		mii_status = velocity_get_opt_media_mode(vptr);

		if (velocity_set_media_mode(vptr, mii_status) !=
		    VELOCITY_LINK_CHANGE) {
			velocity_print_link_status(vptr);
			if (!(vptr->mii_status & VELOCITY_LINK_FAIL))
				printf("Link Failed\n");
//                              netif_wake_queue(vptr->dev);
		}

		enable_flow_control_ability(vptr);

		mac_clear_isr(regs);
		writel(CR0_STOP, &regs->CR0Clr);
		//writel((CR0_DPOLL | CR0_TXON | CR0_RXON | CR0_STRT), 
		writel((CR0_DPOLL | CR0_TXON | CR0_RXON | CR0_STRT),
		       &regs->CR0Set);
		break;

	case VELOCITY_INIT_COLD:
	default:
		/*
		 *      Do reset
		 */
		velocity_soft_reset(vptr);
		mdelay(5);

		mac_eeprom_reload(regs);
		for (i = 0; i < 6; i++) {
			writeb(nic->node_addr[i], &(regs->PAR[i]));
		}
		/*
		 *      clear Pre_ACPI bit.
		 */
		BYTE_REG_BITS_OFF(CFGA_PACPI, &(regs->CFGA));
		mac_set_rx_thresh(regs, vptr->options.rx_thresh);
		mac_set_dma_length(regs, vptr->options.DMA_length);

		writeb(WOLCFG_SAM | WOLCFG_SAB, &regs->WOLCFGSet);
		/*
		 *      Back off algorithm use original IEEE standard
		 */
		BYTE_REG_BITS_SET(CFGB_OFSET,
				  (CFGB_CRANDOM | CFGB_CAP | CFGB_MBA |
				   CFGB_BAKOPT), &regs->CFGB);

		/*
		 *      Init CAM filter
		 */
		velocity_init_cam_filter(vptr);

		/*
		 *      Set packet filter: Receive directed and broadcast address
		 */
//FIXME Multicast               velocity_set_multi(nic);

		/*
		 *      Enable MII auto-polling
		 */
		enable_mii_autopoll(regs);

		vptr->int_mask = INT_MASK_DEF;

		writel(virt_to_le32desc(vptr->rd_ring), &regs->RDBaseLo);
		writew(vptr->options.numrx - 1, &regs->RDCSize);
		mac_rx_queue_run(regs);
		mac_rx_queue_wake(regs);

		writew(vptr->options.numtx - 1, &regs->TDCSize);

//              for (i = 0; i < vptr->num_txq; i++) {
		writel(virt_to_le32desc(vptr->td_rings),
		       &(regs->TDBaseLo[0]));
		mac_tx_queue_run(regs, 0);
//              }

		init_flow_control_register(vptr);

		writel(CR0_STOP, &regs->CR0Clr);
		writel((CR0_DPOLL | CR0_TXON | CR0_RXON | CR0_STRT),
		       &regs->CR0Set);

		mii_status = velocity_get_opt_media_mode(vptr);
//              netif_stop_queue(vptr->dev);

		mii_init(vptr, mii_status);

		if (velocity_set_media_mode(vptr, mii_status) !=
		    VELOCITY_LINK_CHANGE) {
			velocity_print_link_status(vptr);
			if (!(vptr->mii_status & VELOCITY_LINK_FAIL))
				printf("Link Faaailll\n");
//                              netif_wake_queue(vptr->dev);
		}

		enable_flow_control_ability(vptr);
		mac_hw_mibs_init(regs);
		mac_write_int_mask(vptr->int_mask, regs);
		mac_clear_isr(regs);


	}
	velocity_print_link_status(vptr);
}

/**
 *	velocity_soft_reset	-	soft reset
 *	@vptr: velocity to reset
 *
 *	Kick off a soft reset of the velocity adapter and then poll
 *	until the reset sequence has completed before returning.
 */

static int velocity_soft_reset(struct velocity_info *vptr)
{
	struct mac_regs *regs = vptr->mac_regs;
	unsigned int i = 0;

	writel(CR0_SFRST, &regs->CR0Set);

	for (i = 0; i < W_MAX_TIMEOUT; i++) {
		udelay(5);
		if (!DWORD_REG_BITS_IS_ON(CR0_SFRST, &regs->CR0Set))
			break;
	}

	if (i == W_MAX_TIMEOUT) {
		writel(CR0_FORSRST, &regs->CR0Set);
		/* FIXME: PCI POSTING */
		/* delay 2ms */
		mdelay(2);
	}
	return 0;
}

/**
 *	velocity_init_rings	-	set up DMA rings
 *	@vptr: Velocity to set up
 *
 *	Allocate PCI mapped DMA rings for the receive and transmit layer
 *	to use.
 */

static int velocity_init_rings(struct velocity_info *vptr)
{

	int idx;

	vptr->rd_curr = 0;
	vptr->td_curr = 0;
	memset(vptr->td_rings, 0, TX_DESC_DEF * sizeof(struct tx_desc));
	memset(vptr->rd_ring, 0, RX_DESC_DEF * sizeof(struct rx_desc));
//      memset(vptr->tx_buffs, 0, TX_DESC_DEF * PKT_BUF_SZ);


	for (idx = 0; idx < RX_DESC_DEF; idx++) {
		vptr->rd_ring[idx].rdesc0.RSR = 0;
		vptr->rd_ring[idx].rdesc0.len = 0;
		vptr->rd_ring[idx].rdesc0.reserved = 0;
		vptr->rd_ring[idx].rdesc0.owner = 0;
		vptr->rd_ring[idx].len = cpu_to_le32(vptr->rx_buf_sz);
		vptr->rd_ring[idx].inten = 1;
		vptr->rd_ring[idx].pa_low =
		    virt_to_bus(vptr->rxb + (RX_DESC_DEF * idx));
		vptr->rd_ring[idx].pa_high = 0;
		vptr->rd_ring[idx].rdesc0.owner = OWNED_BY_NIC;
	}

/*	for (i = 0; idx < TX_DESC_DEF; idx++ ) {
		vptr->td_rings[idx].tdesc1.TCPLS = TCPLS_NORMAL;
		vptr->td_rings[idx].tdesc1.TCR = TCR0_TIC;
		vptr->td_rings[idx].td_buf[0].queue = 0;
		vptr->td_rings[idx].tdesc0.owner = ~OWNED_BY_NIC;
		vptr->td_rings[idx].tdesc0.pktsize = 0;
		vptr->td_rings[idx].td_buf[0].pa_low = cpu_to_le32(virt_to_bus(vptr->txb + (idx * PKT_BUF_SZ)));
		vptr->td_rings[idx].td_buf[0].pa_high = 0;
		vptr->td_rings[idx].td_buf[0].bufsize = 0;
		vptr->td_rings[idx].tdesc1.CMDZ = 2;
	}
*/
	return 0;
}

/**
 *	velocity_open		-	interface activation callback
 *	@dev: network layer device to open
 *
 *	Called when the network layer brings the interface up. Returns
 *	a negative posix error code on failure, or zero on success.
 *
 *	All the ring allocation and set up is done on open for this
 *	adapter to minimise memory usage when inactive
 */

#define PCI_BYTE_REG_BITS_ON(x,i,p) do{\
    u8 byReg;\
    pci_read_config_byte((p), (i), &(byReg));\
    (byReg) |= (x);\
    pci_write_config_byte((p), (i), (byReg));\
} while (0)

//
// Registers in the PCI configuration space
//
#define PCI_REG_COMMAND         0x04	//
#define PCI_REG_MODE0           0x60	//
#define PCI_REG_MODE1           0x61	//
#define PCI_REG_MODE2           0x62	//
#define PCI_REG_MODE3           0x63	//
#define PCI_REG_DELAY_TIMER     0x64	//

// Bits in the (MODE2, 0x62) register
//
#define MODE2_PCEROPT       0x80	// take PCI bus ERror as a fatal and shutdown from software control
#define MODE2_TXQ16         0x40	// TX write-back Queue control. 0->32 entries available in Tx write-back queue, 1->16 entries
#define MODE2_TXPOST        0x08	// (Not support in VT3119)
#define MODE2_AUTOOPT       0x04	// (VT3119 GHCI without such behavior)
#define MODE2_MODE10T       0x02	// used to control tx Threshold for 10M case
#define MODE2_TCPLSOPT      0x01	// TCP large send field update disable, hardware will not update related fields, leave it to software.

//
// Bits in the MODE3 register
//
#define MODE3_MIION         0x04	// MII symbol codine error detect enable ??

// Bits in the (COMMAND, 0x04) register
#define COMMAND_BUSM        0x04
#define COMMAND_WAIT        0x80
static int velocity_open(struct nic *nic, struct pci_device *pci __unused)
{
	u8 diff;
	u32 TxPhyAddr, RxPhyAddr;
	u32 TxBufPhyAddr, RxBufPhyAddr;
	vptr->TxDescArrays = tx_ring;
	if (vptr->TxDescArrays == 0)
		printf("Allot Error");

	/* Tx Descriptor needs 64 bytes alignment; */
	TxPhyAddr = virt_to_bus(vptr->TxDescArrays);
	printf("Unaligned Address : %X\n", TxPhyAddr);
	diff = 64 - (TxPhyAddr - ((TxPhyAddr >> 6) << 6));
	TxPhyAddr += diff;
	vptr->td_rings = (struct tx_desc *) (vptr->TxDescArrays + diff);

	printf("Aligned Address: %lX\n", virt_to_bus(vptr->td_rings));
	vptr->tx_buffs = txb;
	/* Rx Buffer needs 64 bytes alignment; */
	TxBufPhyAddr = virt_to_bus(vptr->tx_buffs);
	diff = 64 - (TxBufPhyAddr - ((TxBufPhyAddr >> 6) << 6));
	TxBufPhyAddr += diff;
	vptr->txb = (unsigned char *) (vptr->tx_buffs + diff);

	vptr->RxDescArrays = rx_ring;
	/* Rx Descriptor needs 64 bytes alignment; */
	RxPhyAddr = virt_to_bus(vptr->RxDescArrays);
	diff = 64 - (RxPhyAddr - ((RxPhyAddr >> 6) << 6));
	RxPhyAddr += diff;
	vptr->rd_ring = (struct rx_desc *) (vptr->RxDescArrays + diff);

	vptr->rx_buffs = rxb;
	/* Rx Buffer needs 64 bytes alignment; */
	RxBufPhyAddr = virt_to_bus(vptr->rx_buffs);
	diff = 64 - (RxBufPhyAddr - ((RxBufPhyAddr >> 6) << 6));
	RxBufPhyAddr += diff;
	vptr->rxb = (unsigned char *) (vptr->rx_buffs + diff);

	if (vptr->RxDescArrays == NULL || vptr->RxDescArrays == NULL) {
		printf("Allocate tx_ring or rd_ring failed\n");
		return 0;
	}

	vptr->rx_buf_sz = PKT_BUF_SZ;
/*
    // turn this on to avoid retry forever
    PCI_BYTE_REG_BITS_ON(MODE2_PCEROPT, PCI_REG_MODE2, pci);
    // for some legacy BIOS and OS don't open BusM
    // bit in PCI configuration space. So, turn it on.
    PCI_BYTE_REG_BITS_ON(COMMAND_BUSM, PCI_REG_COMMAND, pci);
    // turn this on to detect MII coding error
    PCI_BYTE_REG_BITS_ON(MODE3_MIION, PCI_REG_MODE3, pci);
 */
	velocity_init_rings(vptr);

	/* Ensure chip is running */
//FIXME:        pci_set_power_state(vptr->pdev, PCI_D0);

	velocity_init_registers(nic, vptr, VELOCITY_INIT_COLD);
	mac_write_int_mask(0, vptr->mac_regs);
//      _int(vptr->mac_regs);
	//mac_enable_int(vptr->mac_regs);

	vptr->flags |= VELOCITY_FLAGS_OPENED;
	return 1;

}

/*
 * MII access , media link mode setting functions
 */


/**
 *	mii_init	-	set up MII
 *	@vptr: velocity adapter
 *	@mii_status:  links tatus
 *
 *	Set up the PHY for the current link state.
 */

static void mii_init(struct velocity_info *vptr, u32 mii_status __unused)
{
	u16 BMCR;

	switch (PHYID_GET_PHY_ID(vptr->phy_id)) {
	case PHYID_CICADA_CS8201:
		/*
		 *      Reset to hardware default
		 */
		MII_REG_BITS_OFF((ANAR_ASMDIR | ANAR_PAUSE), MII_REG_ANAR,
				 vptr->mac_regs);
		/*
		 *      Turn on ECHODIS bit in NWay-forced full mode and turn it
		 *      off it in NWay-forced half mode for NWay-forced v.s. 
		 *      legacy-forced issue.
		 */
		if (vptr->mii_status & VELOCITY_DUPLEX_FULL)
			MII_REG_BITS_ON(TCSR_ECHODIS, MII_REG_TCSR,
					vptr->mac_regs);
		else
			MII_REG_BITS_OFF(TCSR_ECHODIS, MII_REG_TCSR,
					 vptr->mac_regs);
		/*
		 *      Turn on Link/Activity LED enable bit for CIS8201
		 */
		MII_REG_BITS_ON(PLED_LALBE, MII_REG_PLED, vptr->mac_regs);
		break;
	case PHYID_VT3216_32BIT:
	case PHYID_VT3216_64BIT:
		/*
		 *      Reset to hardware default
		 */
		MII_REG_BITS_ON((ANAR_ASMDIR | ANAR_PAUSE), MII_REG_ANAR,
				vptr->mac_regs);
		/*
		 *      Turn on ECHODIS bit in NWay-forced full mode and turn it
		 *      off it in NWay-forced half mode for NWay-forced v.s. 
		 *      legacy-forced issue
		 */
		if (vptr->mii_status & VELOCITY_DUPLEX_FULL)
			MII_REG_BITS_ON(TCSR_ECHODIS, MII_REG_TCSR,
					vptr->mac_regs);
		else
			MII_REG_BITS_OFF(TCSR_ECHODIS, MII_REG_TCSR,
					 vptr->mac_regs);
		break;

	case PHYID_MARVELL_1000:
	case PHYID_MARVELL_1000S:
		/*
		 *      Assert CRS on Transmit 
		 */
		MII_REG_BITS_ON(PSCR_ACRSTX, MII_REG_PSCR, vptr->mac_regs);
		/*
		 *      Reset to hardware default 
		 */
		MII_REG_BITS_ON((ANAR_ASMDIR | ANAR_PAUSE), MII_REG_ANAR,
				vptr->mac_regs);
		break;
	default:
		;
	}
	velocity_mii_read(vptr->mac_regs, MII_REG_BMCR, &BMCR);
	if (BMCR & BMCR_ISO) {
		BMCR &= ~BMCR_ISO;
		velocity_mii_write(vptr->mac_regs, MII_REG_BMCR, BMCR);
	}
}

/**
 *	safe_disable_mii_autopoll	-	autopoll off
 *	@regs: velocity registers
 *
 *	Turn off the autopoll and wait for it to disable on the chip
 */

static void safe_disable_mii_autopoll(struct mac_regs *regs)
{
	u16 ww;

	/*  turn off MAUTO */
	writeb(0, &regs->MIICR);
	for (ww = 0; ww < W_MAX_TIMEOUT; ww++) {
		udelay(1);
		if (BYTE_REG_BITS_IS_ON(MIISR_MIDLE, &regs->MIISR))
			break;
	}
}

/**
 *	enable_mii_autopoll	-	turn on autopolling
 *	@regs: velocity registers
 *
 *	Enable the MII link status autopoll feature on the Velocity
 *	hardware. Wait for it to enable.
 */

static void enable_mii_autopoll(struct mac_regs *regs)
{
	unsigned int ii;

	writeb(0, &(regs->MIICR));
	writeb(MIIADR_SWMPL, &regs->MIIADR);

	for (ii = 0; ii < W_MAX_TIMEOUT; ii++) {
		udelay(1);
		if (BYTE_REG_BITS_IS_ON(MIISR_MIDLE, &regs->MIISR))
			break;
	}

	writeb(MIICR_MAUTO, &regs->MIICR);

	for (ii = 0; ii < W_MAX_TIMEOUT; ii++) {
		udelay(1);
		if (!BYTE_REG_BITS_IS_ON(MIISR_MIDLE, &regs->MIISR))
			break;
	}

}

/**
 *	velocity_mii_read	-	read MII data
 *	@regs: velocity registers
 *	@index: MII register index
 *	@data: buffer for received data
 *
 *	Perform a single read of an MII 16bit register. Returns zero
 *	on success or -ETIMEDOUT if the PHY did not respond.
 */

static int velocity_mii_read(struct mac_regs *regs, u8 index, u16 * data)
{
	u16 ww;

	/*
	 *      Disable MIICR_MAUTO, so that mii addr can be set normally
	 */
	safe_disable_mii_autopoll(regs);

	writeb(index, &regs->MIIADR);

	BYTE_REG_BITS_ON(MIICR_RCMD, &regs->MIICR);

	for (ww = 0; ww < W_MAX_TIMEOUT; ww++) {
		if (!(readb(&regs->MIICR) & MIICR_RCMD))
			break;
	}

	*data = readw(&regs->MIIDATA);

	enable_mii_autopoll(regs);
	if (ww == W_MAX_TIMEOUT)
		return -1;
	return 0;
}

/**
 *	velocity_mii_write	-	write MII data
 *	@regs: velocity registers
 *	@index: MII register index
 *	@data: 16bit data for the MII register
 *
 *	Perform a single write to an MII 16bit register. Returns zero
 *	on success or -ETIMEDOUT if the PHY did not respond.
 */

static int velocity_mii_write(struct mac_regs *regs, u8 mii_addr, u16 data)
{
	u16 ww;

	/*
	 *      Disable MIICR_MAUTO, so that mii addr can be set normally
	 */
	safe_disable_mii_autopoll(regs);

	/* MII reg offset */
	writeb(mii_addr, &regs->MIIADR);
	/* set MII data */
	writew(data, &regs->MIIDATA);

	/* turn on MIICR_WCMD */
	BYTE_REG_BITS_ON(MIICR_WCMD, &regs->MIICR);

	/* W_MAX_TIMEOUT is the timeout period */
	for (ww = 0; ww < W_MAX_TIMEOUT; ww++) {
		udelay(5);
		if (!(readb(&regs->MIICR) & MIICR_WCMD))
			break;
	}
	enable_mii_autopoll(regs);

	if (ww == W_MAX_TIMEOUT)
		return -1;
	return 0;
}

/**
 *	velocity_get_opt_media_mode	-	get media selection
 *	@vptr: velocity adapter
 *
 *	Get the media mode stored in EEPROM or module options and load
 *	mii_status accordingly. The requested link state information
 *	is also returned.
 */

static u32 velocity_get_opt_media_mode(struct velocity_info *vptr)
{
	u32 status = 0;

	switch (vptr->options.spd_dpx) {
	case SPD_DPX_AUTO:
		status = VELOCITY_AUTONEG_ENABLE;
		break;
	case SPD_DPX_100_FULL:
		status = VELOCITY_SPEED_100 | VELOCITY_DUPLEX_FULL;
		break;
	case SPD_DPX_10_FULL:
		status = VELOCITY_SPEED_10 | VELOCITY_DUPLEX_FULL;
		break;
	case SPD_DPX_100_HALF:
		status = VELOCITY_SPEED_100;
		break;
	case SPD_DPX_10_HALF:
		status = VELOCITY_SPEED_10;
		break;
	}
	vptr->mii_status = status;
	return status;
}

/**
 *	mii_set_auto_on		-	autonegotiate on
 *	@vptr: velocity
 *
 *	Enable autonegotation on this interface
 */

static void mii_set_auto_on(struct velocity_info *vptr)
{
	if (MII_REG_BITS_IS_ON(BMCR_AUTO, MII_REG_BMCR, vptr->mac_regs))
		MII_REG_BITS_ON(BMCR_REAUTO, MII_REG_BMCR, vptr->mac_regs);
	else
		MII_REG_BITS_ON(BMCR_AUTO, MII_REG_BMCR, vptr->mac_regs);
}


/*
static void mii_set_auto_off(struct velocity_info * vptr)
{
    MII_REG_BITS_OFF(BMCR_AUTO, MII_REG_BMCR, vptr->mac_regs);
}
*/

/**
 *	set_mii_flow_control	-	flow control setup
 *	@vptr: velocity interface
 *
 *	Set up the flow control on this interface according to
 *	the supplied user/eeprom options.
 */

static void set_mii_flow_control(struct velocity_info *vptr)
{
	/*Enable or Disable PAUSE in ANAR */
	switch (vptr->options.flow_cntl) {
	case FLOW_CNTL_TX:
		MII_REG_BITS_OFF(ANAR_PAUSE, MII_REG_ANAR, vptr->mac_regs);
		MII_REG_BITS_ON(ANAR_ASMDIR, MII_REG_ANAR, vptr->mac_regs);
		break;

	case FLOW_CNTL_RX:
		MII_REG_BITS_ON(ANAR_PAUSE, MII_REG_ANAR, vptr->mac_regs);
		MII_REG_BITS_ON(ANAR_ASMDIR, MII_REG_ANAR, vptr->mac_regs);
		break;

	case FLOW_CNTL_TX_RX:
		MII_REG_BITS_ON(ANAR_PAUSE, MII_REG_ANAR, vptr->mac_regs);
		MII_REG_BITS_ON(ANAR_ASMDIR, MII_REG_ANAR, vptr->mac_regs);
		break;

	case FLOW_CNTL_DISABLE:
		MII_REG_BITS_OFF(ANAR_PAUSE, MII_REG_ANAR, vptr->mac_regs);
		MII_REG_BITS_OFF(ANAR_ASMDIR, MII_REG_ANAR,
				 vptr->mac_regs);
		break;
	default:
		break;
	}
}

/**
 *	velocity_set_media_mode		-	set media mode
 *	@mii_status: old MII link state
 *
 *	Check the media link state and configure the flow control
 *	PHY and also velocity hardware setup accordingly. In particular
 *	we need to set up CD polling and frame bursting.
 */

static int velocity_set_media_mode(struct velocity_info *vptr,
				   u32 mii_status)
{
	struct mac_regs *regs = vptr->mac_regs;

	vptr->mii_status = mii_check_media_mode(vptr->mac_regs);

	/* Set mii link status */
	set_mii_flow_control(vptr);

	if (PHYID_GET_PHY_ID(vptr->phy_id) == PHYID_CICADA_CS8201) {
		MII_REG_BITS_ON(AUXCR_MDPPS, MII_REG_AUXCR,
				vptr->mac_regs);
	}

	/*
	 *      If connection type is AUTO
	 */
	if (mii_status & VELOCITY_AUTONEG_ENABLE) {
		printf("Velocity is AUTO mode\n");
		/* clear force MAC mode bit */
		BYTE_REG_BITS_OFF(CHIPGCR_FCMODE, &regs->CHIPGCR);
		/* set duplex mode of MAC according to duplex mode of MII */
		MII_REG_BITS_ON(ANAR_TXFD | ANAR_TX | ANAR_10FD | ANAR_10,
				MII_REG_ANAR, vptr->mac_regs);
		MII_REG_BITS_ON(G1000CR_1000FD | G1000CR_1000,
				MII_REG_G1000CR, vptr->mac_regs);
		MII_REG_BITS_ON(BMCR_SPEED1G, MII_REG_BMCR,
				vptr->mac_regs);

		/* enable AUTO-NEGO mode */
		mii_set_auto_on(vptr);
	} else {
		u16 ANAR;
		u8 CHIPGCR;

		/*
		 * 1. if it's 3119, disable frame bursting in halfduplex mode
		 *    and enable it in fullduplex mode
		 * 2. set correct MII/GMII and half/full duplex mode in CHIPGCR
		 * 3. only enable CD heart beat counter in 10HD mode
		 */

		/* set force MAC mode bit */
		BYTE_REG_BITS_ON(CHIPGCR_FCMODE, &regs->CHIPGCR);

		CHIPGCR = readb(&regs->CHIPGCR);
		CHIPGCR &= ~CHIPGCR_FCGMII;

		if (mii_status & VELOCITY_DUPLEX_FULL) {
			CHIPGCR |= CHIPGCR_FCFDX;
			writeb(CHIPGCR, &regs->CHIPGCR);
			printf
			    ("DEBUG: set Velocity to forced full mode\n");
			if (vptr->rev_id < REV_ID_VT3216_A0)
				BYTE_REG_BITS_OFF(TCR_TB2BDIS, &regs->TCR);
		} else {
			CHIPGCR &= ~CHIPGCR_FCFDX;
			printf
			    ("DEBUG: set Velocity to forced half mode\n");
			writeb(CHIPGCR, &regs->CHIPGCR);
			if (vptr->rev_id < REV_ID_VT3216_A0)
				BYTE_REG_BITS_ON(TCR_TB2BDIS, &regs->TCR);
		}

		MII_REG_BITS_OFF(G1000CR_1000FD | G1000CR_1000,
				 MII_REG_G1000CR, vptr->mac_regs);

		if (!(mii_status & VELOCITY_DUPLEX_FULL)
		    && (mii_status & VELOCITY_SPEED_10)) {
			BYTE_REG_BITS_OFF(TESTCFG_HBDIS, &regs->TESTCFG);
		} else {
			BYTE_REG_BITS_ON(TESTCFG_HBDIS, &regs->TESTCFG);
		}
		/* MII_REG_BITS_OFF(BMCR_SPEED1G, MII_REG_BMCR, vptr->mac_regs); */
		velocity_mii_read(vptr->mac_regs, MII_REG_ANAR, &ANAR);
		ANAR &= (~(ANAR_TXFD | ANAR_TX | ANAR_10FD | ANAR_10));
		if (mii_status & VELOCITY_SPEED_100) {
			if (mii_status & VELOCITY_DUPLEX_FULL)
				ANAR |= ANAR_TXFD;
			else
				ANAR |= ANAR_TX;
		} else {
			if (mii_status & VELOCITY_DUPLEX_FULL)
				ANAR |= ANAR_10FD;
			else
				ANAR |= ANAR_10;
		}
		velocity_mii_write(vptr->mac_regs, MII_REG_ANAR, ANAR);
		/* enable AUTO-NEGO mode */
		mii_set_auto_on(vptr);
		/* MII_REG_BITS_ON(BMCR_AUTO, MII_REG_BMCR, vptr->mac_regs); */
	}
	/* vptr->mii_status=mii_check_media_mode(vptr->mac_regs); */
	/* vptr->mii_status=check_connection_type(vptr->mac_regs); */
	return VELOCITY_LINK_CHANGE;
}

/**
 *	mii_check_media_mode	-	check media state
 *	@regs: velocity registers
 *
 *	Check the current MII status and determine the link status
 *	accordingly
 */

static u32 mii_check_media_mode(struct mac_regs *regs)
{
	u32 status = 0;
	u16 ANAR;

	if (!MII_REG_BITS_IS_ON(BMSR_LNK, MII_REG_BMSR, regs))
		status |= VELOCITY_LINK_FAIL;

	if (MII_REG_BITS_IS_ON(G1000CR_1000FD, MII_REG_G1000CR, regs))
		status |= VELOCITY_SPEED_1000 | VELOCITY_DUPLEX_FULL;
	else if (MII_REG_BITS_IS_ON(G1000CR_1000, MII_REG_G1000CR, regs))
		status |= (VELOCITY_SPEED_1000);
	else {
		velocity_mii_read(regs, MII_REG_ANAR, &ANAR);
		if (ANAR & ANAR_TXFD)
			status |=
			    (VELOCITY_SPEED_100 | VELOCITY_DUPLEX_FULL);
		else if (ANAR & ANAR_TX)
			status |= VELOCITY_SPEED_100;
		else if (ANAR & ANAR_10FD)
			status |=
			    (VELOCITY_SPEED_10 | VELOCITY_DUPLEX_FULL);
		else
			status |= (VELOCITY_SPEED_10);
	}

	if (MII_REG_BITS_IS_ON(BMCR_AUTO, MII_REG_BMCR, regs)) {
		velocity_mii_read(regs, MII_REG_ANAR, &ANAR);
		if ((ANAR & (ANAR_TXFD | ANAR_TX | ANAR_10FD | ANAR_10))
		    == (ANAR_TXFD | ANAR_TX | ANAR_10FD | ANAR_10)) {
			if (MII_REG_BITS_IS_ON
			    (G1000CR_1000 | G1000CR_1000FD,
			     MII_REG_G1000CR, regs))
				status |= VELOCITY_AUTONEG_ENABLE;
		}
	}

	return status;
}

static u32 check_connection_type(struct mac_regs *regs)
{
	u32 status = 0;
	u8 PHYSR0;
	u16 ANAR;
	PHYSR0 = readb(&regs->PHYSR0);

	/*
	   if (!(PHYSR0 & PHYSR0_LINKGD))
	   status|=VELOCITY_LINK_FAIL;
	 */

	if (PHYSR0 & PHYSR0_FDPX)
		status |= VELOCITY_DUPLEX_FULL;

	if (PHYSR0 & PHYSR0_SPDG)
		status |= VELOCITY_SPEED_1000;
	if (PHYSR0 & PHYSR0_SPD10)
		status |= VELOCITY_SPEED_10;
	else
		status |= VELOCITY_SPEED_100;

	if (MII_REG_BITS_IS_ON(BMCR_AUTO, MII_REG_BMCR, regs)) {
		velocity_mii_read(regs, MII_REG_ANAR, &ANAR);
		if ((ANAR & (ANAR_TXFD | ANAR_TX | ANAR_10FD | ANAR_10))
		    == (ANAR_TXFD | ANAR_TX | ANAR_10FD | ANAR_10)) {
			if (MII_REG_BITS_IS_ON
			    (G1000CR_1000 | G1000CR_1000FD,
			     MII_REG_G1000CR, regs))
				status |= VELOCITY_AUTONEG_ENABLE;
		}
	}

	return status;
}

/**
 *	enable_flow_control_ability	-	flow control
 *	@vptr: veloity to configure
 *
 *	Set up flow control according to the flow control options
 *	determined by the eeprom/configuration.
 */

static void enable_flow_control_ability(struct velocity_info *vptr)
{

	struct mac_regs *regs = vptr->mac_regs;

	switch (vptr->options.flow_cntl) {

	case FLOW_CNTL_DEFAULT:
		if (BYTE_REG_BITS_IS_ON(PHYSR0_RXFLC, &regs->PHYSR0))
			writel(CR0_FDXRFCEN, &regs->CR0Set);
		else
			writel(CR0_FDXRFCEN, &regs->CR0Clr);

		if (BYTE_REG_BITS_IS_ON(PHYSR0_TXFLC, &regs->PHYSR0))
			writel(CR0_FDXTFCEN, &regs->CR0Set);
		else
			writel(CR0_FDXTFCEN, &regs->CR0Clr);
		break;

	case FLOW_CNTL_TX:
		writel(CR0_FDXTFCEN, &regs->CR0Set);
		writel(CR0_FDXRFCEN, &regs->CR0Clr);
		break;

	case FLOW_CNTL_RX:
		writel(CR0_FDXRFCEN, &regs->CR0Set);
		writel(CR0_FDXTFCEN, &regs->CR0Clr);
		break;

	case FLOW_CNTL_TX_RX:
		writel(CR0_FDXTFCEN, &regs->CR0Set);
		writel(CR0_FDXRFCEN, &regs->CR0Set);
		break;

	case FLOW_CNTL_DISABLE:
		writel(CR0_FDXRFCEN, &regs->CR0Clr);
		writel(CR0_FDXTFCEN, &regs->CR0Clr);
		break;

	default:
		break;
	}

}

/* FIXME: Move to pci.c */
/**
 * pci_set_power_state - Set the power state of a PCI device
 * @dev: PCI device to be suspended
 * @state: Power state we're entering
 *
 * Transition a device to a new power state, using the Power Management 
 * Capabilities in the device's config space.
 *
 * RETURN VALUE: 
 * -EINVAL if trying to enter a lower state than we're already in.
 * 0 if we're already in the requested state.
 * -EIO if device does not support PCI PM.
 * 0 if we can successfully change the power state.
 */

int pci_set_power_state(struct pci_device *dev, int state)
{
	int pm;
	u16 pmcsr;
	int current_state = 0;

	/* bound the state we're entering */
	if (state > 3)
		state = 3;

	/* Validate current state:
	 * Can enter D0 from any state, but if we can only go deeper 
	 * to sleep if we're already in a low power state
	 */
	if (state > 0 && current_state > state)
		return -1;
	else if (current_state == state)
		return 0;	/* we're already there */

	/* find PCI PM capability in list */
	pm = pci_find_capability(dev, PCI_CAP_ID_PM);

	/* abort if the device doesn't support PM capabilities */
	if (!pm)
		return -2;

	/* check if this device supports the desired state */
	if (state == 1 || state == 2) {
		u16 pmc;
		pci_read_config_word(dev, pm + PCI_PM_PMC, &pmc);
		if (state == 1 && !(pmc & PCI_PM_CAP_D1))
			return -2;
		else if (state == 2 && !(pmc & PCI_PM_CAP_D2))
			return -2;
	}

	/* If we're in D3, force entire word to 0.
	 * This doesn't affect PME_Status, disables PME_En, and
	 * sets PowerState to 0.
	 */
	if (current_state >= 3)
		pmcsr = 0;
	else {
		pci_read_config_word(dev, pm + PCI_PM_CTRL, &pmcsr);
		pmcsr &= ~PCI_PM_CTRL_STATE_MASK;
		pmcsr |= state;
	}

	/* enter specified state */
	pci_write_config_word(dev, pm + PCI_PM_CTRL, pmcsr);

	/* Mandatory power management transition delays */
	/* see PCI PM 1.1 5.6.1 table 18 */
	if (state == 3 || current_state == 3)
		mdelay(10);
	else if (state == 2 || current_state == 2)
		udelay(200);
	current_state = state;

	return 0;
}

static struct pci_device_id velocity_nics[] = {
	PCI_ROM(0x1106, 0x3119, "via-velocity", "VIA Networking Velocity Family Gigabit Ethernet Adapter", 0),
};

PCI_DRIVER ( velocity_driver, velocity_nics, PCI_NO_CLASS );

DRIVER ( "VIA-VELOCITY/PCI", nic_driver, pci_driver, velocity_driver,
         velocity_probe, velocity_disable );
