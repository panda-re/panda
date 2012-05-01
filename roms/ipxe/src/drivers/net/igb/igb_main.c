/*******************************************************************************

  Intel(R) Gigabit Ethernet Linux driver
  Copyright(c) 2007-2009 Intel Corporation.

  Portions Copyright(c) 2010 Marty Connor <mdc@etherboot.org>
  Portions Copyright(c) 2010 Entity Cyber, Inc.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

FILE_LICENCE ( GPL2_ONLY );

#include "igb.h"

/* Low-level support routines */

/**
 * igb_read_pcie_cap_reg - retrieve PCIe capability register contents
 * @hw: address of board private structure
 * @reg: PCIe capability register requested
 * @value: where to store requested value
 **/
int32_t igb_read_pcie_cap_reg(struct e1000_hw *hw, uint32_t reg, uint16_t *value)
{
    struct igb_adapter *adapter = hw->back;
    uint16_t cap_offset;

#define	 PCI_CAP_ID_EXP	       0x10    /* PCI Express */
    cap_offset = pci_find_capability(adapter->pdev, PCI_CAP_ID_EXP);
    if (!cap_offset)
	return -E1000_ERR_CONFIG;

    pci_read_config_word(adapter->pdev, cap_offset + reg, value);

    return E1000_SUCCESS;
}

/**
 * igb_write_pcie_cap_reg - write value to PCIe capability register
 * @hw: address of board private structure
 * @reg: PCIe capability register to write to
 * @value: value to store in given register
 **/
int32_t igb_write_pcie_cap_reg(struct e1000_hw *hw, u32 reg, u16 *value)
{
	struct igb_adapter *adapter = hw->back;
	u16 cap_offset;

	cap_offset = pci_find_capability(adapter->pdev, PCI_CAP_ID_EXP);
	if (!cap_offset)
		return -E1000_ERR_CONFIG;

	pci_write_config_word(adapter->pdev, cap_offset + reg, *value);

	return E1000_SUCCESS;
}

/**
 * igb_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static void igb_irq_disable(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	E1000_WRITE_REG(hw, E1000_IAM, 0);
	E1000_WRITE_REG(hw, E1000_IMC, ~0);
	E1000_WRITE_FLUSH(hw);
}

/**
 * igb_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/
static void igb_irq_enable(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	E1000_WRITE_REG(hw, E1000_IMS, IMS_ENABLE_MASK);
	E1000_WRITE_REG(hw, E1000_IAM, IMS_ENABLE_MASK);
	E1000_WRITE_FLUSH(hw);
}

/**
 * igb_get_hw_control - get control of the h/w from f/w
 * @adapter: address of board private structure
 *
 * igb_get_hw_control sets CTRL_EXT:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means that
 * the driver is loaded.
 *
 **/
void igb_get_hw_control(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl_ext;

	/* Let firmware know the driver has taken over */
	ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
	E1000_WRITE_REG(hw, E1000_CTRL_EXT,
			ctrl_ext | E1000_CTRL_EXT_DRV_LOAD);
}

/**
 * igb_reset - put adapter in known initial state
 * @adapter: board private structure
 **/
void igb_reset(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	struct e1000_mac_info *mac = &hw->mac;
	struct e1000_fc_info *fc = &hw->fc;
	u32 pba = 0;
	u16 hwm;

	/* Repartition Pba for greater than 9k mtu
	 * To take effect CTRL.RST is required.
	 */
	switch (mac->type) {
	case e1000_82576:
		pba = E1000_READ_REG(hw, E1000_RXPBS);
		pba &= E1000_RXPBS_SIZE_MASK_82576;
		break;
	case e1000_82575:
	default:
		pba = E1000_PBA_34K;
		break;
	}

	/* flow control settings */
	/* The high water mark must be low enough to fit one full frame
	 * (or the size used for early receive) above it in the Rx FIFO.
	 * Set it to the lower of:
	 * - 90% of the Rx FIFO size, or
	 * - the full Rx FIFO size minus one full frame */
#define min(a,b) (((a)<(b))?(a):(b))
	hwm = min(((pba << 10) * 9 / 10),
			((pba << 10) - 2 * adapter->max_frame_size));

	if (mac->type < e1000_82576) {
		fc->high_water = hwm & 0xFFF8;	/* 8-byte granularity */
		fc->low_water = fc->high_water - 8;
	} else {
		fc->high_water = hwm & 0xFFF0;	/* 16-byte granularity */
		fc->low_water = fc->high_water - 16;
	}
	fc->pause_time = 0xFFFF;
	fc->send_xon = 1;
	fc->current_mode = fc->requested_mode;

	/* Allow time for pending master requests to run */
	igb_reset_hw(hw);
	E1000_WRITE_REG(hw, E1000_WUC, 0);

	if (igb_init_hw(hw)) {
		DBG ("Hardware Error\n");
        }

	igb_get_phy_info(hw);
}

/**
 * igb_sw_init - Initialize general software structures (struct igb_adapter)
 * @adapter: board private structure to initialize
 **/
int igb_sw_init(struct igb_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct pci_device *pdev = adapter->pdev;

	/* PCI config space info */

	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;

	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);

	pci_read_config_word(pdev, PCI_COMMAND, &hw->bus.pci_cmd_word);

	adapter->max_frame_size = MAXIMUM_ETHERNET_VLAN_SIZE + ETH_HLEN + ETH_FCS_LEN;
	adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;

	/* Initialize the hardware-specific values */
	if (igb_setup_init_funcs(hw, TRUE)) {
		DBG ("Hardware Initialization Failure\n");
		return -EIO;
	}

	/* Explicitly disable IRQ since the NIC can be in any state. */
	igb_irq_disable(adapter);

	return 0;
}

/* TX support routines */

/**
 * igb_setup_tx_resources - allocate Tx resources (Descriptors)
 *
 * @v adapter	e1000 private structure
 *
 * @ret rc	 Returns 0 on success, negative on failure
 **/
static int igb_setup_tx_resources ( struct igb_adapter *adapter )
{
	DBG ( "igb_setup_tx_resources\n" );

	/* Allocate transmit descriptor ring memory.
	   It must not cross a 64K boundary because of hardware errata #23
	   so we use malloc_dma() requesting a 128 byte block that is
	   128 byte aligned. This should guarantee that the memory
	   allocated will not cross a 64K boundary, because 128 is an
	   even multiple of 65536 ( 65536 / 128 == 512 ), so all possible
	   allocations of 128 bytes on a 128 byte boundary will not
	   cross 64K bytes.
	 */

	adapter->tx_base =
		malloc_dma ( adapter->tx_ring_size, adapter->tx_ring_size );

	if ( ! adapter->tx_base ) {
		return -ENOMEM;
	}

	memset ( adapter->tx_base, 0, adapter->tx_ring_size );

	DBG ( "adapter->tx_base = %#08lx\n", virt_to_bus ( adapter->tx_base ) );

	return 0;
}

/**
 * igb_process_tx_packets - process transmitted packets
 *
 * @v netdev	network interface device structure
 **/
static void igb_process_tx_packets ( struct net_device *netdev )
{
	struct igb_adapter *adapter = netdev_priv ( netdev );
	uint32_t i;
	uint32_t tx_status;
	struct e1000_tx_desc *tx_curr_desc;

	/* Check status of transmitted packets
	 */
	DBG ( "process_tx_packets: tx_head = %d, tx_tail = %d\n", adapter->tx_head,
	      adapter->tx_tail );

	while ( ( i = adapter->tx_head ) != adapter->tx_tail ) {

		tx_curr_desc = ( void * )  ( adapter->tx_base ) +
					   ( i * sizeof ( *adapter->tx_base ) );

		tx_status = tx_curr_desc->upper.data;

		DBG ( "	 tx_curr_desc = %#08lx\n", virt_to_bus ( tx_curr_desc ) );
		DBG ( "	 tx_status = %#08x\n", tx_status );

		/* if the packet at tx_head is not owned by hardware it is for us */
		if ( ! ( tx_status & E1000_TXD_STAT_DD ) )
			break;

		DBG ( "Sent packet. tx_head: %d tx_tail: %d tx_status: %#08x\n",
		      adapter->tx_head, adapter->tx_tail, tx_status );

		if ( tx_status & ( E1000_TXD_STAT_EC | E1000_TXD_STAT_LC |
				   E1000_TXD_STAT_TU ) ) {
			netdev_tx_complete_err ( netdev, adapter->tx_iobuf[i], -EINVAL );
			DBG ( "Error transmitting packet, tx_status: %#08x\n",
			      tx_status );
		} else {
			netdev_tx_complete ( netdev, adapter->tx_iobuf[i] );
			DBG ( "Success transmitting packet, tx_status: %#08x\n",
			      tx_status );
		}

		/* Decrement count of used descriptors, clear this descriptor
		 */
		adapter->tx_fill_ctr--;
		memset ( tx_curr_desc, 0, sizeof ( *tx_curr_desc ) );

		adapter->tx_head = ( adapter->tx_head + 1 ) % NUM_TX_DESC;
	}
}

static void igb_free_tx_resources ( struct igb_adapter *adapter )
{
	DBG ( "igb_free_tx_resources\n" );

	free_dma ( adapter->tx_base, adapter->tx_ring_size );
}

/**
 * igb_configure_tx - Configure 8254x Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void igb_configure_tx ( struct igb_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	u32 tctl, txdctl;

	DBG ( "igb_configure_tx\n" );

	/* disable transmits while setting up the descriptors */
	tctl = E1000_READ_REG ( hw, E1000_TCTL );
	E1000_WRITE_REG ( hw, E1000_TCTL, tctl & ~E1000_TCTL_EN );
	E1000_WRITE_FLUSH(hw);
	mdelay(10);

	E1000_WRITE_REG ( hw, E1000_TDBAH(0), 0 );
	E1000_WRITE_REG ( hw, E1000_TDBAL(0), virt_to_bus ( adapter->tx_base ) );
	E1000_WRITE_REG ( hw, E1000_TDLEN(0), adapter->tx_ring_size );

	DBG ( "E1000_TDBAL(0): %#08x\n",  E1000_READ_REG ( hw, E1000_TDBAL(0) ) );
	DBG ( "E1000_TDLEN(0): %d\n",	  E1000_READ_REG ( hw, E1000_TDLEN(0) ) );

	/* Setup the HW Tx Head and Tail descriptor pointers */
	E1000_WRITE_REG ( hw, E1000_TDH(0), 0 );
	E1000_WRITE_REG ( hw, E1000_TDT(0), 0 );

	adapter->tx_head = 0;
	adapter->tx_tail = 0;
	adapter->tx_fill_ctr = 0;

	txdctl = E1000_READ_REG ( hw, E1000_TXDCTL(0) );
	txdctl |= E1000_TXDCTL_QUEUE_ENABLE;
	E1000_WRITE_REG ( hw, E1000_TXDCTL(0), txdctl );

	/* Setup Transmit Descriptor Settings for eop descriptor */
	adapter->txd_cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;

	/* enable Report Status bit */
	adapter->txd_cmd |= E1000_TXD_CMD_RS;

	/* Program the Transmit Control Register */
	tctl &= ~E1000_TCTL_CT;
	tctl |= E1000_TCTL_PSP | E1000_TCTL_RTLC |
		(E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT);

	igb_config_collision_dist(hw);

	/* Enable transmits */
	tctl |= E1000_TCTL_EN;
	E1000_WRITE_REG(hw, E1000_TCTL, tctl);
	E1000_WRITE_FLUSH(hw);
}

/* RX support routines */

static void igb_free_rx_resources ( struct igb_adapter *adapter )
{
	int i;

	DBG ( "igb_free_rx_resources\n" );

	free_dma ( adapter->rx_base, adapter->rx_ring_size );

	for ( i = 0; i < NUM_RX_DESC; i++ ) {
		free_iob ( adapter->rx_iobuf[i] );
	}
}

/**
 * igb_refill_rx_ring - allocate Rx io_buffers
 *
 * @v adapter	e1000 private structure
 *
 * @ret rc	 Returns 0 on success, negative on failure
 **/
static int igb_refill_rx_ring ( struct igb_adapter *adapter )
{
	int i, rx_curr;
	int rc = 0;
	struct e1000_rx_desc *rx_curr_desc;
	struct e1000_hw *hw = &adapter->hw;
	struct io_buffer *iob;

	DBGP ("igb_refill_rx_ring\n");

	for ( i = 0; i < NUM_RX_DESC; i++ ) {
		rx_curr = ( ( adapter->rx_curr + i ) % NUM_RX_DESC );
		rx_curr_desc = adapter->rx_base + rx_curr;

		if ( rx_curr_desc->status & E1000_RXD_STAT_DD )
			continue;

		if ( adapter->rx_iobuf[rx_curr] != NULL )
			continue;

		DBG2 ( "Refilling rx desc %d\n", rx_curr );

		iob = alloc_iob ( MAXIMUM_ETHERNET_VLAN_SIZE );
		adapter->rx_iobuf[rx_curr] = iob;

		if ( ! iob ) {
			DBG ( "alloc_iob failed\n" );
			rc = -ENOMEM;
			break;
		} else {
			rx_curr_desc->buffer_addr = virt_to_bus ( iob->data );

			E1000_WRITE_REG ( hw, E1000_RDT(0), rx_curr );
		}
	}
	return rc;
}

/**
 * igb_setup_rx_resources - allocate Rx resources (Descriptors)
 *
 * @v adapter	e1000 private structure
 *
 * @ret rc	 Returns 0 on success, negative on failure
 **/
static int igb_setup_rx_resources ( struct igb_adapter *adapter )
{
	int i, rc = 0;

	DBGP ( "igb_setup_rx_resources\n" );

	/* Allocate receive descriptor ring memory.
	   It must not cross a 64K boundary because of hardware errata
	 */

	adapter->rx_base =
		malloc_dma ( adapter->rx_ring_size, adapter->rx_ring_size );

	if ( ! adapter->rx_base ) {
		return -ENOMEM;
	}
	memset ( adapter->rx_base, 0, adapter->rx_ring_size );

	for ( i = 0; i < NUM_RX_DESC; i++ ) {
		/* let igb_refill_rx_ring() io_buffer allocations */
		adapter->rx_iobuf[i] = NULL;
	}

	/* allocate io_buffers */
	rc = igb_refill_rx_ring ( adapter );
	if ( rc < 0 )
		igb_free_rx_resources ( adapter );

	return rc;
}

/**
 * igb_configure_rx - Configure 8254x Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void igb_configure_rx ( struct igb_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	uint32_t rctl, rxdctl, rxcsum, mrqc;

	DBGP ( "igb_configure_rx\n" );

	/* disable receives while setting up the descriptors */
	rctl = E1000_READ_REG ( hw, E1000_RCTL );
	E1000_WRITE_REG ( hw, E1000_RCTL, rctl & ~E1000_RCTL_EN );
	E1000_WRITE_FLUSH(hw);
	mdelay(10);

	adapter->rx_curr = 0;

	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring */

	E1000_WRITE_REG ( hw, E1000_RDBAL(0), virt_to_bus ( adapter->rx_base ) );
	E1000_WRITE_REG ( hw, E1000_RDBAH(0), 0 );
	E1000_WRITE_REG ( hw, E1000_RDLEN(0), adapter->rx_ring_size );

	E1000_WRITE_REG ( hw, E1000_RDH(0), 0 );
	E1000_WRITE_REG ( hw, E1000_RDT(0), 0 );

	DBG ( "E1000_RDBAL(0): %#08x\n",  E1000_READ_REG ( hw, E1000_RDBAL(0) ) );
	DBG ( "E1000_RDLEN(0): %d\n",	  E1000_READ_REG ( hw, E1000_RDLEN(0) ) );
	DBG ( "E1000_RCTL:  %#08x\n",	  E1000_READ_REG ( hw, E1000_RCTL ) );

	rxdctl = E1000_READ_REG ( hw, E1000_RXDCTL(0) );
	rxdctl |= E1000_RXDCTL_QUEUE_ENABLE;
	rxdctl &= 0xFFF00000;
	rxdctl |= IGB_RX_PTHRESH;
	rxdctl |= IGB_RX_HTHRESH << 8;
	rxdctl |= IGB_RX_WTHRESH << 16;
	E1000_WRITE_REG ( hw, E1000_RXDCTL(0), rxdctl );
	E1000_WRITE_FLUSH ( hw );

	rxcsum = E1000_READ_REG(hw, E1000_RXCSUM);
	rxcsum &= ~( E1000_RXCSUM_TUOFL | E1000_RXCSUM_IPPCSE );
	E1000_WRITE_REG ( hw, E1000_RXCSUM, 0 );

	/* The initial value for MRQC disables multiple receive
	 * queues, however this setting is not recommended.
	 * - Intel® 82576 Gigabit Ethernet Controller Datasheet r2.41
	 *   Section 8.10.9 Multiple Queues Command Register - MRQC
	 */
	mrqc = E1000_MRQC_ENABLE_VMDQ;
	E1000_WRITE_REG ( hw, E1000_MRQC, mrqc );

	/* Turn off loopback modes */
	rctl &= ~(E1000_RCTL_LBM_TCVR | E1000_RCTL_LBM_MAC);

	/* set maximum packet size */
	rctl |=	 E1000_RCTL_SZ_2048;

	/* Broadcast enable, multicast promisc, unicast promisc */
	rctl |=	 E1000_RCTL_BAM | E1000_RCTL_MPE | E1000_RCTL_UPE;

	/* Store bad packets */
	rctl |=	 E1000_RCTL_SBP;

	/* enable LPE to prevent packets larger than max_frame_size */
	rctl |= E1000_RCTL_LPE;

	/* enable stripping of CRC. */
	rctl |= E1000_RCTL_SECRC;

	/* enable receive control register */
	rctl |= E1000_RCTL_EN;
	E1000_WRITE_REG(hw, E1000_RCTL, rctl);
	E1000_WRITE_FLUSH(hw);

	/* On the 82576, RDT([0]) must not be "bumped" before
	 * the enable bit of RXDCTL([0]) is set.
	 * - Intel® 82576 Gigabit Ethernet Controller Datasheet r2.41
	 *   Section 4.5.9 receive Initialization
	 *
	 * By observation I have found this to occur when the enable bit of
	 * RCTL is set. The datasheet recommends polling for this bit,
	 * however as I see no evidence of this in the Linux igb driver
	 * I have omitted that step.
	 * - Simon Horman, May 2009
	 */
	E1000_WRITE_REG ( hw, E1000_RDT(0), NUM_RX_DESC - 1 );

	DBG ( "RDBAH: %#08x\n",	 E1000_READ_REG ( hw, E1000_RDBAH(0) ) );
	DBG ( "RDBAL: %#08x\n",	 E1000_READ_REG ( hw, E1000_RDBAL(0) ) );
	DBG ( "RDLEN: %d\n",	 E1000_READ_REG ( hw, E1000_RDLEN(0) ) );
	DBG ( "RCTL:  %#08x\n",	 E1000_READ_REG ( hw, E1000_RCTL ) );
}

/**
 * igb_process_rx_packets - process received packets
 *
 * @v netdev	network interface device structure
 **/
static void igb_process_rx_packets ( struct net_device *netdev )
{
	struct igb_adapter *adapter = netdev_priv ( netdev );
	uint32_t i;
	uint32_t rx_status;
	uint32_t rx_len;
	uint32_t rx_err;
	struct e1000_rx_desc *rx_curr_desc;

	DBGP ( "igb_process_rx_packets\n" );

	/* Process received packets
	 */
	while ( 1 ) {

		i = adapter->rx_curr;

		rx_curr_desc = ( void * )  ( adapter->rx_base ) +
				  ( i * sizeof ( *adapter->rx_base ) );
		rx_status = rx_curr_desc->status;

		DBG2 ( "Before DD Check RX_status: %#08x\n", rx_status );

		if ( ! ( rx_status & E1000_RXD_STAT_DD ) )
			break;

		if ( adapter->rx_iobuf[i] == NULL )
			break;

		DBG ( "E1000_RCTL = %#08x\n", E1000_READ_REG ( &adapter->hw, E1000_RCTL ) );

		rx_len = rx_curr_desc->length;

		DBG ( "Received packet, rx_curr: %d  rx_status: %#08x  rx_len: %d\n",
		      i, rx_status, rx_len );

		rx_err = rx_curr_desc->errors;

		iob_put ( adapter->rx_iobuf[i], rx_len );

		if ( rx_err & E1000_RXD_ERR_FRAME_ERR_MASK ) {

			netdev_rx_err ( netdev, adapter->rx_iobuf[i], -EINVAL );
			DBG ( "igb_process_rx_packets: Corrupted packet received!"
			      " rx_err: %#08x\n", rx_err );
		} else	{
			/* Add this packet to the receive queue. */
			netdev_rx ( netdev, adapter->rx_iobuf[i] );
		}
		adapter->rx_iobuf[i] = NULL;

		memset ( rx_curr_desc, 0, sizeof ( *rx_curr_desc ) );

		adapter->rx_curr = ( adapter->rx_curr + 1 ) % NUM_RX_DESC;
	}
}

/** Functions that implement the iPXE driver API **/

/**
 * igb_close - Disables a network interface
 *
 * @v netdev	network interface device structure
 *
 **/
static void igb_close ( struct net_device *netdev )
{
	struct igb_adapter *adapter = netdev_priv ( netdev );
	struct e1000_hw *hw = &adapter->hw;
	uint32_t rctl;

	DBGP ( "igb_close\n" );

	/* Disable and acknowledge interrupts */
	igb_irq_disable ( adapter );
	E1000_READ_REG ( hw, E1000_ICR );

	/* disable receives */
	rctl = E1000_READ_REG ( hw, E1000_RCTL );
	E1000_WRITE_REG ( hw, E1000_RCTL, rctl & ~E1000_RCTL_EN );
	E1000_WRITE_FLUSH(hw);

	igb_reset ( adapter );

	igb_free_tx_resources ( adapter );
	igb_free_rx_resources ( adapter );
}

/**
 * igb_transmit - Transmit a packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 *
 * @ret rc	 Returns 0 on success, negative on failure
 */
static int igb_transmit ( struct net_device *netdev, struct io_buffer *iobuf )
{
	struct igb_adapter *adapter = netdev_priv( netdev );
	struct e1000_hw *hw = &adapter->hw;
	uint32_t tx_curr = adapter->tx_tail;
	struct e1000_tx_desc *tx_curr_desc;

	DBGP ("igb_transmit\n");

	if ( adapter->tx_fill_ctr == NUM_TX_DESC ) {
		DBG ("TX overflow\n");
		return -ENOBUFS;
	}

	/* Save pointer to iobuf we have been given to transmit,
	   netdev_tx_complete() will need it later
	 */
	adapter->tx_iobuf[tx_curr] = iobuf;

	tx_curr_desc = ( void * ) ( adapter->tx_base ) +
		       ( tx_curr * sizeof ( *adapter->tx_base ) );

	DBG ( "tx_curr_desc = %#08lx\n", virt_to_bus ( tx_curr_desc ) );
	DBG ( "tx_curr_desc + 16 = %#08lx\n", virt_to_bus ( tx_curr_desc ) + 16 );
	DBG ( "iobuf->data = %#08lx\n", virt_to_bus ( iobuf->data ) );

	/* Add the packet to TX ring
	 */
	tx_curr_desc->buffer_addr = virt_to_bus ( iobuf->data );
	tx_curr_desc->upper.data = 0;
	tx_curr_desc->lower.data = adapter->txd_cmd | iob_len ( iobuf );

	DBG ( "TX fill: %d tx_curr: %d addr: %#08lx len: %zd\n", adapter->tx_fill_ctr,
	      tx_curr, virt_to_bus ( iobuf->data ), iob_len ( iobuf ) );

	/* Point to next free descriptor */
	adapter->tx_tail = ( adapter->tx_tail + 1 ) % NUM_TX_DESC;
	adapter->tx_fill_ctr++;

	/* Write new tail to NIC, making packet available for transmit
	 */
	E1000_WRITE_REG ( hw, E1000_TDT(0), adapter->tx_tail );
	E1000_WRITE_FLUSH(hw);

	return 0;
}

/**
 * igb_poll - Poll for received packets
 *
 * @v netdev	Network device
 */
static void igb_poll ( struct net_device *netdev )
{
	struct igb_adapter *adapter = netdev_priv( netdev );
	struct e1000_hw *hw = &adapter->hw;

	uint32_t icr;

	DBGP ( "igb_poll\n" );

	/* Acknowledge interrupts */
	icr = E1000_READ_REG ( hw, E1000_ICR );
	if ( ! icr )
		return;

	DBG ( "igb_poll: intr_status = %#08x\n", icr );

	igb_process_tx_packets ( netdev );

	igb_process_rx_packets ( netdev );

	igb_refill_rx_ring(adapter);
}

/**
 * igb_irq - enable or Disable interrupts
 *
 * @v adapter	e1000 adapter
 * @v action	requested interrupt action
 **/
static void igb_irq ( struct net_device *netdev, int enable )
{
	struct igb_adapter *adapter = netdev_priv ( netdev );

	DBGP ( "igb_irq\n" );

	if ( enable ) {
		igb_irq_enable ( adapter );
	} else {
		igb_irq_disable ( adapter );
	}
}

static struct net_device_operations igb_operations;

/**
 * igb_probe - Initial configuration of NIC
 *
 * @v pci	PCI device
 * @v id	PCI IDs
 *
 * @ret rc	Return status code
 **/
int igb_probe ( struct pci_device *pdev )
{
	int i, err;
	struct net_device *netdev;
	struct igb_adapter *adapter;
	unsigned long mmio_start, mmio_len;
	struct e1000_hw *hw;

	DBGP ( "igb_probe\n" );

	err = -ENOMEM;

	/* Allocate net device ( also allocates memory for netdev->priv
	   and makes netdev-priv point to it ) */
	netdev = alloc_etherdev ( sizeof ( struct igb_adapter ) );
	if ( ! netdev ) {
		DBG ( "err_alloc_etherdev\n" );
		goto err_alloc_etherdev;
	}

	/* Associate igb-specific network operations operations with
	 * generic network device layer */
	netdev_init ( netdev, &igb_operations );

	/* Associate this network device with given PCI device */
	pci_set_drvdata ( pdev, netdev );
	netdev->dev = &pdev->dev;

	/* Initialize driver private storage */
	adapter = netdev_priv ( netdev );
	memset ( adapter, 0, ( sizeof ( *adapter ) ) );

	adapter->pdev	    = pdev;

	adapter->ioaddr	    = pdev->ioaddr;
	adapter->hw.io_base = pdev->ioaddr;

	hw		    = &adapter->hw;
	hw->vendor_id	    = pdev->vendor;
	hw->device_id	    = pdev->device;

	adapter->irqno	    = pdev->irq;
	adapter->netdev	    = netdev;
	adapter->hw.back    = adapter;

	adapter->min_frame_size	   = ETH_ZLEN + ETH_FCS_LEN;
	adapter->max_hw_frame_size = ETH_FRAME_LEN + ETH_FCS_LEN;

	adapter->tx_ring_size = sizeof ( *adapter->tx_base ) * NUM_TX_DESC;
	adapter->rx_ring_size = sizeof ( *adapter->rx_base ) * NUM_RX_DESC;

	/* Fix up PCI device */
	adjust_pci_device ( pdev );

	err = -EIO;

	mmio_start = pci_bar_start ( pdev, PCI_BASE_ADDRESS_0 );
	mmio_len   = pci_bar_size  ( pdev, PCI_BASE_ADDRESS_0 );

	DBG ( "mmio_start: %#08lx\n", mmio_start );
	DBG ( "mmio_len: %#08lx\n", mmio_len );

	adapter->hw.hw_addr = ioremap ( mmio_start, mmio_len );
	DBG ( "adapter->hw.hw_addr: %p\n", adapter->hw.hw_addr );

	if ( ! adapter->hw.hw_addr ) {
		DBG ( "err_ioremap\n" );
		goto err_ioremap;
	}

	/* setup adapter struct */
	err = igb_sw_init ( adapter );
	if (err) {
		DBG ( "err_sw_init\n" );
		goto err_sw_init;
	}

	igb_get_bus_info(hw);

	/* Copper options */
	if (adapter->hw.phy.media_type == e1000_media_type_copper) {
		adapter->hw.phy.mdix = AUTO_ALL_MODES;
		adapter->hw.phy.disable_polarity_correction = 0;
		adapter->hw.phy.ms_type = e1000_ms_hw_default;
	}

	DBG ( "adapter->hw.mac.type: %#08x\n", adapter->hw.mac.type );

	/* Force auto-negotiation */
	adapter->hw.mac.autoneg = 1;
	adapter->fc_autoneg = 1;
	adapter->hw.phy.autoneg_wait_to_complete = true;
	adapter->hw.mac.adaptive_ifs = true;
	adapter->hw.fc.requested_mode = e1000_fc_default;
	adapter->hw.fc.current_mode = e1000_fc_default;

	igb_validate_mdi_setting(hw);

	/*
	 * before reading the NVM, reset the controller to
	 * put the device in a known good starting state
	 */
	igb_reset_hw(hw);

	/*
	 * systems with ASPM and others may see the checksum fail on the first
	 * attempt. Let's give it a few tries
	 */
	for (i = 0;; i++) {
		if (igb_validate_nvm_checksum(&adapter->hw) >= 0)
			break;
		if (i == 2) {
			err = -EIO;
			DBG ( "The NVM Checksum Is Not Valid\n" );
			DBG ( "err_eeprom\n" );
			goto err_eeprom;
		}
	}

	/* copy the MAC address out of the EEPROM */
	if ( igb_read_mac_addr ( &adapter->hw ) ) {
		DBG ( "EEPROM Read Error\n" );
	}

	memcpy ( netdev->hw_addr, adapter->hw.mac.perm_addr, ETH_ALEN );

	/* reset the hardware with the new settings */
	igb_reset ( adapter );

	/* let the f/w know that the h/w is now under the control of the
	 * driver. */
	igb_get_hw_control(adapter);

	if ( ( err = register_netdev ( netdev ) ) != 0) {
		DBG ( "err_register\n" );
		goto err_register;
	}

	/* Mark as link up; we don't yet handle link state */
	netdev_link_up ( netdev );

	for (i = 0; i < 6; i++) {
		DBG ("%02x%s", netdev->ll_addr[i], i == 5 ? "\n" : ":");
        }

	DBG ( "igb_probe succeeded!\n" );

	/* No errors, return success */
	return 0;

/* Error return paths */
err_register:
err_eeprom:
err_sw_init:
	iounmap ( adapter->hw.hw_addr );
err_ioremap:
	netdev_put ( netdev );
err_alloc_etherdev:
	return err;
}

/**
 * igb_remove - Device Removal Routine
 *
 * @v pdev PCI device information struct
 *
 **/
void igb_remove ( struct pci_device *pdev )
{
	struct net_device *netdev = pci_get_drvdata ( pdev );
	struct igb_adapter *adapter = netdev_priv ( netdev );

	DBGP ( "igb_remove\n" );

	if ( adapter->hw.flash_address )
		iounmap ( adapter->hw.flash_address );
	if  ( adapter->hw.hw_addr )
		iounmap ( adapter->hw.hw_addr );

	unregister_netdev ( netdev );
	igb_reset  ( adapter );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/**
 * igb_open - Called when a network interface is made active
 *
 * @v netdev	network interface device structure
 * @ret rc	Return status code, 0 on success, negative value on failure
 *
 **/
static int igb_open ( struct net_device *netdev )
{
	struct igb_adapter *adapter = netdev_priv(netdev);
	int err;

	DBGP ( "igb_open\n" );

	/* allocate transmit descriptors */
	err = igb_setup_tx_resources ( adapter );
	if ( err ) {
		DBG ( "Error setting up TX resources!\n" );
		goto err_setup_tx;
	}

	/* allocate receive descriptors */
	err = igb_setup_rx_resources ( adapter );
	if ( err ) {
		DBG ( "Error setting up RX resources!\n" );
		goto err_setup_rx;
	}

	igb_configure_tx ( adapter );

	igb_configure_rx ( adapter );

	DBG ( "E1000_RXDCTL(0): %#08x\n",  E1000_READ_REG ( &adapter->hw, E1000_RXDCTL(0) ) );

	return 0;

err_setup_rx:
	DBG ( "err_setup_rx\n" );
	igb_free_tx_resources ( adapter );
err_setup_tx:
	DBG ( "err_setup_tx\n" );
	igb_reset ( adapter );

	return err;
}

/** igb net device operations */
static struct net_device_operations igb_operations = {
	.open		= igb_open,
	.close		= igb_close,
	.transmit	= igb_transmit,
	.poll		= igb_poll,
	.irq		= igb_irq,
};
