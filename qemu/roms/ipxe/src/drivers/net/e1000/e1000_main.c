/*******************************************************************************

  Intel PRO/1000 Linux driver
  Copyright(c) 1999 - 2008 Intel Corporation.

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
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

FILE_LICENCE ( GPL2_ONLY );

#include "e1000.h"

/**
 * e1000_irq_disable - Disable interrupt generation
 *
 * @adapter: board private structure
 **/
static void e1000_irq_disable ( struct e1000_adapter *adapter )
{
	E1000_WRITE_REG ( &adapter->hw, E1000_IMC, ~0 );
	E1000_WRITE_FLUSH ( &adapter->hw );
}

/**
 * e1000_irq_enable - Enable interrupt generation
 *
 * @adapter: board private structure
 **/
static void e1000_irq_enable ( struct e1000_adapter *adapter )
{
	E1000_WRITE_REG(&adapter->hw, E1000_IMS, IMS_ENABLE_MASK);
	E1000_WRITE_FLUSH(&adapter->hw);
}

/**
 * e1000_sw_init - Initialize general software structures (struct e1000_adapter)
 * @adapter: board private structure to initialize
 *
 * e1000_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int e1000_sw_init(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct pci_device  *pdev = adapter->pdev;

	/* PCI config space info */

	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;

	pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, &hw->subsystem_vendor_id);
	pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &hw->subsystem_device_id);

	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);

	pci_read_config_word(pdev, PCI_COMMAND, &hw->bus.pci_cmd_word);

	adapter->rx_buffer_len = MAXIMUM_ETHERNET_VLAN_SIZE;
	adapter->max_frame_size = MAXIMUM_ETHERNET_VLAN_SIZE +
                                  ETH_HLEN + ETH_FCS_LEN;
	adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;

	hw->fc.requested_mode = e1000_fc_none;

	/* Initialize the hardware-specific values */
	if (e1000_setup_init_funcs(hw, false)) {
		DBG ("Hardware Initialization Failure\n");
		return -EIO;
	}

	/* Explicitly disable IRQ since the NIC can be in any state. */
	e1000_irq_disable ( adapter );

	return 0;
}

int32_t e1000_read_pcie_cap_reg(struct e1000_hw *hw, uint32_t reg, uint16_t *value)
{
    struct e1000_adapter *adapter = hw->back;
    uint16_t cap_offset;

#define  PCI_CAP_ID_EXP        0x10    /* PCI Express */
    cap_offset = pci_find_capability(adapter->pdev, PCI_CAP_ID_EXP);
    if (!cap_offset)
        return -E1000_ERR_CONFIG;

    pci_read_config_word(adapter->pdev, cap_offset + reg, value);

    return 0;
}

void e1000_pci_clear_mwi ( struct e1000_hw *hw )
{
	struct e1000_adapter *adapter = hw->back;

	pci_write_config_word ( adapter->pdev, PCI_COMMAND,
			        hw->bus.pci_cmd_word & ~PCI_COMMAND_INVALIDATE );
}

void e1000_pci_set_mwi ( struct e1000_hw *hw )
{
	struct e1000_adapter *adapter = hw->back;

	pci_write_config_word ( adapter->pdev, PCI_COMMAND,
                                hw->bus.pci_cmd_word );
}

void e1000_read_pci_cfg ( struct e1000_hw *hw, uint32_t reg, uint16_t *value )
{
	struct e1000_adapter *adapter = hw->back;

	pci_read_config_word ( adapter->pdev, reg, value );
}

void e1000_write_pci_cfg ( struct e1000_hw *hw, uint32_t reg, uint16_t *value )
{
	struct e1000_adapter *adapter = hw->back;

	pci_write_config_word ( adapter->pdev, reg, *value );
}

/**
 * e1000_init_manageability - disable interception of ARP packets
 *
 * @v adapter	e1000 private structure
 **/
static void e1000_init_manageability ( struct e1000_adapter *adapter )
{
	if (adapter->en_mng_pt) {
		u32 manc = E1000_READ_REG(&adapter->hw, E1000_MANC);

		/* disable hardware interception of ARP */
		manc &= ~(E1000_MANC_ARP_EN);

		E1000_WRITE_REG(&adapter->hw, E1000_MANC, manc);
	}
}

/**
 * e1000_setup_tx_resources - allocate Tx resources (Descriptors)
 *
 * @v adapter	e1000 private structure
 *
 * @ret rc       Returns 0 on success, negative on failure
 **/
static int e1000_setup_tx_resources ( struct e1000_adapter *adapter )
{
	DBG ( "e1000_setup_tx_resources\n" );

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
 * e1000_process_tx_packets - process transmitted packets
 *
 * @v netdev	network interface device structure
 **/
static void e1000_process_tx_packets ( struct net_device *netdev )
{
	struct e1000_adapter *adapter = netdev_priv ( netdev );
	uint32_t i;
	uint32_t tx_status;
	struct e1000_tx_desc *tx_curr_desc;

	/* Check status of transmitted packets
	 */
	while ( ( i = adapter->tx_head ) != adapter->tx_tail ) {

		tx_curr_desc = ( void * )  ( adapter->tx_base ) +
					   ( i * sizeof ( *adapter->tx_base ) );

		tx_status = tx_curr_desc->upper.data;

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

static void e1000_free_tx_resources ( struct e1000_adapter *adapter )
{
	DBG ( "e1000_free_tx_resources\n" );

        free_dma ( adapter->tx_base, adapter->tx_ring_size );
}

/**
 * e1000_configure_tx - Configure 8254x Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void e1000_configure_tx ( struct e1000_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	uint32_t tctl;

	DBG ( "e1000_configure_tx\n" );

	E1000_WRITE_REG ( hw, E1000_TDBAH(0), 0 );
	E1000_WRITE_REG ( hw, E1000_TDBAL(0), virt_to_bus ( adapter->tx_base ) );
	E1000_WRITE_REG ( hw, E1000_TDLEN(0), adapter->tx_ring_size );

        DBG ( "E1000_TDBAL(0): %#08x\n",  E1000_READ_REG ( hw, E1000_TDBAL(0) ) );
        DBG ( "E1000_TDLEN(0): %d\n",     E1000_READ_REG ( hw, E1000_TDLEN(0) ) );

	/* Setup the HW Tx Head and Tail descriptor pointers */
	E1000_WRITE_REG ( hw, E1000_TDH(0), 0 );
	E1000_WRITE_REG ( hw, E1000_TDT(0), 0 );

	adapter->tx_head = 0;
	adapter->tx_tail = 0;
	adapter->tx_fill_ctr = 0;

	/* Setup Transmit Descriptor Settings for eop descriptor */
	tctl = E1000_TCTL_PSP | E1000_TCTL_EN |
		(E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT) |
		(E1000_COLLISION_DISTANCE  << E1000_COLD_SHIFT);

	e1000_config_collision_dist ( hw );

	E1000_WRITE_REG ( hw, E1000_TCTL, tctl );
        E1000_WRITE_FLUSH ( hw );
}

static void e1000_free_rx_resources ( struct e1000_adapter *adapter )
{
	int i;

	DBG ( "e1000_free_rx_resources\n" );

	free_dma ( adapter->rx_base, adapter->rx_ring_size );

	for ( i = 0; i < NUM_RX_DESC; i++ ) {
		free_iob ( adapter->rx_iobuf[i] );
	}
}

/**
 * e1000_refill_rx_ring - allocate Rx io_buffers
 *
 * @v adapter	e1000 private structure
 *
 * @ret rc       Returns 0 on success, negative on failure
 **/
static int e1000_refill_rx_ring ( struct e1000_adapter *adapter )
{
	int i, rx_curr;
	int rc = 0;
	struct e1000_rx_desc *rx_curr_desc;
	struct e1000_hw *hw = &adapter->hw;
	struct io_buffer *iob;

	DBG ("e1000_refill_rx_ring\n");

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
 * e1000_setup_rx_resources - allocate Rx resources (Descriptors)
 *
 * @v adapter	e1000 private structure
 *
 * @ret rc       Returns 0 on success, negative on failure
 **/
static int e1000_setup_rx_resources ( struct e1000_adapter *adapter )
{
	int i, rc = 0;

	DBG ( "e1000_setup_rx_resources\n" );

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
		/* let e1000_refill_rx_ring() io_buffer allocations */
		adapter->rx_iobuf[i] = NULL;
	}

	/* allocate io_buffers */
	rc = e1000_refill_rx_ring ( adapter );
	if ( rc < 0 )
		e1000_free_rx_resources ( adapter );

	return rc;
}

/**
 * e1000_configure_rx - Configure 8254x Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void e1000_configure_rx ( struct e1000_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	uint32_t rctl;

	DBG ( "e1000_configure_rx\n" );

	/* disable receives while setting up the descriptors */
	rctl = E1000_READ_REG ( hw, E1000_RCTL );
	E1000_WRITE_REG ( hw, E1000_RCTL, rctl & ~E1000_RCTL_EN );
	E1000_WRITE_FLUSH ( hw );
	mdelay(10);

	adapter->rx_curr = 0;

	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring */

	E1000_WRITE_REG ( hw, E1000_RDBAL(0), virt_to_bus ( adapter->rx_base ) );
	E1000_WRITE_REG ( hw, E1000_RDBAH(0), 0 );
	E1000_WRITE_REG ( hw, E1000_RDLEN(0), adapter->rx_ring_size );

	E1000_WRITE_REG ( hw, E1000_RDH(0), 0 );
	E1000_WRITE_REG ( hw, E1000_RDT(0), NUM_RX_DESC - 1 );

	/* Enable Receives */
	rctl |=  E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SZ_2048 |
		 E1000_RCTL_MPE | E1000_RCTL_SECRC;
	E1000_WRITE_REG ( hw, E1000_RCTL, rctl );
	E1000_WRITE_FLUSH ( hw );

        DBG ( "E1000_RDBAL(0): %#08x\n",  E1000_READ_REG ( hw, E1000_RDBAL(0) ) );
        DBG ( "E1000_RDLEN(0): %d\n",     E1000_READ_REG ( hw, E1000_RDLEN(0) ) );
        DBG ( "E1000_RCTL:  %#08x\n",  E1000_READ_REG ( hw, E1000_RCTL ) );
}

/**
 * e1000_process_rx_packets - process received packets
 *
 * @v netdev	network interface device structure
 **/
static void e1000_process_rx_packets ( struct net_device *netdev )
{
	struct e1000_adapter *adapter = netdev_priv ( netdev );
	uint32_t i;
	uint32_t rx_status;
	uint32_t rx_len;
	uint32_t rx_err;
	struct e1000_rx_desc *rx_curr_desc;

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
			DBG ( "e1000_poll: Corrupted packet received!"
			      " rx_err: %#08x\n", rx_err );
		} else {
			/* Add this packet to the receive queue. */
			netdev_rx ( netdev, adapter->rx_iobuf[i] );
		}
		adapter->rx_iobuf[i] = NULL;

		memset ( rx_curr_desc, 0, sizeof ( *rx_curr_desc ) );

		adapter->rx_curr = ( adapter->rx_curr + 1 ) % NUM_RX_DESC;
	}
}

/**
 * e1000_reset - Put e1000 NIC in known initial state
 *
 * @v adapter	e1000 private structure
 **/
void e1000_reset ( struct e1000_adapter *adapter )
{
	struct e1000_mac_info *mac = &adapter->hw.mac;
	u32 pba = 0;

	DBG ( "e1000_reset\n" );

	switch (mac->type) {
	case e1000_82542:
	case e1000_82543:
	case e1000_82544:
	case e1000_82540:
	case e1000_82541:
	case e1000_82541_rev_2:
		pba = E1000_PBA_48K;
		break;
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
		pba = E1000_PBA_48K;
		break;
	case e1000_82547:
	case e1000_82547_rev_2:
		pba = E1000_PBA_30K;
		break;
	case e1000_undefined:
	case e1000_num_macs:
		break;
	}

	E1000_WRITE_REG ( &adapter->hw, E1000_PBA, pba );

	/* Allow time for pending master requests to run */
	e1000_reset_hw ( &adapter->hw );

	if ( mac->type >= e1000_82544 )
		E1000_WRITE_REG ( &adapter->hw, E1000_WUC, 0 );

	if ( e1000_init_hw ( &adapter->hw ) )
		DBG ( "Hardware Error\n" );

	e1000_reset_adaptive ( &adapter->hw );
	e1000_get_phy_info ( &adapter->hw );

	e1000_init_manageability ( adapter );
}

/** Functions that implement the iPXE driver API **/

/**
 * e1000_close - Disables a network interface
 *
 * @v netdev	network interface device structure
 *
 **/
static void e1000_close ( struct net_device *netdev )
{
	struct e1000_adapter *adapter = netdev_priv ( netdev );
	struct e1000_hw *hw = &adapter->hw;
	uint32_t rctl;

	DBG ( "e1000_close\n" );

	/* Disable and acknowledge interrupts */
	e1000_irq_disable ( adapter );
	E1000_READ_REG ( hw, E1000_ICR );

	/* disable receives */
	rctl = E1000_READ_REG ( hw, E1000_RCTL );
	E1000_WRITE_REG ( hw, E1000_RCTL, rctl & ~E1000_RCTL_EN );
	E1000_WRITE_FLUSH ( hw );

	e1000_reset_hw ( hw );

	e1000_free_tx_resources ( adapter );
	e1000_free_rx_resources ( adapter );
}

/**
 * e1000_transmit - Transmit a packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 *
 * @ret rc       Returns 0 on success, negative on failure
 */
static int e1000_transmit ( struct net_device *netdev, struct io_buffer *iobuf )
{
	struct e1000_adapter *adapter = netdev_priv( netdev );
	struct e1000_hw *hw = &adapter->hw;
	uint32_t tx_curr = adapter->tx_tail;
	struct e1000_tx_desc *tx_curr_desc;

	DBG ("e1000_transmit\n");

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
	tx_curr_desc->buffer_addr =
		virt_to_bus ( iobuf->data );
	tx_curr_desc->lower.data =
		E1000_TXD_CMD_RPS  | E1000_TXD_CMD_EOP |
		E1000_TXD_CMD_IFCS | iob_len ( iobuf );
	tx_curr_desc->upper.data = 0;

	DBG ( "TX fill: %d tx_curr: %d addr: %#08lx len: %zd\n", adapter->tx_fill_ctr,
	      tx_curr, virt_to_bus ( iobuf->data ), iob_len ( iobuf ) );

	/* Point to next free descriptor */
	adapter->tx_tail = ( adapter->tx_tail + 1 ) % NUM_TX_DESC;
	adapter->tx_fill_ctr++;

	/* Write new tail to NIC, making packet available for transmit
	 */
	wmb();
	E1000_WRITE_REG ( hw, E1000_TDT(0), adapter->tx_tail );

	return 0;
}

/**
 * e1000_poll - Poll for received packets
 *
 * @v netdev	Network device
 */
static void e1000_poll ( struct net_device *netdev )
{
	struct e1000_adapter *adapter = netdev_priv( netdev );
	struct e1000_hw *hw = &adapter->hw;

	uint32_t icr;

	DBGP ( "e1000_poll\n" );

	/* Acknowledge interrupts */
	icr = E1000_READ_REG ( hw, E1000_ICR );
	if ( ! icr )
		return;

        DBG ( "e1000_poll: intr_status = %#08x\n", icr );

	e1000_process_tx_packets ( netdev );

	e1000_process_rx_packets ( netdev );

	e1000_refill_rx_ring(adapter);
}

/**
 * e1000_irq - enable or Disable interrupts
 *
 * @v adapter   e1000 adapter
 * @v action    requested interrupt action
 **/
static void e1000_irq ( struct net_device *netdev, int enable )
{
	struct e1000_adapter *adapter = netdev_priv ( netdev );

	DBG ( "e1000_irq\n" );

	if ( enable ) {
		e1000_irq_enable ( adapter );
	} else {
		e1000_irq_disable ( adapter );
	}
}

static struct net_device_operations e1000_operations;

/**
 * e1000_probe - Initial configuration of e1000 NIC
 *
 * @v pci	PCI device
 * @v id	PCI IDs
 *
 * @ret rc	Return status code
 **/
int e1000_probe ( struct pci_device *pdev )
{
	int i, err;
	struct net_device *netdev;
	struct e1000_adapter *adapter;
	unsigned long mmio_start, mmio_len;

	DBG ( "e1000_probe\n" );

	err = -ENOMEM;

	/* Allocate net device ( also allocates memory for netdev->priv
	   and makes netdev-priv point to it ) */
	netdev = alloc_etherdev ( sizeof ( struct e1000_adapter ) );
	if ( ! netdev )
		goto err_alloc_etherdev;

	/* Associate e1000-specific network operations operations with
	 * generic network device layer */
	netdev_init ( netdev, &e1000_operations );

	/* Associate this network device with given PCI device */
	pci_set_drvdata ( pdev, netdev );
	netdev->dev = &pdev->dev;

	/* Initialize driver private storage */
	adapter = netdev_priv ( netdev );
        memset ( adapter, 0, ( sizeof ( *adapter ) ) );

	adapter->pdev       = pdev;

	adapter->ioaddr     = pdev->ioaddr;
        adapter->hw.io_base = pdev->ioaddr;

        adapter->irqno      = pdev->irq;
	adapter->netdev     = netdev;
	adapter->hw.back    = adapter;

	adapter->tx_ring_size = sizeof ( *adapter->tx_base ) * NUM_TX_DESC;
	adapter->rx_ring_size = sizeof ( *adapter->rx_base ) * NUM_RX_DESC;

	mmio_start = pci_bar_start ( pdev, PCI_BASE_ADDRESS_0 );
	mmio_len   = pci_bar_size  ( pdev, PCI_BASE_ADDRESS_0 );

	DBG ( "mmio_start: %#08lx\n", mmio_start );
	DBG ( "mmio_len: %#08lx\n", mmio_len );

	/* Fix up PCI device */
	adjust_pci_device ( pdev );

	err = -EIO;

	adapter->hw.hw_addr = ioremap ( mmio_start, mmio_len );
	DBG ( "adapter->hw.hw_addr: %p\n", adapter->hw.hw_addr );

	if ( ! adapter->hw.hw_addr )
		goto err_ioremap;

	/* Hardware features, flags and workarounds */
	if (adapter->hw.mac.type >= e1000_82540) {
		adapter->flags |= E1000_FLAG_HAS_SMBUS;
		adapter->flags |= E1000_FLAG_HAS_INTR_MODERATION;
	}

	if (adapter->hw.mac.type == e1000_82543)
		adapter->flags |= E1000_FLAG_BAD_TX_CARRIER_STATS_FD;

	adapter->hw.phy.autoneg_wait_to_complete = true;
	adapter->hw.mac.adaptive_ifs = true;

	/* setup the private structure */
	if ( ( err = e1000_sw_init ( adapter ) ) )
		goto err_sw_init;

	if ((err = e1000_init_mac_params(&adapter->hw)))
		goto err_hw_init;

	if ((err = e1000_init_nvm_params(&adapter->hw)))
		goto err_hw_init;

        /* Force auto-negotiated speed and duplex */
        adapter->hw.mac.autoneg = 1;

	if ((err = e1000_init_phy_params(&adapter->hw)))
		goto err_hw_init;

	DBG ( "adapter->hw.mac.type: %#08x\n", adapter->hw.mac.type );

	/* before reading the EEPROM, reset the controller to
	 * put the device in a known good starting state
	 */
	err = e1000_reset_hw ( &adapter->hw );
	if ( err < 0 ) {
		DBG ( "Hardware Initialization Failed\n" );
		goto err_reset;
	}
	/* make sure the NVM is good */

	if ( e1000_validate_nvm_checksum(&adapter->hw) < 0 ) {
		DBG ( "The NVM Checksum Is Not Valid\n" );
		err = -EIO;
		goto err_eeprom;
	}

	/* copy the MAC address out of the EEPROM */
	if ( e1000_read_mac_addr ( &adapter->hw ) )
		DBG ( "EEPROM Read Error\n" );

        memcpy ( netdev->hw_addr, adapter->hw.mac.perm_addr, ETH_ALEN );

	/* reset the hardware with the new settings */
	e1000_reset ( adapter );

	if ( ( err = register_netdev ( netdev ) ) != 0)
		goto err_register;

	/* Mark as link up; we don't yet handle link state */
	netdev_link_up ( netdev );

	for (i = 0; i < 6; i++)
		DBG ("%02x%s", netdev->ll_addr[i], i == 5 ? "\n" : ":");

	DBG ( "e1000_probe succeeded!\n" );

	/* No errors, return success */
	return 0;

/* Error return paths */
err_reset:
err_register:
err_hw_init:
err_eeprom:
	if (!e1000_check_reset_block(&adapter->hw))
		e1000_phy_hw_reset(&adapter->hw);
	if (adapter->hw.flash_address)
		iounmap(adapter->hw.flash_address);
err_sw_init:
	iounmap ( adapter->hw.hw_addr );
err_ioremap:
	netdev_put ( netdev );
err_alloc_etherdev:
	return err;
}

/**
 * e1000_remove - Device Removal Routine
 *
 * @v pdev PCI device information struct
 *
 **/
void e1000_remove ( struct pci_device *pdev )
{
	struct net_device *netdev = pci_get_drvdata ( pdev );
	struct e1000_adapter *adapter = netdev_priv ( netdev );

	DBG ( "e1000_remove\n" );

	if ( adapter->hw.flash_address )
		iounmap ( adapter->hw.flash_address );
	if  ( adapter->hw.hw_addr )
		iounmap ( adapter->hw.hw_addr );

	unregister_netdev ( netdev );
	e1000_reset_hw ( &adapter->hw );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/**
 * e1000_open - Called when a network interface is made active
 *
 * @v netdev	network interface device structure
 * @ret rc	Return status code, 0 on success, negative value on failure
 *
 **/
static int e1000_open ( struct net_device *netdev )
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	int err;

	DBG ( "e1000_open\n" );

	/* allocate transmit descriptors */
	err = e1000_setup_tx_resources ( adapter );
	if ( err ) {
		DBG ( "Error setting up TX resources!\n" );
		goto err_setup_tx;
	}

	/* allocate receive descriptors */
	err = e1000_setup_rx_resources ( adapter );
	if ( err ) {
		DBG ( "Error setting up RX resources!\n" );
		goto err_setup_rx;
	}

	e1000_configure_tx ( adapter );

	e1000_configure_rx ( adapter );

        DBG ( "E1000_RXDCTL(0): %#08x\n",  E1000_READ_REG ( &adapter->hw, E1000_RXDCTL(0) ) );

	return 0;

err_setup_rx:
	e1000_free_tx_resources ( adapter );
err_setup_tx:
	e1000_reset ( adapter );

	return err;
}

/** e1000 net device operations */
static struct net_device_operations e1000_operations = {
        .open           = e1000_open,
        .close          = e1000_close,
        .transmit       = e1000_transmit,
        .poll           = e1000_poll,
        .irq            = e1000_irq,
};
