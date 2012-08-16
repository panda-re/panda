/*******************************************************************************

  Intel PRO/1000 Linux driver
  Copyright(c) 1999 - 2009 Intel Corporation.

  Portions Copyright(c) 2010 Marty Connor <mdc@etherboot.org>
  Portions Copyright(c) 2010 Entity Cyber, Inc.
  Portions Copyright(c) 2010 Northrop Grumman Corporation

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

FILE_LICENCE ( GPL2_OR_LATER );

#include "e1000e.h"

static s32 e1000e_get_variants_82571(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	static int global_quad_port_a; /* global port a indication */
	struct pci_device *pdev = adapter->pdev;
	u16 eeprom_data = 0;
	int is_port_b = er32(STATUS) & E1000_STATUS_FUNC_1;

	/* tag quad port adapters first, it's used below */
	switch (pdev->device) {
	case E1000_DEV_ID_82571EB_QUAD_COPPER:
	case E1000_DEV_ID_82571EB_QUAD_FIBER:
	case E1000_DEV_ID_82571EB_QUAD_COPPER_LP:
	case E1000_DEV_ID_82571PT_QUAD_COPPER:
		adapter->flags |= FLAG_IS_QUAD_PORT;
		/* mark the first port */
		if (global_quad_port_a == 0)
			adapter->flags |= FLAG_IS_QUAD_PORT_A;
		/* Reset for multiple quad port adapters */
		global_quad_port_a++;
		if (global_quad_port_a == 4)
			global_quad_port_a = 0;
		break;
	default:
		break;
	}

	switch (adapter->hw.mac.type) {
	case e1000_82571:
		/* these dual ports don't have WoL on port B at all */
		if (((pdev->device == E1000_DEV_ID_82571EB_FIBER) ||
		     (pdev->device == E1000_DEV_ID_82571EB_SERDES) ||
		     (pdev->device == E1000_DEV_ID_82571EB_COPPER)) &&
		    (is_port_b))
			adapter->flags &= ~FLAG_HAS_WOL;
		/* quad ports only support WoL on port A */
		if (adapter->flags & FLAG_IS_QUAD_PORT &&
		    (!(adapter->flags & FLAG_IS_QUAD_PORT_A)))
			adapter->flags &= ~FLAG_HAS_WOL;
		/* Does not support WoL on any port */
		if (pdev->device == E1000_DEV_ID_82571EB_SERDES_QUAD)
			adapter->flags &= ~FLAG_HAS_WOL;
		break;

	case e1000_82573:
		if (pdev->device == E1000_DEV_ID_82573L) {
			if (e1000e_read_nvm(&adapter->hw, NVM_INIT_3GIO_3, 1,
					   &eeprom_data) < 0)
				break;
			if (!(eeprom_data & NVM_WORD1A_ASPM_MASK)) {
				adapter->flags |= FLAG_HAS_JUMBO_FRAMES;
				adapter->max_hw_frame_size = DEFAULT_JUMBO;
			}
		}
		break;

	default:
		break;
	}

	return 0;
}

static struct e1000_info e1000_82571_info = {
	.mac			= e1000_82571,
	.flags			= FLAG_HAS_HW_VLAN_FILTER
				  | FLAG_HAS_JUMBO_FRAMES
				  | FLAG_HAS_WOL
				  | FLAG_APME_IN_CTRL3
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_CTRLEXT_ON_LOAD
				  | FLAG_HAS_SMART_POWER_DOWN
				  | FLAG_RESET_OVERWRITES_LAA /* errata */
				  | FLAG_TARC_SPEED_MODE_BIT /* errata */
				  | FLAG_APME_CHECK_PORT_B,
	.pba			= 38,
	.max_hw_frame_size	= DEFAULT_JUMBO,
	.init_ops		= e1000e_init_function_pointers_82571,
	.get_variants		= e1000e_get_variants_82571,
};

static struct e1000_info e1000_82572_info = {
	.mac			= e1000_82572,
	.flags			= FLAG_HAS_HW_VLAN_FILTER
				  | FLAG_HAS_JUMBO_FRAMES
				  | FLAG_HAS_WOL
				  | FLAG_APME_IN_CTRL3
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_CTRLEXT_ON_LOAD
				  | FLAG_TARC_SPEED_MODE_BIT, /* errata */
	.pba			= 38,
	.max_hw_frame_size	= DEFAULT_JUMBO,
	.init_ops		= e1000e_init_function_pointers_82571,
	.get_variants		= e1000e_get_variants_82571,
};

static struct e1000_info e1000_82573_info = {
	.mac			= e1000_82573,
	.flags			= FLAG_HAS_HW_VLAN_FILTER
				  | FLAG_HAS_WOL
				  | FLAG_APME_IN_CTRL3
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_SMART_POWER_DOWN
				  | FLAG_HAS_AMT
				  | FLAG_HAS_ERT
				  | FLAG_HAS_SWSM_ON_LOAD,
	.pba			= 20,
	.max_hw_frame_size	= ETH_FRAME_LEN + ETH_FCS_LEN,
	.init_ops		= e1000e_init_function_pointers_82571,
	.get_variants		= e1000e_get_variants_82571,
};

static struct e1000_info e1000_82574_info = {
	.mac			= e1000_82574,
	.flags			= FLAG_HAS_HW_VLAN_FILTER
#ifdef CONFIG_E1000E_MSIX
				  | FLAG_HAS_MSIX
#endif
				  | FLAG_HAS_JUMBO_FRAMES
				  | FLAG_HAS_WOL
				  | FLAG_APME_IN_CTRL3
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_SMART_POWER_DOWN
				  | FLAG_HAS_AMT
				  | FLAG_HAS_CTRLEXT_ON_LOAD,
	.pba			= 20,
	.max_hw_frame_size	= DEFAULT_JUMBO,
	.init_ops		= e1000e_init_function_pointers_82571,
	.get_variants		= e1000e_get_variants_82571,
};

static struct e1000_info e1000_82583_info = {
	.mac			= e1000_82583,
	.flags			= FLAG_HAS_HW_VLAN_FILTER
				  | FLAG_HAS_WOL
				  | FLAG_APME_IN_CTRL3
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_SMART_POWER_DOWN
				  | FLAG_HAS_AMT
				  | FLAG_HAS_CTRLEXT_ON_LOAD,
	.pba			= 20,
	.max_hw_frame_size	= ETH_FRAME_LEN + ETH_FCS_LEN,
	.init_ops		= e1000e_init_function_pointers_82571,
	.get_variants		= e1000e_get_variants_82571,
};

static struct e1000_info e1000_es2_info = {
	.mac			= e1000_80003es2lan,
	.flags			= FLAG_HAS_HW_VLAN_FILTER
				  | FLAG_HAS_JUMBO_FRAMES
				  | FLAG_HAS_WOL
				  | FLAG_APME_IN_CTRL3
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_CTRLEXT_ON_LOAD
				  | FLAG_RX_NEEDS_RESTART /* errata */
				  | FLAG_TARC_SET_BIT_ZERO /* errata */
				  | FLAG_APME_CHECK_PORT_B
				  | FLAG_DISABLE_FC_PAUSE_TIME /* errata */
				  | FLAG_TIPG_MEDIUM_FOR_80003ESLAN,
	.pba			= 38,
	.max_hw_frame_size	= DEFAULT_JUMBO,
	.init_ops		= e1000e_init_function_pointers_80003es2lan,
	.get_variants		= NULL,
};

static s32 e1000e_get_variants_ich8lan(struct e1000_adapter *adapter)
{
	if (adapter->hw.phy.type == e1000_phy_ife) {
		adapter->flags &= ~FLAG_HAS_JUMBO_FRAMES;
		adapter->max_hw_frame_size = ETH_FRAME_LEN + ETH_FCS_LEN;
	}

	if ((adapter->hw.mac.type == e1000_ich8lan) &&
	    (adapter->hw.phy.type == e1000_phy_igp_3))
		adapter->flags |= FLAG_LSC_GIG_SPEED_DROP;

	return 0;
}

static struct e1000_info e1000_ich8_info = {
	.mac			= e1000_ich8lan,
	.flags			= FLAG_HAS_WOL
				  | FLAG_IS_ICH
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_CTRLEXT_ON_LOAD
				  | FLAG_HAS_AMT
				  | FLAG_HAS_FLASH
				  | FLAG_APME_IN_WUC,
	.pba			= 8,
	.max_hw_frame_size	= ETH_FRAME_LEN + ETH_FCS_LEN,
	.init_ops		= e1000e_init_function_pointers_ich8lan,
	.get_variants		= e1000e_get_variants_ich8lan,
};

static struct e1000_info e1000_ich9_info = {
	.mac			= e1000_ich9lan,
	.flags			= FLAG_HAS_JUMBO_FRAMES
				  | FLAG_IS_ICH
				  | FLAG_HAS_WOL
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_CTRLEXT_ON_LOAD
				  | FLAG_HAS_AMT
				  | FLAG_HAS_ERT
				  | FLAG_HAS_FLASH
				  | FLAG_APME_IN_WUC,
	.pba			= 10,
	.max_hw_frame_size	= DEFAULT_JUMBO,
	.init_ops		= e1000e_init_function_pointers_ich8lan,
	.get_variants		= e1000e_get_variants_ich8lan,
};

static struct e1000_info e1000_ich10_info = {
	.mac			= e1000_ich10lan,
	.flags			= FLAG_HAS_JUMBO_FRAMES
				  | FLAG_IS_ICH
				  | FLAG_HAS_WOL
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_CTRLEXT_ON_LOAD
				  | FLAG_HAS_AMT
				  | FLAG_HAS_ERT
				  | FLAG_HAS_FLASH
				  | FLAG_APME_IN_WUC,
	.pba			= 10,
	.max_hw_frame_size	= DEFAULT_JUMBO,
	.init_ops		= e1000e_init_function_pointers_ich8lan,
	.get_variants		= e1000e_get_variants_ich8lan,
};

static struct e1000_info e1000_pch_info = {
	.mac			= e1000_pchlan,
	.flags			= FLAG_IS_ICH
				  | FLAG_HAS_WOL
				  | FLAG_RX_CSUM_ENABLED
				  | FLAG_HAS_CTRLEXT_ON_LOAD
				  | FLAG_HAS_AMT
				  | FLAG_HAS_FLASH
				  | FLAG_HAS_JUMBO_FRAMES
				  | FLAG_DISABLE_FC_PAUSE_TIME /* errata */
				  | FLAG_APME_IN_WUC,
	.pba			= 26,
	.max_hw_frame_size	= 4096,
	.init_ops		= e1000e_init_function_pointers_ich8lan,
	.get_variants		= e1000e_get_variants_ich8lan,
};

static const struct e1000_info *e1000_info_tbl[] = {
	[board_82571]		= &e1000_82571_info,
	[board_82572]		= &e1000_82572_info,
	[board_82573]		= &e1000_82573_info,
	[board_82574]		= &e1000_82574_info,
	[board_82583]		= &e1000_82583_info,
	[board_80003es2lan]	= &e1000_es2_info,
	[board_ich8lan]		= &e1000_ich8_info,
	[board_ich9lan]		= &e1000_ich9_info,
	[board_ich10lan]	= &e1000_ich10_info,
	[board_pchlan]		= &e1000_pch_info,
};

/* Low-level support routines */

s32 e1000e_read_pcie_cap_reg(struct e1000_hw *hw, u32 reg, u16 *value)
{
	u16 cap_offset;

	cap_offset = pci_find_capability(hw->adapter->pdev, PCI_CAP_ID_EXP);
	if (!cap_offset)
		return -E1000_ERR_CONFIG;

	pci_read_config_word(hw->adapter->pdev, cap_offset + reg, value);

	return E1000_SUCCESS;
}

/**
 * e1000e_irq_disable - Mask off interrupt generation on the NIC
 **/
static void e1000e_irq_disable(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	ew32(IMC, ~0);
	e1e_flush();
}

/**
 * e1000e_irq_enable - Enable default interrupt generation settings
 **/
static void e1000e_irq_enable(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	ew32(IMS, IMS_ENABLE_MASK);
	e1e_flush();
}

/**
 * e1000_get_hw_control - get control of the h/w from f/w
 * @adapter: address of board private structure
 *
 * e1000_get_hw_control sets {CTRL_EXT|SWSM}:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means that
 * the driver is loaded. For AMT version (only with 82573)
 * of the f/w this means that the network i/f is open.
 **/
static void e1000e_get_hw_control(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl_ext;
	u32 swsm;

	/* Let firmware know the driver has taken over */
	if (adapter->flags & FLAG_HAS_SWSM_ON_LOAD) {
		swsm = er32(SWSM);
		ew32(SWSM, swsm | E1000_SWSM_DRV_LOAD);
	} else if (adapter->flags & FLAG_HAS_CTRLEXT_ON_LOAD) {
		ctrl_ext = er32(CTRL_EXT);
		ew32(CTRL_EXT, ctrl_ext | E1000_CTRL_EXT_DRV_LOAD);
	}
}

/**
 * e1000e_power_up_phy - restore link in case the phy was powered down
 * @adapter: address of board private structure
 *
 * The phy may be powered down to save power and turn off link when the
 * driver is unloaded and wake on lan is not enabled (among others)
 * *** this routine MUST be followed by a call to e1000e_reset ***
 **/
void e1000e_power_up_phy(struct e1000_adapter *adapter)
{
	if (adapter->hw.phy.ops.power_up)
		adapter->hw.phy.ops.power_up(&adapter->hw);

	adapter->hw.mac.ops.setup_link(&adapter->hw);
}

/**
 * e1000_power_down_phy - Power down the PHY
 *
 * Power down the PHY so no link is implied when interface is down.
 * The PHY cannot be powered down if management or WoL is active.
 */
void e1000e_power_down_phy(struct e1000_adapter *adapter)
{
	/* WoL is enabled */
	if (adapter->wol)
		return;

	if (adapter->hw.phy.ops.power_down)
		adapter->hw.phy.ops.power_down(&adapter->hw);
}

/**
 * e1000e_reset - bring the hardware into a known good state
 *
 * This function boots the hardware and enables some settings that
 * require a configuration cycle of the hardware - those cannot be
 * set/changed during runtime. After reset the device needs to be
 * properly configured for Rx, Tx etc.
 */
void e1000e_reset(struct e1000_adapter *adapter)
{
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct e1000_fc_info *fc = &adapter->hw.fc;
	u32 pba = adapter->pba;
	struct e1000_hw *hw = &adapter->hw;

	/* Reset Packet Buffer Allocation to default */
	ew32(PBA, pba);

	hw->fc.requested_mode = e1000_fc_none;
	fc->current_mode = fc->requested_mode;

	/* Allow time for pending master requests to run */
	mac->ops.reset_hw(hw);

	/*
	 * For parts with AMT enabled, let the firmware know
	 * that the network interface is in control
	 */
	if (adapter->flags & FLAG_HAS_AMT)
		e1000e_get_hw_control(adapter);

	ew32(WUC, 0);
	if (adapter->flags2 & FLAG2_HAS_PHY_WAKEUP)
		e1e_wphy(&adapter->hw, BM_WUC, 0);

	if (mac->ops.init_hw(hw))
		DBG("Hardware Error\n");

	/* additional part of the flow-control workaround above */
	if (hw->mac.type == e1000_pchlan)
		ew32(FCRTV_PCH, 0x1000);

	e1000e_reset_adaptive(hw);

	e1000e_get_phy_info(hw);

	if ((adapter->flags & FLAG_HAS_SMART_POWER_DOWN) &&
	    !(adapter->flags & FLAG_SMART_POWER_DOWN)) {
		u16 phy_data = 0;
		/*
		 * speed up time to link by disabling smart power down, ignore
		 * the return value of this function because there is nothing
		 * different we would do if it failed
		 */
		e1e_rphy(hw, IGP02E1000_PHY_POWER_MGMT, &phy_data);
		phy_data &= ~IGP02E1000_PM_SPD;
		e1e_wphy(hw, IGP02E1000_PHY_POWER_MGMT, phy_data);
	}
}

static int e1000e_sw_init(struct e1000_adapter *adapter)
{
	s32 rc;

	/* Set various function pointers */
	adapter->ei->init_ops(&adapter->hw);

	rc = adapter->hw.mac.ops.init_params(&adapter->hw);
	if (rc)
		return rc;

	rc = adapter->hw.nvm.ops.init_params(&adapter->hw);
	if (rc)
		return rc;

	rc = adapter->hw.phy.ops.init_params(&adapter->hw);
	if (rc)
		return rc;

	/* Explicitly disable IRQ since the NIC can be in any state. */
	e1000e_irq_disable(adapter);

	return E1000_SUCCESS;
}

/* TX support routines */

/**
 * e1000_setup_tx_resources - allocate Tx resources (Descriptors)
 *
 * @v adapter	e1000 private structure
 *
 * @ret rc	 Returns 0 on success, negative on failure
 **/
static int e1000e_setup_tx_resources ( struct e1000_adapter *adapter )
{
	DBGP ( "e1000_setup_tx_resources\n" );

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
static void e1000e_process_tx_packets ( struct net_device *netdev )
{
	struct e1000_adapter *adapter = netdev_priv ( netdev );
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

static void e1000e_free_tx_resources ( struct e1000_adapter *adapter )
{
	DBGP ( "e1000_free_tx_resources\n" );

	free_dma ( adapter->tx_base, adapter->tx_ring_size );
}

/**
 * e1000_configure_tx - Configure 8254x Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void e1000e_configure_tx ( struct e1000_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	u32 tctl, tipg, tarc;
	u32 ipgr1, ipgr2;

	DBGP ( "e1000_configure_tx\n" );

	/* disable transmits while setting up the descriptors */
	tctl = E1000_READ_REG ( hw, E1000_TCTL );
	E1000_WRITE_REG ( hw, E1000_TCTL, tctl & ~E1000_TCTL_EN );
	e1e_flush();
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

	/* Set the default values for the Tx Inter Packet Gap timer */
	tipg = DEFAULT_82543_TIPG_IPGT_COPPER;		/*  8  */
	ipgr1 = DEFAULT_82543_TIPG_IPGR1;		/*  8  */
	ipgr2 = DEFAULT_82543_TIPG_IPGR2;		/*  6  */

	if (adapter->flags & FLAG_TIPG_MEDIUM_FOR_80003ESLAN)
		ipgr2 = DEFAULT_80003ES2LAN_TIPG_IPGR2; /*  7  */

	tipg |= ipgr1 << E1000_TIPG_IPGR1_SHIFT;
	tipg |= ipgr2 << E1000_TIPG_IPGR2_SHIFT;
	ew32(TIPG, tipg);

	/* Program the Transmit Control Register */
	tctl = er32(TCTL);
	tctl &= ~E1000_TCTL_CT;
	tctl |= E1000_TCTL_PSP | E1000_TCTL_RTLC |
		(E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT);

	if (adapter->flags & FLAG_TARC_SPEED_MODE_BIT) {
		tarc = er32(TARC(0));
		/*
		 * set the speed mode bit, we'll clear it if we're not at
		 * gigabit link later
		 */
#define SPEED_MODE_BIT (1 << 21)
		tarc |= SPEED_MODE_BIT;
		ew32(TARC(0), tarc);
	}

	/* errata: program both queues to unweighted RR */
	if (adapter->flags & FLAG_TARC_SET_BIT_ZERO) {
		tarc = er32(TARC(0));
		tarc |= 1;
		ew32(TARC(0), tarc);
		tarc = er32(TARC(1));
		tarc |= 1;
		ew32(TARC(1), tarc);
	}

	/* Setup Transmit Descriptor Settings for eop descriptor */
	adapter->txd_cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;

	/* enable Report Status bit */
	adapter->txd_cmd |= E1000_TXD_CMD_RS;

	/*
	 * enable transmits in the hardware, need to do this
	 * after setting TARC(0)
	 */
	tctl |= E1000_TCTL_EN;
	ew32(TCTL, tctl);
	e1e_flush();

	e1000e_config_collision_dist(hw);
}

/* RX support routines */

static void e1000e_free_rx_resources ( struct e1000_adapter *adapter )
{
	int i;

	DBGP ( "e1000_free_rx_resources\n" );

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
 * @ret rc	 Returns 0 on success, negative on failure
 **/
static int e1000e_refill_rx_ring ( struct e1000_adapter *adapter )
{
	int i, rx_curr;
	int rc = 0;
	struct e1000_rx_desc *rx_curr_desc;
	struct e1000_hw *hw = &adapter->hw;
	struct io_buffer *iob;

	DBGP ("e1000_refill_rx_ring\n");

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
 * @ret rc	 Returns 0 on success, negative on failure
 **/
static int e1000e_setup_rx_resources ( struct e1000_adapter *adapter )
{
	int i, rc = 0;

	DBGP ( "e1000_setup_rx_resources\n" );

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
	rc = e1000e_refill_rx_ring ( adapter );
	if ( rc < 0 )
		e1000e_free_rx_resources ( adapter );

	return rc;
}

/**
 * e1000_configure_rx - Configure 8254x Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void e1000e_configure_rx ( struct e1000_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	uint32_t rctl;

	DBGP ( "e1000_configure_rx\n" );

	/* disable receives while setting up the descriptors */
	rctl = E1000_READ_REG ( hw, E1000_RCTL );
	E1000_WRITE_REG ( hw, E1000_RCTL, rctl & ~E1000_RCTL_EN );
	e1e_flush();
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
	rctl |=	 E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SZ_2048 |
		 E1000_RCTL_MPE;
	E1000_WRITE_REG ( hw, E1000_RCTL, rctl );
	e1e_flush();

	DBG ( "E1000_RDBAL(0): %#08x\n",  E1000_READ_REG ( hw, E1000_RDBAL(0) ) );
	DBG ( "E1000_RDLEN(0): %d\n",	  E1000_READ_REG ( hw, E1000_RDLEN(0) ) );
	DBG ( "E1000_RCTL:  %#08x\n",  E1000_READ_REG ( hw, E1000_RCTL ) );
}

/**
 * e1000_process_rx_packets - process received packets
 *
 * @v netdev	network interface device structure
 **/
static void e1000e_process_rx_packets ( struct net_device *netdev )
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
 * e1000_close - Disables a network interface
 *
 * @v netdev	network interface device structure
 *
 **/
static void e1000e_close ( struct net_device *netdev )
{
	struct e1000_adapter *adapter = netdev_priv ( netdev );
	struct e1000_hw *hw = &adapter->hw;
	uint32_t rctl;

	DBGP ( "e1000_close\n" );

	/* Disable and acknowledge interrupts */
	e1000e_irq_disable ( adapter );
	E1000_READ_REG ( hw, E1000_ICR );

	/* disable receives */
	rctl = E1000_READ_REG ( hw, E1000_RCTL );
	E1000_WRITE_REG ( hw, E1000_RCTL, rctl & ~E1000_RCTL_EN );
	e1e_flush();

	e1000e_reset ( adapter );

	e1000e_free_tx_resources ( adapter );
	e1000e_free_rx_resources ( adapter );
}

/**
 * e1000_transmit - Transmit a packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 *
 * @ret rc	 Returns 0 on success, negative on failure
 */
static int e1000e_transmit ( struct net_device *netdev, struct io_buffer *iobuf )
{
	struct e1000_adapter *adapter = netdev_priv( netdev );
	struct e1000_hw *hw = &adapter->hw;
	uint32_t tx_curr = adapter->tx_tail;
	struct e1000_tx_desc *tx_curr_desc;

	DBGP ("e1000_transmit\n");

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
	e1e_flush();

	return 0;
}

/**
 * e1000_poll - Poll for received packets
 *
 * @v netdev	Network device
 */
static void e1000e_poll ( struct net_device *netdev )
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

	e1000e_process_tx_packets ( netdev );

	e1000e_process_rx_packets ( netdev );

	e1000e_refill_rx_ring(adapter);
}

/**
 * e1000_irq - enable or Disable interrupts
 *
 * @v adapter	e1000 adapter
 * @v action	requested interrupt action
 **/
static void e1000e_irq ( struct net_device *netdev, int enable )
{
	struct e1000_adapter *adapter = netdev_priv ( netdev );

	DBGP ( "e1000_irq\n" );

	if ( enable ) {
		e1000e_irq_enable ( adapter );
	} else {
		e1000e_irq_disable ( adapter );
	}
}

static struct net_device_operations e1000e_operations;

/**
 * e1000_probe - Initial configuration of e1000 NIC
 *
 * @v pci	PCI device
 * @v id	PCI IDs
 *
 * @ret rc	Return status code
 **/
int e1000e_probe ( struct pci_device *pdev )
{
	int i, err;
	struct net_device *netdev;
	struct e1000_adapter *adapter;
	unsigned long mmio_start, mmio_len;
	unsigned long flash_start, flash_len;
	struct e1000_hw *hw;
	const struct e1000_info *ei = e1000_info_tbl[pdev->id->driver_data];

	DBGP ( "e1000_probe\n" );

	err = -ENOMEM;

	/* Allocate net device ( also allocates memory for netdev->priv
	   and makes netdev-priv point to it ) */
	netdev = alloc_etherdev ( sizeof ( struct e1000_adapter ) );
	if ( ! netdev ) {
                DBG ( "err_alloc_etherdev\n" );
		goto err_alloc_etherdev;
        }

	/* Associate e1000-specific network operations operations with
	 * generic network device layer */
	netdev_init ( netdev, &e1000e_operations );

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
	hw->device_id	    = pdev->device;

	adapter->irqno	    = pdev->irq;
	adapter->netdev	    = netdev;
	adapter->hw.back    = adapter;

	adapter->ei	    = ei;
	adapter->pba	    = ei->pba;
	adapter->flags	    = ei->flags;
	adapter->flags2	    = ei->flags2;

	adapter->hw.adapter  = adapter;
	adapter->hw.mac.type = ei->mac;
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

	/* Flash BAR mapping depends on mac_type */
	if ( ( adapter->flags & FLAG_HAS_FLASH) && ( pdev->ioaddr ) ) {
		flash_start = pci_bar_start ( pdev, PCI_BASE_ADDRESS_1 );
		flash_len = pci_bar_size ( pdev, PCI_BASE_ADDRESS_1 );
		adapter->hw.flash_address = ioremap ( flash_start, flash_len );
		if ( ! adapter->hw.flash_address ) {
                        DBG ( "err_flashmap\n" );
			goto err_flashmap;
		}
	}

	/* setup adapter struct */
	err = e1000e_sw_init ( adapter );
	if (err) {
                DBG ( "err_sw_init\n" );
		goto err_sw_init;
        }

	if (ei->get_variants) {
		err = ei->get_variants(adapter);
		if (err) {
                        DBG ( "err_hw_initr\n" );
			goto err_hw_init;
                }
	}

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

	/*
	 * before reading the NVM, reset the controller to
	 * put the device in a known good starting state
	 */
	adapter->hw.mac.ops.reset_hw(&adapter->hw);

	/*
	 * systems with ASPM and others may see the checksum fail on the first
	 * attempt. Let's give it a few tries
	 */
	for (i = 0;; i++) {
		if (e1000e_validate_nvm_checksum(&adapter->hw) >= 0)
			break;
		if (i == 2) {
			DBG("The NVM Checksum Is Not Valid\n");
			err = -EIO;
			goto err_eeprom;
		}
	}

	/* copy the MAC address out of the EEPROM */
	if ( e1000e_read_mac_addr ( &adapter->hw ) )
		DBG ( "EEPROM Read Error\n" );

	memcpy ( netdev->hw_addr, adapter->hw.mac.perm_addr, ETH_ALEN );

	/* reset the hardware with the new settings */
	e1000e_reset ( adapter );

	if ( ( err = register_netdev ( netdev ) ) != 0) {
                DBG ( "err_register\n" );
		goto err_register;
        }

	/* Mark as link up; we don't yet handle link state */
	netdev_link_up ( netdev );

	for (i = 0; i < 6; i++)
		DBG ("%02x%s", netdev->ll_addr[i], i == 5 ? "\n" : ":");

	DBG ( "e1000e_probe succeeded!\n" );

	/* No errors, return success */
	return 0;

/* Error return paths */
err_register:
err_hw_init:
err_eeprom:
err_flashmap:
	if (!e1000e_check_reset_block(&adapter->hw))
		e1000e_phy_hw_reset(&adapter->hw);
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
 * e1000e_remove - Device Removal Routine
 *
 * @v pdev PCI device information struct
 *
 **/
void e1000e_remove ( struct pci_device *pdev )
{
	struct net_device *netdev = pci_get_drvdata ( pdev );
	struct e1000_adapter *adapter = netdev_priv ( netdev );

	DBGP ( "e1000e_remove\n" );

	if ( adapter->hw.flash_address )
		iounmap ( adapter->hw.flash_address );
	if  ( adapter->hw.hw_addr )
		iounmap ( adapter->hw.hw_addr );

	unregister_netdev ( netdev );
	e1000e_reset  ( adapter );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/**
 * e1000e_open - Called when a network interface is made active
 *
 * @v netdev	network interface device structure
 * @ret rc	Return status code, 0 on success, negative value on failure
 *
 **/
static int e1000e_open ( struct net_device *netdev )
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	int err;

	DBGP ( "e1000e_open\n" );

	/* allocate transmit descriptors */
	err = e1000e_setup_tx_resources ( adapter );
	if ( err ) {
		DBG ( "Error setting up TX resources!\n" );
		goto err_setup_tx;
	}

	/* allocate receive descriptors */
	err = e1000e_setup_rx_resources ( adapter );
	if ( err ) {
		DBG ( "Error setting up RX resources!\n" );
		goto err_setup_rx;
	}

	e1000e_configure_tx ( adapter );

	e1000e_configure_rx ( adapter );

	DBG ( "E1000_RXDCTL(0): %#08x\n",  E1000_READ_REG ( &adapter->hw, E1000_RXDCTL(0) ) );

	return 0;

err_setup_rx:
        DBG ( "err_setup_rx\n" );
	e1000e_free_tx_resources ( adapter );
err_setup_tx:
        DBG ( "err_setup_tx\n" );
	e1000e_reset ( adapter );

	return err;
}

/** e1000e net device operations */
static struct net_device_operations e1000e_operations = {
	.open		= e1000e_open,
	.close		= e1000e_close,
	.transmit	= e1000e_transmit,
	.poll		= e1000e_poll,
	.irq		= e1000e_irq,
};
