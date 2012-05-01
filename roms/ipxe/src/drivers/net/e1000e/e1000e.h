/*******************************************************************************

  Intel PRO/1000 Linux driver
  Copyright(c) 1999 - 2009 Intel Corporation.

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

/* Linux PRO/1000 Ethernet Driver main header file */

#ifndef _E1000E_H_
#define _E1000E_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ipxe/io.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/malloc.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>

/* Begin OS Dependencies */

#define u8         unsigned char
#define bool       boolean_t
#define dma_addr_t unsigned long
#define __le16     uint16_t
#define __le32     uint32_t
#define __le64     uint64_t

#define __iomem

#define msleep(x) mdelay(x)

#define ETH_FCS_LEN 4

typedef int spinlock_t;
typedef enum {
    false = 0,
    true = 1
} boolean_t;

/* End OS Dependencies */

#include "e1000e_hw.h"

#define E1000_TX_FLAGS_CSUM		0x00000001
#define E1000_TX_FLAGS_VLAN		0x00000002
#define E1000_TX_FLAGS_TSO		0x00000004
#define E1000_TX_FLAGS_IPV4		0x00000008
#define E1000_TX_FLAGS_VLAN_MASK	0xffff0000
#define E1000_TX_FLAGS_VLAN_SHIFT	16

#define E1000_MAX_PER_TXD	8192
#define E1000_MAX_TXD_PWR	12

#define MINIMUM_DHCP_PACKET_SIZE 282

struct e1000_info;

#define e_dbg(arg...) if (0) { printf (arg); };

#ifdef CONFIG_E1000E_MSIX
/* Interrupt modes, as used by the IntMode paramter */
#define E1000E_INT_MODE_LEGACY		0
#define E1000E_INT_MODE_MSI		1
#define E1000E_INT_MODE_MSIX		2

#endif /* CONFIG_E1000E_MSIX */
#ifndef CONFIG_E1000E_NAPI
#define E1000_MAX_INTR 10

#endif /* CONFIG_E1000E_NAPI */
/* Tx/Rx descriptor defines */
#define E1000_DEFAULT_TXD		256
#define E1000_MAX_TXD			4096
#define E1000_MIN_TXD			64

#define E1000_DEFAULT_RXD		256
#define E1000_MAX_RXD			4096
#define E1000_MIN_RXD			64

#define E1000_MIN_ITR_USECS		10 /* 100000 irq/sec */
#define E1000_MAX_ITR_USECS		10000 /* 100    irq/sec */

/* Early Receive defines */
#define E1000_ERT_2048			0x100

#define E1000_FC_PAUSE_TIME		0x0680 /* 858 usec */

/* How many Tx Descriptors do we need to call netif_wake_queue ? */
/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define E1000_RX_BUFFER_WRITE		16 /* Must be power of 2 */

#define AUTO_ALL_MODES			0
#define E1000_EEPROM_APME		0x0400

#define E1000_MNG_VLAN_NONE		(-1)

/* Number of packet split data buffers (not including the header buffer) */
#define PS_PAGE_BUFFERS			(MAX_PS_BUFFERS - 1)

#define MAXIMUM_ETHERNET_VLAN_SIZE 	1522

#define DEFAULT_JUMBO			9234

enum e1000_boards {
	board_82571,
	board_82572,
	board_82573,
	board_82574,
	board_80003es2lan,
	board_ich8lan,
	board_ich9lan,
	board_ich10lan,
	board_pchlan,
	board_82583,
};

/* board specific private data structure */
struct e1000_adapter {
	const struct e1000_info *ei;

	/* OS defined structs */
	struct net_device *netdev;
	struct pci_device *pdev;
	struct net_device_stats net_stats;

	/* structs defined in e1000_hw.h */
	struct e1000_hw hw;

	struct e1000_phy_info phy_info;

	u32 wol;
	u32 pba;
	u32 max_hw_frame_size;

	bool fc_autoneg;

	unsigned int flags;
	unsigned int flags2;

#define NUM_TX_DESC	8
#define NUM_RX_DESC	8

	struct io_buffer *tx_iobuf[NUM_TX_DESC];
	struct io_buffer *rx_iobuf[NUM_RX_DESC];

	struct e1000_tx_desc *tx_base;
	struct e1000_rx_desc *rx_base;

	uint32_t tx_ring_size;
	uint32_t rx_ring_size;

	uint32_t tx_head;
	uint32_t tx_tail;
	uint32_t tx_fill_ctr;

	uint32_t rx_curr;

	uint32_t ioaddr;
	uint32_t irqno;

        uint32_t tx_int_delay;
        uint32_t tx_abs_int_delay;
        uint32_t txd_cmd;
};

struct e1000_info {
	enum e1000_mac_type	mac;
	unsigned int		flags;
	unsigned int		flags2;
	u32			pba;
	u32			max_hw_frame_size;
	s32			(*get_variants)(struct e1000_adapter *);
	void			(*init_ops)(struct e1000_hw *);
};

/* hardware capability, feature, and workaround flags */
#define FLAG_HAS_AMT                      (1 << 0)
#define FLAG_HAS_FLASH                    (1 << 1)
#define FLAG_HAS_HW_VLAN_FILTER           (1 << 2)
#define FLAG_HAS_WOL                      (1 << 3)
#define FLAG_HAS_ERT                      (1 << 4)
#define FLAG_HAS_CTRLEXT_ON_LOAD          (1 << 5)
#define FLAG_HAS_SWSM_ON_LOAD             (1 << 6)
#define FLAG_HAS_JUMBO_FRAMES             (1 << 7)
#define FLAG_IS_ICH                       (1 << 9)
#ifdef CONFIG_E1000E_MSIX
#define FLAG_HAS_MSIX                     (1 << 10)
#endif
#define FLAG_HAS_SMART_POWER_DOWN         (1 << 11)
#define FLAG_IS_QUAD_PORT_A               (1 << 12)
#define FLAG_IS_QUAD_PORT                 (1 << 13)
#define FLAG_TIPG_MEDIUM_FOR_80003ESLAN   (1 << 14)
#define FLAG_APME_IN_WUC                  (1 << 15)
#define FLAG_APME_IN_CTRL3                (1 << 16)
#define FLAG_APME_CHECK_PORT_B            (1 << 17)
#define FLAG_DISABLE_FC_PAUSE_TIME        (1 << 18)
#define FLAG_NO_WAKE_UCAST                (1 << 19)
#define FLAG_MNG_PT_ENABLED               (1 << 20)
#define FLAG_RESET_OVERWRITES_LAA         (1 << 21)
#define FLAG_TARC_SPEED_MODE_BIT          (1 << 22)
#define FLAG_TARC_SET_BIT_ZERO            (1 << 23)
#define FLAG_RX_NEEDS_RESTART             (1 << 24)
#define FLAG_LSC_GIG_SPEED_DROP           (1 << 25)
#define FLAG_SMART_POWER_DOWN             (1 << 26)
#define FLAG_MSI_ENABLED                  (1 << 27)
#define FLAG_RX_CSUM_ENABLED              (1 << 28)
#define FLAG_TSO_FORCE                    (1 << 29)
#define FLAG_RX_RESTART_NOW               (1 << 30)
#define FLAG_MSI_TEST_FAILED              (1 << 31)

/* CRC Stripping defines */
#define FLAG2_CRC_STRIPPING               (1 << 0)
#define FLAG2_HAS_PHY_WAKEUP              (1 << 1)

#define E1000_RX_DESC_PS(R, i)	    \
	(&(((union e1000_rx_desc_packet_split *)((R).desc))[i]))
#define E1000_GET_DESC(R, i, type)	(&(((struct type *)((R).desc))[i]))
#define E1000_RX_DESC(R, i)		E1000_GET_DESC(R, i, e1000_rx_desc)
#define E1000_TX_DESC(R, i)		E1000_GET_DESC(R, i, e1000_tx_desc)
#define E1000_CONTEXT_DESC(R, i)	E1000_GET_DESC(R, i, e1000_context_desc)

enum e1000_state_t {
	__E1000E_TESTING,
	__E1000E_RESETTING,
	__E1000E_DOWN
};

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

extern void e1000e_check_options(struct e1000_adapter *adapter);

extern void e1000e_reset(struct e1000_adapter *adapter);
extern void e1000e_power_up_phy(struct e1000_adapter *adapter);

extern void e1000e_init_function_pointers_82571(struct e1000_hw *hw)
						__attribute__((weak));
extern void e1000e_init_function_pointers_80003es2lan(struct e1000_hw *hw)
						__attribute__((weak));
extern void e1000e_init_function_pointers_ich8lan(struct e1000_hw *hw)
						__attribute__((weak));

extern int e1000e_probe(struct pci_device *pdev);

extern void e1000e_remove(struct pci_device *pdev);

extern s32 e1000e_read_pba_num(struct e1000_hw *hw, u32 *pba_num);

static inline s32 e1000e_commit_phy(struct e1000_hw *hw)
{
	if (hw->phy.ops.commit)
		return hw->phy.ops.commit(hw);

	return 0;
}

extern bool e1000e_enable_mng_pass_thru(struct e1000_hw *hw);

extern bool e1000e_get_laa_state_82571(struct e1000_hw *hw);
extern void e1000e_set_laa_state_82571(struct e1000_hw *hw, bool state);

extern void e1000e_set_kmrn_lock_loss_workaround_ich8lan(struct e1000_hw *hw,
						 bool state);
extern void e1000e_igp3_phy_powerdown_workaround_ich8lan(struct e1000_hw *hw);
extern void e1000e_gig_downshift_workaround_ich8lan(struct e1000_hw *hw);
extern void e1000e_disable_gig_wol_ich8lan(struct e1000_hw *hw);

extern s32 e1000e_check_for_copper_link(struct e1000_hw *hw);
extern s32 e1000e_check_for_fiber_link(struct e1000_hw *hw);
extern s32 e1000e_check_for_serdes_link(struct e1000_hw *hw);
extern s32 e1000e_cleanup_led_generic(struct e1000_hw *hw);
extern s32 e1000e_led_on_generic(struct e1000_hw *hw);
extern s32 e1000e_led_off_generic(struct e1000_hw *hw);
extern s32 e1000e_get_bus_info_pcie(struct e1000_hw *hw);
extern s32 e1000e_get_speed_and_duplex_copper(struct e1000_hw *hw, u16 *speed, u16 *duplex);
extern s32 e1000e_get_speed_and_duplex_fiber_serdes(struct e1000_hw *hw, u16 *speed, u16 *duplex);
extern s32 e1000e_disable_pcie_master(struct e1000_hw *hw);
extern s32 e1000e_get_auto_rd_done(struct e1000_hw *hw);
extern s32 e1000e_id_led_init(struct e1000_hw *hw);
extern void e1000e_clear_hw_cntrs_base(struct e1000_hw *hw);
extern s32 e1000e_setup_fiber_serdes_link(struct e1000_hw *hw);
extern s32 e1000e_copper_link_setup_m88(struct e1000_hw *hw);
extern s32 e1000e_copper_link_setup_igp(struct e1000_hw *hw);
extern s32 e1000e_setup_link(struct e1000_hw *hw);
static inline void e1000e_clear_vfta(struct e1000_hw *hw)
{
	hw->mac.ops.clear_vfta(hw);
}
extern void e1000e_init_rx_addrs(struct e1000_hw *hw, u16 rar_count);
extern void e1000e_update_mc_addr_list_generic(struct e1000_hw *hw,
					       u8 *mc_addr_list,
					       u32 mc_addr_count);
extern void e1000e_rar_set(struct e1000_hw *hw, u8 *addr, u32 index);
extern s32 e1000e_set_fc_watermarks(struct e1000_hw *hw);
extern void e1000e_set_pcie_no_snoop(struct e1000_hw *hw, u32 no_snoop);
extern s32 e1000e_get_hw_semaphore(struct e1000_hw *hw);
extern s32 e1000e_valid_led_default(struct e1000_hw *hw, u16 *data);
extern void e1000e_config_collision_dist(struct e1000_hw *hw);
extern s32 e1000e_config_fc_after_link_up(struct e1000_hw *hw);
extern s32 e1000e_force_mac_fc(struct e1000_hw *hw);
extern s32 e1000e_blink_led(struct e1000_hw *hw);
extern void e1000e_write_vfta_generic(struct e1000_hw *hw, u32 offset, u32 value);
static inline void e1000e_write_vfta(struct e1000_hw *hw, u32 offset, u32 value)
{
	if (hw->mac.ops.write_vfta)
		hw->mac.ops.write_vfta(hw, offset, value);
}
extern void e1000e_reset_adaptive(struct e1000_hw *hw);
extern void e1000e_update_adaptive(struct e1000_hw *hw);

extern s32 e1000e_setup_copper_link(struct e1000_hw *hw);
extern void e1000e_put_hw_semaphore(struct e1000_hw *hw);
extern s32 e1000e_check_reset_block_generic(struct e1000_hw *hw);
#if 0
extern s32 e1000e_phy_force_speed_duplex_igp(struct e1000_hw *hw);
#endif
#if 0
extern s32 e1000e_get_cable_length_igp_2(struct e1000_hw *hw);
#endif
extern s32 e1000e_get_phy_info_igp(struct e1000_hw *hw);
extern s32 e1000e_read_phy_reg_igp(struct e1000_hw *hw, u32 offset, u16 *data);
extern s32 e1000e_phy_hw_reset_generic(struct e1000_hw *hw);
extern s32 e1000e_set_d3_lplu_state(struct e1000_hw *hw, bool active);
extern s32 e1000e_write_phy_reg_igp(struct e1000_hw *hw, u32 offset, u16 data);
extern s32 e1000e_phy_sw_reset(struct e1000_hw *hw);
#if 0
extern s32 e1000e_phy_force_speed_duplex_m88(struct e1000_hw *hw);
#endif
extern s32 e1000e_get_cfg_done(struct e1000_hw *hw);
#if 0
extern s32 e1000e_get_cable_length_m88(struct e1000_hw *hw);
#endif
extern s32 e1000e_get_phy_info_m88(struct e1000_hw *hw);
extern s32 e1000e_read_phy_reg_m88(struct e1000_hw *hw, u32 offset, u16 *data);
extern s32 e1000e_write_phy_reg_m88(struct e1000_hw *hw, u32 offset, u16 data);
extern enum e1000_phy_type e1000e_get_phy_type_from_id(u32 phy_id);
extern s32 e1000e_determine_phy_address(struct e1000_hw *hw);
extern s32 e1000e_write_phy_reg_bm(struct e1000_hw *hw, u32 offset, u16 data);
extern s32 e1000e_read_phy_reg_bm(struct e1000_hw *hw, u32 offset, u16 *data);
#if 0
extern void e1000e_phy_force_speed_duplex_setup(struct e1000_hw *hw, u16 *phy_ctrl);
#endif
extern s32 e1000e_write_kmrn_reg(struct e1000_hw *hw, u32 offset, u16 data);
extern s32 e1000e_read_kmrn_reg(struct e1000_hw *hw, u32 offset, u16 *data);
extern s32 e1000e_phy_has_link_generic(struct e1000_hw *hw, u32 iterations,
			       u32 usec_interval, bool *success);
extern s32 e1000e_phy_reset_dsp(struct e1000_hw *hw);
extern s32 e1000e_read_phy_reg_mdic(struct e1000_hw *hw, u32 offset, u16 *data);
extern s32 e1000e_write_phy_reg_mdic(struct e1000_hw *hw, u32 offset, u16 data);
extern s32 e1000e_check_downshift(struct e1000_hw *hw);

static inline s32 e1000e_phy_hw_reset(struct e1000_hw *hw)
{
	if (hw->phy.ops.reset)
		return hw->phy.ops.reset(hw);

	return 0;
}

static inline s32 e1000e_check_reset_block(struct e1000_hw *hw)
{
	if (hw->phy.ops.check_reset_block)
		return hw->phy.ops.check_reset_block(hw);

	return 0;
}

static inline s32 e1e_rphy(struct e1000_hw *hw, u32 offset, u16 *data)
{
	if (hw->phy.ops.read_reg)
		return hw->phy.ops.read_reg(hw, offset, data);

	return 0;
}

static inline s32 e1e_wphy(struct e1000_hw *hw, u32 offset, u16 data)
{
	if (hw->phy.ops.write_reg)
		return hw->phy.ops.write_reg(hw, offset, data);

	return 0;
}

#if 0
static inline s32 e1000e_get_cable_length(struct e1000_hw *hw)
{
	if (hw->phy.ops.get_cable_length)
		return hw->phy.ops.get_cable_length(hw);

	return 0;
}
#endif

extern s32 e1000e_acquire_nvm(struct e1000_hw *hw);
extern s32 e1000e_write_nvm_spi(struct e1000_hw *hw, u16 offset, u16 words, u16 *data);
extern s32 e1000e_update_nvm_checksum_generic(struct e1000_hw *hw);
extern s32 e1000e_poll_eerd_eewr_done(struct e1000_hw *hw, int ee_reg);
extern s32 e1000e_read_nvm_eerd(struct e1000_hw *hw, u16 offset, u16 words, u16 *data);
extern s32 e1000e_validate_nvm_checksum_generic(struct e1000_hw *hw);
extern void e1000e_release_nvm(struct e1000_hw *hw);

static inline s32 e1000e_read_mac_addr(struct e1000_hw *hw)
{
       if (hw->mac.ops.read_mac_addr)
               return hw->mac.ops.read_mac_addr(hw);

       return e1000e_read_mac_addr_generic(hw);
}

static inline s32 e1000e_validate_nvm_checksum(struct e1000_hw *hw)
{
	return hw->nvm.ops.validate(hw);
}

static inline s32 e1000e_update_nvm_checksum(struct e1000_hw *hw)
{
	return hw->nvm.ops.update(hw);
}

static inline s32 e1000e_read_nvm(struct e1000_hw *hw, u16 offset, u16 words, u16 *data)
{
	return hw->nvm.ops.read(hw, offset, words, data);
}

static inline s32 e1000e_write_nvm(struct e1000_hw *hw, u16 offset, u16 words, u16 *data)
{
	return hw->nvm.ops.write(hw, offset, words, data);
}

static inline s32 e1000e_get_phy_info(struct e1000_hw *hw)
{
	if (hw->phy.ops.get_info)
		return hw->phy.ops.get_info(hw);

	return 0;
}

extern bool e1000e_enable_tx_pkt_filtering(struct e1000_hw *hw);
#if 0
extern s32 e1000e_mng_write_dhcp_info(struct e1000_hw *hw, u8 *buffer, u16 length);
#endif

static inline u32 __er32(struct e1000_hw *hw, unsigned long reg)
{
	return readl(hw->hw_addr + reg);
}

static inline void __ew32(struct e1000_hw *hw, unsigned long reg, u32 val)
{
	writel(val, hw->hw_addr + reg);
}

#define er32(reg)	__er32(hw, E1000_##reg)
#define ew32(reg, val)	__ew32(hw, E1000_##reg, (val))
#define e1e_flush()	er32(STATUS)

#define E1000_WRITE_REG(a, reg, value)  \
    writel((value), ((a)->hw_addr + reg))

#define E1000_READ_REG(a, reg) (readl((a)->hw_addr + reg))

#define E1000_WRITE_REG_ARRAY(a, reg, offset, value)  \
    writel((value), ((a)->hw_addr + reg + ((offset) << 2)))

#define E1000_READ_REG_ARRAY(a, reg, offset) ( \
    readl((a)->hw_addr + reg + ((offset) << 2)))

#define E1000_READ_REG_ARRAY_DWORD E1000_READ_REG_ARRAY
#define E1000_WRITE_REG_ARRAY_DWORD E1000_WRITE_REG_ARRAY

static inline u16 __er16flash(struct e1000_hw *hw, unsigned long reg)
{
	return readw(hw->flash_address + reg);
}

static inline u32 __er32flash(struct e1000_hw *hw, unsigned long reg)
{
	return readl(hw->flash_address + reg);
}

static inline void __ew16flash(struct e1000_hw *hw, unsigned long reg, u16 val)
{
	writew(val, hw->flash_address + reg);
}

static inline void __ew32flash(struct e1000_hw *hw, unsigned long reg, u32 val)
{
	writel(val, hw->flash_address + reg);
}

#define er16flash(reg)		__er16flash(hw, (reg))
#define er32flash(reg)		__er32flash(hw, (reg))
#define ew16flash(reg, val)	__ew16flash(hw, (reg), (val))
#define ew32flash(reg, val)	__ew32flash(hw, (reg), (val))

#endif /* _E1000E_H_ */
