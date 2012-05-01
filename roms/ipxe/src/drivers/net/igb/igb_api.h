/*******************************************************************************

  Intel(R) Gigabit Ethernet Linux driver
  Copyright(c) 2007-2009 Intel Corporation.

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

#ifndef _IGB_API_H_
#define _IGB_API_H_

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

#include "igb_hw.h"

extern void    igb_init_function_pointers_82575(struct e1000_hw *hw) __attribute__((weak));
extern void    igb_rx_fifo_flush_82575(struct e1000_hw *hw) __attribute__((weak));
extern void    igb_init_function_pointers_vf(struct e1000_hw *hw) __attribute__((weak));
extern void    igb_shutdown_fiber_serdes_link(struct e1000_hw *hw) __attribute__((weak));

s32  igb_set_mac_type(struct e1000_hw *hw);
s32  igb_setup_init_funcs(struct e1000_hw *hw, bool init_device);
s32  igb_init_mac_params(struct e1000_hw *hw);
s32  igb_init_nvm_params(struct e1000_hw *hw);
s32  igb_init_phy_params(struct e1000_hw *hw);
s32  igb_init_mbx_params(struct e1000_hw *hw);
s32  igb_get_bus_info(struct e1000_hw *hw);
void igb_clear_vfta(struct e1000_hw *hw);
void igb_write_vfta(struct e1000_hw *hw, u32 offset, u32 value);
s32  igb_force_mac_fc(struct e1000_hw *hw);
s32  igb_check_for_link(struct e1000_hw *hw);
s32  igb_reset_hw(struct e1000_hw *hw);
s32  igb_init_hw(struct e1000_hw *hw);
s32  igb_setup_link(struct e1000_hw *hw);
s32  igb_get_speed_and_duplex(struct e1000_hw *hw, u16 *speed,
                                u16 *duplex);
s32  igb_disable_pcie_master(struct e1000_hw *hw);
void igb_config_collision_dist(struct e1000_hw *hw);
void igb_rar_set(struct e1000_hw *hw, u8 *addr, u32 index);
void igb_mta_set(struct e1000_hw *hw, u32 hash_value);
u32  igb_hash_mc_addr(struct e1000_hw *hw, u8 *mc_addr);
void igb_update_mc_addr_list(struct e1000_hw *hw,
                               u8 *mc_addr_list, u32 mc_addr_count);
s32  igb_setup_led(struct e1000_hw *hw);
s32  igb_cleanup_led(struct e1000_hw *hw);
s32  igb_check_reset_block(struct e1000_hw *hw);
s32  igb_blink_led(struct e1000_hw *hw);
s32  igb_led_on(struct e1000_hw *hw);
s32  igb_led_off(struct e1000_hw *hw);
s32 igb_id_led_init(struct e1000_hw *hw);
void igb_reset_adaptive(struct e1000_hw *hw);
void igb_update_adaptive(struct e1000_hw *hw);
#if 0
s32  igb_get_cable_length(struct e1000_hw *hw);
#endif
s32  igb_validate_mdi_setting(struct e1000_hw *hw);
s32  igb_read_phy_reg(struct e1000_hw *hw, u32 offset, u16 *data);
s32  igb_write_phy_reg(struct e1000_hw *hw, u32 offset, u16 data);
s32  igb_write_8bit_ctrl_reg(struct e1000_hw *hw, u32 reg,
                               u32 offset, u8 data);
s32  igb_get_phy_info(struct e1000_hw *hw);
void igb_release_phy(struct e1000_hw *hw);
s32  igb_acquire_phy(struct e1000_hw *hw);
s32  igb_phy_hw_reset(struct e1000_hw *hw);
s32  igb_phy_commit(struct e1000_hw *hw);
void igb_power_up_phy(struct e1000_hw *hw);
void igb_power_down_phy(struct e1000_hw *hw);
s32  igb_read_mac_addr(struct e1000_hw *hw);
s32  igb_read_pba_num(struct e1000_hw *hw, u32 *part_num);
void igb_reload_nvm(struct e1000_hw *hw);
s32  igb_update_nvm_checksum(struct e1000_hw *hw);
s32  igb_validate_nvm_checksum(struct e1000_hw *hw);
s32  igb_read_nvm(struct e1000_hw *hw, u16 offset, u16 words, u16 *data);
s32  igb_read_kmrn_reg(struct e1000_hw *hw, u32 offset, u16 *data);
s32  igb_write_kmrn_reg(struct e1000_hw *hw, u32 offset, u16 data);
s32  igb_write_nvm(struct e1000_hw *hw, u16 offset, u16 words,
                     u16 *data);
s32  igb_wait_autoneg(struct e1000_hw *hw);
s32  igb_set_d3_lplu_state(struct e1000_hw *hw, bool active);
s32  igb_set_d0_lplu_state(struct e1000_hw *hw, bool active);
bool igb_check_mng_mode(struct e1000_hw *hw);
bool igb_enable_tx_pkt_filtering(struct e1000_hw *hw);
s32  igb_mng_enable_host_if(struct e1000_hw *hw);
s32  igb_mng_host_if_write(struct e1000_hw *hw,
                             u8 *buffer, u16 length, u16 offset, u8 *sum);
s32  igb_mng_write_cmd_header(struct e1000_hw *hw,
                                struct e1000_host_mng_command_header *hdr);
s32  igb_mng_write_dhcp_info(struct e1000_hw * hw,
                                    u8 *buffer, u16 length);

/*
 * TBI_ACCEPT macro definition:
 *
 * This macro requires:
 *      adapter = a pointer to struct e1000_hw
 *      status = the 8 bit status field of the Rx descriptor with EOP set
 *      error = the 8 bit error field of the Rx descriptor with EOP set
 *      length = the sum of all the length fields of the Rx descriptors that
 *               make up the current frame
 *      last_byte = the last byte of the frame DMAed by the hardware
 *      max_frame_length = the maximum frame length we want to accept.
 *      min_frame_length = the minimum frame length we want to accept.
 *
 * This macro is a conditional that should be used in the interrupt
 * handler's Rx processing routine when RxErrors have been detected.
 *
 * Typical use:
 *  ...
 *  if (TBI_ACCEPT) {
 *      accept_frame = true;
 *      e1000_tbi_adjust_stats(adapter, MacAddress);
 *      frame_length--;
 *  } else {
 *      accept_frame = false;
 *  }
 *  ...
 */

/* The carrier extension symbol, as received by the NIC. */
#define CARRIER_EXTENSION   0x0F

#define TBI_ACCEPT(a, status, errors, length, last_byte, min_frame_size, max_frame_size) \
    (e1000_tbi_sbp_enabled_82543(a) && \
     (((errors) & E1000_RXD_ERR_FRAME_ERR_MASK) == E1000_RXD_ERR_CE) && \
     ((last_byte) == CARRIER_EXTENSION) && \
     (((status) & E1000_RXD_STAT_VP) ? \
          (((length) > (min_frame_size - VLAN_TAG_SIZE)) && \
           ((length) <= (max_frame_size + 1))) : \
          (((length) > min_frame_size) && \
           ((length) <= (max_frame_size + VLAN_TAG_SIZE + 1)))))

#endif /* _IGB_API_H_ */
