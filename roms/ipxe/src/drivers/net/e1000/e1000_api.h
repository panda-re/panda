/*******************************************************************************

  Intel PRO/1000 Linux driver
  Copyright(c) 1999 - 2008 Intel Corporation.

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

#ifndef _E1000_API_H_
#define _E1000_API_H_

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

#include "e1000_hw.h"

extern void    e1000_init_function_pointers_82542(struct e1000_hw *hw) __attribute__((weak));
extern void    e1000_init_function_pointers_82543(struct e1000_hw *hw) __attribute__((weak));
extern void    e1000_init_function_pointers_82540(struct e1000_hw *hw) __attribute__((weak));
extern void    e1000_init_function_pointers_82541(struct e1000_hw *hw) __attribute__((weak));

s32  e1000_set_mac_type(struct e1000_hw *hw);
s32  e1000_setup_init_funcs(struct e1000_hw *hw, bool init_device);
s32  e1000_init_mac_params(struct e1000_hw *hw);
s32  e1000_init_nvm_params(struct e1000_hw *hw);
s32  e1000_init_phy_params(struct e1000_hw *hw);
s32  e1000_get_bus_info(struct e1000_hw *hw);
void e1000_clear_vfta(struct e1000_hw *hw);
void e1000_write_vfta(struct e1000_hw *hw, u32 offset, u32 value);
s32  e1000_force_mac_fc(struct e1000_hw *hw);
s32  e1000_check_for_link(struct e1000_hw *hw);
s32  e1000_reset_hw(struct e1000_hw *hw);
s32  e1000_init_hw(struct e1000_hw *hw);
s32  e1000_setup_link(struct e1000_hw *hw);
s32  e1000_get_speed_and_duplex(struct e1000_hw *hw, u16 *speed,
                                u16 *duplex);
s32  e1000_disable_pcie_master(struct e1000_hw *hw);
void e1000_config_collision_dist(struct e1000_hw *hw);
void e1000_rar_set(struct e1000_hw *hw, u8 *addr, u32 index);
void e1000_mta_set(struct e1000_hw *hw, u32 hash_value);
u32  e1000_hash_mc_addr(struct e1000_hw *hw, u8 *mc_addr);
void e1000_update_mc_addr_list(struct e1000_hw *hw,
                               u8 *mc_addr_list, u32 mc_addr_count);
s32  e1000_setup_led(struct e1000_hw *hw);
s32  e1000_cleanup_led(struct e1000_hw *hw);
s32  e1000_check_reset_block(struct e1000_hw *hw);
s32  e1000_blink_led(struct e1000_hw *hw);
s32  e1000_led_on(struct e1000_hw *hw);
s32  e1000_led_off(struct e1000_hw *hw);
s32 e1000_id_led_init(struct e1000_hw *hw);
void e1000_reset_adaptive(struct e1000_hw *hw);
void e1000_update_adaptive(struct e1000_hw *hw);
#if 0
s32  e1000_get_cable_length(struct e1000_hw *hw);
#endif
s32  e1000_validate_mdi_setting(struct e1000_hw *hw);
s32  e1000_read_phy_reg(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_write_phy_reg(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_get_phy_info(struct e1000_hw *hw);
void e1000_release_phy(struct e1000_hw *hw);
s32  e1000_acquire_phy(struct e1000_hw *hw);
s32  e1000_phy_hw_reset(struct e1000_hw *hw);
s32  e1000_phy_commit(struct e1000_hw *hw);
void e1000_power_up_phy(struct e1000_hw *hw);
void e1000_power_down_phy(struct e1000_hw *hw);
s32  e1000_read_mac_addr(struct e1000_hw *hw);
s32  e1000_read_pba_num(struct e1000_hw *hw, u32 *part_num);
void e1000_reload_nvm(struct e1000_hw *hw);
s32  e1000_update_nvm_checksum(struct e1000_hw *hw);
s32  e1000_validate_nvm_checksum(struct e1000_hw *hw);
s32  e1000_read_nvm(struct e1000_hw *hw, u16 offset, u16 words, u16 *data);
s32  e1000_read_kmrn_reg(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_write_kmrn_reg(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_write_nvm(struct e1000_hw *hw, u16 offset, u16 words,
                     u16 *data);
s32  e1000_wait_autoneg(struct e1000_hw *hw);
s32  e1000_set_d3_lplu_state(struct e1000_hw *hw, bool active);
s32  e1000_set_d0_lplu_state(struct e1000_hw *hw, bool active);
bool e1000_check_mng_mode(struct e1000_hw *hw);
bool e1000_enable_tx_pkt_filtering(struct e1000_hw *hw);
s32  e1000_mng_enable_host_if(struct e1000_hw *hw);
s32  e1000_mng_host_if_write(struct e1000_hw *hw,
                             u8 *buffer, u16 length, u16 offset, u8 *sum);
s32  e1000_mng_write_cmd_header(struct e1000_hw *hw,
                                struct e1000_host_mng_command_header *hdr);
s32  e1000_mng_write_dhcp_info(struct e1000_hw * hw,
                                    u8 *buffer, u16 length);
u32  e1000_translate_register_82542(u32 reg) __attribute__((weak));

extern int e1000_probe(struct pci_device *pdev);
extern void e1000_remove(struct pci_device *pdev);

#endif
