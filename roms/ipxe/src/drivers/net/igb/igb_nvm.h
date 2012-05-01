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

#ifndef _IGB_NVM_H_
#define _IGB_NVM_H_

void igb_init_nvm_ops_generic(struct e1000_hw *hw);
s32  igb_acquire_nvm_generic(struct e1000_hw *hw);

s32  igb_poll_eerd_eewr_done(struct e1000_hw *hw, int ee_reg);
s32  igb_read_mac_addr_generic(struct e1000_hw *hw);
s32  igb_read_pba_num_generic(struct e1000_hw *hw, u32 *pba_num);
s32  igb_read_nvm_eerd(struct e1000_hw *hw, u16 offset, u16 words,
                         u16 *data);
s32  igb_valid_led_default_generic(struct e1000_hw *hw, u16 *data);
s32  igb_validate_nvm_checksum_generic(struct e1000_hw *hw);
s32  igb_write_nvm_eewr(struct e1000_hw *hw, u16 offset,
                          u16 words, u16 *data);
s32  igb_write_nvm_spi(struct e1000_hw *hw, u16 offset, u16 words,
                         u16 *data);
s32  igb_update_nvm_checksum_generic(struct e1000_hw *hw);
void igb_release_nvm_generic(struct e1000_hw *hw);

#define E1000_STM_OPCODE  0xDB00

#endif /* _IGB_NVM_H_ */
