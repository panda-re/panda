/*
 * Copyright (c) 2008 Marty Connor <mdc@etherboot.org>
 * Copyright (c) 2008 Entity Cyber, Inc.
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
 *
 * This driver is based on rtl8169 data sheets and work by:
 *
 * Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
 * Copyright (c) 2003 - 2007 Francois Romieu <romieu@fr.zoreil.com>
 * Copyright (c) a lot of people too. Please respect their work.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/io.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/netdevice.h>
#include <ipxe/pci.h>
#include <ipxe/timer.h>
#include <mii.h>

#include "r8169.h"

/*** Low level hardware routines ***/

static void mdio_write(void *ioaddr, int reg_addr, int value)
{
	int i;

	DBGP ( "mdio_write\n" );

	RTL_W32(PHYAR, 0x80000000 | (reg_addr & 0x1f) << 16 | (value & 0xffff));

	for (i = 20; i > 0; i--) {
		/*
		 * Check if the RTL8169 has completed writing to the specified
		 * MII register.
		 */
		if (!(RTL_R32(PHYAR) & 0x80000000))
			break;
		udelay(25);
	}
}

static int mdio_read(void *ioaddr, int reg_addr)
{
	int i, value = -1;

	DBGP ( "mdio_read\n" );

	RTL_W32(PHYAR, 0x0 | (reg_addr & 0x1f) << 16);

	for (i = 20; i > 0; i--) {
		/*
		 * Check if the RTL8169 has completed retrieving data from
		 * the specified MII register.
		 */
		if (RTL_R32(PHYAR) & 0x80000000) {
			value = RTL_R32(PHYAR) & 0xffff;
			break;
		}
		udelay(25);
	}
	return value;
}

static void mdio_patch(void *ioaddr, int reg_addr, int value)
{
	DBGP ( "mdio_patch\n" );

	mdio_write(ioaddr, reg_addr, mdio_read(ioaddr, reg_addr) | value);
}

static void rtl_ephy_write(void *ioaddr, int reg_addr, int value)
{
	unsigned int i;

	DBGP ( "rtl_ephy_write\n" );

	RTL_W32(EPHYAR, EPHYAR_WRITE_CMD | (value & EPHYAR_DATA_MASK) |
		(reg_addr & EPHYAR_REG_MASK) << EPHYAR_REG_SHIFT);

	for (i = 0; i < 100; i++) {
		if (!(RTL_R32(EPHYAR) & EPHYAR_FLAG))
			break;
		udelay(10);
	}
}

static u16 rtl_ephy_read(void *ioaddr, int reg_addr)
{
	u16 value = 0xffff;
	unsigned int i;

	DBGP ( "rtl_ephy_read\n" );

	RTL_W32(EPHYAR, (reg_addr & EPHYAR_REG_MASK) << EPHYAR_REG_SHIFT);

	for (i = 0; i < 100; i++) {
		if (RTL_R32(EPHYAR) & EPHYAR_FLAG) {
			value = RTL_R32(EPHYAR) & EPHYAR_DATA_MASK;
			break;
		}
		udelay(10);
	}

	return value;
}

static void rtl_csi_write(void *ioaddr, int addr, int value)
{
	unsigned int i;

	DBGP ( "rtl_csi_write\n" );

	RTL_W32(CSIDR, value);
	RTL_W32(CSIAR, CSIAR_WRITE_CMD | (addr & CSIAR_ADDR_MASK) |
		CSIAR_BYTE_ENABLE << CSIAR_BYTE_ENABLE_SHIFT);

	for (i = 0; i < 100; i++) {
		if (!(RTL_R32(CSIAR) & CSIAR_FLAG))
			break;
		udelay(10);
	}
}

static u32 rtl_csi_read(void *ioaddr, int addr)
{
	u32 value = ~0x00;
	unsigned int i;

	DBGP ( "rtl_csi_read\n" );

	RTL_W32(CSIAR, (addr & CSIAR_ADDR_MASK) |
		CSIAR_BYTE_ENABLE << CSIAR_BYTE_ENABLE_SHIFT);

	for (i = 0; i < 100; i++) {
		if (RTL_R32(CSIAR) & CSIAR_FLAG) {
			value = RTL_R32(CSIDR);
			break;
		}
		udelay(10);
	}

	return value;
}

static void rtl8169_irq_mask_and_ack(void *ioaddr)
{
	DBGP ( "rtl8169_irq_mask_and_ack\n" );

	RTL_W16(IntrMask, 0x0000);

	RTL_W16(IntrStatus, 0xffff);
}

static unsigned int rtl8169_tbi_reset_pending(void *ioaddr)
{
	DBGP ( "rtl8169_tbi_reset_pending\n" );

	return RTL_R32(TBICSR) & TBIReset;
}

static unsigned int rtl8169_xmii_reset_pending(void *ioaddr)
{
	DBGP ( "rtl8169_xmii_reset_pending\n" );

	return mdio_read(ioaddr, MII_BMCR) & BMCR_RESET;
}

static unsigned int rtl8169_tbi_link_ok(void *ioaddr)
{
	DBGP ( "rtl8169_tbi_link_ok\n" );

	return RTL_R32(TBICSR) & TBILinkOk;
}

static unsigned int rtl8169_xmii_link_ok(void *ioaddr)
{
	DBGP ( "rtl8169_xmii_link_ok\n" );

	return RTL_R8(PHYstatus) & LinkStatus;
}

static void rtl8169_tbi_reset_enable(void *ioaddr)
{
	DBGP ( "rtl8169_tbi_reset_enable\n" );

	RTL_W32(TBICSR, RTL_R32(TBICSR) | TBIReset);
}

static void rtl8169_xmii_reset_enable(void *ioaddr)
{
	unsigned int val;

	DBGP ( "rtl8169_xmii_reset_enable\n" );

	val = mdio_read(ioaddr, MII_BMCR) | BMCR_RESET;
	mdio_write(ioaddr, MII_BMCR, val & 0xffff);
}

static int rtl8169_set_speed_tbi(struct net_device *dev,
				 u8 autoneg, u16 speed, u8 duplex)
{
	struct rtl8169_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	int ret = 0;
	u32 reg;

	DBGP ( "rtl8169_set_speed_tbi\n" );

	reg = RTL_R32(TBICSR);
	if ((autoneg == AUTONEG_DISABLE) && (speed == SPEED_1000) &&
	    (duplex == DUPLEX_FULL)) {
		RTL_W32(TBICSR, reg & ~(TBINwEnable | TBINwRestart));
	} else if (autoneg == AUTONEG_ENABLE)
		RTL_W32(TBICSR, reg | TBINwEnable | TBINwRestart);
	else {
		DBG ( "incorrect speed setting refused in TBI mode\n" );
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int rtl8169_set_speed_xmii(struct net_device *dev,
				  u8 autoneg, u16 speed, u8 duplex)
{
	struct rtl8169_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	int auto_nego, giga_ctrl;

	DBGP ( "rtl8169_set_speed_xmii\n" );

	auto_nego = mdio_read(ioaddr, MII_ADVERTISE);
	auto_nego &= ~(ADVERTISE_10HALF | ADVERTISE_10FULL |
		       ADVERTISE_100HALF | ADVERTISE_100FULL);
	giga_ctrl = mdio_read(ioaddr, MII_CTRL1000);
	giga_ctrl &= ~(ADVERTISE_1000FULL | ADVERTISE_1000HALF);

	if (autoneg == AUTONEG_ENABLE) {
		auto_nego |= (ADVERTISE_10HALF | ADVERTISE_10FULL |
			      ADVERTISE_100HALF | ADVERTISE_100FULL);
		giga_ctrl |= ADVERTISE_1000FULL | ADVERTISE_1000HALF;
	} else {
		if (speed == SPEED_10)
			auto_nego |= ADVERTISE_10HALF | ADVERTISE_10FULL;
		else if (speed == SPEED_100)
			auto_nego |= ADVERTISE_100HALF | ADVERTISE_100FULL;
		else if (speed == SPEED_1000)
			giga_ctrl |= ADVERTISE_1000FULL | ADVERTISE_1000HALF;

		if (duplex == DUPLEX_HALF)
			auto_nego &= ~(ADVERTISE_10FULL | ADVERTISE_100FULL);

		if (duplex == DUPLEX_FULL)
			auto_nego &= ~(ADVERTISE_10HALF | ADVERTISE_100HALF);

		/* This tweak comes straight from Realtek's driver. */
		if ((speed == SPEED_100) && (duplex == DUPLEX_HALF) &&
		    ((tp->mac_version == RTL_GIGA_MAC_VER_13) ||
		     (tp->mac_version == RTL_GIGA_MAC_VER_16))) {
			auto_nego = ADVERTISE_100HALF | ADVERTISE_CSMA;
		}
	}

	/* The 8100e/8101e/8102e do Fast Ethernet only. */
	if ((tp->mac_version == RTL_GIGA_MAC_VER_07) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_08) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_09) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_10) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_13) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_14) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_15) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_16)) {
		if ((giga_ctrl & (ADVERTISE_1000FULL | ADVERTISE_1000HALF))) {
			DBG ( "PHY does not support 1000Mbps.\n" );
		}
		giga_ctrl &= ~(ADVERTISE_1000FULL | ADVERTISE_1000HALF);
	}

	auto_nego |= ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;

	if ((tp->mac_version == RTL_GIGA_MAC_VER_11) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_12) ||
	    (tp->mac_version >= RTL_GIGA_MAC_VER_17)) {
		/*
		 * Wake up the PHY.
		 * Vendor specific (0x1f) and reserved (0x0e) MII registers.
		 */
		mdio_write(ioaddr, 0x1f, 0x0000);
		mdio_write(ioaddr, 0x0e, 0x0000);
	}

	tp->phy_auto_nego_reg = auto_nego;
	tp->phy_1000_ctrl_reg = giga_ctrl;

	mdio_write(ioaddr, MII_ADVERTISE, auto_nego);
	mdio_write(ioaddr, MII_CTRL1000, giga_ctrl);
	mdio_write(ioaddr, MII_BMCR, BMCR_ANENABLE | BMCR_ANRESTART);
	return 0;
}

static int rtl8169_set_speed(struct net_device *dev,
			     u8 autoneg, u16 speed, u8 duplex)
{
	struct rtl8169_private *tp = netdev_priv(dev);
	int ret;

	DBGP ( "rtl8169_set_speed\n" );

	ret = tp->set_speed(dev, autoneg, speed, duplex);

	return ret;
}

static void rtl8169_write_gmii_reg_bit(void *ioaddr, int reg,
				       int bitnum, int bitval)
{
	int val;

	DBGP ( "rtl8169_write_gmii_reg_bit\n" );

	val = mdio_read(ioaddr, reg);
	val = (bitval == 1) ?
		val | (bitval << bitnum) :  val & ~(0x0001 << bitnum);
	mdio_write(ioaddr, reg, val & 0xffff);
}

static void rtl8169_get_mac_version(struct rtl8169_private *tp,
				    void *ioaddr)
{
	/*
	 * The driver currently handles the 8168Bf and the 8168Be identically
	 * but they can be identified more specifically through the test below
	 * if needed:
	 *
	 * (RTL_R32(TxConfig) & 0x700000) == 0x500000 ? 8168Bf : 8168Be
	 *
	 * Same thing for the 8101Eb and the 8101Ec:
	 *
	 * (RTL_R32(TxConfig) & 0x700000) == 0x200000 ? 8101Eb : 8101Ec
	 */
	const struct {
		u32 mask;
		u32 val;
		int mac_version;
	} mac_info[] = {
		/* 8168D family. */
		{ 0x7c800000, 0x28000000,	RTL_GIGA_MAC_VER_25 },

		/* 8168C family. */
		{ 0x7cf00000, 0x3ca00000,	RTL_GIGA_MAC_VER_24 },
		{ 0x7cf00000, 0x3c900000,	RTL_GIGA_MAC_VER_23 },
		{ 0x7cf00000, 0x3c800000,	RTL_GIGA_MAC_VER_18 },
		{ 0x7c800000, 0x3c800000,	RTL_GIGA_MAC_VER_24 },
		{ 0x7cf00000, 0x3c000000,	RTL_GIGA_MAC_VER_19 },
		{ 0x7cf00000, 0x3c200000,	RTL_GIGA_MAC_VER_20 },
		{ 0x7cf00000, 0x3c300000,	RTL_GIGA_MAC_VER_21 },
		{ 0x7cf00000, 0x3c400000,	RTL_GIGA_MAC_VER_22 },
		{ 0x7c800000, 0x3c000000,	RTL_GIGA_MAC_VER_22 },

		/* 8168B family. */
		{ 0x7cf00000, 0x38000000,	RTL_GIGA_MAC_VER_12 },
		{ 0x7cf00000, 0x38500000,	RTL_GIGA_MAC_VER_17 },
		{ 0x7c800000, 0x38000000,	RTL_GIGA_MAC_VER_17 },
		{ 0x7c800000, 0x30000000,	RTL_GIGA_MAC_VER_11 },

		/* 8101 family. */
		{ 0x7cf00000, 0x34a00000,	RTL_GIGA_MAC_VER_09 },
		{ 0x7cf00000, 0x24a00000,	RTL_GIGA_MAC_VER_09 },
		{ 0x7cf00000, 0x34900000,	RTL_GIGA_MAC_VER_08 },
		{ 0x7cf00000, 0x24900000,	RTL_GIGA_MAC_VER_08 },
		{ 0x7cf00000, 0x34800000,	RTL_GIGA_MAC_VER_07 },
		{ 0x7cf00000, 0x24800000,	RTL_GIGA_MAC_VER_07 },
		{ 0x7cf00000, 0x34000000,	RTL_GIGA_MAC_VER_13 },
		{ 0x7cf00000, 0x34300000,	RTL_GIGA_MAC_VER_10 },
		{ 0x7cf00000, 0x34200000,	RTL_GIGA_MAC_VER_16 },
		{ 0x7c800000, 0x34800000,	RTL_GIGA_MAC_VER_09 },
		{ 0x7c800000, 0x24800000,	RTL_GIGA_MAC_VER_09 },
		{ 0x7c800000, 0x34000000,	RTL_GIGA_MAC_VER_16 },
		/* FIXME: where did these entries come from ? -- FR */
		{ 0xfc800000, 0x38800000,	RTL_GIGA_MAC_VER_15 },
		{ 0xfc800000, 0x30800000,	RTL_GIGA_MAC_VER_14 },

		/* 8110 family. */
		{ 0xfc800000, 0x98000000,	RTL_GIGA_MAC_VER_06 },
		{ 0xfc800000, 0x18000000,	RTL_GIGA_MAC_VER_05 },
		{ 0xfc800000, 0x10000000,	RTL_GIGA_MAC_VER_04 },
		{ 0xfc800000, 0x04000000,	RTL_GIGA_MAC_VER_03 },
		{ 0xfc800000, 0x00800000,	RTL_GIGA_MAC_VER_02 },
		{ 0xfc800000, 0x00000000,	RTL_GIGA_MAC_VER_01 },

		{ 0x00000000, 0x00000000,	RTL_GIGA_MAC_VER_01 }	/* Catch-all */
	}, *p = mac_info;
	u32 reg;

	DBGP ( "rtl8169_get_mac_version\n" );

	reg = RTL_R32(TxConfig);
	while ((reg & p->mask) != p->val)
		p++;
	tp->mac_version = p->mac_version;

	DBG ( "tp->mac_version = %d\n", tp->mac_version );

	if (p->mask == 0x00000000) {
		DBG ( "unknown MAC (%08x)\n", reg );
	}
}

struct phy_reg {
	u16 reg;
	u16 val;
};

static void rtl_phy_write(void *ioaddr, struct phy_reg *regs, int len)
{
	DBGP ( "rtl_phy_write\n" );

	while (len-- > 0) {
		mdio_write(ioaddr, regs->reg, regs->val);
		regs++;
	}
}

static void rtl8169s_hw_phy_config(void *ioaddr)
{
	struct {
		u16 regs[5]; /* Beware of bit-sign propagation */
	} phy_magic[5] = { {
		{ 0x0000,	//w 4 15 12 0
		  0x00a1,	//w 3 15 0 00a1
		  0x0008,	//w 2 15 0 0008
		  0x1020,	//w 1 15 0 1020
		  0x1000 } },{	//w 0 15 0 1000
		{ 0x7000,	//w 4 15 12 7
		  0xff41,	//w 3 15 0 ff41
		  0xde60,	//w 2 15 0 de60
		  0x0140,	//w 1 15 0 0140
		  0x0077 } },{	//w 0 15 0 0077
		{ 0xa000,	//w 4 15 12 a
		  0xdf01,	//w 3 15 0 df01
		  0xdf20,	//w 2 15 0 df20
		  0xff95,	//w 1 15 0 ff95
		  0xfa00 } },{	//w 0 15 0 fa00
		{ 0xb000,	//w 4 15 12 b
		  0xff41,	//w 3 15 0 ff41
		  0xde20,	//w 2 15 0 de20
		  0x0140,	//w 1 15 0 0140
		  0x00bb } },{	//w 0 15 0 00bb
		{ 0xf000,	//w 4 15 12 f
		  0xdf01,	//w 3 15 0 df01
		  0xdf20,	//w 2 15 0 df20
		  0xff95,	//w 1 15 0 ff95
		  0xbf00 }	//w 0 15 0 bf00
		}
	}, *p = phy_magic;
	unsigned int i;

	DBGP ( "rtl8169s_hw_phy_config\n" );

	mdio_write(ioaddr, 0x1f, 0x0001);		//w 31 2 0 1
	mdio_write(ioaddr, 0x15, 0x1000);		//w 21 15 0 1000
	mdio_write(ioaddr, 0x18, 0x65c7);		//w 24 15 0 65c7
	rtl8169_write_gmii_reg_bit(ioaddr, 4, 11, 0);	//w 4 11 11 0

	for (i = 0; i < ARRAY_SIZE(phy_magic); i++, p++) {
		int val, pos = 4;

		val = (mdio_read(ioaddr, pos) & 0x0fff) | (p->regs[0] & 0xffff);
		mdio_write(ioaddr, pos, val);
		while (--pos >= 0)
			mdio_write(ioaddr, pos, p->regs[4 - pos] & 0xffff);
		rtl8169_write_gmii_reg_bit(ioaddr, 4, 11, 1); //w 4 11 11 1
		rtl8169_write_gmii_reg_bit(ioaddr, 4, 11, 0); //w 4 11 11 0
	}
	mdio_write(ioaddr, 0x1f, 0x0000); //w 31 2 0 0
}

static void rtl8169sb_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x1f, 0x0002 },
		{ 0x01, 0x90d0 },
		{ 0x1f, 0x0000 }
	};

	DBGP ( "rtl8169sb_hw_phy_config\n" );

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));
}

static void rtl8168bb_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x10, 0xf41b },
		{ 0x1f, 0x0000 }
	};

	mdio_write(ioaddr, 0x1f, 0x0001);
	mdio_patch(ioaddr, 0x16, 1 << 0);

	DBGP ( "rtl8168bb_hw_phy_config\n" );

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));
}

static void rtl8168bef_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x1f, 0x0001 },
		{ 0x10, 0xf41b },
		{ 0x1f, 0x0000 }
	};

	DBGP ( "rtl8168bef_hw_phy_config\n" );

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));
}

static void rtl8168cp_1_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x1f, 0x0000 },
		{ 0x1d, 0x0f00 },
		{ 0x1f, 0x0002 },
		{ 0x0c, 0x1ec8 },
		{ 0x1f, 0x0000 }
	};

	DBGP ( "rtl8168cp_1_hw_phy_config\n" );

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));
}

static void rtl8168cp_2_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x1f, 0x0001 },
		{ 0x1d, 0x3d98 },
		{ 0x1f, 0x0000 }
	};

	DBGP ( "rtl8168cp_2_hw_phy_config\n" );

	mdio_write(ioaddr, 0x1f, 0x0000);
	mdio_patch(ioaddr, 0x14, 1 << 5);
	mdio_patch(ioaddr, 0x0d, 1 << 5);

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));
}

static void rtl8168c_1_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x1f, 0x0001 },
		{ 0x12, 0x2300 },
		{ 0x1f, 0x0002 },
		{ 0x00, 0x88d4 },
		{ 0x01, 0x82b1 },
		{ 0x03, 0x7002 },
		{ 0x08, 0x9e30 },
		{ 0x09, 0x01f0 },
		{ 0x0a, 0x5500 },
		{ 0x0c, 0x00c8 },
		{ 0x1f, 0x0003 },
		{ 0x12, 0xc096 },
		{ 0x16, 0x000a },
		{ 0x1f, 0x0000 },
		{ 0x1f, 0x0000 },
		{ 0x09, 0x2000 },
		{ 0x09, 0x0000 }
	};

	DBGP ( "rtl8168c_1_hw_phy_config\n" );

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));

	mdio_patch(ioaddr, 0x14, 1 << 5);
	mdio_patch(ioaddr, 0x0d, 1 << 5);
	mdio_write(ioaddr, 0x1f, 0x0000);
}

static void rtl8168c_2_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x1f, 0x0001 },
		{ 0x12, 0x2300 },
		{ 0x03, 0x802f },
		{ 0x02, 0x4f02 },
		{ 0x01, 0x0409 },
		{ 0x00, 0xf099 },
		{ 0x04, 0x9800 },
		{ 0x04, 0x9000 },
		{ 0x1d, 0x3d98 },
		{ 0x1f, 0x0002 },
		{ 0x0c, 0x7eb8 },
		{ 0x06, 0x0761 },
		{ 0x1f, 0x0003 },
		{ 0x16, 0x0f0a },
		{ 0x1f, 0x0000 }
	};

	DBGP ( "rtl8168c_2_hw_phy_config\n" );

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));

	mdio_patch(ioaddr, 0x16, 1 << 0);
	mdio_patch(ioaddr, 0x14, 1 << 5);
	mdio_patch(ioaddr, 0x0d, 1 << 5);
	mdio_write(ioaddr, 0x1f, 0x0000);
}

static void rtl8168c_3_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x1f, 0x0001 },
		{ 0x12, 0x2300 },
		{ 0x1d, 0x3d98 },
		{ 0x1f, 0x0002 },
		{ 0x0c, 0x7eb8 },
		{ 0x06, 0x5461 },
		{ 0x1f, 0x0003 },
		{ 0x16, 0x0f0a },
		{ 0x1f, 0x0000 }
	};

	DBGP ( "rtl8168c_3_hw_phy_config\n" );

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));

	mdio_patch(ioaddr, 0x16, 1 << 0);
	mdio_patch(ioaddr, 0x14, 1 << 5);
	mdio_patch(ioaddr, 0x0d, 1 << 5);
	mdio_write(ioaddr, 0x1f, 0x0000);
}

static void rtl8168c_4_hw_phy_config(void *ioaddr)
{
	DBGP ( "rtl8168c_4_hw_phy_config\n" );

	rtl8168c_3_hw_phy_config(ioaddr);
}

static void rtl8168d_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init_0[] = {
		{ 0x1f, 0x0001 },
		{ 0x09, 0x2770 },
		{ 0x08, 0x04d0 },
		{ 0x0b, 0xad15 },
		{ 0x0c, 0x5bf0 },
		{ 0x1c, 0xf101 },
		{ 0x1f, 0x0003 },
		{ 0x14, 0x94d7 },
		{ 0x12, 0xf4d6 },
		{ 0x09, 0xca0f },
		{ 0x1f, 0x0002 },
		{ 0x0b, 0x0b10 },
		{ 0x0c, 0xd1f7 },
		{ 0x1f, 0x0002 },
		{ 0x06, 0x5461 },
		{ 0x1f, 0x0002 },
		{ 0x05, 0x6662 },
		{ 0x1f, 0x0000 },
		{ 0x14, 0x0060 },
		{ 0x1f, 0x0000 },
		{ 0x0d, 0xf8a0 },
		{ 0x1f, 0x0005 },
		{ 0x05, 0xffc2 }
	};

	DBGP ( "rtl8168d_hw_phy_config\n" );

	rtl_phy_write(ioaddr, phy_reg_init_0, ARRAY_SIZE(phy_reg_init_0));

	if (mdio_read(ioaddr, 0x06) == 0xc400) {
		struct phy_reg phy_reg_init_1[] = {
			{ 0x1f, 0x0005 },
			{ 0x01, 0x0300 },
			{ 0x1f, 0x0000 },
			{ 0x11, 0x401c },
			{ 0x16, 0x4100 },
			{ 0x1f, 0x0005 },
			{ 0x07, 0x0010 },
			{ 0x05, 0x83dc },
			{ 0x06, 0x087d },
			{ 0x05, 0x8300 },
			{ 0x06, 0x0101 },
			{ 0x06, 0x05f8 },
			{ 0x06, 0xf9fa },
			{ 0x06, 0xfbef },
			{ 0x06, 0x79e2 },
			{ 0x06, 0x835f },
			{ 0x06, 0xe0f8 },
			{ 0x06, 0x9ae1 },
			{ 0x06, 0xf89b },
			{ 0x06, 0xef31 },
			{ 0x06, 0x3b65 },
			{ 0x06, 0xaa07 },
			{ 0x06, 0x81e4 },
			{ 0x06, 0xf89a },
			{ 0x06, 0xe5f8 },
			{ 0x06, 0x9baf },
			{ 0x06, 0x06ae },
			{ 0x05, 0x83dc },
			{ 0x06, 0x8300 },
		};

		rtl_phy_write(ioaddr, phy_reg_init_1,
			      ARRAY_SIZE(phy_reg_init_1));
	}

	mdio_write(ioaddr, 0x1f, 0x0000);
}

static void rtl8102e_hw_phy_config(void *ioaddr)
{
	struct phy_reg phy_reg_init[] = {
		{ 0x1f, 0x0003 },
		{ 0x08, 0x441d },
		{ 0x01, 0x9100 },
		{ 0x1f, 0x0000 }
	};

	DBGP ( "rtl8102e_hw_phy_config\n" );

	mdio_write(ioaddr, 0x1f, 0x0000);
	mdio_patch(ioaddr, 0x11, 1 << 12);
	mdio_patch(ioaddr, 0x19, 1 << 13);

	rtl_phy_write(ioaddr, phy_reg_init, ARRAY_SIZE(phy_reg_init));
}

static void rtl_hw_phy_config(struct net_device *dev)
{
	struct rtl8169_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;

	DBGP ( "rtl_hw_phy_config\n" );

	DBG ( "mac_version = 0x%02x\n", tp->mac_version );

	switch (tp->mac_version) {
	case RTL_GIGA_MAC_VER_01:
		break;
	case RTL_GIGA_MAC_VER_02:
	case RTL_GIGA_MAC_VER_03:
		rtl8169s_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_04:
		rtl8169sb_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_07:
	case RTL_GIGA_MAC_VER_08:
	case RTL_GIGA_MAC_VER_09:
		rtl8102e_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_11:
		rtl8168bb_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_12:
		rtl8168bef_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_17:
		rtl8168bef_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_18:
		rtl8168cp_1_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_19:
		rtl8168c_1_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_20:
		rtl8168c_2_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_21:
		rtl8168c_3_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_22:
		rtl8168c_4_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_23:
	case RTL_GIGA_MAC_VER_24:
		rtl8168cp_2_hw_phy_config(ioaddr);
		break;
	case RTL_GIGA_MAC_VER_25:
		rtl8168d_hw_phy_config(ioaddr);
		break;

	default:
		break;
	}
}

static void rtl8169_phy_reset(struct net_device *dev __unused,
			      struct rtl8169_private *tp)
{
	void *ioaddr = tp->mmio_addr;
	unsigned int i;

	DBGP ( "rtl8169_phy_reset\n" );

	tp->phy_reset_enable(ioaddr);
	for (i = 0; i < 100; i++) {
		if (!tp->phy_reset_pending(ioaddr))
			return;
		mdelay ( 1 );
	}
	DBG ( "PHY reset failed.\n" );
}

static void rtl8169_init_phy(struct net_device *dev, struct rtl8169_private *tp)
{
	void *ioaddr = tp->mmio_addr;

	DBGP ( "rtl8169_init_phy\n" );

	rtl_hw_phy_config(dev);

	if (tp->mac_version <= RTL_GIGA_MAC_VER_06) {
		DBG ( "Set MAC Reg C+CR Offset 0x82h = 0x01h\n" );
		RTL_W8(0x82, 0x01);
	}

	pci_write_config_byte(tp->pci_dev, PCI_LATENCY_TIMER, 0x40);

	if (tp->mac_version <= RTL_GIGA_MAC_VER_06)
		pci_write_config_byte(tp->pci_dev, PCI_CACHE_LINE_SIZE, 0x08);

	if (tp->mac_version == RTL_GIGA_MAC_VER_02) {
		DBG ( "Set MAC Reg C+CR Offset 0x82h = 0x01h\n" );
		RTL_W8(0x82, 0x01);
		DBG ( "Set PHY Reg 0x0bh = 0x00h\n" );
		mdio_write(ioaddr, 0x0b, 0x0000); //w 0x0b 15 0 0
	}

	rtl8169_phy_reset(dev, tp);

	/*
	 * rtl8169_set_speed_xmii takes good care of the Fast Ethernet
	 * only 8101. Don't panic.
	 */
	rtl8169_set_speed(dev, AUTONEG_ENABLE, SPEED_1000, DUPLEX_FULL);

	if ((RTL_R8(PHYstatus) & TBI_Enable))
		DBG ( "TBI auto-negotiating\n" );
}

static const struct rtl_cfg_info {
	void (*hw_start)(struct net_device *);
	unsigned int region;
	unsigned int align;
	u16 intr_event;
	u16 napi_event;
	unsigned features;
} rtl_cfg_infos [] = {
	[RTL_CFG_0] = {
		.hw_start	= rtl_hw_start_8169,
		.region		= 1,
		.align		= 0,
		.intr_event	= SYSErr | LinkChg | RxOverflow |
				  RxFIFOOver | TxErr | TxOK | RxOK | RxErr,
		.napi_event	= RxFIFOOver | TxErr | TxOK | RxOK | RxOverflow,
		.features	= RTL_FEATURE_GMII
	},
	[RTL_CFG_1] = {
		.hw_start	= rtl_hw_start_8168,
		.region		= 2,
		.align		= 8,
		.intr_event	= SYSErr | LinkChg | RxOverflow |
				  TxErr | TxOK | RxOK | RxErr,
		.napi_event	= TxErr | TxOK | RxOK | RxOverflow,
		.features	= RTL_FEATURE_GMII
	},
	[RTL_CFG_2] = {
		.hw_start	= rtl_hw_start_8101,
		.region		= 2,
		.align		= 8,
		.intr_event	= SYSErr | LinkChg | RxOverflow | PCSTimeout |
				  RxFIFOOver | TxErr | TxOK | RxOK | RxErr,
		.napi_event	= RxFIFOOver | TxErr | TxOK | RxOK | RxOverflow,
	}
};

static void rtl8169_hw_reset(void *ioaddr)
{
	DBGP ( "rtl8169_hw_reset\n" );

	/* Disable interrupts */
	rtl8169_irq_mask_and_ack(ioaddr);

	/* Reset the chipset */
	RTL_W8(ChipCmd, CmdReset);

	/* PCI commit */
	RTL_R8(ChipCmd);
}

static void rtl_set_rx_tx_config_registers(struct rtl8169_private *tp)
{
	void *ioaddr = tp->mmio_addr;
	u32 cfg = rtl8169_rx_config;

	DBGP ( "rtl_set_rx_tx_config_registers\n" );

	cfg |= (RTL_R32(RxConfig) & rtl_chip_info[tp->chipset].RxConfigMask);
	RTL_W32(RxConfig, cfg);

	/* Set DMA burst size and Interframe Gap Time */
	RTL_W32(TxConfig, (TX_DMA_BURST << TxDMAShift) |
		(InterFrameGap << TxInterFrameGapShift));
}

static void rtl_soft_reset ( struct net_device *dev )
{
	struct rtl8169_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	unsigned int i;

	DBGP ( "rtl_hw_soft_reset\n" );

	/* Soft reset the chip. */
	RTL_W8(ChipCmd, CmdReset);

	/* Check that the chip has finished the reset. */
	for (i = 0; i < 100; i++) {
		if ((RTL_R8(ChipCmd) & CmdReset) == 0)
			break;
		mdelay ( 1 );
	}

	if ( i == 100 ) {
		DBG ( "Reset Failed! (> 100 iterations)\n" );
	}
}

static void rtl_hw_start ( struct net_device *dev )
{
	struct rtl8169_private *tp = netdev_priv ( dev );

	DBGP ( "rtl_hw_start\n" );

	/* Soft reset NIC */
	rtl_soft_reset ( dev );

	tp->hw_start ( dev );
}

static void rtl_set_rx_tx_desc_registers(struct rtl8169_private *tp,
					 void *ioaddr)
{
	DBGP ( "rtl_set_rx_tx_desc_registers\n" );

	/*
	 * Magic spell: some iop3xx ARM board needs the TxDescAddrHigh
	 * register to be written before TxDescAddrLow to work.
	 * Switching from MMIO to I/O access fixes the issue as well.
	 */
	RTL_W32 ( TxDescStartAddrHigh, 0 );
	RTL_W32 ( TxDescStartAddrLow, virt_to_bus ( tp->tx_base ) );
	RTL_W32 ( RxDescAddrHigh, 0 );
	RTL_W32 ( RxDescAddrLow, virt_to_bus ( tp->rx_base ) );
}

static u16 rtl_rw_cpluscmd(void *ioaddr)
{
	u16 cmd;

	DBGP ( "rtl_rw_cpluscmd\n" );

	cmd = RTL_R16(CPlusCmd);
	RTL_W16(CPlusCmd, cmd);
	return cmd;
}

static void rtl_set_rx_max_size(void *ioaddr)
{
	DBGP ( "rtl_set_rx_max_size\n" );

	RTL_W16 ( RxMaxSize, RX_BUF_SIZE );
}

static void rtl8169_set_magic_reg(void *ioaddr, unsigned mac_version)
{
	struct {
		u32 mac_version;
		u32 clk;
		u32 val;
	} cfg2_info [] = {
		{ RTL_GIGA_MAC_VER_05, PCI_Clock_33MHz, 0x000fff00 }, // 8110SCd
		{ RTL_GIGA_MAC_VER_05, PCI_Clock_66MHz, 0x000fffff },
		{ RTL_GIGA_MAC_VER_06, PCI_Clock_33MHz, 0x00ffff00 }, // 8110SCe
		{ RTL_GIGA_MAC_VER_06, PCI_Clock_66MHz, 0x00ffffff }
	}, *p = cfg2_info;
	unsigned int i;
	u32 clk;

	DBGP ( "rtl8169_set_magic_reg\n" );

	clk = RTL_R8(Config2) & PCI_Clock_66MHz;
	for (i = 0; i < ARRAY_SIZE(cfg2_info); i++, p++) {
		if ((p->mac_version == mac_version) && (p->clk == clk)) {
			RTL_W32(0x7c, p->val);
			break;
		}
	}
}

static void rtl_set_rx_mode ( struct net_device *netdev )
{
	struct rtl8169_private *tp = netdev_priv ( netdev );
	void *ioaddr = tp->mmio_addr;
	u32 tmp;

	DBGP ( "rtl_set_rx_mode\n" );

	/* Accept all Multicast Packets */

	RTL_W32 ( MAR0 + 0, 0xffffffff );
	RTL_W32 ( MAR0 + 4, 0xffffffff );

	tmp = rtl8169_rx_config | AcceptBroadcast | AcceptMulticast | AcceptMyPhys |
	      ( RTL_R32 ( RxConfig ) & rtl_chip_info[tp->chipset].RxConfigMask );

	RTL_W32 ( RxConfig, tmp );
}

static void rtl_hw_start_8169(struct net_device *dev)
{
	struct rtl8169_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	struct pci_device *pdev = tp->pci_dev;

	DBGP ( "rtl_hw_start_8169\n" );

	if (tp->mac_version == RTL_GIGA_MAC_VER_05) {
		RTL_W16(CPlusCmd, RTL_R16(CPlusCmd) | PCIMulRW);
		pci_write_config_byte(pdev, PCI_CACHE_LINE_SIZE, 0x08);
	}

	RTL_W8(Cfg9346, Cfg9346_Unlock);

	if ((tp->mac_version == RTL_GIGA_MAC_VER_01) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_02) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_03) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_04))
		RTL_W8(ChipCmd, CmdTxEnb | CmdRxEnb);

	RTL_W8(EarlyTxThres, EarlyTxThld);

	rtl_set_rx_max_size(ioaddr);

	if ((tp->mac_version == RTL_GIGA_MAC_VER_01) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_02) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_03) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_04))
		rtl_set_rx_tx_config_registers(tp);

	tp->cp_cmd |= rtl_rw_cpluscmd(ioaddr) | PCIMulRW;

	if ((tp->mac_version == RTL_GIGA_MAC_VER_02) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_03)) {
		DBG ( "Set MAC Reg C+CR Offset 0xE0. "
			"Bit-3 and bit-14 MUST be 1\n" );
		tp->cp_cmd |= (1 << 14);
	}

	RTL_W16(CPlusCmd, tp->cp_cmd);

	rtl8169_set_magic_reg(ioaddr, tp->mac_version);

	/*
	 * Undocumented corner. Supposedly:
	 * (TxTimer << 12) | (TxPackets << 8) | (RxTimer << 4) | RxPackets
	 */
	RTL_W16(IntrMitigate, 0x0000);

	rtl_set_rx_tx_desc_registers(tp, ioaddr);

	if ((tp->mac_version != RTL_GIGA_MAC_VER_01) &&
	    (tp->mac_version != RTL_GIGA_MAC_VER_02) &&
	    (tp->mac_version != RTL_GIGA_MAC_VER_03) &&
	    (tp->mac_version != RTL_GIGA_MAC_VER_04)) {
		RTL_W8(ChipCmd, CmdTxEnb | CmdRxEnb);
		rtl_set_rx_tx_config_registers(tp);
	}

	RTL_W8(Cfg9346, Cfg9346_Lock);

	/* Initially a 10 us delay. Turned it into a PCI commit. - FR */
	RTL_R8(IntrMask);

	RTL_W32(RxMissed, 0);

	rtl_set_rx_mode(dev);

	/* no early-rx interrupts */
	RTL_W16(MultiIntr, RTL_R16(MultiIntr) & 0xF000);

	//        RTL_W16(IntrMask, tp->intr_event);
}

static void rtl_tx_performance_tweak(struct pci_device *pdev, u16 force)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct rtl8169_private *tp = netdev_priv(dev);
	int cap = tp->pcie_cap;

	DBGP ( "rtl_tx_performance_tweak\n" );

	if (cap) {
		u16 ctl;

		pci_read_config_word(pdev, cap + PCI_EXP_DEVCTL, &ctl);
		ctl = (ctl & ~PCI_EXP_DEVCTL_READRQ) | force;
		pci_write_config_word(pdev, cap + PCI_EXP_DEVCTL, ctl);
	}
}

static void rtl_csi_access_enable(void *ioaddr)
{
	u32 csi;

	DBGP ( "rtl_csi_access_enable\n" );

	csi = rtl_csi_read(ioaddr, 0x070c) & 0x00ffffff;
	rtl_csi_write(ioaddr, 0x070c, csi | 0x27000000);
}

struct ephy_info {
	unsigned int offset;
	u16 mask;
	u16 bits;
};

static void rtl_ephy_init(void *ioaddr, struct ephy_info *e, int len)
{
	u16 w;

	DBGP ( "rtl_ephy_init\n" );

	while (len-- > 0) {
		w = (rtl_ephy_read(ioaddr, e->offset) & ~e->mask) | e->bits;
		rtl_ephy_write(ioaddr, e->offset, w);
		e++;
	}
}

static void rtl_disable_clock_request(struct pci_device *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct rtl8169_private *tp = netdev_priv(dev);
	int cap = tp->pcie_cap;

	DBGP ( "rtl_disable_clock_request\n" );

	if (cap) {
		u16 ctl;

		pci_read_config_word(pdev, cap + PCI_EXP_LNKCTL, &ctl);
		ctl &= ~PCI_EXP_LNKCTL_CLKREQ_EN;
		pci_write_config_word(pdev, cap + PCI_EXP_LNKCTL, ctl);
	}
}

#define R8168_CPCMD_QUIRK_MASK (\
	EnableBist | \
	Mac_dbgo_oe | \
	Force_half_dup | \
	Force_rxflow_en | \
	Force_txflow_en | \
	Cxpl_dbg_sel | \
	ASF | \
	PktCntrDisable | \
	Mac_dbgo_sel)

static void rtl_hw_start_8168bb(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8168bb\n" );

	RTL_W8(Config3, RTL_R8(Config3) & ~Beacon_en);

	RTL_W16(CPlusCmd, RTL_R16(CPlusCmd) & ~R8168_CPCMD_QUIRK_MASK);

	rtl_tx_performance_tweak(pdev,
		(0x5 << MAX_READ_REQUEST_SHIFT) | PCI_EXP_DEVCTL_NOSNOOP_EN);
}

static void rtl_hw_start_8168bef(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8168bef\n" );

	rtl_hw_start_8168bb(ioaddr, pdev);

	RTL_W8(EarlyTxThres, EarlyTxThld);

	RTL_W8(Config4, RTL_R8(Config4) & ~(1 << 0));
}

static void __rtl_hw_start_8168cp(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "__rtl_hw_start_8168cp\n" );

	RTL_W8(Config1, RTL_R8(Config1) | Speed_down);

	RTL_W8(Config3, RTL_R8(Config3) & ~Beacon_en);

	rtl_tx_performance_tweak(pdev, 0x5 << MAX_READ_REQUEST_SHIFT);

	rtl_disable_clock_request(pdev);

	RTL_W16(CPlusCmd, RTL_R16(CPlusCmd) & ~R8168_CPCMD_QUIRK_MASK);
}

static void rtl_hw_start_8168cp_1(void *ioaddr, struct pci_device *pdev)
{
	static struct ephy_info e_info_8168cp[] = {
		{ 0x01, 0,	0x0001 },
		{ 0x02, 0x0800,	0x1000 },
		{ 0x03, 0,	0x0042 },
		{ 0x06, 0x0080,	0x0000 },
		{ 0x07, 0,	0x2000 }
	};

	DBGP ( "rtl_hw_start_8168cp_1\n" );

	rtl_csi_access_enable(ioaddr);

	rtl_ephy_init(ioaddr, e_info_8168cp, ARRAY_SIZE(e_info_8168cp));

	__rtl_hw_start_8168cp(ioaddr, pdev);
}

static void rtl_hw_start_8168cp_2(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8168cp_2\n" );

	rtl_csi_access_enable(ioaddr);

	RTL_W8(Config3, RTL_R8(Config3) & ~Beacon_en);

	rtl_tx_performance_tweak(pdev, 0x5 << MAX_READ_REQUEST_SHIFT);

	RTL_W16(CPlusCmd, RTL_R16(CPlusCmd) & ~R8168_CPCMD_QUIRK_MASK);
}

static void rtl_hw_start_8168cp_3(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8168cp_3\n" );

	rtl_csi_access_enable(ioaddr);

	RTL_W8(Config3, RTL_R8(Config3) & ~Beacon_en);

	/* Magic. */
	RTL_W8(DBG_REG, 0x20);

	RTL_W8(EarlyTxThres, EarlyTxThld);

	rtl_tx_performance_tweak(pdev, 0x5 << MAX_READ_REQUEST_SHIFT);

	RTL_W16(CPlusCmd, RTL_R16(CPlusCmd) & ~R8168_CPCMD_QUIRK_MASK);
}

static void rtl_hw_start_8168c_1(void *ioaddr, struct pci_device *pdev)
{
	static struct ephy_info e_info_8168c_1[] = {
		{ 0x02, 0x0800,	0x1000 },
		{ 0x03, 0,	0x0002 },
		{ 0x06, 0x0080,	0x0000 }
	};

	DBGP ( "rtl_hw_start_8168c_1\n" );

	rtl_csi_access_enable(ioaddr);

	RTL_W8(DBG_REG, 0x06 | FIX_NAK_1 | FIX_NAK_2);

	rtl_ephy_init(ioaddr, e_info_8168c_1, ARRAY_SIZE(e_info_8168c_1));

	__rtl_hw_start_8168cp(ioaddr, pdev);
}

static void rtl_hw_start_8168c_2(void *ioaddr, struct pci_device *pdev)
{
	static struct ephy_info e_info_8168c_2[] = {
		{ 0x01, 0,	0x0001 },
		{ 0x03, 0x0400,	0x0220 }
	};

	DBGP ( "rtl_hw_start_8168c_2\n" );

	rtl_csi_access_enable(ioaddr);

	rtl_ephy_init(ioaddr, e_info_8168c_2, ARRAY_SIZE(e_info_8168c_2));

	__rtl_hw_start_8168cp(ioaddr, pdev);
}

static void rtl_hw_start_8168c_3(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8168c_3\n" );

	rtl_hw_start_8168c_2(ioaddr, pdev);
}

static void rtl_hw_start_8168c_4(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8168c_4\n" );

	rtl_csi_access_enable(ioaddr);

	__rtl_hw_start_8168cp(ioaddr, pdev);
}

static void rtl_hw_start_8168d(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8168d\n" );

	rtl_csi_access_enable(ioaddr);

	rtl_disable_clock_request(pdev);

	RTL_W8(EarlyTxThres, EarlyTxThld);

	rtl_tx_performance_tweak(pdev, 0x5 << MAX_READ_REQUEST_SHIFT);

	RTL_W16(CPlusCmd, RTL_R16(CPlusCmd) & ~R8168_CPCMD_QUIRK_MASK);
}

static void rtl_hw_start_8168(struct net_device *dev)
{
	struct rtl8169_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	struct pci_device *pdev = tp->pci_dev;

	DBGP ( "rtl_hw_start_8168\n" );

	RTL_W8(Cfg9346, Cfg9346_Unlock);

	RTL_W8(EarlyTxThres, EarlyTxThld);

	rtl_set_rx_max_size(ioaddr);

	tp->cp_cmd |= RTL_R16(CPlusCmd) | PktCntrDisable | INTT_1;

	RTL_W16(CPlusCmd, tp->cp_cmd);

	RTL_W16(IntrMitigate, 0x5151);

	/* Work around for RxFIFO overflow. */
	if (tp->mac_version == RTL_GIGA_MAC_VER_11) {
		tp->intr_event |= RxFIFOOver | PCSTimeout;
		tp->intr_event &= ~RxOverflow;
	}

	rtl_set_rx_tx_desc_registers(tp, ioaddr);

	rtl_set_rx_mode(dev);

	RTL_W32(TxConfig, (TX_DMA_BURST << TxDMAShift) |
		(InterFrameGap << TxInterFrameGapShift));

	RTL_R8(IntrMask);

	switch (tp->mac_version) {
	case RTL_GIGA_MAC_VER_11:
		rtl_hw_start_8168bb(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_12:
	case RTL_GIGA_MAC_VER_17:
		rtl_hw_start_8168bef(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_18:
		rtl_hw_start_8168cp_1(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_19:
		rtl_hw_start_8168c_1(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_20:
		rtl_hw_start_8168c_2(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_21:
		rtl_hw_start_8168c_3(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_22:
		rtl_hw_start_8168c_4(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_23:
		rtl_hw_start_8168cp_2(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_24:
		rtl_hw_start_8168cp_3(ioaddr, pdev);
	break;

	case RTL_GIGA_MAC_VER_25:
		rtl_hw_start_8168d(ioaddr, pdev);
	break;

	default:
		DBG ( "Unknown chipset (mac_version = %d).\n",
		      tp->mac_version );
	break;
	}

	RTL_W8(ChipCmd, CmdTxEnb | CmdRxEnb);

	RTL_W8(Cfg9346, Cfg9346_Lock);

	RTL_W16(MultiIntr, RTL_R16(MultiIntr) & 0xF000);

	//        RTL_W16(IntrMask, tp->intr_event);
}

#define R810X_CPCMD_QUIRK_MASK (\
	EnableBist | \
	Mac_dbgo_oe | \
	Force_half_dup | \
	Force_half_dup | \
	Force_txflow_en | \
	Cxpl_dbg_sel | \
	ASF | \
	PktCntrDisable | \
	PCIDAC | \
	PCIMulRW)

static void rtl_hw_start_8102e_1(void *ioaddr, struct pci_device *pdev)
{
	static struct ephy_info e_info_8102e_1[] = {
		{ 0x01,	0, 0x6e65 },
		{ 0x02,	0, 0x091f },
		{ 0x03,	0, 0xc2f9 },
		{ 0x06,	0, 0xafb5 },
		{ 0x07,	0, 0x0e00 },
		{ 0x19,	0, 0xec80 },
		{ 0x01,	0, 0x2e65 },
		{ 0x01,	0, 0x6e65 }
	};
	u8 cfg1;

	DBGP ( "rtl_hw_start_8102e_1\n" );

	rtl_csi_access_enable(ioaddr);

	RTL_W8(DBG_REG, FIX_NAK_1);

	rtl_tx_performance_tweak(pdev, 0x5 << MAX_READ_REQUEST_SHIFT);

	RTL_W8(Config1,
	       LEDS1 | LEDS0 | Speed_down | MEMMAP | IOMAP | VPD | PMEnable);
	RTL_W8(Config3, RTL_R8(Config3) & ~Beacon_en);

	cfg1 = RTL_R8(Config1);
	if ((cfg1 & LEDS0) && (cfg1 & LEDS1))
		RTL_W8(Config1, cfg1 & ~LEDS0);

	RTL_W16(CPlusCmd, RTL_R16(CPlusCmd) & ~R810X_CPCMD_QUIRK_MASK);

	rtl_ephy_init(ioaddr, e_info_8102e_1, ARRAY_SIZE(e_info_8102e_1));
}

static void rtl_hw_start_8102e_2(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8102e_2\n" );

	rtl_csi_access_enable(ioaddr);

	rtl_tx_performance_tweak(pdev, 0x5 << MAX_READ_REQUEST_SHIFT);

	RTL_W8(Config1, MEMMAP | IOMAP | VPD | PMEnable);
	RTL_W8(Config3, RTL_R8(Config3) & ~Beacon_en);

	RTL_W16(CPlusCmd, RTL_R16(CPlusCmd) & ~R810X_CPCMD_QUIRK_MASK);
}

static void rtl_hw_start_8102e_3(void *ioaddr, struct pci_device *pdev)
{
	DBGP ( "rtl_hw_start_8102e_3\n" );

	rtl_hw_start_8102e_2(ioaddr, pdev);

	rtl_ephy_write(ioaddr, 0x03, 0xc2f9);
}

static void rtl_hw_start_8101(struct net_device *dev)
{
	struct rtl8169_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	struct pci_device *pdev = tp->pci_dev;

	DBGP ( "rtl_hw_start_8101\n" );

	if ((tp->mac_version == RTL_GIGA_MAC_VER_13) ||
	    (tp->mac_version == RTL_GIGA_MAC_VER_16)) {
		int cap = tp->pcie_cap;

		if (cap) {
			pci_write_config_word(pdev, cap + PCI_EXP_DEVCTL,
					      PCI_EXP_DEVCTL_NOSNOOP_EN);
		}
	}

	switch (tp->mac_version) {
	case RTL_GIGA_MAC_VER_07:
		rtl_hw_start_8102e_1(ioaddr, pdev);
		break;

	case RTL_GIGA_MAC_VER_08:
		rtl_hw_start_8102e_3(ioaddr, pdev);
		break;

	case RTL_GIGA_MAC_VER_09:
		rtl_hw_start_8102e_2(ioaddr, pdev);
		break;
	}

	RTL_W8(Cfg9346, Cfg9346_Unlock);

	RTL_W8(EarlyTxThres, EarlyTxThld);

	rtl_set_rx_max_size(ioaddr);

	tp->cp_cmd |= rtl_rw_cpluscmd(ioaddr) | PCIMulRW;

	RTL_W16(CPlusCmd, tp->cp_cmd);

	RTL_W16(IntrMitigate, 0x0000);

	rtl_set_rx_tx_desc_registers(tp, ioaddr);

	RTL_W8(ChipCmd, CmdTxEnb | CmdRxEnb);
	rtl_set_rx_tx_config_registers(tp);

	RTL_W8(Cfg9346, Cfg9346_Lock);

	RTL_R8(IntrMask);

	rtl_set_rx_mode(dev);

	RTL_W8(ChipCmd, CmdTxEnb | CmdRxEnb);

	RTL_W16(MultiIntr, RTL_R16(MultiIntr) & 0xf000);

	//        RTL_W16(IntrMask, tp->intr_event);
}

/*** iPXE API Support Routines ***/

/**
 * setup_tx_resources - allocate tx resources (descriptors)
 *
 * @v tp	 Driver private storage
 *
 * @ret rc       Returns 0 on success, negative on failure
 **/
static int
rtl8169_setup_tx_resources ( struct rtl8169_private *tp )
{
	DBGP ( "rtl8169_setup_tx_resources\n" );

	tp->tx_base = malloc_dma ( R8169_TX_RING_BYTES, TX_RING_ALIGN );

	if ( ! tp->tx_base ) {
		return -ENOMEM;
	}

	memset ( tp->tx_base, 0, R8169_TX_RING_BYTES );

	DBG ( "tp->tx_base      = %#08lx\n", virt_to_bus ( tp->tx_base ) );

	tp->tx_fill_ctr = 0;
	tp->tx_curr = 0;
	tp->tx_tail = 0;

	return 0;
}

static void
rtl8169_process_tx_packets ( struct net_device *netdev )
{
	struct rtl8169_private *tp = netdev_priv ( netdev );

	uint32_t tx_status;
	struct TxDesc *tx_curr_desc;

	DBGP ( "rtl8169_process_tx_packets\n" );

	while ( tp->tx_tail != tp->tx_curr ) {

		tx_curr_desc = tp->tx_base  + tp->tx_tail;

		tx_status = tx_curr_desc->opts1;

		DBG2 ( "Before DescOwn check tx_status: %#08x\n", tx_status );

		/* if the packet at tx_tail is not owned by hardware it is for us */
		if ( tx_status & DescOwn )
			break;

		DBG ( "Transmitted packet.\n" );
		DBG ( "tp->tx_fill_ctr     = %d\n", tp->tx_fill_ctr );
		DBG ( "tp->tx_tail         = %d\n", tp->tx_tail );
		DBG ( "tp->tx_curr         = %d\n", tp->tx_curr );
		DBG ( "tx_status           = %d\n", tx_status );
		DBG ( "tx_curr_desc        = %#08lx\n", virt_to_bus ( tx_curr_desc ) );

		/* Pass packet to core for processing */
		netdev_tx_complete ( netdev, tp->tx_iobuf[tp->tx_tail] );

		memset ( tx_curr_desc, 0, sizeof ( *tx_curr_desc ) );

		/* Decrement count of used descriptors */
		tp->tx_fill_ctr--;

		/* Increment sent packets index */
		tp->tx_tail = ( tp->tx_tail + 1 ) % NUM_TX_DESC;
	}
}

static void
rtl8169_free_tx_resources ( struct rtl8169_private *tp )
{
	DBGP ( "rtl8169_free_tx_resources\n" );

	free_dma ( tp->tx_base, R8169_TX_RING_BYTES );
}

static void
rtl8169_populate_rx_descriptor ( struct rtl8169_private *tp, struct RxDesc *rx_desc, uint32_t index )
{
	DBGP ( "rtl8169_populate_rx_descriptor\n" );

	DBG ( "Populating rx descriptor %d\n", index );

	memset ( rx_desc, 0, sizeof ( *rx_desc ) );

	rx_desc->addr_hi = 0;
	rx_desc->addr_lo = virt_to_bus ( tp->rx_iobuf[index]->data );
	rx_desc->opts2 = 0;
	rx_desc->opts1 = ( index == ( NUM_RX_DESC - 1 ) ? RingEnd : 0 ) |
		RX_BUF_SIZE;
	rx_desc->opts1 |= DescOwn;
}

/**
 * Refill descriptor ring
 *
 * @v netdev		Net device
 */
static void rtl8169_refill_rx_ring ( struct rtl8169_private *tp )
{
	struct RxDesc *rx_curr_desc;
	int i;

	DBGP ( "rtl8169_refill_rx_ring\n" );

	for ( i = 0; i < NUM_RX_DESC; i++ ) {

		rx_curr_desc = ( tp->rx_base ) + i;

		/* Don't touch descriptors owned by the NIC */
		if ( rx_curr_desc->opts1 & DescOwn )
			continue;

		/* Don't touch descriptors with iobufs, they still need to be
		   processed by the poll routine */
		if ( tp->rx_iobuf[tp->rx_curr] != NULL )
			continue;

		/** If we can't get an iobuf for this descriptor
		    try again later (next poll).
		 */
		if ( ! ( tp->rx_iobuf[i] = alloc_iob ( RX_BUF_SIZE ) ) ) {
			DBG ( "Refill rx ring failed!!\n" );
			break;
		}

		rtl8169_populate_rx_descriptor ( tp, rx_curr_desc, i );
	}
}

/**
 * setup_rx_resources - allocate Rx resources (Descriptors)
 *
 * @v tp:	 Driver private structure
 *
 * @ret rc       Returns 0 on success, negative on failure
 *
 **/
static int
rtl8169_setup_rx_resources ( struct rtl8169_private *tp )
{
	DBGP ( "rtl8169_setup_rx_resources\n" );

	tp->rx_base = malloc_dma ( R8169_RX_RING_BYTES, RX_RING_ALIGN );

	DBG ( "tp->rx_base      = %#08lx\n", virt_to_bus ( tp->rx_base ) );

	if ( ! tp->rx_base ) {
		return -ENOMEM;
	}
	memset ( tp->rx_base, 0, R8169_RX_RING_BYTES );

	rtl8169_refill_rx_ring ( tp );

	tp->rx_curr = 0;

	return 0;
}

static void
rtl8169_process_rx_packets ( struct net_device *netdev )
{
	struct rtl8169_private *tp = netdev_priv ( netdev );
	uint32_t rx_status;
	uint16_t rx_len;
	struct RxDesc *rx_curr_desc;
	int i;

	DBGP ( "rtl8169_process_rx_packets\n" );

	for ( i = 0; i < NUM_RX_DESC; i++ ) {

		rx_curr_desc = tp->rx_base  + tp->rx_curr;

		rx_status = rx_curr_desc->opts1;

		DBG2 ( "Before DescOwn check rx_status: %#08x\n", rx_status );

		/* Hardware still owns the descriptor */
		if ( rx_status & DescOwn )
			break;

		/* We own the descriptor, but it has not been refilled yet */
		if ( tp->rx_iobuf[tp->rx_curr] == NULL )
			break;

		rx_len = rx_status & 0x3fff;

		DBG ( "Received packet.\n" );
		DBG ( "tp->rx_curr         = %d\n", tp->rx_curr );
		DBG ( "rx_len              = %d\n", rx_len );
		DBG ( "rx_status           = %#08x\n", rx_status );
		DBG ( "rx_curr_desc        = %#08lx\n", virt_to_bus ( rx_curr_desc ) );

		if ( rx_status & RxRES ) {

			netdev_rx_err ( netdev, tp->rx_iobuf[tp->rx_curr], -EINVAL );

			DBG ( "rtl8169_poll: Corrupted packet received!\n"
			       " rx_status: %#08x\n", rx_status );

		} else 	{

			/* Adjust size of the iobuf to reflect received data */
			iob_put ( tp->rx_iobuf[tp->rx_curr], rx_len );

			/* Add this packet to the receive queue.  */
			netdev_rx ( netdev, tp->rx_iobuf[tp->rx_curr] );
		}

		/* Invalidate this iobuf and descriptor */
		tp->rx_iobuf[tp->rx_curr] = NULL;
		memset ( rx_curr_desc, 0, sizeof ( *rx_curr_desc ) );

		/* Update pointer to next available rx descriptor */
		tp->rx_curr = ( tp->rx_curr + 1 ) % NUM_RX_DESC;
	}
	rtl8169_refill_rx_ring ( tp );
}

static void
rtl8169_free_rx_resources ( struct rtl8169_private *tp )
{
	int i;

	DBGP ( "rtl8169_free_rx_resources\n" );

	free_dma ( tp->rx_base, R8169_RX_RING_BYTES );

	for ( i = 0; i < NUM_RX_DESC; i++ ) {
		free_iob ( tp->rx_iobuf[i] );
		tp->rx_iobuf[i] = NULL;
	}
}

static void rtl8169_irq_enable ( struct rtl8169_private *tp )
{
	void *ioaddr = tp->mmio_addr;

	DBGP ( "rtl8169_irq_enable\n" );

	RTL_W16 ( IntrMask, tp->intr_event );
}

static void rtl8169_irq_disable ( struct rtl8169_private *tp )
{
	void *ioaddr = tp->mmio_addr;

	DBGP ( "rtl8169_irq_disable\n" );

	RTL_W16 ( IntrMask, 0x0000 );
}

/*** iPXE Core API Routines ***/

/**
 * open - Called when a network interface is made active
 *
 * @v netdev	network interface device structure
 * @ret rc	Return status code, 0 on success, negative value on failure
 *
 **/
static int
rtl8169_open ( struct net_device *netdev )
{
	struct rtl8169_private *tp = netdev_priv ( netdev );
	void *ioaddr = tp->mmio_addr;
	int rc;

	DBGP ( "rtl8169_open\n" );

	/* allocate transmit descriptors */
	rc = rtl8169_setup_tx_resources ( tp );
	if ( rc ) {
		DBG ( "Error setting up TX resources!\n" );
		goto err_setup_tx;
	}

	/* allocate receive descriptors */
	rc = rtl8169_setup_rx_resources ( tp );
	if ( rc ) {
		DBG ( "Error setting up RX resources!\n" );
		goto err_setup_rx;
	}

	rtl_hw_start ( netdev );

	DBG ( "TxDescStartAddrHigh   = %#08lx\n", RTL_R32 ( TxDescStartAddrHigh ) );
	DBG ( "TxDescStartAddrLow    = %#08lx\n", RTL_R32 ( TxDescStartAddrLow  ) );
	DBG ( "RxDescAddrHigh        = %#08lx\n", RTL_R32 ( RxDescAddrHigh ) );
	DBG ( "RxDescAddrLow         = %#08lx\n", RTL_R32 ( RxDescAddrLow  ) );

	return 0;

err_setup_rx:
	rtl8169_free_tx_resources ( tp );
err_setup_tx:
	rtl8169_hw_reset ( ioaddr );

	return rc;
}

/**
 * transmit - Transmit a packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 *
 * @ret rc       Returns 0 on success, negative on failure
 */
static int
rtl8169_transmit ( struct net_device *netdev, struct io_buffer *iobuf )
{
	struct rtl8169_private *tp = netdev_priv ( netdev );
	void *ioaddr = tp->mmio_addr;
	uint32_t tx_len = iob_len ( iobuf );

	struct TxDesc *tx_curr_desc;

	DBGP ("rtl8169_transmit\n");

	if ( tp->tx_fill_ctr == NUM_TX_DESC ) {
		DBG ("TX overflow\n");
		return -ENOBUFS;
	}

	/**
	 *  The rtl8169 family automatically pads short packets to a
	 *  minimum size, but if it did not, like some older cards,
	 *  we could do:
	 *  iob_pad ( iobuf, ETH_ZLEN );
	 */

	/* Save pointer to this iobuf we have been given to transmit so
	   we can pass it to netdev_tx_complete() later */
	tp->tx_iobuf[tp->tx_curr] = iobuf;

	tx_curr_desc = tp->tx_base + tp->tx_curr;

	DBG ( "tp->tx_fill_ctr = %d\n", tp->tx_fill_ctr );
	DBG ( "tp->tx_curr     = %d\n", tp->tx_curr );
	DBG ( "tx_curr_desc    = %#08lx\n", virt_to_bus ( tx_curr_desc ) );
	DBG ( "iobuf->data     = %#08lx\n", virt_to_bus ( iobuf->data ) );
	DBG ( "tx_len          = %d\n", tx_len );

	/* Configure current descriptor to transmit supplied packet */
	tx_curr_desc->addr_hi = 0;
	tx_curr_desc->addr_lo = virt_to_bus ( iobuf->data );
	tx_curr_desc->opts2 = 0;
	tx_curr_desc->opts1 = FirstFrag | LastFrag |
		( tp->tx_curr == ( NUM_TX_DESC - 1 ) ? RingEnd : 0 ) |
		tx_len;

	/* Mark descriptor as owned by NIC */
	tx_curr_desc->opts1 |= DescOwn;

	DBG ( "tx_curr_desc->opts1   = %#08x\n", tx_curr_desc->opts1 );
	DBG ( "tx_curr_desc->opts2   = %#08x\n", tx_curr_desc->opts2 );
	DBG ( "tx_curr_desc->addr_hi = %#08x\n", tx_curr_desc->addr_hi );
	DBG ( "tx_curr_desc->addr_lo = %#08x\n", tx_curr_desc->addr_lo );

	RTL_W8 ( TxPoll, NPQ );	/* set polling bit */

	/* Point to next free descriptor */
	tp->tx_curr = ( tp->tx_curr + 1 ) % NUM_TX_DESC;

	/* Increment number of tx descriptors in use */
	tp->tx_fill_ctr++;

	return 0;
}

/**
 * poll - Poll for received packets
 *
 * @v netdev	Network device
 */
static void
rtl8169_poll ( struct net_device *netdev )
{
	struct rtl8169_private *tp = netdev_priv ( netdev );
	void *ioaddr = tp->mmio_addr;

	uint16_t intr_status;
	uint16_t intr_mask;

	DBGP ( "rtl8169_poll\n" );

	intr_status = RTL_R16 ( IntrStatus );
	intr_mask   = RTL_R16 ( IntrMask );

	DBG2 ( "rtl8169_poll (before): intr_mask = %#04x  intr_status = %#04x\n",
	      intr_mask, intr_status );

	RTL_W16 ( IntrStatus, 0xffff );

	/* hotplug / major error / no more work / shared irq */
	if ( intr_status == 0xffff )
		return;

	/* Process transmitted packets */
	rtl8169_process_tx_packets ( netdev );

	/* Process received packets  */
	rtl8169_process_rx_packets ( netdev );
}

/**
 * close - Disable network interface
 *
 * @v netdev	network interface device structure
 *
 **/
static void
rtl8169_close ( struct net_device *netdev )
{
	struct rtl8169_private *tp = netdev_priv ( netdev );
	void *ioaddr = tp->mmio_addr;

	DBGP ( "r8169_close\n" );

	rtl8169_hw_reset ( ioaddr );

	rtl8169_free_tx_resources ( tp );
	rtl8169_free_rx_resources ( tp );
}

/**
 * irq - enable or Disable interrupts
 *
 * @v netdev    network adapter
 * @v action    requested interrupt action
 *
 **/
static void
rtl8169_irq ( struct net_device *netdev, int action )
{
	struct rtl8169_private *tp = netdev_priv ( netdev );

	DBGP ( "rtl8169_irq\n" );

	switch ( action ) {
	case 0 :
		rtl8169_irq_disable ( tp );
		break;
	default :
		rtl8169_irq_enable ( tp );
		break;
	}
}

static struct net_device_operations rtl8169_operations = {
	.open           = rtl8169_open,
	.transmit       = rtl8169_transmit,
	.poll           = rtl8169_poll,
	.close          = rtl8169_close,
	.irq            = rtl8169_irq,
};

/**
 * probe - Initial configuration of NIC
 *
 * @v pci	PCI device
 * @v id	PCI IDs
 *
 * @ret rc	Return status code
 **/
static int
rtl8169_probe ( struct pci_device *pdev )
{
	int i, rc;
	struct net_device *netdev;
	struct rtl8169_private *tp;
	void *ioaddr;

	const struct rtl_cfg_info *cfg = rtl_cfg_infos + pdev->id->driver_data;

	DBGP ( "rtl8169_probe\n" );

	DBG ( "id->vendor = %#04x, id->device = %#04x\n",
	      pdev->id->vendor, pdev->id->device );

	DBG ( "cfg->intr_event = %#04x\n", cfg->intr_event );

	rc = -ENOMEM;

	/* Allocate net device ( also allocates memory for netdev->priv
	   and makes netdev-priv point to it )
	 */
	netdev = alloc_etherdev ( sizeof ( *tp ) );

	if ( ! netdev )
		goto err_alloc_etherdev;

	/* Associate driver-specific network operations with
	   generic network device layer
	 */
	netdev_init ( netdev, &rtl8169_operations );

	/* Associate this network device with the given PCI device */
	pci_set_drvdata ( pdev, netdev );
	netdev->dev = &pdev->dev;

	/* Initialize driver private storage */
	tp = netdev_priv ( netdev );
	memset ( tp, 0, ( sizeof ( *tp ) ) );

	tp->pci_dev    = pdev;
	tp->irqno      = pdev->irq;
	tp->netdev     = netdev;
	tp->intr_event = cfg->intr_event;
	tp->cp_cmd     = PCIMulRW;

	tp->hw_start = cfg->hw_start;

	rc = -EIO;

	adjust_pci_device ( pdev );

	/* ioremap MMIO region */
	ioaddr = ioremap ( pdev->membase, R8169_REGS_SIZE );

	if ( ! ioaddr ) {
		DBG ( "cannot remap MMIO\n" );
		rc = -EIO;
		goto err_ioremap;
	}

	tp->mmio_addr = ioaddr;

	tp->pcie_cap = pci_find_capability ( pdev, PCI_CAP_ID_EXP );
	if ( tp->pcie_cap ) {
		DBG (  "PCI Express capability\n" );
	} else {
		DBG (  "No PCI Express capability\n" );
	}

	/* Mask interrupts just in case */
	rtl8169_irq_mask_and_ack ( ioaddr );

	/* Soft reset NIC */
	rtl_soft_reset ( netdev );

	/* Identify chip attached to board */
	rtl8169_get_mac_version ( tp, ioaddr );

	for ( i = 0; (u32) i < ARRAY_SIZE ( rtl_chip_info ); i++ ) {
		if ( tp->mac_version == rtl_chip_info[i].mac_version )
			break;
	}
	if ( i == ARRAY_SIZE(rtl_chip_info ) ) {
		/* Unknown chip: assume array element #0, original RTL-8169 */
		DBG ( "Unknown chip version, assuming %s\n", rtl_chip_info[0].name );
		i = 0;
	}
	tp->chipset = i;

	if ((tp->mac_version <= RTL_GIGA_MAC_VER_06) &&
	    (RTL_R8(PHYstatus) & TBI_Enable)) {
		tp->set_speed = rtl8169_set_speed_tbi;
		tp->phy_reset_enable = rtl8169_tbi_reset_enable;
		tp->phy_reset_pending = rtl8169_tbi_reset_pending;
		tp->link_ok = rtl8169_tbi_link_ok;

		tp->phy_1000_ctrl_reg = ADVERTISE_1000FULL; /* Implied by TBI */
	} else {
		tp->set_speed = rtl8169_set_speed_xmii;
		tp->phy_reset_enable = rtl8169_xmii_reset_enable;
		tp->phy_reset_pending = rtl8169_xmii_reset_pending;
		tp->link_ok = rtl8169_xmii_link_ok;
	}

	/* Get MAC address */
	for ( i = 0; i < MAC_ADDR_LEN; i++ )
		netdev->hw_addr[i] = RTL_R8 ( MAC0 + i );

	DBG ( "%s\n", eth_ntoa ( netdev->hw_addr ) );

	rtl8169_init_phy ( netdev, tp );

	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	/* Mark as link up; we don't yet handle link state */
	netdev_link_up ( netdev );

	DBG ( "rtl8169_probe succeeded!\n" );

	/* No errors, return success */
	return 0;

/* Error return paths */
err_register:
err_ioremap:
	netdev_put ( netdev );
err_alloc_etherdev:
	return rc;
}

/**
 * remove - Device Removal Routine
 *
 * @v pdev PCI device information struct
 *
 **/
static void
rtl8169_remove ( struct pci_device *pdev )
{
	struct net_device *netdev = pci_get_drvdata ( pdev );
	struct rtl8169_private *tp = netdev_priv ( netdev );
	void *ioaddr = tp->mmio_addr;

	DBGP ( "rtl8169_remove\n" );

	rtl8169_hw_reset ( ioaddr );

	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

static struct pci_device_id rtl8169_nics[] = {
	PCI_ROM(0x10ec, 0x8129, "rtl8169-0x8129", "rtl8169-0x8129", RTL_CFG_0),
	PCI_ROM(0x10ec, 0x8136, "rtl8169-0x8136", "rtl8169-0x8136", RTL_CFG_2),
	PCI_ROM(0x10ec, 0x8167, "rtl8169-0x8167", "rtl8169-0x8167", RTL_CFG_0),
	PCI_ROM(0x10ec, 0x8168, "rtl8169-0x8168", "rtl8169-0x8168", RTL_CFG_1),
	PCI_ROM(0x10ec, 0x8169, "rtl8169-0x8169", "rtl8169-0x8169", RTL_CFG_0),
	PCI_ROM(0x1186, 0x4300, "rtl8169-0x4300", "rtl8169-0x4300", RTL_CFG_0),
	PCI_ROM(0x1259, 0xc107, "rtl8169-0xc107", "rtl8169-0xc107", RTL_CFG_0),
	PCI_ROM(0x16ec, 0x0116, "rtl8169-0x0116", "rtl8169-0x0116", RTL_CFG_0),
	PCI_ROM(0x1737, 0x1032, "rtl8169-0x1032", "rtl8169-0x1032", RTL_CFG_0),
	PCI_ROM(0x0001, 0x8168, "rtl8169-0x8168", "rtl8169-0x8168", RTL_CFG_2),
};

struct pci_driver rtl8169_driver __pci_driver = {
  .ids = rtl8169_nics,
  .id_count = ( sizeof ( rtl8169_nics ) / sizeof ( rtl8169_nics[0] ) ),
  .probe = rtl8169_probe,
  .remove = rtl8169_remove,
};

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
