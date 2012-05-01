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

/* Linux PRO/1000 Ethernet Driver main header file */

#ifndef _IGB_H_
#define _IGB_H_

#include "igb_api.h"

extern int igb_probe ( struct pci_device *pdev );
extern void igb_remove ( struct pci_device *pdev );

struct igb_adapter;

/* Interrupt defines */
#define IGB_START_ITR                    648 /* ~6000 ints/sec */

/* Interrupt modes, as used by the IntMode paramter */
#define IGB_INT_MODE_LEGACY                0
#define IGB_INT_MODE_MSI                   1
#define IGB_INT_MODE_MSIX                  2

#define HW_PERF
/* TX/RX descriptor defines */
#define IGB_DEFAULT_TXD                  256
#define IGB_MIN_TXD                       80
#define IGB_MAX_TXD                     4096

#define IGB_DEFAULT_RXD                  256
#define IGB_MIN_RXD                       80
#define IGB_MAX_RXD                     4096

#define IGB_MIN_ITR_USECS                 10 /* 100k irq/sec */
#define IGB_MAX_ITR_USECS               8191 /* 120  irq/sec */

#define NON_Q_VECTORS                      1
#define MAX_Q_VECTORS                      8

/* Transmit and receive queues */
#define IGB_MAX_RX_QUEUES                  (adapter->vfs_allocated_count ? 2 : \
                                           (hw->mac.type > e1000_82575 ? 8 : 4))
#define IGB_ABS_MAX_TX_QUEUES              8
#define IGB_MAX_TX_QUEUES                  IGB_MAX_RX_QUEUES

#define IGB_MAX_VF_MC_ENTRIES              30
#define IGB_MAX_VF_FUNCTIONS               8
#define IGB_MAX_VFTA_ENTRIES               128
#define IGB_MAX_UTA_ENTRIES                128
#define MAX_EMULATION_MAC_ADDRS            16
#define OUI_LEN                            3

struct vf_data_storage {
	unsigned char vf_mac_addresses[ETH_ALEN];
	u16 vf_mc_hashes[IGB_MAX_VF_MC_ENTRIES];
	u16 num_vf_mc_hashes;
	u16 default_vf_vlan_id;
	u16 vlans_enabled;
	unsigned char em_mac_addresses[MAX_EMULATION_MAC_ADDRS * ETH_ALEN];
	u32 uta_table_copy[IGB_MAX_UTA_ENTRIES];
	u32 flags;
	unsigned long last_nack;
};

#define IGB_VF_FLAG_CTS            0x00000001 /* VF is clear to send data */
#define IGB_VF_FLAG_UNI_PROMISC    0x00000002 /* VF has unicast promisc */
#define IGB_VF_FLAG_MULTI_PROMISC  0x00000004 /* VF has multicast promisc */

/* RX descriptor control thresholds.
 * PTHRESH - MAC will consider prefetch if it has fewer than this number of
 *           descriptors available in its onboard memory.
 *           Setting this to 0 disables RX descriptor prefetch.
 * HTHRESH - MAC will only prefetch if there are at least this many descriptors
 *           available in host memory.
 *           If PTHRESH is 0, this should also be 0.
 * WTHRESH - RX descriptor writeback threshold - MAC will delay writing back
 *           descriptors until either it has this many to write back, or the
 *           ITR timer expires.
 */
#define IGB_RX_PTHRESH                    (hw->mac.type <= e1000_82576 ? 16 : 8)
#define IGB_RX_HTHRESH                     8
#define IGB_RX_WTHRESH                     1
#define IGB_TX_PTHRESH                     8
#define IGB_TX_HTHRESH                     1
#define IGB_TX_WTHRESH                     ((hw->mac.type == e1000_82576 && \
                                             adapter->msix_entries) ? 0 : 16)

/* this is the size past which hardware will drop packets when setting LPE=0 */
#define MAXIMUM_ETHERNET_VLAN_SIZE 1522

/* Supported Rx Buffer Sizes */
#define IGB_RXBUFFER_128   128    /* Used for packet split */
#define IGB_RXBUFFER_256   256    /* Used for packet split */
#define IGB_RXBUFFER_512   512
#define IGB_RXBUFFER_1024  1024
#define IGB_RXBUFFER_2048  2048
#define IGB_RXBUFFER_4096  4096
#define IGB_RXBUFFER_8192  8192
#define IGB_RXBUFFER_16384 16384

/* Packet Buffer allocations */
#define IGB_PBA_BYTES_SHIFT 0xA
#define IGB_TX_HEAD_ADDR_SHIFT 7
#define IGB_PBA_TX_MASK 0xFFFF0000

#define IGB_FC_PAUSE_TIME 0x0680 /* 858 usec */

/* How many Tx Descriptors do we need to call netif_wake_queue ? */
#define IGB_TX_QUEUE_WAKE	32
/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define IGB_RX_BUFFER_WRITE	16	/* Must be power of 2 */

#define AUTO_ALL_MODES            0
#define IGB_EEPROM_APME         0x0400

#ifndef IGB_MASTER_SLAVE
/* Switch to override PHY master/slave setting */
#define IGB_MASTER_SLAVE	e1000_ms_hw_default
#endif

#define IGB_MNG_VLAN_NONE -1

/* wrapper around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer */
struct igb_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
	dma_addr_t page_dma;
	union {
		/* TX */
		struct {
			unsigned long time_stamp;
			u16 length;
			u16 next_to_watch;
		};

#ifndef CONFIG_IGB_DISABLE_PACKET_SPLIT
		/* RX */
		struct {
			unsigned long page_offset;
			struct page *page;
		};
#endif
	};
};

struct igb_queue_stats {
	u64 packets;
	u64 bytes;
};

struct igb_q_vector {
	struct igb_adapter *adapter; /* backlink */
	struct igb_ring *rx_ring;
	struct igb_ring *tx_ring;
#if 0
	struct napi_struct napi;
#endif
	u32 eims_value;
	u16 cpu;

	u16 itr_val;
	u8 set_itr;
	u8 itr_shift;
	void __iomem *itr_register;

#if 0
	char name[IFNAMSIZ + 9];
#endif
#ifndef HAVE_NETDEV_NAPI_LIST
	struct net_device poll_dev;
#endif
};

struct igb_ring {
	struct igb_q_vector *q_vector; /* backlink to q_vector */
	struct pci_dev *pdev;          /* pci device for dma mapping */
	dma_addr_t dma;                /* phys address of the ring */
	void *desc;                    /* descriptor ring memory */
	unsigned int size;             /* length of desc. ring in bytes */
	u16 count;                     /* number of desc. in the ring */
	u16 next_to_use;
	u16 next_to_clean;
	u8 queue_index;
	u8 reg_idx;
	void __iomem *head;
	void __iomem *tail;
	struct igb_buffer *buffer_info; /* array of buffer info structs */

	unsigned int total_bytes;
	unsigned int total_packets;

	struct igb_queue_stats stats;

	union {
		/* TX */
		struct {
			unsigned int restart_queue;
			u32 ctx_idx;
			bool detect_tx_hung;
		};
		/* RX */
		struct {
			u64 hw_csum_err;
			u64 hw_csum_good;
			u32 rx_buffer_len;
			u16 rx_ps_hdr_size;
			bool rx_csum;
#ifdef IGB_LRO
			struct net_lro_mgr lro_mgr;
			bool lro_used;
#endif
		};
	};
};


#define IGB_ADVTXD_DCMD (E1000_ADVTXD_DCMD_EOP | E1000_ADVTXD_DCMD_RS)

#define IGB_DESC_UNUSED(R) \
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

#define E1000_RX_DESC_ADV(R, i)	    \
	(&(((union e1000_adv_rx_desc *)((R).desc))[i]))
#define E1000_TX_DESC_ADV(R, i)	    \
	(&(((union e1000_adv_tx_desc *)((R).desc))[i]))
#define E1000_TX_CTXTDESC_ADV(R, i)	    \
	(&(((struct e1000_adv_tx_context_desc *)((R).desc))[i]))
#define E1000_GET_DESC(R, i, type)	(&(((struct type *)((R).desc))[i]))
#define E1000_TX_DESC(R, i)		E1000_GET_DESC(R, i, e1000_tx_desc)
#define E1000_RX_DESC(R, i)		E1000_GET_DESC(R, i, e1000_rx_desc)

#define MAX_MSIX_COUNT 10
/* board specific private data structure */

/* board specific private data structure */
struct igb_adapter {

	/* OS defined structs */
	struct net_device *netdev;
	struct pci_device *pdev;
	struct net_device_stats net_stats;

	/* structs defined in e1000_hw.h */
	struct e1000_hw hw;

	struct e1000_phy_info phy_info;

        u32 min_frame_size;
        u32 max_frame_size;

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

#define IGB_FLAG_HAS_MSI           (1 << 0)
#define IGB_FLAG_MSI_ENABLE        (1 << 1)
#define IGB_FLAG_DCA_ENABLED       (1 << 3)
#define IGB_FLAG_LLI_PUSH          (1 << 4)
#define IGB_FLAG_IN_NETPOLL        (1 << 5)
#define IGB_FLAG_QUAD_PORT_A       (1 << 6)
#define IGB_FLAG_QUEUE_PAIRS       (1 << 7)

#define IGB_82576_TSYNC_SHIFT 19

#endif /* _IGB_H_ */
