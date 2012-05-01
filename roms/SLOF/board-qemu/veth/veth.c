/******************************************************************************
 * Copyright (c) 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdint.h>
#include "netdriver_int.h"
#include "libhvcall.h"

static snk_kernel_t     *snk_kernel_interface;
static snk_module_t	*snk_module_interface;
static unsigned int	g_reg;

#define printk(fmt...)  do { snk_kernel_interface->print(fmt); } while(0)
#define malloc(args...) snk_kernel_interface->k_malloc(args)
#define malloc_aligned(args...) snk_kernel_interface->k_malloc_aligned(args)
#define free(args...)  do { snk_kernel_interface->k_free(args); } while(0)

#define dprintk(fmt...)
//#define dprintk(fmt...)	printk(fmt)

/* *** WARNING: We pass our addresses as-is as DMA addresses,
 *     we -do- rely on the forth code to have enabled TCE bypass
 *     on our device !
 */
#define vaddr_to_dma(vaddr)	((uint64_t)vaddr)

struct ibmveth_buf_desc_fields {
	uint32_t flags_len;
#define IBMVETH_BUF_VALID	0x80000000
#define IBMVETH_BUF_TOGGLE	0x40000000
#define IBMVETH_BUF_NO_CSUM	0x02000000
#define IBMVETH_BUF_CSUM_GOOD	0x01000000
#define IBMVETH_BUF_LEN_MASK	0x00FFFFFF
	uint32_t address;
};

union ibmveth_buf_desc {
	uint64_t desc;
	struct ibmveth_buf_desc_fields fields;
};

struct ibmveth_rx_q_entry {
	uint32_t flags_off;
#define IBMVETH_RXQ_TOGGLE		0x80000000
#define IBMVETH_RXQ_TOGGLE_SHIFT	31
#define IBMVETH_RXQ_VALID		0x40000000
#define IBMVETH_RXQ_NO_CSUM		0x02000000
#define IBMVETH_RXQ_CSUM_GOOD		0x01000000
#define IBMVETH_RXQ_OFF_MASK		0x0000FFFF

	uint32_t length;
	uint64_t correlator;
};

static void *buffer_list; 
static void *filter_list; 
static uint64_t *rx_bufs;
static uint64_t *rx_bufs_aligned;
static uint32_t cur_rx_toggle;
static uint32_t cur_rx_index;

#define RX_QUEUE_SIZE	16
#define RX_BUF_SIZE	2048
#define RX_BUF_MULT	(RX_BUF_SIZE >> 3)

static struct ibmveth_rx_q_entry *rx_queue;

static char * memcpy( char *dest, const char *src, size_t n )
{
        char *ret = dest;
        while( n-- ) {
                *dest++ = *src++;
        }

        return( ret );
}

static inline uint64_t *veth_get_rx_buf(unsigned int i)
{
	return &rx_bufs_aligned[i * RX_BUF_MULT];
}

static int veth_init(void)
{
	char *mac_addr = snk_module_interface->mac_addr;
	union ibmveth_buf_desc rxq_desc;
	unsigned long rx_queue_len = sizeof(struct ibmveth_rx_q_entry) *
		RX_QUEUE_SIZE;
	unsigned int i;
	long rc;

	dprintk("veth_init(%02x:%02x:%02x:%02x:%02x:%02x)\n",
		mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);

	if (snk_module_interface->running != 0)
		return 0;

	cur_rx_toggle = IBMVETH_RXQ_TOGGLE;
	cur_rx_index = 0;
	buffer_list = malloc_aligned(8192, 4096);
	filter_list = buffer_list + 4096;
	rx_queue = malloc_aligned(rx_queue_len, 16);
	rx_bufs = malloc(2048 * RX_QUEUE_SIZE + 4);
	if (!buffer_list || !filter_list || !rx_queue || !rx_bufs) {
		printk("veth: Failed to allocate memory !\n");
		goto fail;
	}
	rx_bufs_aligned = (uint64_t *)(((uint64_t)rx_bufs | 3) + 1);
	rxq_desc.fields.address = vaddr_to_dma(rx_queue);
	rxq_desc.fields.flags_len = IBMVETH_BUF_VALID | rx_queue_len;

	rc = h_register_logical_lan(g_reg,
				    vaddr_to_dma(buffer_list),
				    rxq_desc.desc,
				    vaddr_to_dma(filter_list),
				    (*(uint64_t *)mac_addr) >> 16);
	if (rc != H_SUCCESS) {
		printk("veth: Error %ld registering interface !\n", rc);
		goto fail;
	}
	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		uint64_t *buf = veth_get_rx_buf(i);
		union ibmveth_buf_desc desc;
		*buf = (uint64_t)buf;
		desc.fields.address = vaddr_to_dma(buf);
		desc.fields.flags_len = IBMVETH_BUF_VALID | RX_BUF_SIZE;
		h_add_logical_lan_buffer(g_reg, desc.desc);
	}

	snk_module_interface->running = 1;

	return 0;
 fail:
	if (filter_list)
		free(filter_list);
	if (buffer_list)
		free(buffer_list);
	if (rx_queue)
		free(rx_queue);
	if (rx_bufs)
		free(rx_bufs);
	return -1;
}

static int veth_term(void)
{
	dprintk("veth_term()\n");

	if (snk_module_interface->running == 0)
		return 0;

	h_free_logical_lan(g_reg);

	if (filter_list)
		free(filter_list);
	if (buffer_list)
		free(buffer_list);
	if (rx_queue)
		free(rx_queue);
	if (rx_bufs)
		free(rx_bufs);

	snk_module_interface->running = 0;

	return 0;
}

static int veth_xmit(char *f_buffer_pc, int f_len_i)
{
	union ibmveth_buf_desc tx_desc;
	long rc;

	dprintk("veth_xmit(packet at %p, %d bytes)\n", f_buffer_pc, f_len_i);

	tx_desc.fields.address = vaddr_to_dma(f_buffer_pc);
	tx_desc.fields.flags_len = IBMVETH_BUF_VALID | f_len_i;

	rc = hv_send_logical_lan(g_reg, tx_desc.desc, 0, 0, 0, 0, 0);
	if (rc != H_SUCCESS) {
		printk("veth: Error %ld sending packet !\n", rc);
		return -1;
	}

	return f_len_i;
}

static int veth_receive(char *f_buffer_pc, int f_len_i)
{
	int packet = 0;

	dprintk("veth_receive()\n");

	while(!packet) {
		struct ibmveth_rx_q_entry *desc = &rx_queue[cur_rx_index];
		union ibmveth_buf_desc bdesc;
		void *buf;

		buf = (void *)desc->correlator;

		if ((desc->flags_off & IBMVETH_RXQ_TOGGLE) != cur_rx_toggle)
			break;

		if (!(desc->flags_off & IBMVETH_RXQ_VALID))
			goto recycle;
		if (desc->length > f_len_i) {
			printk("veth: Dropping too big packet [%d bytes]\n",
			       desc->length);
			goto recycle;
		}

		packet = desc->length;
		memcpy(f_buffer_pc,
		       buf + (desc->flags_off & IBMVETH_RXQ_OFF_MASK), packet);
	recycle:
		bdesc.fields.address = vaddr_to_dma(buf);
		bdesc.fields.flags_len = IBMVETH_BUF_VALID | RX_BUF_SIZE;
		h_add_logical_lan_buffer(g_reg, bdesc.desc);

		cur_rx_index = (cur_rx_index + 1) % RX_QUEUE_SIZE;
		if (cur_rx_index == 0)
			cur_rx_toggle ^= IBMVETH_RXQ_TOGGLE;
	}

	return packet;
}

static int veth_ioctl(int request, void* data)
{
	dprintk("veth_ioctl()\n");

	return 0;
}

static snk_module_t veth_interface = {
	.version = 1,
	.type    = MOD_TYPE_NETWORK,
	.running = 0,
	.init    = veth_init,
	.term    = veth_term,
	.write   = veth_xmit,
	.read    = veth_receive,
	.ioctl   = veth_ioctl
};


static int check_driver(vio_config_t *conf)
{
	
        if (snk_kernel_interface->strcmp(conf->compat, "IBM,l-lan")) {
		printk( "veth: netdevice not supported\n" );
		return -1;
	}
	g_reg = conf->reg;
	
	return 0;
}

snk_module_t* veth_module_init(snk_kernel_t *snk_kernel_int, vio_config_t *conf)
{
	snk_kernel_interface = snk_kernel_int;
	snk_module_interface = &veth_interface;

	if (snk_kernel_int->version != snk_module_interface->version)
		return 0;

	/* Check if this is the right driver */
	if (check_driver(conf) < 0)
		return 0;

	snk_module_interface->link_addr = module_init;
	return snk_module_interface;
}
