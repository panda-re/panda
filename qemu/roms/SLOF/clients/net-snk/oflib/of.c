/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/


#include <of.h>
#include <rtas.h>
#include <string.h>
#include <netdriver_int.h>
#include <fileio.h>
#include <stdint.h>

extern void call_client_interface(of_arg_t *);

static int ofmod_init(void);
static int ofmod_term(void);
static int ofmod_open(snk_fileio_t*, const char* name, int flags);
static int ofmod_read(char *buffer, int len);
static int ofmod_write(char *buffer, int len);
static int ofmod_ioctl(int request, void *data);

snk_module_t of_module = {
	.version = 1,
	.type    = MOD_TYPE_OTHER,
	.running = 1,
	.link_addr = (char*) 1,
	.init    = ofmod_init,
	.term    = ofmod_term,
	.open    = ofmod_open,
	.write   = ofmod_write,
	.read    = ofmod_read,
	.ioctl   = ofmod_ioctl
};

static ihandle_t fd_ihandle_array[FILEIO_MAX];
static int claim_rc = 0;
static void* client_start;
static size_t client_size;

extern inline int
of_0_1(const char *serv)
{
	of_arg_t arg = {
		p32cast serv,
		0, 1,
		{ 0 }
	};

	call_client_interface(&arg);

	return arg.args[0];
}

extern inline void
of_1_0(const char *serv, int arg0)
{
	of_arg_t arg = {
		p32cast serv,
		1, 0,
		{arg0, 0}
	};

	call_client_interface(&arg);
}

extern inline unsigned int
of_1_1(const char *serv, int arg0)
{
	of_arg_t arg = {
		p32cast serv,
		1, 1,
		{arg0, 0}
	};

	call_client_interface(&arg);
	return arg.args[1];
}

extern inline unsigned int
of_1_2(const char *serv, int arg0, int *ret0)
{
        of_arg_t arg = {
                p32cast serv,
                1, 2,
                {arg0, 0, 0}
        };

        call_client_interface(&arg);
        *ret0 = arg.args[2];
        return arg.args[1];
}

extern inline void
of_2_0(const char *serv, int arg0, int arg1)
{
	of_arg_t arg = {
		p32cast serv,
		2, 0,
		{arg0, arg1, 0}
	};

	call_client_interface(&arg);
}

extern inline unsigned int
of_2_1(const char *serv, int arg0, int arg1)
{
	of_arg_t arg = {
		p32cast serv,
		2, 1,
		{arg0, arg1, 0}
	};

	call_client_interface(&arg);
	return arg.args[2];
}

extern inline unsigned int
of_2_2(const char *serv, int arg0, int arg1, int *ret0)
{
	of_arg_t arg = {
		p32cast serv,
		2, 2,
		{arg0, arg1, 0, 0}
	};

	call_client_interface(&arg);
	*ret0 = arg.args[3];
	return arg.args[2];
}

extern inline unsigned int
of_2_3(const char *serv, int arg0, int arg1, int *ret0, int *ret1)
{
	of_arg_t arg = {
		p32cast serv,
		2, 3,
		{arg0, arg1, 0, 0, 0}
	};

	call_client_interface(&arg);
	*ret0 = arg.args[3];
	*ret1 = arg.args[4];
	return arg.args[2];
}

extern inline void
of_3_0(const char *serv, int arg0, int arg1, int arg2)
{
	of_arg_t arg = {
		p32cast serv,
		3, 0,
		{arg0, arg1, arg2, 0}
	};

	call_client_interface(&arg);
	return;
}

extern inline unsigned int
of_3_1(const char *serv, int arg0, int arg1, int arg2)
{
	of_arg_t arg = {
		p32cast serv,
		3, 1,
		{arg0, arg1, arg2, 0}
	};

	call_client_interface(&arg);
	return arg.args[3];
}

extern inline unsigned int
of_3_2(const char *serv, int arg0, int arg1, int arg2, int *ret0)
{
	of_arg_t arg = {
		p32cast serv,
		3, 2,
		{arg0, arg1, arg2, 0, 0}
	};

	call_client_interface(&arg);
	*ret0 = arg.args[4];
	return arg.args[3];
}

extern inline unsigned int
of_3_3(const char *serv, int arg0, int arg1, int arg2, int *ret0, int *ret1)
{
	of_arg_t arg = {
		p32cast serv,
		3, 3,
		{arg0, arg1, arg2, 0, 0, 0}
	};

	call_client_interface(&arg);
	*ret0 = arg.args[4];
	*ret1 = arg.args[5];
	return arg.args[3];
}

extern inline unsigned int
of_4_1(const char *serv, int arg0, int arg1, int arg2, int arg3)
{
	of_arg_t arg = {
		p32cast serv,
		4, 1,
		{arg0, arg1, arg2, arg3, 0}
	};

	call_client_interface(&arg);
	return arg.args[4];
}

int
of_interpret_1(void *s, void *ret)
{
	return of_1_2("interpret", p32cast s, ret);
}

void
of_close(ihandle_t ihandle)
{
	of_1_0("close", ihandle);
}

int
of_write(ihandle_t ihandle, void *s, int len)
{
	return of_3_1("write", ihandle, p32cast s, len);
}

int
of_read(ihandle_t ihandle, void *s, int len)
{
	return of_3_1("read", ihandle, p32cast s, len);
}

int
of_seek(ihandle_t ihandle, int poshi, int poslo)
{
	return of_3_1("seek", ihandle, poshi, poslo);
}

int
of_getprop(phandle_t phandle, const char *name, void *buf, int len)
{
	return of_4_1("getprop", phandle, p32cast name, p32cast buf, len);
}

phandle_t
of_peer(phandle_t phandle)
{
	return (phandle_t) of_1_1("peer", phandle);
}

phandle_t
of_child(phandle_t phandle)
{
	return (phandle_t) of_1_1("child", phandle);
}

phandle_t
of_parent(phandle_t phandle)
{
	return (phandle_t) of_1_1("parent", phandle);
}

phandle_t
of_finddevice(const char *name)
{
	return (phandle_t) of_1_1("finddevice", p32cast name);
}

ihandle_t
of_open(const char *name)
{
	return (ihandle_t) of_1_1("open", p32cast name);
}

void *
of_claim(void *start, unsigned int size, unsigned int align)
{
	return(void *)(long)(size_t)of_3_1("claim", p32cast start, size, align);
}

void
of_release(void *start, unsigned int size)
{
	(void) of_2_0("release", p32cast start, size);
}

unsigned int
romfs_lookup(const char *name, void **addr)
{
	unsigned int high, low;
	unsigned int i = of_2_3("ibm,romfs-lookup", p32cast name, strlen(name),
				(int *) &high, (int *) &low);
	*addr = (void*)(((unsigned long) high << 32) | (unsigned long) low);
	return i;
}

void *
of_call_method_3(const char *name, ihandle_t ihandle, int arg0)
{
	int entry, rc;
	rc = of_3_2("call-method", p32cast name, ihandle, arg0, &entry);
	return rc != 0 ? 0 : (void *) (long) entry;
}

int
vpd_read(unsigned int offset, unsigned int length, char *data)
{
	int result;
	long tmp = (long) data;
	result = of_3_1("rtas-read-vpd", offset, length, (int) tmp);
	return result;
}

int
vpd_write(unsigned int offset, unsigned int length, char *data)
{
	int result;
	long tmp = (long) data;
	result = of_3_1("rtas-write-vpd", offset, length, (int) tmp);
	return result;
}

static void
ipmi_oem_led_set(int type, int instance, int state)
{
	return of_3_0("set-led", type, instance, state);
}

int
write_mm_log(char *data, unsigned int length, unsigned short type)
{
	long tmp = (long) data;

	ipmi_oem_led_set(2, 0, 1);
	return of_3_1("write-mm-log", (int) tmp, length, type);
}

int
of_yield(void)
{
	return of_0_1("yield");
}

void *
of_set_callback(void *addr)
{
	return (void *) (long) (size_t) of_1_1("set-callback", p32cast addr);
}

void
bootmsg_warning(short id, const char *str, short lvl)
{
	(void) of_3_0("bootmsg-warning", id, lvl, p32cast str);
}

void
bootmsg_error(short id, const char *str)
{
	(void) of_2_0("bootmsg-error", id, p32cast str);
}

void
bootmsg_debugcp(short id, const char *str, short lvl)
{
	(void) of_3_0("bootmsg-debugcp", id, lvl, p32cast str);
}

void
bootmsg_cp(short id)
{
	(void) of_1_0("bootmsg-cp", id);
}


static long
of_fileio_read(snk_fileio_t *fileio, char *buf, long len)
{
	if(!fileio)
		return -1;
	return of_read( * (ihandle_t*) fileio->data, buf, len );
}

static long
of_fileio_write(snk_fileio_t *fileio, char *buf, long len)
{
	if(!fileio)
		return -1;
	return of_write( * (ihandle_t*) fileio->data, buf, len );
}

static int
of_fileio_close(snk_fileio_t *fileio)
{
	if(!fileio)
		return -1;

	fileio->type = FILEIO_TYPE_EMPTY;
	of_close( * (ihandle_t*) fileio->data );
	return 0;
}


#define CONFIG_SPACE 0
#define IO_SPACE 1
#define MEM_SPACE 2

#define ASSIGNED_ADDRESS_PROPERTY 0
#define REG_PROPERTY 1

#define DEBUG_TRANSLATE_ADDRESS 0
#if DEBUG_TRANSLATE_ADDRESS != 0
#define DEBUG_TR(str...) printk(str)
#else
#define DEBUG_TR(str...)
#endif

/**
 * pci_address_type tries to find the type for which a
 * mapping should be done. This is PCI specific and is done by
 * looking at the first 32bit of the phys-addr in
 * assigned-addresses
 *
 * @param node     the node of the device which requests
 *                 translatation
 * @param address  the address which needs to be translated
 * @param prop_type the type of the property to search in (either REG_PROPERTY or ASSIGNED_ADDRESS_PROPERTY)
 * @return         the corresponding type (config, i/o, mem)
 */
static int
pci_address_type(phandle_t node, uint64_t address, uint8_t prop_type)
{
	char *prop_name = "assigned-addresses";
	if (prop_type == REG_PROPERTY)
		prop_name = "reg";
	/* #address-cells */
	const unsigned int nac = 3;	//PCI
	/* #size-cells */
	const unsigned int nsc = 2;	//PCI
	/* up to 11 pairs of (phys-addr(3) size(2)) */
	unsigned char buf[11 * (nac + nsc) * sizeof(int)];
	unsigned int *assigned_ptr;
	int result = -1;
	int len;
	len = of_getprop(node, prop_name, buf, 11 * (nac + nsc) * sizeof(int));
	assigned_ptr = (unsigned int *) &buf[0];
	while (len > 0) {
		if ((prop_type == REG_PROPERTY)
		    && ((assigned_ptr[0] & 0xFF) != 0)) {
			//BARs and Expansion ROM must be in assigned-addresses... so in reg
			// we only look for those without config space offset set...
			assigned_ptr += (nac + nsc);
			len -= (nac + nsc) * sizeof(int);
			continue;
		}
		DEBUG_TR("%s %x size %x\n", prop_name, assigned_ptr[2],
			 assigned_ptr[4]);
		if (address >= assigned_ptr[2]
		    && address <= assigned_ptr[2] + assigned_ptr[4]) {
			DEBUG_TR("found a match\n");
			result = (assigned_ptr[0] & 0x03000000) >> 24;
			break;
		}
		assigned_ptr += (nac + nsc);
		len -= (nac + nsc) * sizeof(int);
	}
	/* this can only handle 32bit memory space and should be
	 * removed as soon as translations for 64bit are available */
	return (result == 3) ? MEM_SPACE : result;
}

/**
 * this is a hack which returns the lower 64 bit of any number of cells
 * all the higher bits will silently discarded
 * right now this works pretty good as long 64 bit addresses is all we want
 *
 * @param addr  a pointer to the first address cell
 * @param nc    number of cells addr points to
 * @return      the lower 64 bit to which addr points
 */
static uint64_t
get_dt_address(uint32_t *addr, uint32_t nc)
{
	uint64_t result = 0;
	while (nc--)
		result = (result << 32) | *(addr++);
	return result;
}

/**
 * this functions tries to find a mapping for the given address
 * it assumes that if we have #address-cells == 3 that we are trying
 * to do a PCI translation
 *
 * @param  addr    a pointer to the address that should be translated
 *                 if a translation has been found the address will
 *                 be modified
 * @param  type    this is required for PCI devices to find the
 *                 correct translation
 * @param ranges   this is one "range" containing the translation
 *                 information (one range = nac + pnac + nsc)
 * @param nac      the OF property #address-cells
 * @param nsc      the OF property #size-cells
 * @param pnac     the OF property #address-cells from the parent node
 * @return         -1 if no translation was possible; else 0
 */
static int
map_one_range(uint64_t *addr, int type, uint32_t *ranges, uint32_t nac,
	      uint32_t nsc, uint32_t pnac)
{
	long offset;
	/* cm - child mapping */
	/* pm - parent mapping */
	uint64_t cm, size, pm;
	/* only check for the type if nac == 3 (PCI) */
	DEBUG_TR("type %x, nac %x\n", ranges[0], nac);
	if (((ranges[0] & 0x03000000) >> 24) != type && nac == 3)
		return -1;
	/* okay, it is the same type let's see if we find a mapping */
	size = get_dt_address(ranges + nac + pnac, nsc);
	if (nac == 3)		/* skip type if PCI */
		cm = get_dt_address(ranges + 1, nac - 1);
	else
		cm = get_dt_address(ranges, nac);

	DEBUG_TR("\t\tchild_mapping %lx\n", cm);
	DEBUG_TR("\t\tsize %lx\n", size);
	DEBUG_TR("\t\t*address %lx\n", (uint64_t) * addr);
	if (cm + size <= (uint64_t) * addr || cm > (uint64_t) * addr)
		/* it is not inside the mapping range */
		return -1;
	/* get the offset */
	offset = *addr - cm;
	/* and add the offset on the parent mapping */
	if (pnac == 3)		/* skip type if PCI */
		pm = get_dt_address(ranges + nac + 1, pnac - 1);
	else
		pm = get_dt_address(ranges + nac, pnac);
	DEBUG_TR("\t\tparent_mapping %lx\n", pm);
	*addr = pm + offset;
	DEBUG_TR("\t\t*address %lx\n", *addr);
	return 0;
}

/**
 * translate_address_dev tries to translate the device specific address
 * to a host specific address by walking up in the device tree
 *
 * @param address  a pointer to a 64 bit value which will be
 *                 translated
 * @param current_node phandle of the device from which the
 *                     translation will be started
 */
void
translate_address_dev(uint64_t *addr, phandle_t current_node)
{
	unsigned char buf[1024];
	phandle_t parent;
	unsigned int pnac;
	unsigned int nac;
	unsigned int nsc;
	int addr_type;
	int len;
	unsigned int *ranges;
	unsigned int one_range;
	DEBUG_TR("translate address %lx, node: %lx\n", *addr, current_node);
	of_getprop(current_node, "name", buf, 400);
	DEBUG_TR("current node: %s\n", buf);
	addr_type =
	    pci_address_type(current_node, *addr, ASSIGNED_ADDRESS_PROPERTY);
	if (addr_type == -1) {
		// check in "reg" property if not found in "assigned-addresses"
		addr_type = pci_address_type(current_node, *addr, REG_PROPERTY);
	}
	DEBUG_TR("address_type %x\n", addr_type);
	current_node = of_parent(current_node);
	while (1) {
		parent = of_parent(current_node);
		if (!parent) {
			DEBUG_TR("reached root node...\n");
			break;
		}
		of_getprop(current_node, "#address-cells", &nac, 4);
		of_getprop(current_node, "#size-cells", &nsc, 4);
		of_getprop(parent, "#address-cells", &pnac, 4);
		one_range = nac + pnac + nsc;
		len = of_getprop(current_node, "ranges", buf, 400);
		if (len < 0) {
			DEBUG_TR("no 'ranges' property; not translatable\n");
			return;
		}
		ranges = (unsigned int *) &buf[0];
		while (len > 0) {
			if (!map_one_range
			    ((uint64_t *) addr, addr_type, ranges, nac, nsc,
			     pnac))
				/* after a successful mapping we stop
				 * going through the ranges */
				break;
			ranges += one_range;
			len -= one_range * sizeof(int);
		}
		DEBUG_TR("address %lx\n", *addr);
		of_getprop(current_node, "name", buf, 400);
		DEBUG_TR("current node: %s\n", buf);
		DEBUG_TR("\t#address-cells: %x\n", nac);
		DEBUG_TR("\t#size-cells: %x\n", nsc);
		of_getprop(parent, "name", buf, 400);
		DEBUG_TR("parent node: %s\n", buf);
		DEBUG_TR("\t#address-cells: %x\n", pnac);
		current_node = parent;
	}
}

static phandle_t
get_boot_device(void)
{
	char buf[1024];
	phandle_t dev = of_finddevice("/chosen");

	if (dev == -1) {
		dev = of_finddevice("/aliases");
		if (dev == -1)
			return dev;
		of_getprop(dev, "net", buf, 1024);
	} else
		of_getprop(dev, "bootpath", buf, 1024);

	return of_finddevice(buf);
}

/**
 * translate_address tries to translate the device specific address
 * of the boot device to a host specific address
 *
 * @param address  a pointer to a 64 bit value which will be
 *                 translated
 */
void
translate_address(unsigned long *addr)
{
	translate_address_dev((uint64_t*) addr, get_boot_device());
}

/**
 * get_puid walks up in the device tree until it finds a parent
 * node without a reg property. get_puid is assuming that if the
 * parent node has no reg property it has found the pci host bridge
 *
 * this is not the correct way to find PHBs but it seems to work
 * for all our systems
 *
 * @param node   the device for which to find the puid
 *
 * @return       the puid or 0
 */
uint64_t
get_puid(phandle_t node)
{
	uint64_t puid = 0;
	uint64_t tmp = 0;
	phandle_t curr_node, last_node;

	curr_node = last_node = of_parent(node);

	while (curr_node) {
		puid = tmp;
		if (of_getprop(curr_node, "reg", &tmp, 8) < 8) {
			/* if the found PHB is not directly under
			 * root we need to translate the found address */
			translate_address_dev(&puid, last_node);
			return puid;
		}
		last_node = curr_node;
		curr_node = of_parent(curr_node);
	}

	return 0;
}

static int set_vio_config(vio_config_t * vio_config, phandle_t net)
{
	of_getprop(net, "reg", &vio_config->reg, 4);
	of_getprop(net, "compatible", &vio_config->compat, 64);

	return 0;
}

/* Fill in the pci config structure from the device tree */
static int set_pci_config(pci_config_t * pci_config, phandle_t net)
{
	unsigned char buf[400];
	int len, bar_nr;
	unsigned int *assigned_ptr;

	of_getprop(net, "vendor-id", &pci_config->vendor_id, 4);
	of_getprop(net, "device-id", &pci_config->device_id, 4);
	of_getprop(net, "revision-id", &pci_config->revision_id, 4);
	of_getprop(net, "class-code", &pci_config->class_code, 4);
	of_getprop(net, "interrupts", &pci_config->interrupt_line, 4);

	len = of_getprop(net, "assigned-addresses", buf, 400);
	if (len <= 0)
		return -1;

	assigned_ptr = (unsigned int *) &buf[0];
	pci_config->bus = (assigned_ptr[0] & 0x00ff0000) >> 16;
	pci_config->devfn = (assigned_ptr[0] & 0x0000ff00) >> 8;

	while (len > 0) {
		/* Fixme 64 bit bars */
		bar_nr = ((assigned_ptr[0] & 0xff) - 0x10) / 4;
		pci_config->bars[bar_nr].type =
		    (assigned_ptr[0] & 0x0f000000) >> 24;
		pci_config->bars[bar_nr].addr = assigned_ptr[2];
		pci_config->bars[bar_nr].size = assigned_ptr[4];
		assigned_ptr += 5;
		len -= 5 * sizeof(int);
	}

	pci_config->puid = get_puid(net);

	return 0;
}

static int set_config(snk_kernel_t * snk_kernel_interface)
{
	phandle_t parent, net = get_boot_device();
	char compat[64];

	if (net == -1)
		return -1;

	parent = of_parent(net);
	of_getprop(parent, "compatible", compat, 64);
	if (!strcmp(compat, "IBM,vdevice"))
		return set_vio_config(&snk_kernel_interface->vio_conf, net);
	return set_pci_config(&snk_kernel_interface->pci_conf, net);
}

void
get_mac(char *mac)
{
	uint8_t localmac[8];
	int len;

	phandle_t net = get_boot_device();

	if (net == -1)
		return;

	len = of_getprop(net, "local-mac-address", localmac, 8);

	if (len == 8) {
		/* Some bad FDT nodes like veth use a 8-byte wide
		 * property instead of 6-byte wide MACs... :-( */
		memcpy(mac, &localmac[2], 6);
	}
	else {
		memcpy(mac, localmac, 6);
	}
}

static void
get_timebase(unsigned int *timebase)
{
	phandle_t cpu;
	phandle_t cpus = of_finddevice("/cpus");

	if (cpus == -1)
		return;

	cpu = of_child(cpus);

	if (cpu == -1)
		return;

	of_getprop(cpu, "timebase-frequency", timebase, 4);
}

int
glue_init(snk_kernel_t * snk_kernel_interface, unsigned int * timebase,
          size_t _client_start, size_t _client_size)
{
	phandle_t chosen = of_finddevice("/chosen");

	client_start = (void *) (long) _client_start;
	client_size = _client_size;

	if (chosen == -1)
		return -1;

	fd_array[0].type  = FILEIO_TYPE_USED;
	fd_array[0].read  = of_fileio_read;
	fd_array[0].write = of_fileio_write;
	fd_array[0].ioctl = 0;
	fd_array[0].close = of_fileio_close;
	fd_array[0].data  = &fd_ihandle_array[0];
	of_getprop(chosen, "stdin", fd_array[0].data, sizeof(ihandle_t));

	fd_array[1].type  = FILEIO_TYPE_USED;
	fd_array[1].read  = of_fileio_read;
	fd_array[1].write = of_fileio_write;
	fd_array[1].ioctl = 0;
	fd_array[1].close = of_fileio_close;
	fd_array[1].data  = &fd_ihandle_array[1];
	of_getprop(chosen, "stdout", fd_array[1].data, sizeof(ihandle_t));

	if (of_write(fd_ihandle_array[1], " ", 1) < 0)
		return -2;

	/* Setup Kernel Struct */
	if (set_config(snk_kernel_interface) == -1) {
		snk_kernel_interface->print(" No net device found \n");
	}

	get_timebase(timebase);
	rtas_init();

	snk_kernel_interface->k_romfs_lookup = romfs_lookup;
	snk_kernel_interface->translate_addr = translate_address;
	snk_kernel_interface->pci_config_read = rtas_pci_config_read;
	snk_kernel_interface->pci_config_write = rtas_pci_config_write;
	claim_rc=(int)(long)of_claim(client_start, client_size, 0);

	return 0;
}

void
glue_release(void)
{
	if (claim_rc >= 0) {
		of_release(client_start, client_size);
	}
}

static int
ofmod_init(void)
{
	of_module.running = 1;
	return 0;
}

static int
ofmod_term(void)
{
	of_module.running = 0;
	return 0;
}

static int
ofmod_open(snk_fileio_t *fileio, const char* name, int flags)
{
	if ((fd_ihandle_array[fileio->idx] = of_open (name)) == 0)
	{
		/* this module can not open this file */
		return -1;
	}

	fileio->type  = FILEIO_TYPE_USED;
	fileio->read  = of_fileio_read;
	fileio->write = of_fileio_write;
	fileio->close = of_fileio_close;
	fileio->data  = &fd_ihandle_array[fileio->idx];
	return 0;
}

static int
ofmod_read(char *buffer, int len)
{
	return len;
}

static int
ofmod_write(char *buffer, int len)
{
	return len;
}

static int
ofmod_ioctl(int request, void *data)
{
	return 0;
}

