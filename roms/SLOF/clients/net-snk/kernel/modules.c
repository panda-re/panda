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

#include <netdriver_int.h>
#include <kernel.h>
#include <of.h>
#include <rtas.h> 
#include <libelf.h>
#include <cpu.h> /* flush_cache */
#include <unistd.h> /* open, close, read, write */
#include <stdio.h>


unsigned int read_io(void *, size_t);
int write_io(void *, unsigned int, size_t);

extern void get_mac(char *mac);
extern snk_module_t of_module;

extern char __client_start[];


typedef snk_module_t *(*module_init_t) (snk_kernel_t *, pci_config_t *);

typedef struct {
	const char *name;
	int        type;
} mod_descriptor_t;

static const mod_descriptor_t modules[] = {
	{ "net_e1000",  MOD_TYPE_NETWORK },
	{ "net_bcm",    MOD_TYPE_NETWORK },
	{ "net_veth",   MOD_TYPE_NETWORK },
	{ NULL,         0                }
};

snk_module_t *snk_modules[MODULES_MAX];

extern snk_kernel_t snk_kernel_interface;

/* Load module and call init code.
   Init code will check, if module is responsible for device.
   Returns -1, if not responsible for device, 0 otherwise.
*/

static int
load_module(const char *name)
{
	int len, i;
	void *addr;
	void *link_addr;
	module_init_t module_init;

	// Load modules right after the SNK...
	// FIXME: hard-coded offset!
	link_addr = (void*)__client_start + 0x800000;

	// snk_kernel_interface.print("Loading Module '%s'\n", name);

	/* find module in module list and lookup link address */
	for(i=0; modules[i].name; ++i) {
		if(strcmp(modules[i].name, name) == 0)
			break;
	}
	if( modules[i].name == 0 ) {
		/* module not in list */
		return -1;
	}

	/* check if link address is used already */
	for(i=1; i<MODULES_MAX; ++i) {
		if(snk_modules[i] /* && snk_modules[i]->link_addr == link_addr*/) {
			// busy, can't load modules
			return -2;
		}
	}

	/* find empty position in array of loaded modules */
	for(i=0; i<MODULES_MAX; ++i) {
		if(snk_modules[i] == 0) {
			break;
		}
	}
	if(i == MODULES_MAX) {
		// no space avaliable!
		return -3;
	}

	/* Read module from FLASH */
	len = romfs_lookup(name, &addr);
	if (len <= 0) {
		/* file not found */
		return -4;
	}

	/* Copy image from flash to RAM */
	if (elf_load_file_to_addr(addr, link_addr, (void*)&module_init,
				  NULL, flush_cache) != 2) {
		snk_kernel_interface.print("ELF loading failed!\n");
		return -5;
	}

	snk_modules[i] = module_init(&snk_kernel_interface, &snk_kernel_interface.pci_conf);
	if(snk_modules[i] == 0) {
		/* no device found that can be managed by this module */
		return -5;
	}

	if(snk_modules[i]->type == MOD_TYPE_NETWORK) {
		/* Get mac address from device tree */
		get_mac(snk_modules[i]->mac_addr);
	}

	return i;
}

void
modules_init(void)
{
	int i;

	snk_kernel_interface.io_read  = read_io;
	snk_kernel_interface.io_write = write_io;

	snk_modules[0] = &of_module;

	/* Setup Module List */
	for(i=1; i<MODULES_MAX; ++i) {
		snk_modules[i] = 0;
	}

	/* Load all modules */
	for(i=0; modules[i].name; ++i) {
		load_module(modules[i].name);
	}
}

void
modules_term()
{
	int i;

	/* remove all modules */
	for(i=0; i<MODULES_MAX; ++i) {
		if(snk_modules[i] && snk_modules[i]->running != 0) {
			snk_modules[i]->term();
		}
		snk_modules[i] = 0;
	}
}

snk_module_t *
get_module_by_type(int type) {
	int i;

	for(i=0; i<MODULES_MAX; ++i) {
		if(snk_modules[i] && snk_modules[i]->type == type) {
			return snk_modules[i];
		}
	}
	return 0;
}

/**
 * insmod_by_type - Load first module of given type
 *
 * @param type  Type of module that we want to load
 * @return      module descriptor on success
 *              NULL              if not successful
 */
snk_module_t *
insmod_by_type(int type) {
	int i, j;
	for(i = 0; modules[i].name; ++i) {
		if(modules[i].type != type)
			continue;
		j = load_module(modules[i].name);
		if(j >= 0)
			return snk_modules[j];
	}
	return 0;
}

/**
 * rmmod_by_type - Remove all module of given type
 *
 * @param type  Type of module that we want to load
 */
void
rmmod_by_type(int type) {
	int i;

	for (i = 0; i < MODULES_MAX; ++i) {
		if (snk_modules[i] && snk_modules[i]->type == type) {
			if (snk_modules[i]->running)
				snk_modules[i]->term();
			snk_modules[i] = 0;
		}
	}
}
