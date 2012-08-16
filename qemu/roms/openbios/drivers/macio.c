/*
 *   derived from mol/mol.c,
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "arch/common/nvram.h"
#include "packages/nvram.h"
#include "libopenbios/bindings.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "drivers/drivers.h"
#include "macio.h"
#include "cuda.h"
#include "escc.h"
#include "drivers/pci.h"

#define OW_IO_NVRAM_SIZE   0x00020000
#define OW_IO_NVRAM_OFFSET 0x00060000
#define OW_IO_NVRAM_SHIFT  4

#define NW_IO_NVRAM_SIZE   0x00004000
#define NW_IO_NVRAM_OFFSET 0xfff04000
#define NW_IO_NVRAM_SHIFT  1

#define IO_OPENPIC_SIZE    0x00040000
#define IO_OPENPIC_OFFSET  0x00040000

static char *nvram;

int
arch_nvram_size( void )
{
        if (is_oldworld())
                return OW_IO_NVRAM_SIZE >> OW_IO_NVRAM_SHIFT;
        else
                return NW_IO_NVRAM_SIZE >> NW_IO_NVRAM_SHIFT;
}

void macio_nvram_init(const char *path, phys_addr_t addr)
{
	phandle_t chosen, aliases;
	phandle_t dnode;
	int props[2];
	char buf[64];
        unsigned long nvram_size, nvram_offset;

        if (is_oldworld()) {
                nvram_offset = OW_IO_NVRAM_OFFSET;
                nvram_size = OW_IO_NVRAM_SIZE;
        } else {
                nvram_offset = NW_IO_NVRAM_OFFSET;
                nvram_size = NW_IO_NVRAM_SIZE;
                push_str("/");
                fword("find-device");
                fword("new-device");
                push_str("nvram");
                fword("device-name");
                fword("finish-device");
        }
	nvram = (char*)addr + nvram_offset;
        snprintf(buf, sizeof(buf), "%s/nvram", path);
	nvram_init(buf);
	dnode = find_dev(buf);
	set_int_property(dnode, "#bytes", arch_nvram_size() );
	props[0] = __cpu_to_be32(nvram_offset);
	props[1] = __cpu_to_be32(nvram_size);
	set_property(dnode, "reg", (char *)&props, sizeof(props));
	set_property(dnode, "device_type", "nvram", 6);
	NEWWORLD(set_property(dnode, "compatible", "nvram,flash", 12));

	chosen = find_dev("/chosen");
	push_str(buf);
	fword("open-dev");
	set_int_property(chosen, "nvram", POP());

	aliases = find_dev("/aliases");
	set_property(aliases, "nvram", buf, strlen(buf) + 1);
}

#ifdef DUMP_NVRAM
static void
dump_nvram(void)
{
  int i, j;
  for (i = 0; i < 10; i++)
    {
      for (j = 0; j < 16; j++)
      printk ("%02x ", nvram[(i*16+j)<<4]);
      printk (" ");
      for (j = 0; j < 16; j++)
        if (isprint(nvram[(i*16+j)<<4]))
            printk("%c", nvram[(i*16+j)<<4]);
        else
          printk(".");
      printk ("\n");
      }
}
#endif


void
arch_nvram_put( char *buf )
{
	int i;
        unsigned int it_shift;

        if (is_oldworld())
                it_shift = OW_IO_NVRAM_SHIFT;
        else
                it_shift = NW_IO_NVRAM_SHIFT;

	for (i=0; i< arch_nvram_size() ; i++)
		nvram[i << it_shift] = buf[i];
#ifdef DUMP_NVRAM
	printk("new nvram:\n");
	dump_nvram();
#endif
}

void
arch_nvram_get( char *buf )
{
	int i;
        unsigned int it_shift;

        if (is_oldworld())
                it_shift = OW_IO_NVRAM_SHIFT;
        else
                it_shift = NW_IO_NVRAM_SHIFT;

	for (i=0; i< arch_nvram_size(); i++)
                buf[i] = nvram[i << it_shift];

#ifdef DUMP_NVRAM
	printk("current nvram:\n");
	dump_nvram();
#endif
}

static void
openpic_init(const char *path, phys_addr_t addr)
{
        phandle_t target_node;
        phandle_t dnode;
        int props[2];
        char buf[128];

        push_str(path);
        fword("find-device");
        fword("new-device");
        push_str("interrupt-controller");
        fword("device-name");

        snprintf(buf, sizeof(buf), "%s/interrupt-controller", path);
        dnode = find_dev(buf);
        set_property(dnode, "device_type", "open-pic", 9);
        set_property(dnode, "compatible", "chrp,open-pic", 14);
        set_property(dnode, "built-in", "", 0);
        props[0] = __cpu_to_be32(IO_OPENPIC_OFFSET);
        props[1] = __cpu_to_be32(IO_OPENPIC_SIZE);
        set_property(dnode, "reg", (char *)&props, sizeof(props));
        set_int_property(dnode, "#interrupt-cells", 2);
        set_int_property(dnode, "#address-cells", 0);
        set_property(dnode, "interrupt-controller", "", 0);
        set_int_property(dnode, "clock-frequency", 4166666);

        fword("finish-device");

        if (is_newworld()) {
            u32 *interrupt_map;
            int len, i;

            /* patch in interrupt parent */
            dnode = find_dev(buf);

            target_node = find_dev("/pci/mac-io");
            set_int_property(target_node, "interrupt-parent", dnode);

            target_node = find_dev("/pci/mac-io/escc/ch-a");
            set_int_property(target_node, "interrupt-parent", dnode);

            target_node = find_dev("/pci/mac-io/escc/ch-b");
            set_int_property(target_node, "interrupt-parent", dnode);

            target_node = find_dev("/pci");
            set_int_property(target_node, "interrupt-parent", dnode);

            interrupt_map = (u32 *)get_property(target_node, "interrupt-map", &len);
            for (i = 0; i < 4; i++) {
                interrupt_map[(i * 7) + PCI_INT_MAP_PIC_HANDLE] = (u32)dnode;
            }
            set_property(target_node, "interrupt-map", (char *)interrupt_map, len);
        }
}

DECLARE_NODE(ob_macio, INSTALL_OPEN, sizeof(int), "Tmac-io");

/* ( str len -- addr ) */

static void
ob_macio_decode_unit(void *private)
{
	ucell addr;

	const char *arg = pop_fstr_copy();

	addr = strtol(arg, NULL, 16);

	free((char*)arg);

	PUSH(addr);
}

/*  ( addr -- str len ) */

static void
ob_macio_encode_unit(void *private)
{
	char buf[8];

	ucell addr = POP();

	snprintf(buf, sizeof(buf), "%x", addr);

	push_str(buf);
}

NODE_METHODS(ob_macio) = {
        { "decode-unit",	ob_macio_decode_unit	},
        { "encode-unit",	ob_macio_encode_unit	},
};

void
ob_macio_heathrow_init(const char *path, phys_addr_t addr)
{
        phandle_t aliases;

	REGISTER_NODE(ob_macio);
	aliases = find_dev("/aliases");
	set_property(aliases, "mac-io", path, strlen(path) + 1);

	cuda_init(path, addr);
	macio_nvram_init(path, addr);
        escc_init(path, addr);
	macio_ide_init(path, addr, 1);
}

void
ob_macio_keylargo_init(const char *path, phys_addr_t addr)
{
        phandle_t aliases;

        aliases = find_dev("/aliases");
        set_property(aliases, "mac-io", path, strlen(path) + 1);

        cuda_init(path, addr);
        /* The NewWorld NVRAM is not located in the MacIO device */
        macio_nvram_init("", 0);
        escc_init(path, addr);
        macio_ide_init(path, addr, 3);
        openpic_init(path, addr);
}
