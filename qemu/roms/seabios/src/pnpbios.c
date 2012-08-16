// PNP BIOS calls
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // checksum
#include "config.h" // BUILD_BIOS_ADDR
#include "farptr.h" // SET_FARVAR

struct pnpheader {
    u32 signature;
    u8 version;
    u8 length;
    u16 control;
    u8 checksum;
    u32 eventloc;
    u16 real_ip;
    u16 real_cs;
    u16 prot_ip;
    u32 prot_base;
    u32 oemid;
    u16 real_ds;
    u32 prot_database;
} PACKED;

extern struct pnpheader PNPHEADER;
extern char pnp_string[];

#if CONFIG_PNPBIOS
struct pnpheader PNPHEADER __aligned(16) VAR16EXPORT = {
    .signature = PNP_SIGNATURE,
    .version = 0x10,
    .length = sizeof(PNPHEADER),
    .real_cs = SEG_BIOS,
    .prot_base = BUILD_BIOS_ADDR,
    .real_ds = SEG_BIOS,
    .prot_database = BUILD_BIOS_ADDR,
};
#else
// We need a copy of this string in the 0xf000 segment, but we are not
// actually a PnP BIOS, so make sure it is *not* aligned, so OSes will
// not see it if they scan.
char pnp_string[] __aligned(2) VAR16VISIBLE = " $PnP";
#endif

#define FUNCTION_NOT_SUPPORTED 0x82

// BBS - Get Version and Installation Check
static u16
handle_pnp60(u16 *args)
{
    u16 version_ptr = args[1];
    u16 version_seg = args[2];
    SET_FARVAR(version_seg, *(u16*)(version_ptr+0), 0x0101);
    return 0;
}

static u16
handle_pnpXX(u16 *args)
{
    return FUNCTION_NOT_SUPPORTED;
}

u16 VISIBLE16
handle_pnp(u16 *args)
{
    if (! CONFIG_PNPBIOS)
        return FUNCTION_NOT_SUPPORTED;

    u16 arg1 = args[0];
    dprintf(DEBUG_HDL_pnp, "pnp call arg1=%x\n", arg1);

    switch (arg1) {
    case 0x60: return handle_pnp60(args);
    default:   return handle_pnpXX(args);
    }
}

u16
get_pnp_offset(void)
{
    if (! CONFIG_PNPBIOS)
        return (u32)pnp_string + 1 - BUILD_BIOS_ADDR;
    return (u32)&PNPHEADER - BUILD_BIOS_ADDR;
}

// romlayout.S
extern void entry_pnp_real(void);
extern void entry_pnp_prot(void);

void
pnp_setup(void)
{
    if (! CONFIG_PNPBIOS)
        return;

    dprintf(3, "init PNPBIOS table\n");

    PNPHEADER.real_ip = (u32)entry_pnp_real - BUILD_BIOS_ADDR;
    PNPHEADER.prot_ip = (u32)entry_pnp_prot - BUILD_BIOS_ADDR;
    PNPHEADER.checksum -= checksum(&PNPHEADER, sizeof(PNPHEADER));
}
