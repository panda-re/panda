// Coreboot interface support.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // CONFIG_*
#include "util.h" // dprintf
#include "pci.h" // struct pir_header
#include "acpi.h" // struct rsdp_descriptor
#include "mptable.h" // MPTABLE_SIGNATURE
#include "smbios.h" // struct smbios_entry_point

void
copy_pir(void *pos)
{
    struct pir_header *p = pos;
    if (p->signature != PIR_SIGNATURE)
        return;
    if (PirOffset)
        return;
    if (p->size < sizeof(*p))
        return;
    if (checksum(pos, p->size) != 0)
        return;
    void *newpos = malloc_fseg(p->size);
    if (!newpos) {
        warn_noalloc();
        return;
    }
    dprintf(1, "Copying PIR from %p to %p\n", pos, newpos);
    memcpy(newpos, pos, p->size);
    PirOffset = (u32)newpos - BUILD_BIOS_ADDR;
}

void
copy_mptable(void *pos)
{
    struct mptable_floating_s *p = pos;
    if (p->signature != MPTABLE_SIGNATURE)
        return;
    if (!p->physaddr)
        return;
    if (checksum(pos, sizeof(*p)) != 0)
        return;
    u32 length = p->length * 16;
    u16 mpclength = ((struct mptable_config_s *)p->physaddr)->length;
    struct mptable_floating_s *newpos = malloc_fseg(length + mpclength);
    if (!newpos) {
        warn_noalloc();
        return;
    }
    dprintf(1, "Copying MPTABLE from %p/%x to %p\n", pos, p->physaddr, newpos);
    memcpy(newpos, pos, length);
    newpos->physaddr = (u32)newpos + length;
    newpos->checksum -= checksum(newpos, sizeof(*newpos));
    memcpy((void*)newpos + length, (void*)p->physaddr, mpclength);
}

void
copy_acpi_rsdp(void *pos)
{
    if (RsdpAddr)
        return;
    struct rsdp_descriptor *p = pos;
    if (p->signature != RSDP_SIGNATURE)
        return;
    u32 length = 20;
    if (checksum(pos, length) != 0)
        return;
    if (p->revision > 1) {
        length = p->length;
        if (checksum(pos, length) != 0)
            return;
    }
    void *newpos = malloc_fseg(length);
    if (!newpos) {
        warn_noalloc();
        return;
    }
    dprintf(1, "Copying ACPI RSDP from %p to %p\n", pos, newpos);
    memcpy(newpos, pos, length);
    RsdpAddr = newpos;
}

void
copy_smbios(void *pos)
{
    struct smbios_entry_point *p = pos;
    if (memcmp(p->anchor_string, "_SM_", 4))
        return;
    if (checksum(pos, 0x10) != 0)
        return;
    if (memcmp(p->intermediate_anchor_string, "_DMI_", 5))
        return;
    if (checksum(pos+0x10, p->length-0x10) != 0)
        return;
    struct smbios_entry_point *newpos = malloc_fseg(p->length);
    if (!newpos) {
        warn_noalloc();
        return;
    }
    dprintf(1, "Copying SMBIOS entry point from %p to %p\n", pos, newpos);
    memcpy(newpos, pos, p->length);
}
