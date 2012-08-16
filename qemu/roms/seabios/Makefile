# SeaBIOS build system
#
# Copyright (C) 2008-2010  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU LGPLv3 license.

# Program version
VERSION=pre-0.6.3-$(shell date +"%Y%m%d_%H%M%S")-$(shell hostname)

# Output directory
OUT=out/

# Source files
SRCBOTH=misc.c pmm.c stacks.c output.c util.c block.c floppy.c ata.c mouse.c \
        kbd.c pci.c serial.c clock.c pic.c cdrom.c ps2port.c smp.c resume.c \
        pnpbios.c pirtable.c vgahooks.c ramdisk.c pcibios.c blockcmd.c \
        usb.c usb-uhci.c usb-ohci.c usb-ehci.c usb-hid.c usb-msc.c \
        virtio-ring.c virtio-pci.c virtio-blk.c apm.c ahci.c
SRC16=$(SRCBOTH) system.c disk.c font.c
SRC32FLAT=$(SRCBOTH) post.c shadow.c memmap.c coreboot.c boot.c \
      acpi.c smm.c mptable.c smbios.c pciinit.c optionroms.c mtrr.c \
      lzmadecode.c bootsplash.c jpeg.c usb-hub.c paravirt.c \
      biostables.c xen.c bmp.c
SRC32SEG=util.c output.c pci.c pcibios.c apm.c stacks.c

cc-option = $(shell if test -z "`$(1) $(2) -S -o /dev/null -xc \
              /dev/null 2>&1`"; then echo "$(2)"; else echo "$(3)"; fi ;)

# Default compiler flags
COMMONCFLAGS = -I$(OUT) -Os -MD \
               -Wall -Wno-strict-aliasing -Wold-style-definition \
               $(call cc-option,$(CC),-Wtype-limits,) \
               -m32 -march=i386 -mregparm=3 -mpreferred-stack-boundary=2 \
               -mrtd -minline-all-stringops \
               -freg-struct-return -ffreestanding -fomit-frame-pointer \
               -fno-delete-null-pointer-checks \
               -ffunction-sections -fdata-sections -fno-common
COMMONCFLAGS += $(call cc-option,$(CC),-nopie,)
COMMONCFLAGS += $(call cc-option,$(CC),-fno-stack-protector,)
COMMONCFLAGS += $(call cc-option,$(CC),-fno-stack-protector-all,)

CFLAGS32FLAT = $(COMMONCFLAGS) -g -DMODE16=0 -DMODESEGMENT=0
CFLAGSSEG = $(COMMONCFLAGS) -DMODESEGMENT=1 -fno-defer-pop \
            $(call cc-option,$(CC),-fno-jump-tables,-DMANUAL_NO_JUMP_TABLE) \
            $(call cc-option,$(CC),-fno-tree-switch-conversion,)
CFLAGS32SEG = $(CFLAGSSEG) -DMODE16=0 -g
CFLAGS16INC = $(CFLAGSSEG) -DMODE16=1 \
              $(call cc-option,$(CC),--param large-stack-frame=4,-fno-inline)
CFLAGS16 = $(CFLAGS16INC) -g

all: $(OUT) $(OUT)bios.bin

# Run with "make V=1" to see the actual compile commands
ifdef V
Q=
else
Q=@
MAKEFLAGS += --no-print-directory
endif

OBJCOPY=objcopy
OBJDUMP=objdump
STRIP=strip

.PHONY : all clean distclean FORCE

vpath %.c src vgasrc
vpath %.S src vgasrc

################ Build rules

# Verify the gcc configuration and test if -fwhole-program works.
TESTGCC:=$(shell CC="$(CC)" LD="$(LD)" tools/test-gcc.sh)
ifeq "$(TESTGCC)" "-1"
$(error "Please upgrade GCC and/or binutils")
endif

ifndef COMPSTRAT
COMPSTRAT=$(TESTGCC)
endif

# Do a whole file compile - three methods are supported.
ifeq "$(COMPSTRAT)" "1"
# First method - use -fwhole-program without -combine.
define whole-compile
@echo "  Compiling whole program $3"
$(Q)printf '$(foreach i,$2,#include "../$i"\n)' > $3.tmp.c
$(Q)$(CC) $1 -fwhole-program -DWHOLE_PROGRAM -c $3.tmp.c -o $3
endef
else
ifeq "$(COMPSTRAT)" "2"
# Second menthod - don't use -fwhole-program at all.
define whole-compile
@echo "  Compiling whole program $3"
$(Q)printf '$(foreach i,$2,#include "../$i"\n)' > $3.tmp.c
$(Q)$(CC) $1 -c $3.tmp.c -o $3
endef
else
# Third (and preferred) method - use -fwhole-program with -combine
define whole-compile
@echo "  Compiling whole program $3"
$(Q)$(CC) $1 -fwhole-program -DWHOLE_PROGRAM -combine -c $2 -o $3
endef
endif
endif

%.strip.o: %.o
	@echo "  Stripping $@"
	$(Q)$(STRIP) $< -o $@

$(OUT)%.s: %.c
	@echo "  Compiling to assembler $@"
	$(Q)$(CC) $(CFLAGS16INC) -S -c $< -o $@

$(OUT)%.lds: %.lds.S
	@echo "  Precompiling $@"
	$(Q)$(CPP) -P -D__ASSEMBLY__ $< -o $@

$(OUT)asm-offsets.s: $(OUT)autoconf.h

$(OUT)asm-offsets.h: $(OUT)asm-offsets.s
	@echo "  Generating offset file $@"
	$(Q)./tools/gen-offsets.sh $< $@


$(OUT)ccode.16.s: $(OUT)autoconf.h ; $(call whole-compile, $(CFLAGS16) -S, $(addprefix src/, $(SRC16)),$@)

$(OUT)code32seg.o: $(OUT)autoconf.h ; $(call whole-compile, $(CFLAGS32SEG), $(addprefix src/, $(SRC32SEG)),$@)

$(OUT)ccode32flat.o: $(OUT)autoconf.h ; $(call whole-compile, $(CFLAGS32FLAT), $(addprefix src/, $(SRC32FLAT)),$@)

$(OUT)code16.o: romlayout.S $(OUT)ccode.16.s $(OUT)asm-offsets.h
	@echo "  Compiling (16bit) $@"
	$(Q)$(CC) $(CFLAGS16INC) -c -D__ASSEMBLY__ $< -o $@

$(OUT)romlayout16.lds: $(OUT)ccode32flat.o $(OUT)code32seg.o $(OUT)code16.o tools/layoutrom.py
	@echo "  Building ld scripts (version \"$(VERSION)\")"
	$(Q)echo 'const char VERSION[] = "$(VERSION)";' > $(OUT)version.c
	$(Q)$(CC) $(CFLAGS32FLAT) -c $(OUT)version.c -o $(OUT)version.o
	$(Q)$(LD) -melf_i386 -r $(OUT)ccode32flat.o $(OUT)version.o -o $(OUT)code32flat.o
	$(Q)$(OBJDUMP) -thr $(OUT)code32flat.o > $(OUT)code32flat.o.objdump
	$(Q)$(OBJDUMP) -thr $(OUT)code32seg.o > $(OUT)code32seg.o.objdump
	$(Q)$(OBJDUMP) -thr $(OUT)code16.o > $(OUT)code16.o.objdump
	$(Q)./tools/layoutrom.py $(OUT)code16.o.objdump $(OUT)code32seg.o.objdump $(OUT)code32flat.o.objdump $(OUT)romlayout16.lds $(OUT)romlayout32seg.lds $(OUT)romlayout32flat.lds

# These are actually built by tools/layoutrom.py above, but by pulling them
# into an extra rule we prevent make -j from spawning layoutrom.py 4 times.
$(OUT)romlayout32seg.lds $(OUT)romlayout32flat.lds $(OUT)code32flat.o: $(OUT)romlayout16.lds

$(OUT)rom16.o: $(OUT)code16.o $(OUT)romlayout16.lds
	@echo "  Linking $@"
	$(Q)$(LD) -T $(OUT)romlayout16.lds $< -o $@

$(OUT)rom32seg.o: $(OUT)code32seg.o $(OUT)romlayout32seg.lds
	@echo "  Linking $@"
	$(Q)$(LD) -T $(OUT)romlayout32seg.lds $< -o $@

$(OUT)rom.o: $(OUT)rom16.strip.o $(OUT)rom32seg.strip.o $(OUT)code32flat.o $(OUT)romlayout32flat.lds
	@echo "  Linking $@"
	$(Q)$(LD) -T $(OUT)romlayout32flat.lds $(OUT)rom16.strip.o $(OUT)rom32seg.strip.o $(OUT)code32flat.o -o $@

$(OUT)bios.bin.elf $(OUT)bios.bin: $(OUT)rom.o tools/checkrom.py
	@echo "  Prepping $@"
	$(Q)$(OBJDUMP) -thr $< > $<.objdump
	$(Q)$(OBJCOPY) -O binary $< $(OUT)bios.bin.raw
	$(Q)./tools/checkrom.py $<.objdump $(OUT)bios.bin.raw $(OUT)bios.bin
	$(Q)$(STRIP) -R .comment $< -o $(OUT)bios.bin.elf


################ VGA build rules

# VGA src files
SRCVGA=src/output.c src/util.c vgasrc/vga.c vgasrc/vgafb.c vgasrc/vgaio.c \
       vgasrc/vgatables.c vgasrc/vgafonts.c vgasrc/clext.c

$(OUT)vgaccode.16.s: $(OUT)autoconf.h ; $(call whole-compile, $(CFLAGS16) -S -Isrc, $(SRCVGA),$@)

$(OUT)vgalayout16.o: vgaentry.S $(OUT)vgaccode.16.s $(OUT)asm-offsets.h
	@echo "  Compiling (16bit) $@"
	$(Q)$(CC) $(CFLAGS16INC) -c -D__ASSEMBLY__ -Isrc $< -o $@

$(OUT)vgarom.o: $(OUT)vgalayout16.o $(OUT)vgalayout.lds
	@echo "  Linking $@"
	$(Q)$(LD) --gc-sections -T $(OUT)vgalayout.lds $(OUT)vgalayout16.o -o $@

$(OUT)vgabios.bin.raw: $(OUT)vgarom.o
	@echo "  Extracting binary $@"
	$(Q)$(OBJCOPY) -O binary $< $@

$(OUT)vgabios.bin: $(OUT)vgabios.bin.raw tools/buildrom.py
	@echo "  Finalizing rom $@"
	$(Q)./tools/buildrom.py $< $@

####### dsdt build rules
src/%.hex: src/%.dsl
	@echo "Compiling DSDT"
	$(Q)cpp -P $< > $(OUT)$*.dsl.i
	$(Q)iasl -tc -p $(OUT)$* $(OUT)$*.dsl.i
	$(Q)cp $(OUT)$*.hex $@

$(OUT)ccode32flat.o: src/acpi-dsdt.hex

####### Kconfig rules
export HOSTCC             := $(CC)
export CONFIG_SHELL       := sh
export KCONFIG_AUTOHEADER := autoconf.h
export KCONFIG_CONFIG     := $(CURDIR)/.config

$(OUT)autoconf.h : $(KCONFIG_CONFIG)
	$(Q)$(MAKE) silentoldconfig

$(KCONFIG_CONFIG):
	$(Q)$(MAKE) defconfig

%onfig:
	$(Q)mkdir -p $(OUT)/tools/kconfig/lxdialog
	$(Q)mkdir -p $(OUT)/include/config
	$(Q)$(MAKE) -C $(OUT) -f $(CURDIR)/tools/kconfig/Makefile srctree=$(CURDIR) src=tools/kconfig obj=tools/kconfig Q=$(Q) Kconfig=$(CURDIR)/src/Kconfig $@

####### Generic rules
clean:
	$(Q)rm -rf $(OUT)

distclean: clean
	$(Q)rm -f .config .config.old

$(OUT):
	$(Q)mkdir $@

-include $(OUT)*.d
