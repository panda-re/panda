###############################################################################
#
# Initialise various variables
#

CLEANUP		:=
CFLAGS		:=
ASFLAGS		:=
LDFLAGS		:=
MAKEDEPS	:= Makefile

###############################################################################
#
# Locations of tools
#
HOST_CC		:= gcc
RM		:= rm -f
TOUCH		:= touch
MKDIR		:= mkdir
CP		:= cp
ECHO		:= echo
PRINTF		:= printf
PERL		:= perl
TRUE		:= true
CC		:= $(CROSS_COMPILE)gcc
CPP		:= $(CC) -E
AS		:= $(CROSS_COMPILE)as
LD		:= $(CROSS_COMPILE)ld
SIZE		:= $(CROSS_COMPILE)size
AR		:= $(CROSS_COMPILE)ar
RANLIB		:= $(CROSS_COMPILE)ranlib
OBJCOPY		:= $(CROSS_COMPILE)objcopy
NM		:= $(CROSS_COMPILE)nm
OBJDUMP		:= $(CROSS_COMPILE)objdump
PARSEROM	:= ./util/parserom.pl
FIXROM		:= ./util/fixrom.pl
SYMCHECK	:= ./util/symcheck.pl
SORTOBJDUMP	:= ./util/sortobjdump.pl
PADIMG		:= ./util/padimg.pl
LICENCE		:= ./util/licence.pl
NRV2B		:= ./util/nrv2b
ZBIN		:= ./util/zbin
ELF2EFI32	:= ./util/elf2efi32
ELF2EFI64	:= ./util/elf2efi64
EFIROM		:= ./util/efirom
ICCFIX		:= ./util/iccfix
EINFO		:= ./util/einfo
GENKEYMAP	:= ./util/genkeymap.pl
DOXYGEN		:= doxygen
BINUTILS_DIR	:= /usr
BFD_DIR		:= $(BINUTILS_DIR)
ZLIB_DIR	:= /usr

###############################################################################
#
# SRCDIRS lists all directories containing source files.
#
SRCDIRS		:=
SRCDIRS		+= libgcc
SRCDIRS		+= core
SRCDIRS		+= net net/tcp net/udp net/infiniband net/80211
SRCDIRS		+= image
SRCDIRS		+= drivers/bus
SRCDIRS		+= drivers/net
SRCDIRS		+= drivers/net/e1000
SRCDIRS		+= drivers/net/e1000e
SRCDIRS		+= drivers/net/igb
SRCDIRS		+= drivers/net/igbvf
SRCDIRS		+= drivers/net/phantom
SRCDIRS		+= drivers/net/rtl818x
SRCDIRS		+= drivers/net/ath5k
SRCDIRS		+= drivers/net/vxge
SRCDIRS		+= drivers/net/efi
SRCDIRS		+= drivers/block
SRCDIRS		+= drivers/nvs
SRCDIRS		+= drivers/bitbash
SRCDIRS		+= drivers/infiniband
SRCDIRS		+= interface/pxe interface/efi interface/smbios
SRCDIRS		+= interface/bofm
SRCDIRS		+= tests
SRCDIRS		+= crypto crypto/axtls crypto/matrixssl
SRCDIRS		+= hci hci/commands hci/tui
SRCDIRS		+= hci/mucurses hci/mucurses/widgets
SRCDIRS		+= hci/keymap
SRCDIRS		+= usr
SRCDIRS		+= config

# NON_AUTO_SRCS lists files that are excluded from the normal
# automatic build system.
#
NON_AUTO_SRCS	:=
NON_AUTO_SRCS	+= drivers/net/prism2.c

# INCDIRS lists the include path
#
INCDIRS		:=
INCDIRS		+= include .

###############################################################################
#
# Default build target: build the most common targets and print out a
# helpfully suggestive message
#
ALL		:= bin/blib.a bin/ipxe.dsk bin/ipxe.lkrn bin/ipxe.iso \
		   bin/ipxe.usb bin/undionly.kpxe bin/rtl8139.rom
all : $(ALL)
	@$(ECHO) '==========================================================='
	@$(ECHO)
	@$(ECHO) 'To create a bootable floppy, type'
	@$(ECHO) '    cat bin/ipxe.dsk > /dev/fd0'
	@$(ECHO) 'where /dev/fd0 is your floppy drive.  This will erase any'
	@$(ECHO) 'data already on the disk.'
	@$(ECHO)
	@$(ECHO) 'To create a bootable USB key, type'
	@$(ECHO) '    cat bin/ipxe.usb > /dev/sdX'
	@$(ECHO) 'where /dev/sdX is your USB key, and is *not* a real hard'
	@$(ECHO) 'disk on your system.  This will erase any data already on'
	@$(ECHO) 'the USB key.'
	@$(ECHO)
	@$(ECHO) 'To create a bootable CD-ROM, burn the ISO image '
	@$(ECHO) 'bin/ipxe.iso to a blank CD-ROM.'
	@$(ECHO)
	@$(ECHO) 'These images contain drivers for all supported cards.  You'
	@$(ECHO) 'can build more customised images, and ROM images, using'
	@$(ECHO) '    make bin/<rom-name>.<output-format>'
	@$(ECHO)
	@$(ECHO) '==========================================================='

###############################################################################
#
# Comprehensive build target: build a selection of cross-platform
# targets to expose potential build errors that show up only on
# certain platforms
#
everything :
	$(Q)$(MAKE) --no-print-directory $(ALL) \
		bin-i386-efi/ipxe.efi bin-i386-efi/ipxe.efidrv \
		bin-i386-efi/ipxe.efirom \
		bin-x86_64-efi/ipxe.efi bin-x86_64-efi/ipxe.efidrv \
		bin-x86_64-efi/ipxe.efirom \
		bin-i386-linux/tap.linux bin-x86_64-linux/tap.linux

###############################################################################
#
# Build targets that do nothing but might be tried by users
#
configure :
	@$(ECHO) "No configuration needed."

install :
	@$(ECHO) "No installation required."

###############################################################################
#
# Version number calculations
#
VERSION_MAJOR	= 1
VERSION_MINOR	= 0
VERSION_PATCH	= 0
EXTRAVERSION	= +
MM_VERSION	= $(VERSION_MAJOR).$(VERSION_MINOR)
VERSION		= $(MM_VERSION).$(VERSION_PATCH)$(EXTRAVERSION)
CFLAGS		+= -DVERSION_MAJOR=$(VERSION_MAJOR) \
		   -DVERSION_MINOR=$(VERSION_MINOR) \
		   -DVERSION_PATCH=$(VERSION_PATCH) \
		   -DVERSION=\"$(VERSION)\"
IDENT		= '$(@F) $(VERSION) (GPL) ipxe.org'
version :
	@$(ECHO) $(VERSION)

###############################################################################
#
# Drag in the bulk of the build system
#

MAKEDEPS	+= Makefile.housekeeping
include Makefile.housekeeping
