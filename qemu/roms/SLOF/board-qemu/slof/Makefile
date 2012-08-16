# *****************************************************************************
# * Copyright (c) 2004, 2011 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/


include ../Makefile.dirs

include $(TOPBRDDIR)/config
include $(TOPCMNDIR)/make.rules


all: Makefile.dep OF.ffs paflof $(SLOFCMNDIR)/xvect.bin

CPPFLAGS = -I$(LIBCMNDIR)/libbootmsg -I$(LIBCMNDIR)/libhvcall \
	 -I$(LIBCMNDIR)/libnvram
SLOF_LIBS = \
	$(LIBCMNDIR)/libbootmsg.a \
	$(LIBCMNDIR)/libelf.a \
	$(LIBCMNDIR)/libhvcall.a \
	$(LIBCMNDIR)/libnvram.a
BOARD_SLOF_IN = \
	$(LIBCMNDIR)/libhvcall/hvcall.in \
	$(LIBCMNDIR)/libbootmsg/bootmsg.in \
	$(LIBCMNDIR)/libelf/libelf.in \
	$(LIBCMNDIR)/libnvram/libnvram.in \
	$(LIBCMNDIR)/libbases/libbases.in
BOARD_SLOF_CODE = $(BOARD_SLOF_IN:%.in=%.code)

include $(SLOFCMNDIR)/Makefile.inc

FPPINCLUDES = -I. -I$(SLOFCMNDIR)/fs -I$(SLOFCMNDIR)

# FCode Evaluator files for the ROM fs:
FCODE_FFS_FILES = \
	$(SLOFCMNDIR)/fs/fcode/core.fs \
	$(SLOFCMNDIR)/fs/fcode/evaluator.fs \
	$(SLOFCMNDIR)/fs/fcode/big.fs \
	$(SLOFCMNDIR)/fs/fcode/tokens.fs \
	$(SLOFCMNDIR)/fs/fcode/1275.fs


USB_FFS_FILES = \
	$(SLOFCMNDIR)/fs/devices/pci-class_0c.fs \
	$(SLOFCMNDIR)/fs/usb/usb-ohci.fs \
	$(SLOFCMNDIR)/fs/usb/usb-support.fs \
	$(SLOFCMNDIR)/fs/usb/usb-hub.fs \
	$(SLOFCMNDIR)/fs/usb/usb-enumerate.fs \
	$(SLOFCMNDIR)/fs/usb/usb-storage.fs \
	$(SLOFCMNDIR)/fs/usb/usb-storage-support.fs \
	$(SLOFCMNDIR)/fs/usb/usb-storage-wrapper.fs \
	$(SLOFCMNDIR)/fs/usb/usb-keyboard.fs \
	$(SLOFCMNDIR)/fs/usb/usb-kbd-device-support.fs \
	$(SLOFCMNDIR)/fs/usb/usb-mouse.fs \
	$(SLOFCMNDIR)/fs/scsi-support.fs

VIO_FFS_FILES = \
	$(SLOFBRDDIR)/vio-hvterm.fs \
	$(SLOFBRDDIR)/vio-vscsi.fs \
	$(SLOFBRDDIR)/vio-vscsi-device.fs \
	$(SLOFBRDDIR)/vio-veth.fs

# Files that should go into the ROM fs (and so have to be listed in OF.ffs):
OF_FFS_FILES = \
	$(SLOFCMNDIR)/fs/ide.fs \
	$(SLOFCMNDIR)/fs/fbuffer.fs \
	$(SLOFCMNDIR)/fs/generic-disk.fs \
	$(SLOFCMNDIR)/fs/pci-device.fs \
	$(SLOFCMNDIR)/fs/pci-bridge.fs \
	$(SLOFCMNDIR)/fs/pci-properties.fs \
	$(SLOFCMNDIR)/fs/pci-config-bridge.fs \
	$(SLOFCMNDIR)/fs/update_flash.fs \
	$(SLOFCMNDIR)/fs/xmodem.fs \
	$(SLOFBRDDIR)/default-font.bin \
	$(FCODE_FFS_FILES)

# Uncomment the following line to enable the USB code:
OF_FFS_FILES += $(USB_FFS_FILES) $(VIO_FFS_FILES)

OF_FFS_FILES := $(OF_FFS_FILES:%.fs=%.fsi)

OF.ffs: Makefile $(SLOFCMNDIR)/Makefile.inc $(OF_FFS_FILES)
	$(MAKE) create_OF_ffs

# Rules for cleaning up:
.PHONY: clean_here clean distclean

clean_here:
	rm -f *.o OF.fsi OF.ffs

clean: clean_here clean_slof

distclean: clean_here distclean_slof
