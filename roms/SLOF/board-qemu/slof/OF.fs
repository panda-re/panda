\ *****************************************************************************
\ * Copyright (c) 2004, 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ The master file.  Everything else is included into here.

hex

' ll-cr to cr

#include "header.fs"

#include "hvterm.fs"

#include "base.fs"

\ Adjust load-base to point to paflof-start / 2:
paflof-start 1 rshift fff not and to load-base

\ Little-endian accesses.  Also known as `wrong-endian'.
#include <little-endian.fs>

: #join  ( lo hi #bits -- x )  lshift or ;
: #split ( x #bits -- lo hi )  2dup rshift dup >r swap lshift xor r> ;

: blink ;
: reset-dual-emit ;
: console-clean-fifo ;
: bootmsg-nvupdate ;
: asm-cout 2drop drop ;

#include "logging.fs"

: log-string 2drop ;

#include "bootmsg.fs"

000 cp

#include "exception.fs"

: mm-log-warning 2drop ;

: write-mm-log ( data length type -- status )
	3drop 0
;

080 cp

100 cp

\ Input line editing.
#include "accept.fs"

120 cp

#include "dump.fs"

cistack ciregs >r1 ! \ kernel wants a stack :-)

#include "romfs.fs"

140 cp

200 cp

201 cp
#include <slof-logo.fs>
#include <banner.fs>

: .banner .slof-logo .banner ;

220 cp

DEFER find-boot-sector ( -- )

240 cp
\ Timebase frequency, in Hz. Start with a good default
\ Use device-tree later to fix it up
d# 512000000 VALUE tb-frequency   \ default value - needed for "ms" to work
-1 VALUE cpu-frequency

#include "helper.fs"
260 cp

#include <timebase.fs>

280 cp

2c0 cp

2e0 cp

#include <quiesce.fs>

300 cp

#include <usb/usb-static.fs>

320 cp

#include <scsi-loader.fs>

340 cp

360 cp

#include "fdt.fs"

370 cp

#include "tree.fs"

800 cp

#include "nvram.fs"

880 cp

#include "envvar.fs"
check-for-nvramrc

890 cp

#include "qemu-bootlist.fs"

8a0 cp

\ The client interface.
#include "client.fs"
\ ELF binary file format.
#include "elf.fs"
#include <loaders.fs>

8b0 cp

\ Claim remaining memory that is used by firmware:
romfs-base 400000 0 ' claim CATCH IF ." claim failed!" cr 2drop THEN drop

8ff cp

#include <start-up.fs>

."      "   \ Clear last checkpoint

#include <boot.fs>

cr .(   Welcome to Open Firmware)
cr
#include "copyright-oss.fs"
cr cr

\ this CATCH is to ensure the code bellow always executes:  boot may ABORT!
' start-it CATCH drop

cr ." Ready!"
