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

: strequal ( str1 len1 str2 len2 -- flag )
  rot dup rot = IF comp 0= ELSE 2drop drop 0 THEN ; 

400 cp

0 value puid

440 cp

480 cp

\ The root of the device tree and some of its kids.
" /" find-device

" QEMU" encode-string s" model" property

2 encode-int s" #address-cells" property
2 encode-int s" #size-cells" property

\ Yaboot is stupid.  Without this, it can't/won't find /etc/yaboot.conf.
s" chrp" device-type

\ See 3.6.5, and the PowerPC OF binding document.
new-device
s" mmu" 2dup device-name device-type
0 0 s" translations" property

: open  true ;
: close ;

finish-device
device-end

4c0 cp

\ Fixup timebase frequency from device-tree
: fixup-tbfreq
    " /cpus/@0" find-device
    " timebase-frequency" get-node get-package-property IF
        2drop
    ELSE
        decode-int to tb-frequency 2drop
    THEN
    device-end
;
fixup-tbfreq

4d0 cp

\ Grab rtas from qemu
#include "rtas.fs"

500 cp

: populate-vios ( -- )
    \ Populate the /vdevice children with their methods
    \ WARNING: Quite a few SLOFisms here like get-node, set-node, ...

    ." Populating /vdevice methods" cr
    " /vdevice" find-device get-node child
    BEGIN
        dup 0 <>
    WHILE
        dup set-node
        dup " compatible" rot get-package-property 0 = IF
            drop dup from-cstring
            2dup " hvterm1" strequal IF
                " vio-hvterm.fs" included
            THEN
            2dup " IBM,v-scsi" strequal IF
                " vio-vscsi.fs" included
            THEN
            2dup " IBM,l-lan" strequal IF
                " vio-veth.fs" included
            THEN
            2drop
       THEN
       peer
    REPEAT drop

    device-end
;

\ Now do it
populate-vios

580 cp

5a0 cp

600 cp

\ Add rtas cleanup last
' rtas-quiesce add-quiesce-xt

640 cp

690 cp

6a0 cp

6a8 cp

6b0 cp

6b8 cp

6c0 cp

s" /cpus/@0" open-dev encode-int s" cpu" set-chosen
s" /memory" open-dev encode-int s" memory" set-chosen

6e0 cp

700 cp

\ See 3.5.
s" /openprom" find-device
   s" SLOF," slof-build-id here swap rmove here slof-build-id nip $cat encode-string s" model" property
   0 0 s" relative-addressing" property
device-end

s" /aliases" find-device
   : open  true ;
   : close ;
device-end

s" /mmu" open-dev encode-int s" mmu" set-chosen

#include "available.fs"

\ Setup terminal IO

#include <term-io.fs>

" hvterm" find-alias IF drop
  " hvterm" io
THEN
