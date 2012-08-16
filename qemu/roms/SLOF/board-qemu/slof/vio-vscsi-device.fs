\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Create new VSCSI child device
\ ( lun id $name is_cdrom -- )

\ Create device
new-device

VALUE is_cdrom

2swap	( $name lun id )

\ Set reg & unit
2dup set-unit encode-phys " reg" property

\ Set name
2dup device-name

2dup find-alias 0= IF
    get-node node>path set-alias
ELSE 2drop THEN 

s" block" device-type      

\ Required interface for deblocker

0 INSTANCE VALUE block-size
0 INSTANCE VALUE max-block-num
0 INSTANCE VALUE max-transfer

: read-blocks ( addr block# #blocks -- #read )
    block-size " dev-read-blocks" $call-parent
    not IF
        ." Read blocks failed !" cr -1 throw
    THEN
;    

INSTANCE VARIABLE deblocker

: open ( -- true | false )
    my-unit " set-address" $call-parent
    is_cdrom IF " dev-prep-cdrom" ELSE " dev-prep-disk" THEN $call-parent
    " dev-max-transfer" $call-parent to max-transfer

    " dev-get-capacity" $call-parent to max-block-num to block-size
    max-block-num 0=  block-size 0= OR IF
       ." Failed to get disk capacity!" cr
       FALSE EXIT
    THEN

    0 0 " deblocker" $open-package dup deblocker ! dup IF 
        " disk-label" find-package IF
            my-args rot interpose
        THEN
   THEN 0<>
;

: close ( -- )
    deblocker @ close-package ;

: seek ( pos.lo pos.hi -- status )
    s" seek" deblocker @ $call-method ;

: read ( addr len -- actual )
    s" read" deblocker @ $call-method ;

finish-device
