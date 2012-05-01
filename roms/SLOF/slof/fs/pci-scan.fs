\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ ----------------------------------------------------------
\ **********  Variables to be set by host bridge  **********
\ ----------------------------------------------------------

\ Values of the next free memory area
VARIABLE pci-next-mem           \ prefetchable memory mapped
VARIABLE pci-max-mem
VARIABLE pci-next-mmio          \ non-prefetchable memory
VARIABLE pci-max-mmio
VARIABLE pci-next-io            \ I/O space
VARIABLE pci-max-io

\ Counter of busses found
0 VALUE pci-bus-number
\ Counter of devices found
0 VALUE pci-device-number
\ bit field of devices plugged into this bridge
0 VALUE pci-device-slots
\ byte field holding the device-slot number vector of the current device
\ the vector can be as deep as the max depth of bridges possible
\ 3,4,5 means
\       the 5th slot on the bus of the bridge in
\       the 4th slot on the bus of the bridge in
\       the 3rd slot on the HostBridge bus
here 100 allot CONSTANT pci-device-vec
0 VALUE pci-device-vec-len


\ Fixme Glue to the pci-devices ... remove this later
: next-pci-mem ( addr -- addr ) pci-next-mem ;
: next-pci-mmio ( addr -- addr ) pci-next-mmio ;
: next-pci-io ( addr -- addr ) pci-next-io ;

\ ----------------------------------------------------------
\ ******************  Helper functions  ********************
\ ----------------------------------------------------------

\ convert an integer to string of len digits
: int2str ( int len -- str len ) swap s>d rot <# 0 ?DO # LOOP #> ;

\ convert addr to busnr
: pci-addr2bus ( addr -- busnr ) 10 rshift FF and ;

\ convert addr to devnr
: pci-addr2dev ( addr -- dev ) B rshift 1F and ;

\ convert addr to functionnumber
: pci-addr2fn ( addr -- dev ) 8 rshift 7 and ;

\ convert busnr devnr to addr
: pci-bus2addr ( busnr devnr -- addr ) B lshift swap 10 lshift + ;

\ print out a pci config addr
: pci-addr-out ( addr -- ) dup pci-addr2bus 2 0.r space FFFF and 4 0.r ;

\ Dump out the whole configspace
: pci-dump ( addr -- )
        10 0 DO
                dup
                cr i 4 * +
                dup pci-addr-out space
                rtas-config-l@ 8 0.r
        LOOP
        drop cr
;

\ Dump out the pci device-slot vector
: pci-vec ( -- )
        cr s" device-vec(" type
        pci-device-vec-len dup 2 0.r s" ):" type
        1+ 0 DO
                pci-device-vec i + c@
                space 2 0.r
        LOOP
        cr
;

\ prints out all relevant pci variables
: var-out ( --)
        s"   mem:" type pci-next-mem @ 16 0.r cr
        s"  mmio:" type pci-next-mmio @ 16 0.r cr
        s"    io:" type pci-next-io @ 16 0.r cr
;

\ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
\ the following functions use l@ to fetch the data,
\ that's because the pcie core on spider has some probs with w@ !!!
\ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
\ read Vendor ID
: pci-vendor@ ( addr -- id )                 rtas-config-l@ FFFF and ;
\ read Device ID
: pci-device@ ( addr -- id )                 rtas-config-l@ 10 rshift ;
\ read Status
: pci-status@ ( addr -- status )         4 + rtas-config-l@ 10 rshift ;
\ read Revision ID
: pci-revision@ ( addr -- id )           8 + rtas-config-b@ ;
\ read Class Code
: pci-class@  ( addr -- class )          8 + rtas-config-l@ 8 rshift ;
\ read Cache Line Size
: pci-cache@  ( addr -- size )           C + rtas-config-b@ ;
\ read Header Type
: pci-htype@  ( addr -- type )           E + rtas-config-b@  ;
\ read Sub Vendor ID
: pci-sub-vendor@ ( addr -- sub-id )    2C + rtas-config-l@ FFFF and ;
\ read Sub Device ID
: pci-sub-device@ ( addr -- sub-id )    2C + rtas-config-l@ 10 rshift FFFF and ;
\ read Interrupt Pin
: pci-interrupt@  ( addr -- interrupt ) 3D + rtas-config-b@ ;
\ read Minimum Grant
: pci-min-grant@  ( addr -- min-gnt )   3E + rtas-config-b@ ;
\ read Maximum Latency
: pci-max-lat@  ( addr -- max-lat )     3F + rtas-config-b@ ;
\ Check if Capabilities are valid
: pci-capabilities?  ( addr -- 0|1 ) pci-status@ 4 rshift 1 and ;
\ fetch the offset of the next capability
: pci-cap-next  ( cap-addr -- next-cap-off ) rtas-config-b@ FC and ;
\ calc the address of the next capability
: pci-cap-next-addr  ( cap-addr -- next-cap-addr ) 1+ dup pci-cap-next dup IF swap -100 and + ELSE nip THEN ;

\ Dump out all capabilities
: pci-cap-dump ( addr -- )
        cr
        dup pci-capabilities? IF
                33 + BEGIN
                        pci-cap-next-addr dup 0<>
                WHILE
                        dup pci-addr-out s"  : " type
                        dup rtas-config-b@ 2 0.r cr
                REPEAT
                s" end found "
        ELSE
                s" capabilities not enabled!"
        THEN
        type cr drop
;

\ search the capability-list for this id
: pci-cap-find ( addr id -- capp-addr|0 )
        swap dup pci-capabilities? IF
                33 + BEGIN
                        pci-cap-next-addr dup 0<> IF
                                dup rtas-config-b@ 2 pick =
                        ELSE
                                true
                        THEN
                UNTIL
                nip
        ELSE
                2drop 0
        THEN
;

\ check wether this device is a pci-express device
: pci-express? ( addr -- 0|1 ) 10 pci-cap-find 0<> ;

\ check wether this device is a pci-express device
: pci-x? ( addr -- 0|1 ) 07 pci-cap-find 0<> ;

\ check wether this device has extended config space
: pci-config-ext? ( addr -- 0|1 ) pci-express? ;

\ set and fetch the interrupt Pin
: pci-irq-line@  ( addr -- irq-pin ) 3C + rtas-config-b@ ;
: pci-irq-line!  ( pin addr -- ) 3C + rtas-config-b! ;

\ set and fetch primary bus number
: pci-bus-prim! ( nr addr -- ) 18 + dup rtas-config-l@ FFFFFF00 and rot + swap rtas-config-l! ;
: pci-bus-prim@ ( addr -- nr ) 18 + rtas-config-l@ FF and ;

\ set and fetch secondary bus number
: pci-bus-scnd! ( nr addr -- ) 18 + dup rtas-config-l@ FFFF00FF and rot 8 lshift + swap rtas-config-l! ;
: pci-bus-scnd@ ( addr -- nr ) 18 + rtas-config-l@ 8 rshift FF and ;

\ set and fetch subordinate bus number
: pci-bus-subo! ( nr addr -- ) 18 + dup rtas-config-l@ FF00FFFF and rot 10 lshift + swap rtas-config-l! ;
: pci-bus-subo@ ( addr -- nr ) 18 + rtas-config-l@ 10 rshift FF and ;

\ set and fetch primary, secondary and subordinate bus number
: pci-bus! ( subo scnd prim addr -- ) swap rot 8 lshift + rot 10 lshift + swap 18 + dup rtas-config-l@ FF000000 and rot + swap rtas-config-l! ;
: pci-bus@ ( addr -- subo scnd prim ) 18 + rtas-config-l@ dup 10 rshift FF and swap dup 8 rshift FF and swap FF and ;

\ Reset secondary Status
: pci-reset-2nd ( addr -- ) 1C + dup rtas-config-l@ FFFF0000 or swap rtas-config-l! ;

\ Disable Bus Master, Memory Space and I/O Space for this device
: pci-device-disable ( -- ) my-space 4 + dup rtas-config-l@ 7 invert and swap rtas-config-l! ;

\ Enable Bus Master
: pci-master-enable ( -- ) my-space 4 + dup rtas-config-l@ 4 or swap rtas-config-l! ;

\ Disable Bus Master
: pci-master-disable ( -- ) my-space 4 + dup rtas-config-l@ 4 invert and swap rtas-config-l! ;

\ Enable response to mem accesses of pci device
: pci-mem-enable ( -- ) my-space 4 + dup rtas-config-w@ 2 or swap rtas-config-w! ;
: enable-mem-access ( -- ) pci-mem-enable ;

\ Enable response to I/O accesses of pci-device
: pci-io-enable ( -- ) my-space 4 + dup rtas-config-w@ 1 or swap rtas-config-w! ;
: enable-io-access ( -- ) pci-io-enable ;

\ Enable Bus Master, I/O and mem access
: pci-enable ( -- ) my-space 4 + dup rtas-config-w@ 7 or swap rtas-config-w! ;

\ Enable #PERR and #SERR errors of pci-device
: pci-error-enable ( -- ) my-space 4 + dup rtas-config-w@ 140 or swap rtas-config-w! ;

\ prints out the ScanInformation about a device
\ char is a sign for device type e.g. D - device ; B - bridge
: pci-out ( addr char -- )
        15 spaces
        over pci-addr-out
        s"  (" type emit s" ) : " type
        dup pci-vendor@ 4 0.r space
        pci-device@ 4 0.r
        4 spaces
;

\ Update the device-slot number vector
\ Set the bit of the DeviceSlot in the Slot array
: pci-set-slot ( addr -- )
        pci-addr2dev dup                \ calc slot number
        pci-device-vec-len              \ the end of the vector
        pci-device-vec + c!             \ and update the vector
        80000000 swap rshift            \ calc bit position of the device slot
        pci-device-slots or             \ set this bit
        TO pci-device-slots             \ and write it back
;

\ Update pci-next-mmio to be 1MB aligned and set the mmio-base register
\ and set the Limit register to the maximum available address space
\ needed for scanning possible devices behind the bridge
: pci-bridge-set-mmio-base ( addr -- )
        pci-next-mmio @ 100000 #aligned         \ read the current Value and align to 1MB boundary
        dup pci-next-mmio !                     \ and write it back
        10 rshift                               \ mmio-base reg is only the upper 16 bits
        pci-max-mmio @ FFFF0000 and or          \ and Insert mmio Limit (set it to max)
        swap 20 + rtas-config-l!                \ and write it into the bridge
;

\ Update pci-next-mmio to be 1MB aligned and set the mmio-limit register
\ The Limit Value is one less then the upper boundary
\ If the limit is less than the base the mmio is disabled
: pci-bridge-set-mmio-limit ( addr -- )
        pci-next-mmio @ 100000 #aligned         \ fetch current value and align to 1MB
        dup pci-next-mmio !                     \ and write it back
        1- FFFF0000 and                         \ make it one less and keep upper 16 bits
        over 20 + rtas-config-l@ 0000FFFF and   \ fetch original value
        or swap 20 + rtas-config-l!             \ and write it into the Reg
;

\ Update pci-next-mem to be 1MB aligned and set the mem-base and mem-base-upper register
\ and set the Limit register to the maximum available address space
\ needed for scanning possible devices behind the bridge
: pci-bridge-set-mem-base ( addr -- )
        pci-next-mem @ 100000 #aligned          \ read the current Value and align to 1MB boundary
        dup pci-next-mem !                      \ and write it back
        over 24 + rtas-config-w@                \ check if 64bit support
        1 and IF                                \ IF 64 bit support
                2dup 20 rshift                  \ | keep upper 32 bits
                swap 28 + rtas-config-l!        \ | and write it into the Base-Upper32-bits
                pci-max-mem @ 20 rshift         \ | fetch max Limit address and keep upper 32 bits
                2 pick 2C + rtas-config-l!      \ | and set the Limit
        THEN                                    \ FI
        10 rshift                               \ keep upper 16 bits
        pci-max-mem @ FFFF0000 and or           \ and Insert mmem Limit (set it to max)
        swap 24 + rtas-config-l!                \ and write it into the bridge
;

\ Update pci-next-mem to be 1MB aligned and set the mem-limit register
\ The Limit Value is one less then the upper boundary
\ If the limit is less than the base the mem is disabled
: pci-bridge-set-mem-limit ( addr -- )
        pci-next-mem @ 100000 #aligned          \ read the current Value and align to 1MB boundary
        dup pci-next-mem !                      \ and write it back
        1-                                      \ make limit one less than boundary
        over 24 + rtas-config-w@                \ check if 64bit support
        1 and IF                                \ IF 64 bit support
                2dup 20 rshift                  \ | keep upper 32 bits
                swap 2C + rtas-config-l!        \ | and write it into the Limit-Upper32-bits
        THEN                                    \ FI
        FFFF0000 and                            \ keep upper 16 bits
        over 24 + rtas-config-l@ 0000FFFF and   \ fetch original Value
        or swap 24 + rtas-config-l!             \ and write it into the bridge
;

\ Update pci-next-io to be 4KB aligned and set the io-base and io-base-upper register
\ and set the Limit register to the maximum available address space
\ needed for scanning possible devices behind the bridge
: pci-bridge-set-io-base ( addr -- )
        pci-next-io @ 1000 #aligned             \ read the current Value and align to 4KB boundary
        dup pci-next-io !                       \ and write it back
        over 1C + rtas-config-l@                \ check if 32bit support
        1 and IF                                \ IF 32 bit support
                2dup 10 rshift                  \ | keep upper 16 bits
                pci-max-io @ FFFF0000 and or    \ | insert upper 16 bits of Max-Limit
                swap 30 + rtas-config-l!        \ | and write it into the Base-Upper16-bits
        THEN                                    \ FI
        8 rshift 000000FF and                   \ keep upper 8 bits
        pci-max-io @ 0000FF00 and or            \ insert upper 8 bits of Max-Limit
        over rtas-config-l@ FFFF0000 and        \ fetch original Value
        or swap 1C + rtas-config-l!             \ and write it into the bridge
;

\ Update pci-next-io to be 4KB aligned and set the io-limit register
\ The Limit Value is one less then the upper boundary
\ If the limit is less than the base the io is disabled
: pci-bridge-set-io-limit ( addr -- )
        pci-next-io @ 1000 #aligned             \ read the current Value and align to 4KB boundary
        dup pci-next-io !                       \ and write it back
        1-                                      \ make limit one less than boundary
        over 1D + rtas-config-b@                \ check if 32bit support
        1 and IF                                \ IF 32 bit support
                2dup FFFF0000 and               \ | keep upper 16 bits
                over 30 + rtas-config-l@        \ | fetch original Value
                or swap 30 + rtas-config-l!     \ | and write it into the Limit-Upper16-bits
        THEN                                    \ FI
        0000FF00 and                            \ keep upper 8 bits
        over 1C + rtas-config-l@ FFFF00FF and   \ fetch original Value
        or swap 1C + rtas-config-l!             \ and write it into the bridge
;

\ set up all base registers to the current variable Values
: pci-bridge-set-bases ( addr -- )
        dup pci-bridge-set-mmio-base
        dup pci-bridge-set-mem-base
            pci-bridge-set-io-base
;

\ set up all limit registers to the current variable Values
: pci-bridge-set-limits ( addr -- )
        dup pci-bridge-set-mmio-limit
        dup pci-bridge-set-mem-limit
            pci-bridge-set-io-limit
;

\ ----------------------------------------------------------
\ ******************  PCI Scan functions  ******************
\ ----------------------------------------------------------

\ define function pointer as forward declaration of pci-probe-bus
DEFER func-pci-probe-bus

\ Setup the Base and Limits in the Bridge
\ and scan the bus(es) beyond that Bridge
: pci-bridge-probe ( addr -- )
        dup pci-bridge-set-bases                        \ SetUp all Base Registers
        pci-bus-number 1+ TO pci-bus-number             \ increase number of busses found
        pci-device-vec-len 1+ TO pci-device-vec-len     \ increase the device-slot vector depth
        dup                                             \ stack config-addr for pci-bus!
        FF swap                                         \ Subordinate Bus Number ( for now to max to open all subbusses )
        pci-bus-number swap                             \ Secondary   Bus Number ( the new busnumber )
        dup pci-addr2bus swap                           \ Primary     Bus Number ( the current bus )
        pci-bus!                                        \ and set them into the bridge
        pci-enable                                      \ enable mem/IO transactions
        dup pci-bus-scnd@ func-pci-probe-bus            \ and probe the secondary bus
        dup pci-bus-number swap pci-bus-subo!           \ set SubOrdinate Bus Number to current number of busses
        pci-device-vec-len 1- TO pci-device-vec-len     \ decrease the device-slot vector depth
        dup pci-bridge-set-limits                       \ SetUp all Limit Registers
        drop                                            \ forget the config-addr
;

\ set up the pci-device
: pci-device-setup ( addr -- )
        drop                            \ since the config-addr is coded in my-space, drop it here
        s" pci-device.fs" included      \ and setup the device as node in the device tree
;

\ set up the pci bridge
: pci-bridge-setup ( addr -- )
        drop                            \ since the config-addr is coded in my-space, drop it here
        s" pci-bridge.fs" included      \ and setup the bridge as node in the device tree
;

\ add the new found device/bridge to the device tree and set it up
: pci-add-device ( addr -- )
        new-device                      \ create a new device-tree node
            dup set-space               \ set the config addr for this device tree entry
            dup pci-set-slot            \ set the slot bit
            dup pci-htype@              \ read HEADER-Type
            1 and IF                    \ IF BRIDGE
                    pci-bridge-setup    \ | set up the bridge
            ELSE                        \ ELSE
                    pci-device-setup    \ | set up the device
            THEN                        \ FI
        finish-device                   \ and close the device-tree node
;

\ check for multifunction and for each function
\ (dependig from header type) call device or bridge setup
: pci-setup-device ( addr -- )
        dup pci-htype@                      \ read HEADER-Type
        80 and IF 8 ELSE 1 THEN             \ check for multifunction
        0 DO                                \ LOOP over all possible functions (either 8 or only 1)
                dup
                i 8 lshift +                \ calc device-function-config-addr
                dup pci-vendor@             \ check if valid function
                FFFF = IF
                        drop                \ non-valid so forget the address
                ELSE
                    pci-device-number 1+    \ increase the number of devices
                    TO pci-device-number    \ and store it
                    pci-add-device          \ and add the device to the device tree and set it up
                THEN
        LOOP                                \ next function
        drop                                \ forget the device-addr
;

\ check if a device is plugged into this bus at this device number
: pci-probe-device ( busnr devicenr -- )
        pci-bus2addr                                    \ calc pci-address
        dup pci-vendor@                                 \ fetch Vendor-ID
        FFFF = IF                                       \ check if valid
                drop                                    \ if not forget it
        ELSE
                pci-setup-device                        \ if valid setup the device
        THEN
;

\ walk through all 32 possible pci devices on this bus and probe them
: pci-probe-bus ( busnr -- )
        0 TO pci-device-slots           \ reset slot array to unpoppulated
        20 0 DO
                dup
                i pci-probe-device
        LOOP
        drop
;

\ setup the function pointer used in pci-bridge-setup
' pci-probe-bus TO func-pci-probe-bus

\ ----------------------------------------------------------
\ ******************  System functions  ********************
\ ----------------------------------------------------------
\ Setup the whole system for pci devices
\ start with the bus-min and try all busses
\ until at least 1 device was found
\ ( needed for HostBridges that don't start with Bus 0 )
: pci-probe-all ( bus-max bus-min -- )                  \ Check all busses from bus-min up to bus-max if needed
        0 TO pci-device-vec-len                         \ reset the device-slot vector
        DO
                i TO pci-bus-number                     \ set current Busnumber
                0 TO pci-device-number                  \ reset Device Number
                pci-bus-number pci-probe-bus            \ and probe this bus
                pci-device-number 0 > IF LEAVE THEN     \ if we found a device we're done
        LOOP                                            \ else next bus
;

\ probe the hostbridge that is specified in my-puid
\ for the mmio mem and io addresses:
\ base is the least available address
\ max is the highest available address
: probe-pci-host-bridge ( bus-max bus-min mmio-max mmio-base mem-max mem-base io-max io-base my-puid -- )
        puid >r TO puid                                 \ save puid and set the new
        pci-next-io !                                   \ save the next io-base address
        pci-max-io !                                    \ save the max io-space address
        pci-next-mem !                                  \ save the next mem-base address
        pci-max-mem !                                   \ save the max mem-space address
        pci-next-mmio !                                 \ save the next mmio-base address
        pci-max-mmio !                                  \ save the max mmio-space address

        0d emit ."  Adapters on " puid 10 0.r cr        \ print the puid we're looking at
        ( bus-max bus-min ) pci-probe-all               \ and walk the bus
        pci-device-number 0= IF                         \ IF no devices found
                15 spaces                               \ | indent the output
                ." None" cr                             \ | tell the world our result
        THEN                                            \ FI
        r> TO  puid                                     \ restore puid
;

\ provide the device-alias definition words
#include <pci-aliases.fs>

\ provide all words for the interrupts settings
#include <pci-interrupts.fs>

\ provide all words for the pci capabilities init
#include <pci-capabilities.fs>

\ provide all words needed to generate the properties and/or assign BAR values
#include "pci-properties.fs"

