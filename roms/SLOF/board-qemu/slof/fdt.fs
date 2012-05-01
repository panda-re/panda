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

0 VALUE fdt-debug

\ Bail out if no fdt
fdt-start 0 = IF -1 throw THEN

struct
  4 field >fdth_magic
  4 field >fdth_tsize
  4 field >fdth_struct_off
  4 field >fdth_string_off
  4 field >fdth_rsvmap_off
  4 field >fdth_version
  4 field >fdth_compat_vers
  4 field >fdth_boot_cpu
  4 field >fdth_string_size
  4 field >fdth_struct_size
drop

h# d00dfeed constant OF_DT_HEADER
h#        1 constant OF_DT_BEGIN_NODE
h#        2 constant OF_DT_END_NODE
h#        3 constant OF_DT_PROP
h#        4 constant OF_DT_NOP
h#        9 constant OF_DT_END

\ Create some variables early
fdt-start
dup dup >fdth_struct_off l@ + value fdt-struct
dup dup >fdth_string_off l@ + value fdt-strings
drop

\ Dump fdt header for all to see and check FDT validity
: fdt-check-header ( -- )
    fdt-start dup 0 = IF
        ." No flat device tree !" cr drop -1 throw EXIT THEN
    hex
    fdt-debug IF
        ." Flat device tree header at 0x" dup . s" :" type cr
        ."  magic            : 0x" dup >fdth_magic l@ . cr
        ."  total size       : 0x" dup >fdth_tsize l@ . cr
        ."  offset to struct : 0x" dup >fdth_struct_off l@ . cr
        ."  offset to strings: 0x" dup >fdth_string_off l@ . cr
        ."  offset to rsvmap : 0x" dup >fdth_rsvmap_off l@ . cr
        ."  version          : " dup >fdth_version l@ decimal . hex cr
        ."  last compat vers : " dup >fdth_compat_vers l@ decimal . hex cr
        dup >fdth_version l@ 2 >= IF
            ."  boot CPU         : 0x" dup >fdth_boot_cpu l@ . cr
        THEN
        dup >fdth_version l@ 3 >= IF
            ."  strings size     : 0x" dup >fdth_string_size l@ . cr
        THEN
        dup >fdth_version l@ 17 >= IF
            ."  struct size      : 0x" dup >fdth_struct_size l@ . cr
        THEN
    THEN
    dup >fdth_magic l@ OF_DT_HEADER <> IF
        ." Flat device tree has incorrect magic value !" cr
	drop -1 throw EXIT
    THEN
    dup >fdth_version l@ 10 < IF
        ." Flat device tree has usupported version !" cr
	drop -1 throw EXIT
    THEN

    drop
;
fdt-check-header

\ Fetch next tag, skip nops and increment address
: fdt-next-tag ( addr -- nextaddr tag )
  0	       	      	 	( dummy tag on stack for loop )
  BEGIN
    drop			( drop previous tag )
    dup l@			( read new tag )
    swap 4 + swap		( increment addr )
  dup OF_DT_NOP <> UNTIL 	( loop until not nop )
;

\ Parse unit name and advance addr
: fdt-fetch-unit ( addr -- addr $name )
  dup from-cstring	       \  get string size
  2dup + 1 + 3 + fffffffc and -rot
;

\ Lookup a string by index
: fdt-fetch-string ( index -- $string)  
  fdt-strings + dup from-cstring
;

: fdt-create-dec  s" decode-unit" $CREATE , DOES> @ hex-decode-unit ;
: fdt-create-enc  s" encode-unit" $CREATE , DOES> @ hex-encode-unit ;

\ Method to unflatten a node
: fdt-unflatten-node ( start -- end )
  \ this can and will recurse
  recursive

  \ Get & check first tag of node ( addr -- addr)
  fdt-next-tag dup OF_DT_BEGIN_NODE <> IF
    s" Weird tag 0x" type . " at start of node" type cr
    -1 throw
  THEN drop

  new-device

  \ Parse name, split unit address
  fdt-fetch-unit
  dup 0 = IF drop drop " /" THEN
  40 left-parse-string
  \ Set name
  device-name

  \ Set unit address
  dup IF
     " #address-cells" get-parent get-package-property IF
        2drop
     ELSE
        decode-int nip nip
	hex-decode-unit
	set-unit
     THEN
  ELSE 2drop THEN

  \ Iterate sub tags
  BEGIN
    fdt-next-tag dup OF_DT_END_NODE <>
  WHILE
    dup OF_DT_PROP = IF
      \ Found property
      drop dup			( drop tag, dup addr     : a1 a1 )
      dup l@ dup rot 4 +	( fetch size, stack is   : a1 s s a2)
      dup l@ swap 4 +		( fetch nameid, stack is : a1 s s i a3 )
      rot                       ( we now have: a1 s i a3 s )
      encode-bytes rot		( a1 s pa ps i)
      fdt-fetch-string		( a1 s pa ps $pn )
      property
      + 8 + 3 + fffffffc and
    ELSE dup OF_DT_BEGIN_NODE = IF
      drop			( drop tag )
      4 -
      fdt-unflatten-node
    ELSE
      drop -1 throw
    THEN THEN
  REPEAT drop \ drop tag

  \ Create encode/decode unit
  " #address-cells" get-node get-package-property IF ELSE
    decode-int dup fdt-create-dec fdt-create-enc 2drop
  THEN

  finish-device  
;

\ Start unflattening
: fdt-unflatten-tree
    fdt-debug IF
        ." Unflattening device tree..." cr THEN
    fdt-struct fdt-unflatten-node drop
    fdt-debug IF
        ." Done !" cr THEN
;
fdt-unflatten-tree

\ Find memory size
: fdt-parse-memory
    " /memory" find-device
    " reg" get-node get-package-property IF throw -1 THEN

    \ XXX FIXME Assume one entry only in "reg" property for now
    decode-phys 2drop decode-phys
    my-#address-cells 1 > IF 20 << or THEN
    
    fdt-debug IF
        dup ." Memory size: " . cr
    THEN
    \ claim.fs already released the memory between 0 and MIN-RAM-SIZE,
    \ so we've got only to release the remaining memory now:
    MIN-RAM-SIZE swap MIN-RAM-SIZE - release
    2drop device-end
;
fdt-parse-memory


\ Claim fdt memory and reserve map
: fdt-claim-reserve
    fdt-start
    dup dup >fdth_tsize l@ 0 claim drop
    dup >fdth_rsvmap_off l@ +
    BEGIN
        dup dup x@ swap 8 + x@
	dup 0 <>
    WHILE
	fdt-debug IF
	    2dup swap ." Reserve map entry: " . ." : " . cr
	THEN
	0 claim drop
	10 +
    REPEAT drop drop drop
;
fdt-claim-reserve 

\ Remaining bits from root.fs

defer (client-exec)
defer client-exec

\ defined in slof/fs/client.fs
defer callback
defer continue-client

: set-chosen ( prop len name len -- )
  s" /chosen" find-node set-property ;

: get-chosen ( name len -- [ prop len ] success )
  s" /chosen" find-node get-property 0= ;

" /" find-device

new-device
  s" aliases" device-name
finish-device

new-device
  s" options" device-name
finish-device

new-device
  s" openprom" device-name
  s" BootROM" device-type
finish-device

new-device 
#include <packages.fs>
finish-device

: open true ;
: close ;

device-end

