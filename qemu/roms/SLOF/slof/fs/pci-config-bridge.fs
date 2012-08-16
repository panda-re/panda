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

\ define the config reads
: config-b@  puid >r my-puid TO puid my-space + rtas-config-b@ r> TO puid ;
: config-w@  puid >r my-puid TO puid my-space + rtas-config-w@ r> TO puid ;
: config-l@  puid >r my-puid TO puid my-space + rtas-config-l@ r> TO puid ;

\ define the config writes
: config-b!  puid >r my-puid TO puid my-space + rtas-config-b! r> TO puid ;
: config-w!  puid >r my-puid TO puid my-space + rtas-config-w! r> TO puid ;
: config-l!  puid >r my-puid TO puid my-space + rtas-config-l! r> TO puid ;

\ for Debug purposes: dumps the whole config space
: config-dump puid >r my-puid TO puid my-space pci-dump r> TO puid ;

\ needed to find the right path in the device tree
: decode-unit ( addr len -- phys.lo ... phys.hi )
        2 hex-decode-unit       \ decode string
        B lshift swap           \ shift the devicenumber to the right spot
        8 lshift or             \ add the functionnumber
        my-bus 10 lshift or     \ add the busnumber
        0 0 rot                 \ make phys.lo = 0 = phys.mid
;

\ needed to have the right unit address in the device tree listing
\ phys.lo=phys.mid=0 , phys.hi=config-address
: encode-unit ( phys.lo ... phys.hi -- unit-str unit-len )
        nip nip                         \ forget the both zeros
        dup 8 rshift 7 and swap         \ calc Functionnumber
        B rshift 1F and                 \ calc Devicenumber
        over IF                         \ IF Function!=0
                2 hex-encode-unit       \ | create string with DevNum,FnNum
        ELSE                            \ ELSE
                nip 1 hex-encode-unit   \ | create string with only DevNum
        THEN                            \ FI
;

: map-in ( phys.lo ... phys.hi size -- virt )
   \ ." map-in called: " .s cr
   2drop drop
;

: map-out ( virt size -- )
   \ ." map-out called: " .s cr
   2drop 
;

: dma-alloc ( ... size -- virt )
   \ ." dma-alloc called: " .s cr
   alloc-mem
;

: dma-free ( virt size -- )
   \ ." dma-free called: " .s cr
   free-mem
;

: dma-map-in ( ... virt size cacheable? -- devaddr )
   \ ." dma-map-in called: " .s cr
   2drop
;

: dma-map-out ( virt devaddr size -- )
   \ ." dma-map-out called: " .s cr
   2drop drop
;

: dma-sync ( virt devaddr size -- )
   \ XXX should we add at least a memory barrier here?
   \ ." dma-sync called: " .s cr
   2drop drop
;

: open true ;
: close ;
