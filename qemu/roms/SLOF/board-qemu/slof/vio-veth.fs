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

." Populating " pwd cr

" network" device-type

INSTANCE VARIABLE obp-tftp-package
: open  ( -- okay? )
   my-unit 1 rtas-set-tce-bypass
   my-args s" obp-tftp" $open-package obp-tftp-package ! true
;

: close  ( -- )
   s" close" obp-tftp-package @ $call-method
   my-unit 0 rtas-set-tce-bypass
;

: load  ( addr -- len )
    s" load" obp-tftp-package @ $call-method 
;

: ping  ( -- )
    s" ping" obp-tftp-package @ $call-method
;

: setup-alias
    " net" find-alias 0= IF
        " net" get-node node>path set-alias
    ELSE THEN 
;
setup-alias
