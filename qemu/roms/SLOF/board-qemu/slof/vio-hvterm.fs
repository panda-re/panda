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

: open true ;
: close ;

: write ( adr len -- actual )  tuck type ;

: read  ( adr len -- actual )
   0= IF drop 0 EXIT THEN
   hvterm-key? 0= IF 0 swap c! -2 EXIT THEN
   hvterm-key swap c! 1
;

: setup-alias
    " hvterm" find-alias 0= IF
        " hvterm" get-node node>path set-alias
    ELSE THEN 
;

setup-alias
