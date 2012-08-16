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

\ KVM/qemu RTAS

\ rtas control block

4d0 cp

STRUCT
    /l field rtas>token
    /l field rtas>nargs
    /l field rtas>nret
    /l field rtas>args0
    /l field rtas>args1
    /l field rtas>args2
    /l field rtas>args3
    /l field rtas>args4
    /l field rtas>args5
    /l field rtas>args6
    /l field rtas>args7
    /l C * field rtas>args
    /l field rtas>bla
CONSTANT /rtas-control-block

CREATE rtas-cb /rtas-control-block allot
rtas-cb /rtas-control-block erase

0 VALUE rtas-base
0 VALUE rtas-size
0 VALUE rtas-entry
0 VALUE rtas-node

\ Locate qemu RTAS, remove the linux,... properties we really don't
\ want them to stick around

4d1 cp

: find-qemu-rtas ( -- )
    " /rtas" find-device get-node to rtas-node

    " linux,rtas-base" rtas-node get-package-property IF
         device-end EXIT THEN
    drop l@ to rtas-base
    " linux,rtas-base" delete-property

    " rtas-size" rtas-node get-package-property IF
         device-end EXIT THEN
    drop l@ to rtas-size

    " linux,rtas-entry" rtas-node get-package-property IF
        rtas-base to rtas-entry
    ELSE
        drop l@ to rtas-entry
        " linux,rtas-entry" delete-property
    THEN

    \ ." RTAS found, base=" rtas-base . ."  size=" rtas-size . cr

    device-end
;
find-qemu-rtas

4d2 cp

: enter-rtas ( -- )
    rtas-cb rtas-base 0 rtas-entry call-c drop
;

: rtas-get-token ( str len -- token | 0 )
    rtas-node get-package-property IF 0 ELSE drop l@ THEN
;

: rtas-start-cpu  ( pid loc r3 -- status )
   " start-cpu" rtas-get-token rtas-cb rtas>token l!
   3  rtas-cb rtas>nargs l!
   1  rtas-cb rtas>nret l!
   rtas-cb rtas>args2 l!
   rtas-cb rtas>args1 l!
   rtas-cb rtas>args0 l!
   0 rtas-cb rtas>args3 l!
   enter-rtas
   rtas-cb rtas>args3 l@
;

: rtas-set-tce-bypass ( unit enable -- )
    " ibm,set-tce-bypass" rtas-get-token rtas-cb rtas>token l!
    2 rtas-cb rtas>nargs l!
    0 rtas-cb rtas>nret l!
    rtas-cb rtas>args1 l!
    rtas-cb rtas>args0 l!
    enter-rtas
;

: rtas-quiesce ( -- )
    " quiesce" rtas-get-token rtas-cb rtas>token l!
    0 rtas-cb rtas>nargs l!
    0 rtas-cb rtas>nret l!
    enter-rtas
;

: of-start-cpu rtas-start-cpu ;

\ Methods of the rtas node proper
rtas-node set-node

: open true ;
: close ;

: instantiate-rtas ( adr -- entry )
    dup rtas-base swap rtas-size move
    rtas-entry rtas-base - +
;

device-end

4d8 cp
