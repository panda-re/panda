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

defer set-boot-device
defer add-boot-device

: qemu-read-bootlist ( -- )
   0 0 set-boot-device

   \ check nvram
   " boot-device" evaluate swap drop 0 <> IF EXIT THEN   

   \ check qemu boot list
   " qemu,boot-device" get-chosen not IF EXIT THEN
   
   0 ?DO
       dup i + c@ CASE
           0        OF ENDOF
           [char] a OF ENDOF
           [char] b OF ENDOF
           [char] c OF " disk"  add-boot-device ENDOF
           [char] d OF " cdrom" add-boot-device ENDOF
           [char] n OF " net"   add-boot-device ENDOF
       ENDCASE cr
   LOOP
   drop
;

' qemu-read-bootlist to read-bootlist
