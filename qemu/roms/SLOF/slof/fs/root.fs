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

\ this creates the root and common branches of the device tree

defer (client-exec)
defer client-exec

\ defined in slof/fs/client.fs
defer callback
defer continue-client

: set-chosen ( prop len name len -- )
  s" /chosen" find-node set-property ;

: get-chosen ( name len -- [ prop len ] success )
  s" /chosen" find-node get-property 0= ;

new-device
  s" /" device-name
  new-device
    s" chosen" device-name
    s" " encode-string s" bootargs" property
    s" " encode-string s" bootpath" property
  finish-device

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

finish-device
