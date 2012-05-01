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


00 value kbd-addr
to kbd-addr
8 alloc-mem to kbd-report
4 chars alloc-mem value kbd-data

: rw-endpoint
  s" rw-endpoint" $call-parent ;

: controlxfer
  s" controlxfer" $call-parent ;

: control-std-get-device-descriptor
  s" control-std-get-device-descriptor" $call-parent ;

: control-std-get-configuration-descriptor
  s" control-std-get-configuration-descriptor" $call-parent ;

: control-std-set-configuration
  s" control-std-set-configuration" $call-parent ;

: control-cls-set-protocol ( reportvalue FuncAddr -- TRUE|FALSE )
  to temp1
  to temp2
  210b000000000100 setup-packet ! 
  temp2 kbd-data l!-le
  1 kbd-data 1 setup-packet DEFAULT-CONTROL-MPS temp1 controlxfer  
;

: control-cls-set-idle ( reportvalue FuncAddr -- TRUE|FALSE )
  to temp1
  to temp2
  210a000000000000 setup-packet ! 
  temp2 kbd-data l!-le
  0 kbd-data 0 setup-packet DEFAULT-CONTROL-MPS temp1 controlxfer  
;

: control-std-get-report-descriptor ( data-buffer data-len MPS FuncAddr -- TRUE|FALSE )
  to temp1
  to temp2
  to temp3
  8106002200000000 setup-packet ! 
  temp3 setup-packet 6 + w!-le
  0 swap temp3 setup-packet temp2 temp1 controlxfer  
;

: kbd-init
    s" Starting to initialize keyboard" usb-debug-print
    s" MPS-INTIN" get-my-property
    if
	s" not possible" usb-debug-print
    else
	decode-int nip nip to mps-int-in
    then
    s" INT-IN-EP-ADDR" get-my-property
    if
	s" not possible" usb-debug-print
    else
	decode-int nip nip to int-in-ep
    then

  7f alloc-mem to cfg-buffer
  s" Allocated buffers!!" usb-debug-print

  cfg-buffer 12 8 kbd-addr                   \ get device descriptor
  control-std-get-device-descriptor
  drop
  \ s" dev_desc=" type cfg-buffer 12 dump cr

  cfg-buffer 9 8 kbd-addr                    \ get config descriptor  
  control-std-get-configuration-descriptor
  drop
  \ s" cfg_desc=" type cfg-buffer 9 dump cr

  cfg-buffer 5 + c@ kbd-addr                 \ set configuration  
  control-std-set-configuration
  drop
  s" KBDS: Set config returned" usb-debug-print 

  0 kbd-addr control-cls-set-idle drop       \ set idle  
  s" KBDS: Set idle returned" usb-debug-print

  cfg-buffer 40 8 kbd-addr                   \ get report descriptor
  control-std-get-report-descriptor
  drop
  \ s" report_desc=" type cfg-buffer 40 dump cr

  s" Finished initializing keyboard" usb-debug-print 
;

