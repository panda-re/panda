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


\ ---------------------------------------------------------------------------
\ Parent methods
\ ---------------------------------------------------------------------------

: rw-endpoint
   ( pt ed-type toggle buffer length mps addres -- toggle TRUE | toggle FALSE )
   s" rw-endpoint" $call-parent
   ( toggle TRUE | toggle FALSE )
;

: controlxfer ( dir addr dlen setup-packet MPS ep-fun --- TRUE|FALSE )
   s" controlxfer" $call-parent
   ( TRUE | FALSE )
;

: control-std-get-configuration-descriptor
   ( data-buffer data-len MPS FuncAddr -- TRUE | FALSE )
   s" control-std-get-configuration-descriptor" $call-parent
   ( TRUE | FALSE )
;

: control-std-set-configuration ( configvalue FuncAddr -- TRUE | FALSE )
   s" control-std-set-configuration" $call-parent   ( TRUE | FALSE )
;

: bulk-reset-recovery-procedure ( bulk-out-endp bulk-in-endp usb-addr -- )
  s" bulk-reset-recovery-procedure" $call-parent
;


\ ---------------------------------------------------------------------------
\ Bulk support package methods
\ ---------------------------------------------------------------------------

: build-cbw ( address tag transfer-len direction lun command-len -- )
   s" build-cbw" ihandle-bulk @ $call-method
;

: analyze-csw ( address -- residue tag TRUE | reason FALSE )
   s" analyze-csw" ihandle-bulk @ $call-method
   ( residue tag TRUE | reason FALSE )
;


\ =======================================================
\ NATIVE METHODS USED EITHER AT PROBE TIME OR TIME
\ WHEN INSTANCE IS CREATED
\ =======================================================


\ --------------------------------------------------------
\ COLON DEFINITION: the method is a probe-time method
\ used to:
\ 1. decode the properties and store in variables
\ 2. allocat buffers required for the device and
\ 3. set the right configuration after extracting the
\ configuration descriptor
\ --------------------------------------------------------

: device-init ( -- )
   s" Starting to initialize usb-storage device" usb-debug-print
   s" USB-ADDRESS" get-my-property         ( TRUE | propaddr proplen FALSE )
   IF
      s" not possible" usb-debug-print
   ELSE
      decode-int nip nip to my-usb-address
   THEN
   s" MPS-BULKOUT" get-my-property         ( TRUE | propaddr proplen FALSE )
   IF
      s" not possible"   usb-debug-print
   ELSE
      decode-int nip nip to mps-bulk-out
   THEN
   s" MPS-BULKIN" get-my-property          ( TRUE | propaddr proplen FALSE )
   IF
      s" not possible" usb-debug-print
   ELSE
      decode-int nip nip to mps-bulk-in
   THEN
   s" BULK-IN-EP-ADDR" get-my-property     ( TRUE | propaddr proplen FALSE )
   IF
      s" not possible" usb-debug-print
   ELSE
      decode-int nip nip to bulk-in-ep
   THEN
   s" BULK-OUT-EP-ADDR" get-my-property    ( TRUE | propaddr proplen FALSE )
   IF
      s" not possible"  usb-debug-print
   ELSE
      decode-int nip nip to bulk-out-ep
   THEN
   s" MPS-DCP" get-my-property             ( TRUE | propaddr proplen FALSE )
   IF
      s" Not possible" usb-debug-print
   ELSE
      decode-int nip nip to mps-dcp
   THEN
   s" LUN" get-my-property                 ( TRUE | propaddr proplen FALSE )
   IF
      s" NOT Possible to extract LUN" usb-debug-print
   ELSE
      decode-int nip nip to lun
   THEN
   s" Extracted properties inherited from parent."  usb-debug-print

   \ PENDING:
   \ Do some return value check here...

   40 alloc-mem to command-buffer
   80 alloc-mem to response-buffer
   10 alloc-mem to csw-buffer
   8 alloc-mem to cfg-buffer
   s" Allocated buffers." usb-debug-print
   cfg-buffer 8 mps-dcp my-usb-address      ( buffer len mps fun-addr )
   control-std-get-configuration-descriptor ( TRUE | FALSE )
   drop
   s" Configuration descriptor extracted." usb-debug-print
   cfg-buffer 5 + c@ my-usb-address         ( configvalue fun-addr )
   control-std-set-configuration            ( TRUE | FALSE )
   s" usb-storage: Set config returned: " rot usb-debug-print-val
;


\ ----------------------------------------------------
\ Internal methods
\ ----------------------------------------------------


: (open-package)  ( ihandle-var name-str name-len -- )
   find-package IF                 ( ihandle-var phandle )
      0 0 rot open-package         ( ihandle-var ihandle )
      swap !
   ELSE
      s" Support package not found"  usb-debug-print
   THEN
;

: (close-package)  ( ihandle-var -- )
   dup @ close-package
   0 swap !
;

