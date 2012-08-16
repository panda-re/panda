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

\ -----------------------------------------------------------
\ OF properties
\ -----------------------------------------------------------

s" scsi" device-name
s" block-type" device-type
1 encode-int s" #address-cells" property
0 encode-int s" #size-cells" property


: encode-unit   1 hex-encode-unit ;

: decode-unit   1 hex-decode-unit ;


\ -----------------------------------------------------------
\ Specific properties
\ -----------------------------------------------------------

1 chars alloc-mem VALUE ch-buffer
8 VALUE mps-dcp
0 VALUE port-number
0 VALUE my-usb-address


: control-std-get-maxlun
   ( MPS fun-addr dir data-buff data-len -- TRUE | FALSE )
   s" control-std-get-maxlun" $call-parent
;


: control-std-get-configuration-descriptor
   ( data-buffer data-len MPS funcAddr -- TRUE|FALSE )
   s" control-std-get-configuration-descriptor" $call-parent
;

: rw-endpoint
   ( pt ed-type toggle buffer length mps address -- toggle TRUE|toggle FALSE )
   s" rw-endpoint" $call-parent
;

: controlxfer ( dir addr dlen setup-packet MPS ep-fun -- TRUE|FALSE )
   s" controlxfer" $call-parent
;

: control-std-set-configuration
   ( configvalue FuncAddr -- TRUE|FALSE )
   s" control-std-set-configuration" $call-parent
;

\ This method is used for extracting the properties from it's parent and
\ storing these value to temporary variable so that they can used later.

: extract-properties ( -- )
   s" USB-ADDRESS" get-inherited-property ( prop-addr prop-len FALSE | TRUE )
   IF
      s" notpossible" usb-debug-print
   ELSE
      decode-int nip nip to my-usb-address
   THEN
   s" MPS-DCP" get-inherited-property  ( prop-addr prop-len FALSE | TRUE )
   IF
      s" MPS-DCP property not found.Assume 8 as MAX PACKET SIZE" usb-debug-print
      s" for the default control pipe"  usb-debug-print
      8 to mps-dcp
   ELSE
      s" MPS-DCP property found!!"  usb-debug-print
      decode-int nip nip to mps-dcp
   THEN
   s" reg" get-inherited-property   ( prop-addr prop-len FLASE | TRUE )
   IF
      s" notpossible" usb-debug-print
   ELSE
      decode-int nip nip to port-number
   THEN
;


\ This method is used for creating the child nodes for every Logical unit
\ available in the device, this method will call control-std-get-maxlun for
\ for finding the maximum Logical units supported by the device and along with
\ the creation of nodes this method encodes the properties of the node also.

: create-tree ( -- )
   mps-dcp my-usb-address 0 ch-buffer 1 ( MPS fun-addr dir data-buff data-len )
   control-std-get-maxlun     ( TRUE | FALSE )

   \ This method extracts the maximum number of Logical Units Supported by
   \ the Device . if no Logical Units are present then 0 will be taken as the
   \ max logical units. if the device doesn't support the GET-MAX-LUN command
   \ then the device may can be stalled as a temporary fix to come out from
   \ the stalling situations we can issue the control-std-set-configuration with
   \ appropriate arguments


   IF
      s" GET-MAX-LUN IS WORKING :" usb-debug-print
   ELSE
      s" ERROR in GET-MAX-LUN " usb-debug-print
   THEN
   ch-buffer c@ 1 +  0                              ( max-lun+1 0 )
   DO
      s" iManufacturer" get-inherited-property drop ( prop-addr prop-len TRUE )
      decode-int nip nip                  ( iManu )
      s" iProduct" get-inherited-property drop
      ( iManu prop-addr prop-len TRUE | FALSE )
      decode-int nip nip                  ( iManu iProd )
      s" iSerialNumber" get-inherited-property drop
      ( iManu iProd prop-addr prop-len TRUE | FALSE )
      decode-int nip nip                  ( iManu iProd iSerNum )
      s" MPS-BULKOUT" get-inherited-property drop
      ( iManu iProd iSerNum prop-len prop-addr TRUE | FALSE )
      decode-int nip nip                  ( iManu iProd iSerNum MPS-BULKOUT )
      s" BULK-OUT-EP-ADDR" get-inherited-property drop
      ( iManu iProd iSerNum MPS-BULKOUT prop-addr prop-len TRUE|FALSE )
      decode-int nip nip ( iManu iProd iSerNum MPS-BULKOUT BULK-OUT-EP-ADDR )
      s" MPS-BULKIN" get-inherited-property drop
      ( iManu iProd iSerNum MPS-BULKOUT BULK-OUT-EP-ADDR prop-addr prop-len
        TRUE | FALSE )
      decode-int nip nip
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN )
      s" BULK-IN-EP-ADDR" get-inherited-property drop
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN prop-addr
        prop-len TRUE | FALSE )
      decode-int nip nip
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN
        BULKIN-EP-ADDR )
      mps-dcp  port-number  my-usb-address I
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN
        BULKIN-EP-ADDR mps-dcp port-address my-usb-address lun-number )
      new-device

      \ creates new device child node, doesn't consume any argument from stack

      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN
      BULKIN-EP-ADDR mps-dcp port-address my-usb-address lun-number )

      set-space
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN
        BULKIN-EP-ADDR mps-dcp port-number my-usb-address )
      encode-int s" USB-ADDRESS" property
       ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN
         BULKIN-EP-ADDR mps-dcp port-number )
      encode-int s" reg" property
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN )
      ( BULKIN-EP-ADDR mps-dcp port-number )
      encode-int s" MPS-DCP" property
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN
        BULKIN-EP-ADDR )
      I encode-int s" LUN" property
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN
       BULKIN-EP-ADDR )
      encode-int s" BULK-IN-EP-ADDR" property
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR MPS-BULKIN )
      encode-int s" MPS-BULKIN" property
      ( iManu iProd iSernum MPS-BULKOUT BULK-OUT-EP-ADDR )
      encode-int s" BULK-OUT-EP-ADDR" property
      ( iManu iProd iSernum MPS-BULKOUT )
      encode-int s" MPS-BULKOUT" property ( iManu iProd iSerNum )
      encode-int s" iSerialNumber" property ( iManu iProd )
      encode-int s" iProduct" property  ( iManu )
      encode-int s" iManufacturer" property ( -- )
      s" usb-storage.fs" INCLUDED
      finish-device
   LOOP
;

extract-properties  \ Extract the properties from parent
create-tree       \ this method creates the node for every lun with properties
