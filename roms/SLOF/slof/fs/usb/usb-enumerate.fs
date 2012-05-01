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


\ create the device tree for hub

: (hub-create) ( -- )
   mps port-number new-device-address port-number 
   ( mps port-number usb-address port-number )
   new-device set-space                ( mps port-number usb-address )
   encode-int s" USB-ADDRESS" property ( mps port-number )
   s" Address Set"  usb-debug-print
   encode-int s" reg" property         ( mps )
   s" Port Number Set"   usb-debug-print 
   encode-int s" MPS-DCP" property
   s" MPS Set"   usb-debug-print
   s" usb-hub.fs" INCLUDED
   s" Driver Included"   usb-debug-print
   finish-device
;


\ encode properties for scsi or atapi device

: (atapi-scsi-property-set) ( -- )
   dd-buffer @ e + c@     ( Manuf )
   dd-buffer @ f + c@     ( Manuf Prod )
   dd-buffer @ 10 + c@    ( Manuf Prod Serial-Num )
   cd-buffer @ 16 + w@-le ( Manuf Prod Serial-Num ep-mps )
   cd-buffer @ 14 + c@    ( Manuf Prod Serial-Num ep-mps ep-addr )
   cd-buffer @ 1d + w@-le ( Manuf Prod Serial-Num ep-mps ep-addr ep-mps )
   cd-buffer @ 1b + c@    ( Manuf Prod Serial-Num ep-mps ep-addr ep-mps ep-addr )
   mps port-number new-device-address port-number
                        ( Manuf Prod Serial-Num ep-mps ep-addr ep-mps ep-addr 
                          mps port-num usb-addr port-num )
   new-device set-space
                        ( Manuf Prod Serial-Num ep-mps ep-addr ep-mps ep-addr
                           mps port-num usb-addr )
   encode-int s" USB-ADDRESS" property
                        ( Manuf Prod Serial-Num ep-mps ep-addr ep-mps ep-addr
                           mps port-num )
   encode-int s" reg" property
                        ( Manuf Prod Serial-Num ep-mps ep-addr ep-mps ep-addr 
                           mps )
   encode-int s" MPS-DCP" property
                        ( Manuf Prod Serial-Num ep-mps ep-addr ep-mps ep-addr )
   2 0  DO
      dup 80 and IF
         7f and encode-int
         s" BULK-IN-EP-ADDR" property
         encode-int s" MPS-BULKIN" property
      ELSE
         encode-int s" BULK-OUT-EP-ADDR" property
         encode-int s" MPS-BULKOUT" property
      THEN
   LOOP                                  ( Manuf Prod Serial-Num )
   encode-int s" iSerialNumber" property ( Manuf Prod )
   encode-int s" iProduct" property      ( Manuf )
   encode-int s" iManufacturer" property
;


\ To classify device as hub/atapi/scsi/HID device

: (device-classify) 
   ( -- Interface-protocol Interface-subclass Interface-class TRUE|FALSE )
   cd-buffer @ BULK-CONFIG-DESCRIPTOR-LEN erase
   cd-buffer @ BULK-CONFIG-DESCRIPTOR-LEN mps new-device-address 
                                  ( buffer descp-len mps usb-address )
   control-std-get-configuration-descriptor
   IF
      cd-buffer @ 1+ c@           ( Descriptor-type )
      2 =   IF
         cd-buffer @ 10 + c@      ( protocol )
         cd-buffer @ f + c@       ( protocol subclass )
         cd-buffer @ e + c@       ( protocol subclass class )
         TRUE
      ELSE
         s" Not a valid configuration descriptor!!" usb-debug-print
         FALSE
      THEN
   ELSE
      s" Unable to read configuration descriptor!!" usb-debug-print
      FALSE
   THEN
;


\ create device tree for Atapi SFF-8020 device

: (atapi-8020-create) ( -- )
   (atapi-scsi-property-set)
   s" usb-storage.fs" INCLUDED
   finish-device
;

\ create device tree for Atapi SFF-8070 device

: (atapi-8070-create) ( -- )
   (atapi-scsi-property-set)
   s" usb-storage.fs" INCLUDED
   \ s" storage" device-name
   finish-device
;


\ create device tree for SCSI device

: (scsi-create) ( -- )
   s" SCSI-CREATE " usb-debug-print

\ ***********************************************************************
\ a problem was encountered on Media-Tray (REV-0):
\ The CDROM is connected to USB via an ATA/USB-Bridge (U38: CYPRESS CY7C68300)
\ The C-Revision of this chip has an malfunction which results in a
\ hanging IORD Signal at the ATA-Interface and so prevents from reading.
\ The B-Revision doesn't have this problem (populated on Media-Tray REV-5)
\ Two additional Mass-Storage-Resets are necessary to reset the ATA-Interface.
\ (see CYPRESS Application Notes to CY7C68300)
\ (see USB-Spec: 'Bulk-Only-Transport')
\ ***********************************************************************
\ a mounted ISO image (via USB) doesn't accept this bulk-reset-command!
\ ***********************************************************************

   dd-buffer @ 8 + w@-le 4b4 =         \ VendorID = CYPRESS ?
   IF
      dd-buffer @ a + w@-le 6830 =     \ Device = CY7C68300 ?
      IF
       \ here a Cypress ATA/USB Bridge is detected
       d# 20 ms
       mps new-device-address 0 0 0   ( MPS fun-addr dir data-buff data-len )
       control-bulk-reset             ( TRUE|FALSE )
       d# 100 ms
       mps new-device-address 0 0 0   ( TRUE|FALSE MPS fun-addr dir data-buff data-len )
       control-bulk-reset             ( TRUE|FALSE TRUE|FALSE )
       and invert
       IF
          ."   ** BULK-RESET failed **" cr
       THEN
       d# 20 ms
      THEN
   THEN

   0 ch-buffer !                 \ preset a clean response
   mps new-device-address 0 ch-buffer 1 control-std-get-maxlun ( TRUE|FALSE )
   IF
\      s" GET-MAX-LUN IS WORKING :" usb-debug-print
\      ch-buffer  5 dump cr      \ dump the responsed message
   ELSE
      s" ERROR in GET-MAX-LUN " usb-debug-print
      0 ch-buffer !              \ clear invalid numbers
      cd-buffer @ 5 + c@ to temp1
      temp1 new-device-address control-std-set-configuration drop
   THEN
   \ FIXME: an IBM external HDD reported a number of 127 LUNs which could
   \        not be set up. We need to understand how to set up the device
   \        to report the correct number of LUNs.
   \        The USB Massbulk Standard 1.0 defines a maximum of 15 mult. LUNs.
   \ Workaround: Devices that might report a higher number are treated
   \             as having exactly one LUN. Without this workaround the
   \             USB scan hangs during the setup of non-available LUNs.
   \
   \ Concerns: "FUJITSU MHV2040AT" (VendorID: 0x984 / DeviceID: 0x70)
   \
   \ MR: This Device reports an invalid MaxLUN number within the first
   \ three seconds after power-on or USB-Reset. The following loop repeats
   \ the MaxLUN request up to 8 times until a valid ( <15 ) value is responded.
   \ This can last up to four seconds as there is a delay of 500ms in every loop

   0                       ( counter )
   begin
      dup 8 <              ( counter flag )           \ max 8 * 500 ms
      ch-buffer c@ f >     ( counter flag flag )      \ is MuxLUN above limit ?
      AND                  ( counter flag )
      while
         d# 500 ms                     \ this device is not yet ready
         0 ch-buffer !                 \ preset a clean response
         mps new-device-address 0 ch-buffer 1 control-std-get-maxlun ( TRUE|FALSE )
         not
         IF
            s"  ** ERROR in GET-MAX-LUN ** " usb-debug-print
            drop 10                    \ replace counter to force loop end
         THEN
         1+                ( counter+1 )
      repeat
   drop

   \ here is still the workaround to handle invalid MaxLUNs as '0'
   \
   ch-buffer c@ dup 0= swap f > or IF   
      s" + LUN: " ch-buffer c@  usb-debug-print-val
      (atapi-scsi-property-set)
      s" usb-storage.fs" INCLUDED
      finish-device

   ELSE
      s" - LUN: " ch-buffer c@ usb-debug-print-val
      (atapi-scsi-property-set)
      s" usb-storage-wrapper.fs" INCLUDED
      finish-device

   THEN
;


\ Classify USB storage device by sub-class code

: (classify-storage)  ( interface-protocol interface-subclass -- )
   s" USB: Mass Storage Device Found!" usb-debug-print
   swap 50 <> IF
      s" USB storage: Protocol is not 50." usb-debug-print
      drop EXIT
   THEN
   ( interface-subclass )
   CASE
      02 OF  (atapi-8020-create) s" ATAPI Interface " usb-debug-print ENDOF
      05 OF  (atapi-8070-create) s" ATAPI Interface " usb-debug-print ENDOF
      06 OF  (scsi-create) s" SCSI Interface " usb-debug-print ENDOF
      dup OF  s" USB storage: Unsupported sub-class code." usb-debug-print ENDOF
   ENDCASE
;


\ create keyboard device tree

: (keyboard-create) ( -- )
   cd-buffer @ 1f + c@                 ( ep-mps )
   cd-buffer @ 1d + c@                 ( ep-mps ep-addr )  
   mps port-number new-device-address port-number
                                        ( ep-mps ep-addr mps port-num usb-addr port-num )
   new-device set-space                 ( ep-mps ep-addr mps port-num usb-addr )
   encode-int s" USB-ADDRESS" property  ( ep-mps ep-addr mps port-num )
   encode-int s" reg" property          ( ep-mps ep-addr mps )
   encode-int s" MPS-DCP" property      ( ep-mps ep-addr )
   7f and encode-int s" INT-IN-EP-ADDR" property
   encode-int s" MPS-INTIN" property
   new-device-address   \ device-speed
   s" usb-keyboard.fs" INCLUDED
   finish-device
;

: (mouse-create) ( -- )
   mps port-number new-device-address port-number
                                        ( mps port-num usb-addr port-num )
   new-device set-space                 ( mps port-num usb-addr )
   encode-int s" USB-ADDRESS" property  ( mps port-num )
   encode-int s" reg" property          ( mps )
   encode-int s" MPS-DCP" property
   s" usb-mouse.fs" INCLUDED
   finish-device
;


\ Classify by interface class code

: (classify-by-interface) ( -- )
   (device-classify)  IF
      ( Interface-protocol Interface-subclass Interface-class )
      CASE
         08 OF
            ( Interface-protocol Interface-subclass )
            (classify-storage)
         ENDOF
         03 OF
	         ( Interface-protocol Interface-subclass )
	         s" USB: HID Found!" usb-debug-print
	         01 =
            IF
		         case
		            01 of
			            s" USB keyboard!" usb-debug-print
			            (keyboard-create)
		            endof
		            02 of
		     	         s" USB mouse!" usb-debug-print
		     	         (mouse-create)
		            endof
		            dup of
			            s" USB: unsupported HID!" usb-debug-print
		            endof
		         endcase
	         ELSE
		         s" USB: unsupported HID!" usb-debug-print
	         THEN
	      ENDOF
         dup OF
            ( Interface-protocol Interface-subclass )
            s" USB: unsupported interface type." usb-debug-print
            2drop
         ENDOF
      ENDCASE
   THEN
;


\ create usb device tree depending upon classification of the device
\ after encoding apt properties

: create-usb-device-tree ( -- )
   dd-buffer @ DEVICE-DESCRIPTOR-DEVCLASS-OFFSET + c@    ( Device-class )
   CASE
      HUB-DEVICE-CLASS OF s" USB: HUB found"   usb-debug-print
         (hub-create)
      ENDOF
      NO-CLASS  OF
         \ In this case, the INTERFACE descriptor
         \ tells you whats what -- Refer USB spec.
         (classify-by-interface)
      ENDOF
      DUP OF
         s" USB: Unknown device found." usb-debug-print
      ENDOF
   ENDCASE
   uDOC-present 0f and to uDOC-present \ remove uDOC processing flag
;
