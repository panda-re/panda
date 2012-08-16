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


\ ----------------------------------------------------------------------------
\ On detection of a hub after reading the device descriptor this package has to
\ be called so that the hub enumeration is done to idenitify the down stream 
\ device  
\ --------------------------------------------------------------------------
\ OF properties
\ --------------------------------------------------------------------------


s" hub" device-name
s" usb" device-type
1 encode-int s" #address-cells" property
0 encode-int s" #size-cells" property

\ converts physical address to text unit string 


: encode-unit ( port-addr -- unit-str unit-len )  1 hex-encode-unit ;


\ Converts text unit string to phyical address 


: decode-unit ( addr len -- port-addr ) 1 hex-decode-unit ;

0 VALUE new-device-address
0 VALUE port-number
0 VALUE MPS-DCP
0 VALUE mps
0 VALUE my-usb-address

00 value device-speed


\ Get parameters passed from the parent.

: mps-property-set ( -- )
   s"  HUB Compiling mps-property-set " usb-debug-print
   s" USB-ADDRESS" get-my-property ( TRUE | prop-addr prop-len FALSE )
   IF
      s" notpossible" usb-debug-print
   ELSE
      decode-int nip nip to my-usb-address
   THEN  
   s" MPS-DCP" get-my-property ( TRUE | prop-addr prop-len FALSE )
   IF 
      s" MPS-DCP property not found Assuming 8 as MAX PACKET SIZE" ( str len )  
      usb-debug-print
      s" for the default control pipe"  usb-debug-print
      8 to MPS-DCP
   ELSE
      s" MPS-DCP property found!!" usb-debug-print ( prop-addr prop-len FALSE )
      decode-int nip nip to MPS-DCP
   THEN
;


\ --------------------------------------------------------------------------
\ Constant declarations
\ --------------------------------------------------------------------------


2303080000000000 CONSTANT hppwr-set
2301080000000000 CONSTANT hppwr-clear
2303040000000000 CONSTANT hprst-set
A300000000000400 CONSTANT hpsta-get
2303010000000000 CONSTANT hpena-set
A006002900000000 CONSTANT hubds-get
8  CONSTANT DEFAULT-CONTROL-MPS
12 CONSTANT DEVICE-DESCRIPTOR-LEN
9  CONSTANT CONFIG-DESCRIPTOR-LEN
20 CONSTANT BULK-CONFIG-DESCRIPTOR-LEN


\ TODO:
\ CONFIG-DESCRIPTOR-LEN should be only 9. The interface
\ and endpoint descriptors returned along with config
\ descriptor are variable and 0x19 is a very wrong VALUE
\ to specify for this #define.


1 CONSTANT DEVICE-DESCRIPTOR-TYPE
1 CONSTANT DEVICE-DESCRIPTOR-TYPE-OFFSET
4 CONSTANT DEVICE-DESCRIPTOR-DEVCLASS-OFFSET
7 CONSTANT DEVICE-DESCRIPTOR-MPS-OFFSET
9 CONSTANT HUB-DEVICE-CLASS
0 CONSTANT NO-CLASS


\ --------------------------------------------------------------------------
\ Temporary Variable declarations
\ --------------------------------------------------------------------------

00 VALUE temp1
00 VALUE temp2
00 VALUE temp3
00 VALUE po2pg            \ Power On to Power Good


\ --------------------------------------------------------------------------
\ Buffer allocations
\ --------------------------------------------------------------------------


VARIABLE setup-packet     \ 8 bytes for setup packet
VARIABLE ch-buffer        \ 1 byte character buffer

INSTANCE VARIABLE dd-buffer
INSTANCE VARIABLE cd-buffer

\ TODO:
\ Should arrive a proper value for the size of the "cd-buffer"

8 chars alloc-mem VALUE status-buffer
9 chars alloc-mem VALUE hd-buffer


: (allocate-mem)  ( -- )
   DEVICE-DESCRIPTOR-LEN chars alloc-mem dd-buffer !
   BULK-CONFIG-DESCRIPTOR-LEN chars alloc-mem cd-buffer !
;


: (de-allocate-mem)  ( -- )
   dd-buffer @ ?dup IF
      DEVICE-DESCRIPTOR-LEN free-mem
      0 dd-buffer !
   THEN
   cd-buffer @ ?dup IF
      BULK-CONFIG-DESCRIPTOR-LEN free-mem
      0 cd-buffer !
   THEN
;


\ standard open firmware methods 

: open ( -- TRUE )
   (allocate-mem)
   TRUE
;

: close ( -- )
   (de-allocate-mem)
;


\ --------------------------------------------------------------------------
\ Parent's method
\ --------------------------------------------------------------------------


: controlxfer ( dir addr dlen setup-packet MPS ep-fun -- TRUE|FALSE )
   s" controlxfer" $call-parent 
;

: control-std-set-address ( speedbit -- usb-address TRUE|FALSE )
   s" control-std-set-address" $call-parent 
; 

: control-std-get-device-descriptor 
   ( data-buffer data-len MPS funcAddr -- TRUE|FALSE )
   s" control-std-get-device-descriptor" $call-parent 
;

: control-std-get-configuration-descriptor 
   ( data-buffer data-len MPS funcAddr -- TRUE|FALSE )
   s" control-std-get-configuration-descriptor" $call-parent 
;

: control-std-get-maxlun
   ( MPS fun-addr dir data-buff data-len -- TRUE|FALSE )
   s" control-std-get-maxlun" $call-parent 
;

: control-std-set-configuration 
   ( configvalue FuncAddr -- TRUE|FALSE )
   s" control-std-set-configuration" $call-parent 
;

: control-std-get-string-descriptor
   ( StringIndex data-buffer data-len MPS FuncAddr -- TRUE|FALSE )
   s" control-std-get-string-descriptor" $call-parent 
;

: rw-endpoint 
   ( pt ed-type toggle buffer length mps address -- toggle TRUE|toggle FALSE )
   s" rw-endpoint" $call-parent 
;

: debug-td ( -- )
   s" debug-td" $call-parent
;

\ *** NEW ****
: control-bulk-reset ( MPS fun-addr dir data-buff data-len -- TRUE | FALSE )
   s" control-bulk-reset" $call-parent
;


\ --------------------------------------------------------------------------
\ HUB specific methods
\ --------------------------------------------------------------------------
\ To bring on the power on a valid port of a hub with a valid USB address
\ --------------------------------------------------------------------------


: control-hub-port-power-set  ( port# -- TRUE|FALSE )
   hppwr-set setup-packet !	( port#)
   setup-packet 4 + c!
   0 0 0 setup-packet MPS-DCP my-usb-address controlxfer ( TRUE | FALSE )
;


\ --------------------------------------------------------------------------
\ To put power off on ports where device detection or enumeration has failed
\ --------------------------------------------------------------------------


: control-hub-port-power-clear ( port#-- TRUE|FALSE )
   hppwr-clear setup-packet !	( port#)
   setup-packet 4 + c!
   0 0 0 setup-packet MPS-DCP my-usb-address controlxfer ( TRUE|FALSE )
;


\ -------------------------------------------------------------------------
\ To reset a valid port of a hub with a valid USB 
\ address
\ --------------------------------------------------------------------------


: control-hub-port-reset-set ( port# -- TRUE|FALSE )
   hprst-set setup-packet !	( port# )
   setup-packet 4 + c!
   0 0 0 setup-packet MPS-DCP my-usb-address controlxfer ( TRUE|FALSE )
;


\ -------------------------------------------------------------------------
\ To enable a particular valid port of a hub with a valid USB address
\ -------------------------------------------------------------------------


: control-hub-port-enable ( port# -- TRUE|FALSE )
   hpena-set setup-packet !	( port# )
   setup-packet 4 +  c!
   0 0 0 setup-packet MPS-DCP my-usb-address controlxfer ( TRUE|FALSE )
;


\ -------------------------------------------------------------------------
\ To get the status of a valid port of a hub with 
\ a valid USB address
\ -------------------------------------------------------------------------


: control-hub-port-status-get ( buffer port# -- TRUE|FALSE )
   hpsta-get setup-packet !	( buffer port# )
   setup-packet 4 + c!		( buffer )
   0 swap 4 setup-packet MPS-DCP my-usb-address controlxfer ( TRUE|FALSE )
;


\ --------------------------------------------------------------------------
\ To get the hub descriptor to understand how many ports are vailable and the 
\ specs of those ports
\ ---------------------------------------------------------------------------


: control-get-hub-descriptor ( buffer buffer-length -- TRUE|FALSE )
   hubds-get setup-packet ! 
   dup setup-packet 6 + w!-le ( buffer buffer-length )
   0 -rot setup-packet MPS-DCP my-usb-address controlxfer ( TRUE|FALSE )
;


s" usb-enumerate.fs" INCLUDED


: hub-configure-port ( port# -- )

\ this port has been powered on
\ send reset to enable port and
\ start device detection by hub
\ some devices require a long timeout here (10s)

   \ Step 1: check if reset state ended

   BEGIN				( port# )
      status-buffer 4 erase             ( port# )
      status-buffer over control-hub-port-status-get drop ( port# ) 
      status-buffer w@-le 102 and 0= 	( port# TRUE|FALSE )
   WHILE				( port# )
   REPEAT			( port# )
   po2pg 3 * ms    \ wait for bPwrOn2PwrGood*3 ms
   
   \ STEP 2: Reset the port.
   \         (this also enables the port)
   dup control-hub-port-reset-set drop	( port# )
   BEGIN				( port# )
      status-buffer 4 erase             ( port# )
      status-buffer over control-hub-port-status-get drop ( port# ) 
      status-buffer w@-le 10 and 	( port# TRUE|FALSE )
   WHILE				( port# )
   REPEAT				( port# )

   \ STEP 3: Check if a device is connected to the port.

   status-buffer 4 erase                ( port# )
   status-buffer over control-hub-port-status-get drop ( port# ) 
   status-buffer w@-le    103 and    103 <> 	       ( port# TRUE|FALSE )
   s" Port status bits: " status-buffer w@-le usb-debug-print-val
   IF					( port# ) 
      drop			
      s" Connect status: No device connected "  usb-debug-print
      EXIT 
   THEN 


   \ STEP 4: Assign an address to this device.

   status-buffer w@-le 200 and 4 lshift \ get speed bit
   dup to device-speed                  \ store speed bit
                                ( port# speedbit )
   control-std-set-address	( port# usb-addr TRUE|FALSE )
   50 ms			( port# usb-addr TRUE|FALSE )
   debug-td			( port# usb-addr TRUE|FALSE )
   IF 				( port# usb-addr )
      device-speed or           ( port# usb-addr+speedbit )
      to new-device-address     ( port# )
      to port-number
      dd-buffer @ DEVICE-DESCRIPTOR-LEN erase
      dd-buffer @ DEFAULT-CONTROL-MPS DEFAULT-CONTROL-MPS new-device-address
      ( buffer mps mps usb-addr ) 
      control-std-get-device-descriptor     ( TRUE|FALSE )
      IF
         dd-buffer @ DEVICE-DESCRIPTOR-TYPE-OFFSET + c@ ( descriptor-type )
         DEVICE-DESCRIPTOR-TYPE <>          ( TRUE|FALSE )
         IF 
            s" HUB: ERROR!! Invalid Device Descriptor for the new device"
            usb-debug-print
         ELSE
            dd-buffer @ DEVICE-DESCRIPTOR-MPS-OFFSET + c@ to mps

            \ Re-read the device descriptor again with the known MPS.

            dd-buffer @ DEVICE-DESCRIPTOR-LEN erase
            dd-buffer @ DEVICE-DESCRIPTOR-LEN mps new-device-address
            ( buffer descp-len mps usb-addr )
            \ s" DEVICE DESCRIPTOR: " usb-debug-print
            control-std-get-device-descriptor invert
            IF
               s" ** reading dev-descriptor failed ** " usb-debug-print
            THEN
            create-usb-device-tree
         THEN
      ELSE
         s" ERROR!! Failed to get device descriptor" usb-debug-print 
      THEN
   ELSE						    ( port# )
      s" USB Set Adddress failed!!" usb-debug-print ( port# )
      s" Clearing Port Power..."  usb-debug-print   ( port# )
      control-hub-port-power-clear		    ( TRUE|FALSE )
      IF 
         s" Port power down " usb-debug-print
      ELSE
         s" Unable to clear port power!!!" usb-debug-print
      THEN
   THEN
;


\ ---------------------------------------------------------------------------
\ To enumerate all the valid ports of hub
\ TODO:
\ 1. Remove hardcoded constants.
\ 2. Remove Endian Dependencies.
\ 3. Return values of controlxfer should be checked. 
\ ---------------------------------------------------------------------------

: hub-enumerate ( -- )
   cd-buffer @ CONFIG-DESCRIPTOR-LEN erase

   \ Get HUB configuration and SET the configuration
   \ note: remove hard-coded constants.

   cd-buffer @ CONFIG-DESCRIPTOR-LEN MPS-DCP my-usb-address 
   ( buffer descp-len mps usb-address )
   control-std-get-configuration-descriptor drop 
   cd-buffer @ 1+ c@ 2 <>  IF
      s" Unable to read configuration descriptor" usb-debug-print
      EXIT 
   THEN 
   cd-buffer @ 4 + c@ 1 <> IF
      s" Not a valid HUB config descriptor" usb-debug-print 
      EXIT 
   THEN 

   \ TODO: Do further checkings on the returned Configuration descriptor
   \ before proceeding to accept it.

   cd-buffer @ 5 + c@ to temp1 \ Store the configuration in temp1
   temp1 my-usb-address control-std-set-configuration drop
   my-usb-address to temp1
   hd-buffer 9 erase
   hd-buffer 9 control-get-hub-descriptor drop

   \ PENDING: 1. Check Return value.
   \          2. HUB descriptor size is variable. Currently we r hardcoding
   \             a value of 9.

   hd-buffer 2 + c@ to temp2     \ number of downstream ports

   s" HUB: Found " usb-debug-print
   s" number of downstream hub ports! : " temp2 usb-debug-print-val
   hd-buffer 5 + c@ to po2pg     \ get bPwrOn2PwrGood

   \ power on all present hub ports
   \ to allow slow devices to set up

   temp2 1+ 1 DO
      i control-hub-port-power-set drop
      d# 20 ms
   LOOP

   d# 200 ms      \ some devices need a long time (10s)

   \ now start detection and configuration for these ports
   
   temp2 1+ 1 DO
       s" hub-configure-port: " i usb-debug-print-val
       i hub-configure-port
   LOOP
; 


\ --------------------------------------------------------------------------  
\ To initialize hub
\ --------------------------------------------------------------------------

(allocate-mem)
mps-property-set
hub-enumerate
(de-allocate-mem)

