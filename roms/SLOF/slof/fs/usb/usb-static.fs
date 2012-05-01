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

\ #include "scsi-support.fs"

\ Set usb-debug flag to TRUE for debugging output:
0 VALUE usb-debug-flag
false VALUE scan-time?

VARIABLE ihandle-bulk-tran
\ -scsi-supp-  VARIABLE ihandle-scsi-tran

\ uDOC (Micro-Disk-On-Chip) is a FLASH-device
\ normally connected to usb-port 5 on ELBA
\
0 VALUE uDOC-present       \ device present and working?

\ Print a debug message when usb-debug-flag is set
: usb-debug-print  ( str len -- )
   usb-debug-flag  IF type cr ELSE 2drop THEN
;

\ Print a debug message with corresponding value when usb-debug-flag is set
: usb-debug-print-val  ( str len val -- )
   usb-debug-flag  IF -ROT type . cr ELSE drop 2drop THEN
;

\ show proceeding propeller only during scan process.
\ As soon USB-keyboard can be used, this must be suppressed.
0 VALUE proceed-char
: show-proceed ( -- )
   scan-time?              \ are we on usb-scan ?
   IF
      proceed-char
      CASE
         0   OF 2d ENDOF   \ show '-'
         1   OF 5c ENDOF   \ show '\'
         2   OF 7c ENDOF   \ show '|'
         dup OF 2f ENDOF   \ show '/'
      ENDCASE
      emit 8 emit
      proceed-char 1 + 3 AND to proceed-char
   THEN
;

\ delay with proceeding signs
: wait-proceed ( nl -- )
   show-proceed
   BEGIN
      dup d# 100 >         ( nl true|false )
      WHILE
      100 - show-proceed
      100 ms               \ do it in steps of 100ms
   REPEAT
   ms                      \ rest delay
;

\ register device alias
: do-alias-setting ( num name-str name-len )
   rot $cathex strdup            \ create alias name
   get-node node>path            \ get path string
   set-alias                     \ and set the alias
;


0 VALUE ohci-alias-num

\ create a new ohci device alias for the current node:
: set-ohci-alias  ( -- )
   ohci-alias-num dup 1+ TO ohci-alias-num    ( num )
   s" ohci"
   do-alias-setting
;

0 VALUE cdrom-alias-num
0 VALUE disk-alias-num        \ shall start with: pci-disk-num
FALSE VALUE ext-disk-alias    \ first external disk: not yet assigned

\ create a new ohci device alias for the current node:
: set-drive-alias  ( --  )
   space 5b emit
   s" cdrom" drop                ( name-str )
   get-node node>name comp 0=    ( true|false )
   IF                            \ is this a cdrom ?
      cdrom-alias-num dup 1+ TO cdrom-alias-num    ( num )
      s" cdrom"                  \ yes, alias = cdrom
   ELSE
      s" sbc-dev" drop           \ is this a scsi-block-device?
      get-node node>name comp 0= ( true|false )
      IF
         disk-alias-num dup 1 + to disk-alias-num
         s" disk"                \ all block devices will be named "disk"

         \ this is a block-device.
         \ check if parent is 'usb' and not 'hub'
         \ if so this block-device is directly connected
         \ to root-hub and must be the uDOC-device in Elba
         s" usb" drop            \ parent = usb controller ? (not hub)
         get-node node>parent @ node>name
         comp 0=                 \ parent node starts with 'usb' ?
         IF                      ( true|false )
            1 s" hdd"            \ add extra alias hdd1 for IntFlash
            2dup type 2 pick .
            8 emit 2f emit
            do-alias-setting
            uDOC-present 1 and
            IF
               uDOC-present 2 or to uDOC-present \ present and ready
            THEN
         ELSE
            ext-disk-alias not   \ flag for first ext. disk already assigned
            IF
               TRUE to ext-disk-alias
               2 s" hdd"         \ add extra alias hdd2 for first USB disk
               2dup type 2 pick .
               8 emit 2f emit
               do-alias-setting
            THEN
         THEN
      ELSE
         0 s" ??? "              \ unknown device
      THEN
   THEN     ( num name-str name-len )
   2dup type 2 pick .
   8 emit 5d emit cr
   do-alias-setting
;

: usb-create-alias-name ( num -- str len )
    >r s" ohciX" 2dup + 1-           ( str len last-char-ptr  R: num )
    r> [char] 0 + swap c!            ( str len  R: )
;


\ *****************************************************
\ This is a final check to see, if a uDOC-device
\ is ready for booting
\ If physically present, but not working, an
\ Error-LED must be activated (on ELBA only!)
\ *****************************************************
\ uDOC is now replaced by ModFD (Modular-Flash-Drive)
\ due to right properties
\ 'sys-signal-modfd-fault' sends an IPMI-Message to
\ aMM for generating a log entry and to switch on
\ an error LED (call to libsystem->libipmi)
\ *****************************************************
\ although there are IPMI-warnings defined concerning
\ detected media errors, it doesn't make sense to send
\ a warning when booting from this device is impossible.
\ The decision was made to send an error call in this
\ case as well
\ *****************************************************
\ uDOC-present bits:
\ *****************************************************
\ D0: any device is connected on port 3 of root-hub
\ D1: device on port 3 is directly connected (no hub)
\ D2: warnings were received (scancodes)
\ D3: OverCurrentIndicator on USB-Port was set
\ D7: flag, set while ModFD is beeing processed

: uDOC-check   ( -- )
#ifdef ELBA
   uDOC-present 7 and               \ flags concerning ModFD device
   CASE
      0  OF                         \ not present not detected
         uDOC-present 8 and 0<>     \ not detected due to OverCurrent?
         IF
            0d emit ."   * OverCurrent on ModFD *" cr
            sys-signal-modfd-fault     ( -- )      \ send IPMI-call to BMC
         ELSE
            0d emit ."   ModFD not present" cr
         THEN
      ENDOF

      1  OF       \ present but not detected by USB
         0d emit ."   * ModFD not accessible *" cr
         sys-signal-modfd-fault     ( -- )      \ send IPMI-call to BMC
      ENDOF

      3  OF       \ present and detected
\        0d emit ."   ModFD OK" cr
      ENDOF

      7  OF       \ present and detected but with warnings
         0d emit ."   * ModFD Warnings *" cr
         sys-signal-modfd-fault     ( -- )      \ send IPMI-call to BMC
      ENDOF

      dup OF      \ we have a fault in our firmware !
         s"   *** ModFD detection error ***" usb-debug-print
      ENDOF
   ENDCASE
#endif
;

\ *****************************************************
\ check if actual processed device is ModFD and
\ then sets its warning bit
\ *****************************************************
: uDOC-failure?   ( -- )
   uDOC-present 80 and 0<>                \ is ModFD actual beeing processed?
   IF
      uDOC-present 04 or to uDOC-present  \ set Warning flag
   THEN
;

\ Scan all USB host controllers for attached devices:
: usb-scan
   \ Scan all OHCI chips:
   space ." Scan USB... " cr
   true to scan-time?            \ show proceeding signs
   0 to uDOC-present             \ mark as not present
   0 to disk-alias-num           \ start with disk0
   s" pci-disk-num" $find        \ previously detected disks ?
   IF
      execute to disk-alias-num  \ overwrite start number
   ELSE
      2drop
   THEN

   0 >r                             \ Counter for alias
   BEGIN
      r@ usb-create-alias-name
      find-alias ?dup               ( false | str len len  R: num )
   WHILE
      usb-debug-flag IF
         ." * Scanning hub " 2dup type ." ..." cr
      THEN
      open-dev ?dup IF              ( ihandle  R: num )
         dup to my-self
         dup ihandle>phandle dup set-node
          child ?dup IF
              delete-node s" Deleting node" usb-debug-print
          THEN
         >r s" enumerate" r@ $call-method   \ Scan host controller
         r> close-dev  0 set-node 0 to my-self
      THEN                          ( R: num )
      r> 1+ >r                      ( R: num+1 )
   REPEAT   r> drop
   0 TO ohci-alias-num
   0 TO cdrom-alias-num
   s" cdrom0" find-alias            ( false | dev-path len )
   dup IF
       s" cdrom" 2swap              ( alias-name len' dev-path len )
       set-alias                    ( -- )
       \ cdrom-alias-num 1 + TO cdrom-alias-num
   ELSE 
       drop                         ( -- )
   THEN
   uDOC-check  \ check if uDOC-device is present and working (ELBA only)
   false to scan-time?                 \ suppress proceeding signs
;

: usb-probe

  usb-scan

  cdrom-alias-num 0= IF
     ." Not found CDROM! " cr
  THEN
     ." CDROM found " cdrom-alias-num . cr 
;

 
: usb-dev-test ( -- TRUE )
   s" USB Device Test " usb-debug-print
   1 usb-create-alias-name
   find-alias ?dup IF
      ." * open " 2dup type . cr
   ELSE
      s" can't found alias " usb-debug-print
   THEN
   open-dev ?dup IF
      dup to my-self
      dup ihandle>phandle dup set-node
      s" bulk" $open-package ihandle-bulk-tran !
\      make-media-ready
      s" close all " usb-debug-print
      close-dev 0 set-node 0 to my-self

      ihandle-bulk-tran close-package
   ELSE
      s" can't open usb hub" usb-debug-print
   THEN

   TRUE
;

