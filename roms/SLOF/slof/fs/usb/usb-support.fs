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

0 value NEXT-TD

0 VALUE num-tds
0 VALUE td-retire-count
0 VALUE saved-tail
0 VALUE poll-timer
VARIABLE controlxfer-cmd

\  Allocate an ED and populate it

: (ed-prepare) ( dir addr dlen setup-packet MPS ep-fun --
                 FALSE | dir addr dlen ed-ptr setup-ptr )
   allocate-ed dup 0=  IF ( dir addr dlen setup-packet MPS ep-fun ed-ptr )
      drop 3drop 2drop FALSE EXIT  ( FALSE )
   THEN
   TO temp1               ( dir addr dlen setup-packet MPS ep-fun )
   temp1 zero-out-an-ed-except-link ( dir addr dlen setup-packet MPS ep-fun )
   temp1 ed>eattr l@-le or temp1 ed>eattr l!-le ( dir addr dlen setup-ptr MPS )
   dup TO temp2 10 lshift temp1 ed>eattr l@-le or temp1 ed>eattr l!-le
                          ( dir addr dlen setup-packet-address )
   temp1 swap TRUE            ( dir addr dlen ed-ptr setup-ptr TRUE )
;


\ Allocate TD list


: (td-prepare) ( dir addr dlen ed-ptr setup-ptr --
                 dir FALSE | dir addr dlen ed-ptr setup-ptr td-head td-tail )
   2 pick         ( dir addr dlen ed-ptr setup-ptr dlen )
   temp2          ( dir addr dlen ed-ptr setup-ptr dlen MPS )
   /mod           ( dir addr dlen ed-ptr setup-ptr rem quo )
   swap 0<>   IF  ( dir addr dlen ed-ptr setup-ptr quo )
      1+
   THEN
   2+
   dup TO num-tds                ( dir addr dlen ed-ptr setup-ptr quo+2 )
   allocate-td-list dup 0=  IF   ( dir addr dlen ed-ptr setup-ptr quo+2 )
      2drop                      ( dir addr dlen ed-ptr setup-ptr )
      drop                       ( dir addr dlen ed-ptr )
      free-ed                    ( dir addr dlen )
      2drop                      ( dir )
      FALSE                      ( dir FALSE )
      EXIT
   THEN TRUE
;


\ Fill in the ED structure completely.


: (td-ready)  ( dir addr dlen ed-ptr setup-ptr td-head td-tail -- )
              ( dir addr dlen ed-ptr setup-ptr )
   3 pick     ( dir addr dlen ed-ptr setup-ptr td-head td-tail ed-ptr )
   tuck       ( dir addr dlen ed-ptr setup-ptr td-head ed-ptr td-tail ed-ptr )
   ed>tdqtp l!-le            ( dir addr dlen ed-ptr setup-ptr td-head ed-ptr )
   ed>tdqhp l!-le            ( dir addr dlen ed-ptr setup-ptr )
   over ed>ned 0 swap l!-le  ( dir addr dlen ed-ptr setup-ptr )
;


\ Initialize the HEAD and TAIL TDs for SETUP and
\ STATUS phase respectively.


: (td-setup-status) ( dir addr dlen ed-ptr setup-ptr -- dir addr dlen ed-ptr )
   over ed>tdqhp l@-le             ( dir addr dlen ed-ptr setup-ptr td-head )
   dup zero-out-a-td-except-link   ( dir addr dlen ed-ptr setup-ptr td-head )
   dup td>tattr DATA0-TOGGLE CC-FRESH-TD or swap l!-le
                                   ( dir addr dlen ed-ptr setup-ptr td-head )
   2dup td>cbptr l!-le             ( dir addr dlen ed-ptr setup-ptr td-head )
   2dup td>bfrend swap STD-REQUEST-SETUP-SIZE 1- + swap l!-le
                                   ( dir addr dlen ed-ptr setup-ptr td-head )
   2drop                           ( dir addr dlen ed-ptr )
;

\ Initialize the TD TAIL pointer.


: (td-tailpointer) ( dir addr dlen ed-ptr -- dir addr dlen ed-ptr )
   dup ed>tdqtp l@-le              ( dir addr dlen ed-ptr td-tail )
   dup zero-out-a-td-except-link   ( dir addr dlen ed-ptr td-tail )
   dup td>tattr dup l@-le DATA1-TOGGLE CC-FRESH-TD or or swap l!-le
                                   ( dir addr dlen ed-ptr td-tail )
   4 pick 0=                       ( dir addr dlen ed-ptr td-tail flag )
   3 pick 0<>                      ( dir addr dlen ed-ptr td-tail flag flag )
   and   IF                        ( dir addr dlen ed-ptr td-tail )
      dup td>tattr dup l@-le TD-DP-OUT or swap l!-le
                                   ( dir addr dlen ed-ptr td-tail )
   ELSE
      dup td>tattr dup l@-le TD-DP-IN or swap l!-le
                                  ( dir addr dlen ed-ptr td-tail )
   THEN
   drop                           ( dir addr dlen ed-ptr )
;

\  Initialize the Data TDs.


: (td-data) ( dir addr dlen ed-ptr --  ed-ptr )
   -rot             ( dir ed-ptr addr dlen )
   dup 0<>  IF      ( dir ed-ptr addr dlen )
      >r >r >r TO temp1 r> r> r> temp1 ( ed-ptr addr dlen dir )
      3 pick 		            ( ed-ptr addr dlen dir ed-ptr )
      ed>tdqhp l@-le td>ntd l@-le   ( ed-ptr addr dlen dir td-datahead )
      4 pick 		           ( ed-ptr addr dlen dir td-datahead ed-ptr )
      td>tattr l@-le 10 rshift ( ed-ptr addr dlen dir td-head-data MPS )
      swap 			    ( ed-ptr addr dlen dir MPS td-head-data )
      >r >r >r >r >r 1 r> r> r> r> r>
                                   ( ed-ptr 1 addr dlen dir MPS td-head-data )
      >r >r 0=  IF                 ( ed-ptr 1 addr dlen dir )
         OHCI-DP-IN                ( ed-ptr 1 addr dlen dir  OHCI-DP-IN )
      ELSE
         OHCI-DP-OUT               ( ed-ptr 1 addr dlen dir  OHCI-DP-OUT )
      THEN
      r> r>               ( ed-ptr 1 addr dlen dir  OHCI-DP- MPS td-head-data )
      fill-TD-list
   ELSE
      2drop nip           ( ed-ptr )
   THEN
;


\ Program the HC with the ed-ptr value and wait for status to
\ from the HC.
\ Free the ED and TDs associated with it.
\ PENDING: Above said.

10 CONSTANT max-retire-td

: (transfer-wait-for-doneq)  ( ed-ptr -- TRUE | FALSE )
   dup                               ( ed-ptr ed-ptr )
   hcctrhead rl!-le                  ( ed-ptr )
   HC-enable-control-list-processing ( ed-ptr )
   0 TO td-retire-count              ( ed-ptr )
   0 TO poll-timer                   ( ed-ptr )
   BEGIN
      td-retire-count num-tds <>     ( ed-ptr TRUE | FALSE )
      poll-timer max-retire-td < and       ( ed-ptr TRUE | FALSE )
      WHILE
      (HC-CHECK-WDH)                                      ( ed-ptr )
      IF
         hchccadneq l@-le find-td-list-tail-and-size nip ( ed-ptr n )
         td-retire-count + TO td-retire-count             ( ed-ptr )
         hchccadneq l@-le dup              ( ed-ptr done-td done-td )
         (td-list-status)                  ( ed-ptr done-td failed-td CCcode )
         IF
            \ keep condition code of TD on return stack
            dup >r
            s" (transfer-wait-for-doneq: USB device communication error."
            usb-debug-print                 ( ed-ptr done-td failed-td CCcode R: CCcode )
            dup 4 = swap dup 5 = rot or     ( ed-ptr done-td failed-td CCcode R: CCcode )
            IF
                max-retire-td TO poll-timer ( ed-ptr done-td failed-td CCcode R: CCcode )
            THEN
            ( ed-ptr done-td failed-td CCcode R: CCcode )
            usb-debug-flag
            IF
               s" CC code ->" type . cr
               s" Failing TD contents:" type cr display-td
            ELSE
               2drop
            THEN                           ( ed-ptr done-td R: CCcode )
            controlxfer-cmd @ GET-MAX-LUN = r> 4 = and
            IF
               s" (transfer-wait-for-doneq): GET-MAX-LUN ControlXfer STALLed"
               usb-debug-print
               \ Condition Code = 4 means that the device does not support multiple LUNS
               \ see USB Massbulk 1.0 Standard
            ELSE
               drop
               5030 error" (USB) Device communication error."
               ABORT
               \ FIXME: ABORTing here might leave the HC in an unusable state.
               \        We should maybe rather ABORT at the end of this Forth
               \        word, when clean-up has been done (or not ABORT at all)
            THEN
         THEN                              ( ed-ptr done-td )
         (free-td-list)                    ( ed-ptr )
         0 hchccadneq l!-le                ( ed-ptr )
         (HC-ACK-WDH) \ TDs were written to DOne queue. ACK the HC.
      THEN
      poll-timer 1+ TO poll-timer
      4 ms              \ longer  1 ms
   REPEAT                                  ( ed-ptr )
   disable-control-list-processing         ( ed-ptr )
   td-retire-count num-tds <>              ( ed-ptr )
   IF
      dup display-descriptors              ( ed-ptr )
      s" maximum of retire " usb-debug-print						     
   THEN
   free-ed
   td-retire-count num-tds <>
   IF
      FALSE                                ( FALSE )
   ELSE
      TRUE                                 ( TRUE )
   THEN
;


\ COLON DEFINITION: controlxfer
\                     INTERFACE FUNCTION

\ ARGUMENTS:
\ (from the bottom OF stack)
\ 1. dir -- This is the direction OF data transfer associated with
\           the DATA STAGE OF the control xfer.
\           If there is no data transfer (argument dlen is zero)
\           THEN this argument DOes not matter, nonethless it has
\           to be passed.
\           A "0" represents an IN and "1" represents an "OUT".
\ 2. addr -- If therez a data stage associated with the transfer,
\            THEN, this argument holds the address OF the data buffer
\ 3. dlen -- This arg holds the length OF the data buffer discussed
\            in previous step (addr)
\ 4. setup-packet -- This holds the pointer to the setup packet that
\                    will be transmitted during the SETUP stage OF
\                    the control xfer. The function assumes the length
\                    OF the status packet to be 8 bytes.
\ 5. MPS -- This is the MAX PACKET SIZE OF the endpoint.
\ 6. ep-fun -- This is the 11-bit value that holds the Endpoint and
\              the function address. bit 7 to bit 10 holds the Endpoint
\              address. Bits 0 to Bit 6 holds the Function Address.
\              The BIT numbering followed : The left most bit is referred
\              as bit 0. (not the one followed by PPC)
\              Bit 13 must be set for low-speed devices.

\ RETURN VALUE:
\ Returns TRUE | FALSE depending on the success OF the transaction.

\ ASSUMPTIONS:
\ 1. Function assumes that the setup packet is 8-bytes in length.
\    If in future, IF we need to add a new argument, we need to change
\    the function in lot OF places.

\ RISKS:
\ 1. If for some reason, the USB controller DOes not retire all the TDs
\    THEN, the status checking part OF this "word" can spin forever.


: controlxfer ( dir addr dlen setup-packet MPS ep-fun -- TRUE | FALSE )
   2 pick @ controlxfer-cmd !
   (ed-prepare)       ( FALSE | dir addr dlen ed-ptr setup-ptr  )
   invert IF FALSE EXIT THEN
   (td-prepare)       ( pt ed-type toggle buffer length mps head )
   invert IF FALSE EXIT THEN
   (td-ready)         ( dir addr dlen ed-ptr setup-ptr )
   (td-setup-status)  ( dir addr dlen ed-ptr )
   (td-tailpointer)   ( dir addr dlen ed-ptr )
   (td-data)          ( ed-ptr )


   \ FIXME:
   \ Clear the TAIL pointer in ED. This has got sthg to DO with how
   \ the HC finds an EMPTY queue condition. Refer spec.


   dup ed>tdqtp l@-le TO saved-tail    ( ed-ptr )
   dup ed>tdqtp 0 swap l!-le           ( ed-ptr )
   (transfer-wait-for-doneq)           ( TRUE | FALSE )
;

0201000000000000 CONSTANT CLEARHALTFEATURE
0 VALUE endpt-num
0 VALUE usb-addr-contr-req
: control-std-clear-feature ( endpoint-nr usb-addr -- TRUE|FALSE )
   TO usb-addr-contr-req                        \ usb address
   TO endpt-num                                 \ endpoint number
   CLEARHALTFEATURE setup-packet !
   endpt-num setup-packet 4 + c!                \ endpoint number
   0 0 0 setup-packet DEFAULT-CONTROL-MPS usb-addr-contr-req controlxfer
   ( TRUE|FALSE )
;  

\ It resets the usb bulk-device
21FF000000000000 CONSTANT BULK-RESET
: control-std-bulk-reset ( usb-addr -- TRUE|FALSE )
  TO usb-addr-contr-req
  BULK-RESET setup-packet !
  0 0 0 setup-packet DEFAULT-CONTROL-MPS usb-addr-contr-req controlxfer
  ( TRUE|FALSE )
;

: bulk-reset-recovery-procedure ( bulk-out-endp bulk-in-endp usb-addr -- )
    >r                                          ( bulk-out-endp bulk-in-endp R: usb-addr )
    \ perform a bulk reset
    r@ control-std-bulk-reset
    IF s" bulk reset OK" 
    ELSE s" bulk reset failed" 
    THEN usb-debug-print
    
    \ clear bulk-in endpoint                    ( bulk-out-endp bulk-in-endp R: usb-addr )
    80 or r@ control-std-clear-feature
    IF s" control-std-clear IN endpoint OK" 
    ELSE s" control-std-clear-IN endpoint failed" 
    THEN usb-debug-print

    \ clear bulk-out endpoint                   ( bulk-out-endp R: usb-addr )
    r@ control-std-clear-feature
    IF s" control-std-clear OUT endpoint OK" 
    ELSE s" control-std-clear-OUT endpoint failed" 
    THEN usb-debug-print
    r> drop
;

0 VALUE saved-rw-ed
0 VALUE num-rw-tds
0 VALUE num-rw-retired-tds
0 VALUE saved-rw-start-toggle
0 VALUE saved-list-type

\ Allocate an ED and populate what you can.


: (ed-prepare-rw)
   ( pt ed-type toggle buffer length mps address ed-ptr --
      FALSE | pt ed-type toggle buffer length mps )
   allocate-ed dup 0=  IF
   ( pt ed-type toggle buffer length mps address ed-ptr )
      drop 2drop 2drop 2drop drop
      saved-rw-start-toggle FALSE EXIT  ( toggle FALSE )
   THEN
   TO saved-rw-ed             ( pt ed-type toggle buffer length mps address )
   saved-rw-ed zero-out-an-ed-except-link
                              ( pt ed-type toggle buffer length mps address )
   saved-rw-ed ed>eattr l!-le   ( pt ed-type toggle buffer length mps )
   dup 10 lshift saved-rw-ed ed>eattr l@-le or
                              ( pt ed-type toggle buffer length mps mps~ )
   saved-rw-ed ed>eattr l!-le TRUE  ( pt ed-type toggle buffer length mps TRUE )
;


\  Allocate TD List


: (td-prepare-rw)
   ( pt ed-type toggle buffer length mps --
     FALSE | pt ed-type toggle buffer length mps head )
   2dup              ( pt ed-type toggle buffer length mps  length mps )
   /mod              ( pt ed-type toggle buffer length mps num-tds rem )
   swap 0<> IF       ( pt ed-type toggle buffer length mps num-tds )
      1+             ( pt ed-type toggle buffer length mps num-tds+1 )
   THEN
   dup TO num-rw-tds ( pt ed-type toggle buffer length mps num-tds )
   allocate-td-list  ( pt ed-type toggle buffer length mps head tail )
   dup 0=  IF
      2drop 2drop 2drop 2drop
      saved-rw-ed free-ed
      ." rw-endpoint: TD list allocation failed" cr
      saved-rw-start-toggle FALSE   ( FALSE )
      EXIT
   THEN
   drop  TRUE         ( pt ed-type toggle buffer length mps head TRUE )
;


\ Populate TD list with data buffers and toggle info.


: (td-data-rw)
   ( pt ed-type toggle buffer length mps head -- FALSE | pt et head )
   6 pick                    ( pt ed-type toggle buffer length mps head  pt )
   FALSE TO case-failed  CASE
      0   OF OHCI-DP-IN    ENDOF
      1   OF OHCI-DP-OUT   ENDOF
      2   OF OHCI-DP-SETUP ENDOF
      dup OF TRUE TO case-failed
      ." rw-endpoint: Invalid Packet Type!" cr
      ENDOF
   ENDCASE                   ( pt ed-type toggle buffer length mps head dp )
   case-failed  IF
      saved-rw-ed free-ed    ( pt ed-type toggle buffer length mps head dp )
      drop (free-td-list)         ( pt ed-type toggle buffer length mps head )
      2drop 2drop 2drop
      saved-rw-start-toggle FALSE ( FALSE )
      EXIT                        ( FALSE )
   THEN
   -rot                      ( pt ed-type toggle buffer length dp mps head )
   dup >r                      ( pt ed-type toggle buffer length dp mps head )
   fill-TD-list r>  TRUE      ( pt et head TRUE )
;


\ Enqueue the ED with the appropriate list


: (ed-ready-rw)  ( pt et  -- - | toggle FALSE )
   nip           ( et )
   FALSE TO case-failed  CASE
      0   OF \ Control List. Queue the ED to control list
      0 TO saved-list-type
      saved-rw-ed hcctrhead rl!-le
      HC-enable-control-list-processing
      ENDOF
      1   OF \ Bulk List. Queue the ED to bulk list
      1 TO saved-list-type
      saved-rw-ed hcbulkhead rl!-le
      HC-enable-bulk-list-processing
      ENDOF
      2   OF \ Interrupt List.
      2 TO saved-list-type
      saved-rw-ed hchccareg rl@-le rl!-le
      HC-enable-interrupt-list-processing
      ENDOF
      dup OF
      saved-rw-ed ed>tdqhp l@-le (free-td-list)
      saved-rw-ed free-ed
      TRUE TO case-failed
      ENDOF
   ENDCASE
   case-failed  IF
      saved-rw-start-toggle FALSE ( toggle FALSE )
      EXIT
   THEN
   TRUE                           ( TRUE )
;

\  Wait for TDs to return to the Done Q.

: (wait-td-retire) ( -- )
   0 TO num-rw-retired-tds
   FALSE TO while-failed
   BEGIN
      num-rw-retired-tds num-rw-tds <           ( TRUE | FALSE )
      while-failed FALSE =  and                 ( TRUE | FALSE )
      WHILE
      d# 5000 (wait-for-done-q)                  ( TD-list TRUE|FALSE )
      IF
         dup find-td-list-tail-and-size nip         ( td-list size )
         num-rw-retired-tds + TO num-rw-retired-tds ( td-list )
         dup (td-list-status)                   ( td-list failed-TD CC )
         IF
            dup 4 =
            IF
               saved-list-type
               CASE
                  0 OF
		               0 0 control-std-clear-feature
		               s" clear feature " usb-debug-print
                  ENDOF
                  1 OF                             \ clean bulk stalled
                     s" clear bulk when stalled " usb-debug-print
		               disable-bulk-list-processing   \ disable procesing
                     saved-rw-ed ed>eattr l@-le dup \ extract
                     780 and 7 rshift 80 or         \ endpoint and
                     swap 7f and                    \ usb addr
                     control-std-clear-feature
		            ENDOF
                  2 OF
		               0 saved-rw-ed ed>eattr l@-le
                     control-std-clear-feature
		            ENDOF
		            dup OF
		               s" unknown status " usb-debug-print
		            ENDOF
               ENDCASE
            ELSE                             ( td-list failed-TD CC )
               ."  TD failed  " 5b emit .s 5d emit cr
               5040 error" (USB) device transaction error (wait-td-retire)."
               ABORT
            THEN
            2drop drop
            TRUE TO while-failed                \ transaction failed
            NEXT-TD 0<>                         \ clean the TD if we
            IF
               NEXT-TD (free-td-list)           \ had a stalled
   	      THEN
         THEN
         (free-td-list)
      ELSE
         drop                                   \ drop td-list pointer
         scan-time? IF 2e emit THEN             \ show proceeding dots
         TRUE TO while-failed
	      s" time out wait for done" usb-debug-print
	      20 ms     \ wait for bad device
      THEN
   REPEAT
;


\ Process retired TDs


: (process-retired-td)   ( -- TRUE | FALSE )
   saved-list-type  CASE
      0 OF disable-control-list-processing ENDOF
      1 OF disable-bulk-list-processing ENDOF
      2 OF disable-interrupt-list-processing ENDOF
   ENDCASE
   saved-rw-ed ed>tdqhp l@-le 2 and 0<> IF 
      1 
      s" retired 1" usb-debug-print
   ELSE
      0 
      s" retired 0" usb-debug-print
   THEN
   \ s" retired " usb-debug-print-val
   WHILE-failed   IF
      FALSE           ( FALSE )
   ELSE
      TRUE            ( TRUE )
   THEN
   saved-rw-ed free-ed
;


\ (DO-rw-endpoint): T1 12 80 0 0chis method is an privately visible function
\ 		    to be used by the "rw-endpoint" the required
\ 		    number OF times based on the actual length
\ 		    to be transferred

\ Arguments:
\ pt: Packet type
\     0 -> IN
\     1 -> OUT
\     2 -> SETUP
\ et: Endpoint type
\     0 -> Control
\     1 -> Bulk
\ toggle: Starting toggle for this transfer
\ buffer length: Data buffer associated with the transfer limited
\     accordingly by the "rw-endpoint" method to the
\     value OF max packet size
\ mps: Max Packet Size.
\ address: Address OF endpoint. 11-bit address. The lower 7-bits represent
\          the USB addres and the upper 4-bits represent the Endpoint
\          number.



: (do-rw-endpoint)
   ( pt ed-type toggle buffer length mps address -- toggle TRUE|toggle FALSE )
   4 pick              ( pt ed-type toggle buffer length mps address toggle )
   TO saved-rw-start-toggle ( pt ed-type toggle buffer length mps address )
   (ed-prepare-rw)     ( FALSE | pt ed-type toggle buffer length mps )
    invert IF FALSE EXIT THEN
   (td-prepare-rw)     ( FALSE | pt ed-type toggle buffer length mps head )
   invert IF FALSE EXIT THEN
   (td-data-rw)        ( FALSE | pt et head )
   invert IF FALSE EXIT THEN
   saved-rw-ed ed>tdqhp l!-le ( pt et )
   saved-rw-ed ed>tdqhp l@-le td>ntd l@-le TO NEXT-TD \ save for a stalled
   (ed-ready-rw)
   invert IF FALSE EXIT THEN
   (wait-td-retire)
   (process-retired-td)         ( TRUE | FALSE )
;


\ rw-endpoint: The method is an externally visible method to be exported
\	       to the child nodes. It uses the internal method
\	       "(DO-rw-endpoint)", the required number OF times based on the
\	       actual length OF transfer, so that the limitataion OF MAX-TDS
\	       DO not hinder the transfer.

\ Arguments:
\ pt: Packet type
\     0 -> IN
\     1 -> OUT
\     2 -> SETUP
\ et: Endpoint type
\     0 -> Control
\     1 -> Bulk
\ toggle: Starting toggle for this transfer
\ buffer length: Data buffer associated with the transfer
\ mps: Max Packet Size.
\ address: Address OF endpoint. 11-bit address. The lower 7-bits represent
\          the USB addres and the upper 4-bits represent the Endpoint
\          number.


0 VALUE transfer-len
0 VALUE mps-current
0 VALUE addr-current
0 VALUE usb-addr
0 VALUE toggle-current
0 VALUE type-current
0 VALUE pt-current
0 VALUE read-status
0 VALUE counter
0 VALUE residue


: rw-endpoint
   ( pt ed-type toggle buffer length mps address -- )
   ( toggle TRUE |toggle FALSE )

   \ a single transfer descriptor can point to a buffer OF
   \ 8192 bytes a block on the CDROM has 2048 bytes
   \ but a single transfer is constrained by the MPS

   2 pick TO transfer-len  ( pt ed-type toggle buffer length mps address )
   1 pick TO mps-current   ( pt ed-type toggle buffer length mps address )
   TRUE TO read-status     ( pt ed-type toggle buffer length mps address )
   transfer-len mps-current num-free-tds * <=  IF
      (do-rw-endpoint)     ( toggle TRUE | toggle FALSE )
      TO read-status       ( toggle )
      TO toggle-current
   ELSE
      TO usb-addr          ( pt ed-type toggle buffer length mps )
      2drop                ( pt ed-type toggle buffer )
      TO addr-current      ( pt ed-type toggle )
      TO toggle-current    ( pt ed-type )
      TO type-current      ( pt )
      TO pt-current
      transfer-len mps-current num-free-tds * /mod  ( residue count )
                           ( remainder=residue quotient=count )
      TO counter           ( residue )
      TO residue
      mps-current num-free-tds * TO transfer-len   BEGIN
         counter 0 >       ( TRUE | FALSE )
         read-status TRUE = and   ( TRUE | FALSE )
      WHILE
         pt-current type-current toggle-current ( pt ed-type toggle )
         addr-current transfer-len  ( pt ed-type toggle buffer length )
         mps-current                ( pt ed-type toggle buffer length mps )
         usb-addr (do-rw-endpoint)  ( toggle TRUE | toggle FALSE )
         TO read-status             ( toggle )
         TO toggle-current
         addr-current transfer-len + TO addr-current
         counter 1- TO counter
      REPEAT
      residue 0<>                    ( TRUE |FALSE )
      read-status TRUE = and IF
         residue TO transfer-len
         pt-current type-current toggle-current ( pt ed-type toggle )
         addr-current transfer-len   ( pt ed-type toggle buffer length )
         mps-current                 ( pt ed-type toggle buffer length mps )
         usb-addr (do-rw-endpoint)   ( toggle TRUE | toggle FALSE )
         TO read-status
         TO toggle-current
      THEN
   THEN
   read-status invert  IF
   THEN
   toggle-current                    ( toggle )
   read-status                       ( TRUE | FALSE )
;
