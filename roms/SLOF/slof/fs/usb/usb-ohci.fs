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


\ We expect to base address of the OHCI controller on the stack:

CONSTANT baseaddrs

s" OHCI base address = " baseaddrs usb-debug-print-val


\ Open Firmware Properties


s" usb" 2dup device-name device-type
1 encode-int s" #address-cells" property
0 encode-int s" #size-cells" property


\ converts physical address to text unit string


: encode-unit ( port -- unit-str unit-len ) 1 hex-encode-unit ;


\ Converts text unit string to phyical address


: decode-unit ( addr len -- port ) 1 hex-decode-unit ;


\  Data Structure Definitions
\ OHCI Task Descriptor Structure.


STRUCT
   /l field td>tattr
   /l field td>cbptr
   /l field td>ntd
   /l field td>bfrend
CONSTANT /tdlen


\ OHCI Endpoint Descriptor Structure.


STRUCT
   /l field ed>eattr
   /l field ed>tdqtp
   /l field ed>tdqhp
   /l field ed>ned
CONSTANT /edlen


\ HCCA Done queue location packaged as a structure for ease OF use.


STRUCT
   /l field hc>hcattr
   /l field hc>hcdone
CONSTANT /hclen


\ OHCI Memory Mapped Registers


\ : get-base-address ( -- baseaddr )
\    s" assigned-addresses" get-my-property  IF
\       s" not possible"  usb-debug-print
\       -1
\    ELSE                  ( addr len )
\       decode-int drop    ( addr len )
\       decode-int drop    ( addr len )
\       decode-int nip nip ( n )
\    THEN
\    \ TODO: Use translate-address here
\ ;

\ get-base-address CONSTANT baseaddrs

baseaddrs      CONSTANT HcRevision
baseaddrs 4  + CONSTANT hccontrol
baseaddrs 8  + CONSTANT hccomstat
baseaddrs 0c + CONSTANT hcintstat
baseaddrs 14 + CONSTANT hcintdsbl
baseaddrs 18 + CONSTANT hchccareg
baseaddrs 20 + CONSTANT hcctrhead
baseaddrs 24 + CONSTANT hccurcont
baseaddrs 28 + CONSTANT hcbulkhead
baseaddrs 2c + CONSTANT hccurbulk
baseaddrs 30 + CONSTANT hcdnehead
baseaddrs 34 + CONSTANT hcintrval
baseaddrs 40 + CONSTANT HcPeriodicStart
baseaddrs 48 + CONSTANT hcrhdescA
baseaddrs 4c + CONSTANT hcrhdescB
baseaddrs 50 + CONSTANT HcRhStatus
baseaddrs 54 + CONSTANT hcrhpstat
baseaddrs 58 + CONSTANT hcrhpstat2
baseaddrs 5c + CONSTANT hcrhpstat3

usb-debug-flag IF
    0 config-l@ ."    - VENDOR: " 8 .r cr
   40 config-l@ ."    - PMC   : " 8 .r
   44 config-l@ ."      PMCSR : " 8 .r cr
   E0 config-l@ ."    - EXT1  : " 8 .r
   E4 config-l@ ."      EXT2  : " 8 .r cr
THEN

\ Constants for INTSTAT register

2 CONSTANT WDH

\ Constants for RH Port Status Register

1      CONSTANT RHP-CCS    \ Current Connect Status
2      CONSTANT RHP-PES    \ Port Enable Status
10     CONSTANT RHP-PRS    \ Port Reset Status
100    CONSTANT RHP-PPS    \ Port Power Status
10000  CONSTANT RHP-CSC    \ Connect Status Changed
100000 CONSTANT RHP-PRSC   \ Port Reset Status Changed


\ Constants for OHCI

0 CONSTANT OHCI-DP-SETUP
1 CONSTANT OHCI-DP-OUT
2 CONSTANT OHCI-DP-IN
3 CONSTANT OHCI-DP-INVALID

\ 8-byte Standard Device Requests + Hub class specific requests.

8006000100001200 CONSTANT get-ddescp
8006000200000900 CONSTANT get-cdescp
8006000400000900 CONSTANT get-idescp
8006000500000700 CONSTANT get-edescp
A006000000001000 CONSTANT get-hdescp
0009010000000000 CONSTANT set-cdescp
2303010004000000 CONSTANT hpenable-set
2303040001000000 CONSTANT hp1rst-set
2303040002000000 CONSTANT hp2rst-set
2303040003000000 CONSTANT hp3rst-set
2303040004000000 CONSTANT hp4rst-set
2303080001000000 CONSTANT hp1pwr-set
2303080002000000 CONSTANT hp2pwr-set
2303080003000000 CONSTANT hp3pwr-set
2303080004000000 CONSTANT hp4pwr-set
A003000000000400 CONSTANT hstatus-get
A300000001000400 CONSTANT hp1sta-get
A300000002000400 CONSTANT hp2sta-get
A300000003000400 CONSTANT hp3sta-get
A300000004000400 CONSTANT hp4sta-get
8008000000000100 CONSTANT get-config

A1FE000000000100 CONSTANT GET-MAX-LUN

2    18 lshift CONSTANT DATA0-TOGGLE
3    18 lshift CONSTANT DATA1-TOGGLE
0f   1c lshift CONSTANT CC-FRESH-TD
8 CONSTANT STD-REQUEST-SETUP-SIZE
0    13 lshift CONSTANT TD-DP-SETUP
1    13 lshift CONSTANT TD-DP-OUT
2    13 lshift CONSTANT TD-DP-IN

400001    CONSTANT ed-cntatr
400002    CONSTANT ed-cntatr1
80081     CONSTANT ed-hubatr
80000     CONSTANT ed-defatr
0f0e40000 CONSTANT td-attr
00 VALUE ptr


\ TD Management constants and Data structures.


200 CONSTANT MAX-TDS
0 VALUE td-freelist-head
0 VALUE td-freelist-tail
0 VALUE num-free-tds
0 VALUE max-rh-ports
0 VALUE current-stat

INSTANCE VARIABLE td-list-region

\ ED Management constants


14 CONSTANT MAX-EDS
0 VALUE ed-freelist-head
0 VALUE num-free-eds
INSTANCE VARIABLE ed-list-region
0 VALUE usb-address
0 VALUE initial-hub-address
0 VALUE new-device-address
0 VALUE mps
0 VALUE DEBUG-TDS
0 VALUE case-failed  \ available for general use to see IF a CASE statement
                     \ failed or not.
0 VALUE WHILE-failed \ available for general use to see IF a WHILE LOOP
                     \ failed in the middle. Used to break from the
                     \ WHILE LOOP

8 CONSTANT DEFAULT-CONTROL-MPS
12 CONSTANT DEVICE-DESCRIPTOR-LEN
1 CONSTANT DEVICE-DESCRIPTOR-TYPE
1 CONSTANT DEVICE-DESCRIPTOR-TYPE-OFFSET
4 CONSTANT DEVICE-DESCRIPTOR-DEVCLASS-OFFSET
7 CONSTANT DEVICE-DESCRIPTOR-MPS-OFFSET

20 CONSTANT BULK-CONFIG-DESCRIPTOR-LEN

9 CONSTANT HUB-DEVICE-CLASS
0 CONSTANT NO-CLASS

VARIABLE  setup-packet     \ 8 bytes for setup packet
VARIABLE  ch-buffer        \ 1 byte character buffer

INSTANCE VARIABLE dd-buffer
INSTANCE VARIABLE cd-buffer


\ Temporary variables for functions. These variables have to be initialized
\ before usage in functions and their values assume significance only during
\ the function's execution time. Should be used like local variables.
\ CAUTION:
\ If you are calling functions that destroy contents OF these variables, be
\ smart enuf to save the values before calling them.
\ It is recommended that these temporary variables are used only amidst normal
\ FORTH words -- not among the vicinity OF any OF the functions OF this node.


0 VALUE temp1
0 VALUE temp2
0 VALUE temp3
0 VALUE extra-bytes
0 VALUE num-td
0 VALUE current

0 VALUE device-speed


\ Debug functions for displaying ED, TD and their combo list.

: Show-OHCI-Register
   ." -> OHCI-Register: " cr
   ." - HcControl : " hccontrol       rl@-le 8 .r
   ."   CmdStat   : " hccomstat       rl@-le 8 .r
   ."   HcInterr. : " hcintstat       rl@-le 8 .r cr

   ." - HcFmIntval: " hcintrval       rl@-le 8 .r
   ."   Per. Start: " HcPeriodicStart rl@-le 8 .r cr

   ." - PortStat-1: " hcrhpstat       rl@-le 8 .r
   ."   PortStat-2: " hcrhpstat2      rl@-le 8 .r
   ."   PortStat-3: " hcrhpstat3      rl@-le 8 .r cr

   ."   Descr-A   : " hcrhdescA       rl@-le 8 .r
   ."   Descr-B   : " hcrhdescB       rl@-le 8 .r
   ."   HcRhStat  : " HcRhStatus      rl@-le 8 .r cr
;

: display-ed ( ED-ADDRESS -- )
   TO temp1
   usb-debug-flag IF
      s" Dump OF ED " type temp1 u. cr
      s" eattr    : " type temp1 ed>eattr l@-le u. cr
      s" tdqhp    : " type temp1 ed>tdqhp l@-le u. cr
      s" tdqtp    : " type temp1 ed>tdqtp l@-le u. cr
      s" ned      : " type temp1 ed>ned   l@-le u. cr
   THEN
;


\ Displays the transfer descriptors

: display-td ( TD-ADDRESS -- )
   TO temp1
   usb-debug-flag IF
      s" TD " type temp1 u. s" dump: " type cr
      s" td>tattr  : " type temp1 td>tattr l@-le u. cr
      s" td>cbptr  : " type temp1 td>cbptr l@-le u. cr
      s" td>ntd    : " type temp1 td>ntd l@-le u. cr
      s" td>bfrend : " type temp1 td>bfrend l@-le u. cr
   THEN
;


\ display's the descriptors


: display-descriptors ( ED-ADDRESS -- )
   10  1- not and             ( ED-ADDRESS~ )
   dup display-ed ed>tdqhp l@-le  BEGIN ( ED-ADDRESS~ )
      10  1- not and         ( ED-ADDRESS~ )
      dup 0<>                ( ED-ADDRESS~ TRUE | FALSE )
   WHILE
      dup  display-td td>ntd l@-le ( ED-ADDRESS~ )
   REPEAT
   drop
;


\ ---------------------------------------------------------------------------
\                   	TD LIST MANAGEMENT WORDS
\                       ------------------------
\        The following are WORDS internal to this node. They are supposed to
\        be used by other WORDS inside this device node.
\        The first three WORDS below form the interface. The fourth and fifth
\        word is a helper function and is not exposed to other portions OF this
\        device node.
\        a) initialize-td-free-list
\        b) allocate-td-list
\        c) (free-td-list)
\        d) find-td-list-tail-and-size
\        e) zero-out-a-td-except-link
\ ----------------------------------------------------------------------------


: zero-out-a-td-except-link ( td -- )


   \ There r definitely smarter ways to DO it especially
   \ on a 64-bit machine.

   \ Optimization, Portability:
   \ --------------------------
   \ Replace the following code by two "!" OF zeroes. Since
   \ we know that an "td" is actually 16 bytes and that we
   \ will be executing on a 64-bit machine, we can finish OFf
   \ with 2 stores.  But that WONT be portable.


   dup 0 swap td>tattr  l!-le		( td )
   dup 0 swap td>cbptr  l!-le		( td )
   dup 0 swap td>bfrend l!-le		( td )
   drop
;


\ COLON DEFINITION: initialize-td-free-list - Internal Function

\ Initialize the TD Free List Region and create a linked list OF successive
\ TDs. Note that the NEXT pointers are all in little-endian and they
\ can be directly used for HC purposes.


: initialize-td-free-list ( -- )
   MAX-TDS 0= IF EXIT THEN
   td-list-region @ 0= IF EXIT THEN
   td-list-region @ TO temp1
   0 TO temp2  BEGIN
      temp1 zero-out-a-td-except-link
      temp1 /tdlen + dup   temp1 td>ntd   l!-le TO temp1
      temp2 1+ TO temp2
      temp2 MAX-TDS = 		( TRUE | FALSE )
   UNTIL
   temp1 /tdlen - dup 0 swap td>ntd l!-le TO td-freelist-tail
   td-list-region @ TO td-freelist-head
   MAX-TDS TO num-free-tds
;


\ COLON DEFINITION: allocate-td-list -- Internal function
\ Argument:
\ The function accepts a non-negative number and allocates
\ a TD-LIST containing that many TDs. A TD-LIST is a list
\ OF TDs that are linked by the next-td field. The next-td
\ field is in little-endian mode so that the TD list can
\ be directly re-used by the HC.
\ Return value:
\ The function returns "head" and "tail" OF the allocated
\ TD-LIST. If for any reason, the function cannot allocate
\ the TD-LIST, the function returns 2 NULL pointers in the
\ stack indicating that the allocation failed.

\ Note that the TD list returned is NULL terminated. i.e
\ the nextTd field OF the tail is NULL.



: allocate-td-list ( n -- head tail )
   dup 0= IF drop 0 0 EXIT THEN 		( 0 0 )
   dup num-free-tds > IF drop 0 0 EXIT THEN     ( 0 0 )
   dup num-free-tds = IF			( n )
      drop td-freelist-head td-freelist-tail	( td-freelist-head td-freelist-tail )
      0 TO td-freelist-head			( td-freelist-head td-freelist-tail )
      0 TO td-freelist-tail			( td-freelist-head td-freelist-tail )
      0 TO num-free-tds				( td-freelist-head td-freelist-tail )
      EXIT
   THEN

   \ If we are here THEN we know that the requested number OF TDs is less
   \ than what we actually have. We need TO traverse the list and find the
   \ new Head pointer position and THEN update the head pointer accordingly.
   \ Update num-free-tds

   dup num-free-tds swap - TO num-free-tds	( n )

   \ Traverse through the Free list to identify the element that exists after
   \ "n" TDs. Use the info to return the head and tail pointer and update
   \ the new td-list-head

   td-freelist-head 				( n td-list-head )
   dup TO temp1					( n td-list-head )
   swap 					( td-list-head n )
   0 DO						( td-list-head   )
      temp1 TO temp2				( td-list-head   )
      temp1 td>ntd l@-le   TO   temp1		( td-list-head   )
   LOOP						( td-list-head   )
   temp2 					( td-list-head td-list-tail )
   dup td>ntd 0 swap l!-le 			( td-list-head td-list-tail )
   temp1 TO td-freelist-head 			( td-list-head td-list-tail )
;


\ COLON DEFINITION: find-td-list-tail-and-size
\ This function counts the number OF TD elements
\ in the given list. It also returns the last tail
\ TD OF the TD list.

\ ASSUMPTION:
\ A NULL terminated TD list is assumed. A not-well formed
\ list can result in in-determinate behaviour.

\ ROOM FOR ENHANCEMENT:
\ We could arrive at a generic function for counting
\ list elements to which the next-ptr OFfset can also
\ be passed as an argument (in this case it is >ntd)
\ This function can THEN be changed to call the
\ function with "0 >ntd" as an additional argument
\ (apart from head and tail)


: find-td-list-tail-and-size  ( head -- tail n )
   TO temp1
   0 TO temp2
   0 TO temp3
   DEBUG-TDS  IF
      s" BEGIN find-td-list-tail-and-size: "   usb-debug-print
   THEN
   BEGIN
      temp1 0<>					( TRUE|FALSE )
   WHILE
      DEBUG-TDS  IF
         temp1 u. cr
      THEN
      temp1 TO temp3
      temp1 td>ntd l@-le TO temp1
      temp2 1+ TO temp2
   REPEAT
   temp3 temp2					( tail n )
   DEBUG-TDS  IF
      s" END find-td-list-tail-and-size"   usb-debug-print
   THEN
;


\ COLON DEFINITION: (free-td-list)

\ Arguments: (head  --)
\ The "head" pointer OF the TD-LIST to be freed is passed as
\ an argument to this function. The function merely adds the list to the
\ already existing TD-LIST

\ Assumptions:
\ The function assumes that the TD-LIST passed as argument is a well-formed
\ list. The function does not DO any check on it.
\ But since, the "TD-LIST" is generally freed from the DONE-QUEUE which is
\ a well-formed list, the interface makes much sense.

\ Return values:
\ Nothing is returned. The arguments passed are popped OFf.


: (free-td-list) ( head  -- )

   \ Enhancement:
   \ We could zero-out-a-td-except-link for the TD list that is being freed.
   \ This way, we could prevent some nasty repercussions OF bugs (that r yet
   \ to be discovered). but we can include this enhancement during the testing
   \ phase.

   dup find-td-list-tail-and-size num-free-tds + TO num-free-tds ( head tail )
   td-freelist-tail 0=  IF					 ( head tail )
      dup TO td-freelist-tail					 ( head tail )
   THEN								 ( head tail )
   td>ntd td-freelist-head swap l!-le				 ( head )
   TO td-freelist-head
;


\          END OF TD LIST MANAGEMENT WORDS
\ 	   ED Management section BEGINs
\ 	   ----------------------------


: zero-out-an-ed-except-link ( ed -- )

   \ There are definitely smarter ways to do it especially
   \ on a 64-bit machine.

   \ Optimization, Portability:
   \ --------------------------
   \ Replace by a  "!" and "l!". we know that an "ed" is
   \ actually 16 bytes and that we will be executing on
   \ a 64-bit machine, we can finish OFf with 2 stores.
   \ But that WONT be portable.

   dup 0 swap ed>eattr  l!-le 		( ed )
   dup 0 swap ed>tdqtp  l!-le		( ed )
   dup 0 swap ed>tdqhp  l!-le		( ed )
   drop
;

\ Intialises ed-list afresh

: initialize-ed-free-list ( -- )
   MAX-EDS 0= IF EXIT THEN
   ed-list-region @ 0= IF
      s" init-ed-list: ed-list-region is not allocated!"   usb-debug-print
      EXIT
   THEN
   ed-list-region @ TO temp1
   0 TO temp2   BEGIN
      temp1 zero-out-an-ed-except-link
      temp1 /edlen + dup   temp1 ed>ned   l!-le TO temp1
      temp2 1+ TO temp2
      temp2 MAX-EDS =
   UNTIL
   temp1 /edlen - ed>ned 0 swap l!-le
   ed-list-region @ TO ed-freelist-head
   MAX-EDS TO num-free-eds
;


\ allocate an ed and return ed address


: allocate-ed	( -- ed-ptr )
   num-free-eds 0= IF 0 EXIT THEN
   ed-freelist-head					( ed-freelist-head )
   ed-freelist-head ed>ned l@-le TO ed-freelist-head	( ed-freelist-head )
   num-free-eds 1- TO num-free-eds			( ed-freelist-head )
   dup ed>ned 0 swap l!-le \ Terminate the Link.	( ed-freelist-head )
;


\ free the given ed pointer

: free-ed ( ed-ptr  -- )
   dup zero-out-an-ed-except-link			( ed-ptr )
   dup ed>ned ed-freelist-head swap l!-le 		( ed-ptr )
   TO ed-freelist-head
   num-free-eds 1+ TO num-free-eds
;


\ Buffer allocations
\ ------------------
\ Note:
\ -----
\ 1. What should we DO IF alloc-mem fails ?
\ 2. alloc-mem must return aligned memory addresses.
\ 3. alloc-mem must return DMAable memory!

\ Memory for the HCCA - must stay allocated as long as the HC is operational!
100 alloc-mem VALUE hchcca
hchcca ff and IF
   \ This should never happen - alloc-mem always aligns
   s" Warning: hchcca not aligned!" usb-debug-print
THEN

84 hchcca + CONSTANT hchccadneq


: (allocate-mem)  ( -- )
   /tdlen MAX-TDS * 10 + alloc-mem dup td-list-region !  ( td-list-region-ptr )
   f and IF
      s" Warning: td-list-region not aligned!" usb-debug-print
   THEN
   initialize-td-free-list

   /edlen MAX-EDS * 10 + alloc-mem dup ed-list-region !  ( ed-list-region-ptr )
   f and IF
      s" Warning: ed-list-region not aligned!" usb-debug-print
   THEN
   initialize-ed-free-list

   DEVICE-DESCRIPTOR-LEN chars alloc-mem dd-buffer !
   BULK-CONFIG-DESCRIPTOR-LEN chars alloc-mem cd-buffer !
;


\ The method makes sure that when the host node is closed all
\ associated buffer allocations made for data-structures as
\ well as data-buffers are freed

: (de-allocate-mem)  ( -- )
   td-list-region @ ?dup IF
      /tdlen MAX-TDS * 10 + free-mem
      0 td-list-region !
   THEN
   ed-list-region @ ?dup IF
      /edlen MAX-EDS * 10 + free-mem
      0 ed-list-region !
   THEN
   dd-buffer @ ?dup IF
      DEVICE-DESCRIPTOR-LEN free-mem
      0 dd-buffer !
   THEN
   cd-buffer @ ?dup IF
      BULK-CONFIG-DESCRIPTOR-LEN free-mem
      0 cd-buffer !
   THEN
;


\ Suspend hostcontroller (and the bus).
\ This method must be called before the operating system starts.
\ It prevents the HC from doing DMA in the background during boot
\ (e.g. updating its frame number counter in the HCCA)

: hc-suspend  ( -- )
   \ s" USB HC suspend with hccontrol=" type hccontrol . cr
   00C3 hccontrol rl!-le             \ Suspend USB host controller
;


\ OF methods

: open  ( -- TRUE|FALSE )
   (allocate-mem)
   TRUE
;

: close  ( -- )
   (de-allocate-mem)
;


\ COLON DEFINITION: HC-enable-control-list-processing
\ Enables USB HC transactions on control list.

: HC-enable-control-list-processing ( -- )
   hccomstat dup rl@-le 02 or swap rl!-le
   hccontrol dup rl@-le 10 or swap rl!-le
;


\ COLON DEFINTION: HC-enable-bulk-list-processing
\ PENDING: Remove Hard coded constants.

: HC-enable-bulk-list-processing ( -- )
   hccomstat dup rl@-le 04 or swap rl!-le
   hccontrol dup rl@-le 20 or swap rl!-le
;


: HC-enable-interrupt-list-processing ( -- )
   hccontrol dup rl@-le 04 or swap rl!-le
;


\ Clearing WDH to allow HC to write into DOne queue again

: (HC-ACK-WDH) ( -- )   WDH hcintstat rl!-le ;

\ Checking whether anything has been written into DOne queue

: (HC-CHECK-WDH) ( -- ) hcintstat rl@-le WDH and 0<> ;


\ Disable USB transaction and keep it ready

: disable-control-list-processing ( -- )
   hccontrol dup rl@-le ffffffef and swap rl!-le
   hccomstat dup rl@-le fffffffd and swap rl!-le
;

: disable-bulk-list-processing ( -- )
   hccontrol dup rl@-le ffffffdf and swap rl!-le
   hccomstat dup rl@-le fffffffb and swap rl!-le
;


: disable-interrupt-list-processing ( -- )
   hccontrol dup rl@-le fffffffb and swap rl!-le
;


\ COLON DEFINITION: fill-TD-list

\ This function accepts a TD list and a data-buffer and
\ distributes this data buffer over the TD list depending
\ on the Max Packet Size.

\ Arguments:
\ ----------
\ (from bottom OF stack)
\ 1. addr -- Address OF the data buffer
\ 2. dlen -- Length OF the data buffer above.
\ 3. dir  -- Tells whether the TDs r for an IN or
\            OUT transaction.
\ 4. MPS  -- Maximum Packet Size associated with the endpoint
\            that will use this TD list.
\ 5. TD-List-Head - Head pointer OF the List OF TDs.
\            This list is NOT expected to be NULL terminated.

\ Assumptions:
\ -----------
\ 1. TD-List for data is well-formed and has sufficient entries
\    to hold "dlen".
\ 2. The TDs toggle field is assumed to be taken from the endpoint
\    descriptor's "toggle carry" field.
\ 3. Assumes that the caller specifies the correct start-toggle.
\    If the caller specifies a wrong data toggle OF 1 for a SETUP
\    PACKET, this method will not find it out.

\ COLON DEFINTION: (toggle-current-toggle)
\ Scope: Internal to fill-TD-list
\ Functionality:
\        Toggles the "T" field that is passed as argument.
\        "T" as in the "T" field OF the TD.

0 VALUE current-toggle
: fill-TD-list ( start-toggle addr dlen dp MPS TD-List-Head -- )
   TO temp1 				( start-toggle addr dlen dp MPS )
   TO temp2 				( start-toggle addr dlen dp )
   CASE					( start-toggle addr dlen )
      OHCI-DP-SETUP  OF  TD-DP-SETUP TO temp3 ENDOF ( start-toggle addr dlen )
      OHCI-DP-IN     OF  TD-DP-IN    TO temp3 ENDOF ( start-toggle addr dlen )
      OHCI-DP-OUT    OF  TD-DP-OUT   TO temp3 ENDOF ( start-toggle addr dlen )
      dup            OF  -1          TO temp3       ( start-toggle addr dlen )
      s" fill-TD-list: Invalid DP specified"   usb-debug-print
                                                  ENDOF
   ENDCASE
   temp3 -1 = IF EXIT THEN                          ( start-toggle addr dlen )


\ temp1 -- TD-List-Head
\ temp2 -- Max Packet Size
\ temp3 -- TD-DP-IN or TD-DP-OUT or TD-DP-SETUP

   rot                                              ( addr dlen start-toggle )
   TO current-toggle swap 			    ( dlen addr )
   BEGIN
      over temp2 >= 				    ( dlen addr TRUE|FALSE )
   WHILE					    ( dlen addr )
      dup temp1 td>cbptr l!-le			    ( dlen addr )
      current-toggle 18 lshift                      ( dlen addr current-toggle~ )
      DATA0-TOGGLE                        ( dlen  addr current-toggle~ toggle )
      CC-FRESH-TD temp3 or or or          ( dlen  addr or-result )
      temp1 td>tattr l!-le                ( dlen addr~  )
      dup temp2 1- + temp1 td>bfrend l!-le ( dlen addr~  )
      temp2 +                             ( dlen next-addr )
      swap temp2 - swap
      temp1 td>ntd l@-le TO temp1         ( dlen next-addr )
      current-toggle                      ( dlen next-addr current-toggle )
      CASE
         0 OF 1 TO current-toggle ENDOF
         1 OF 0 TO current-toggle ENDOF
      ENDCASE
   REPEAT                                   ( dlen addr )
   over 0<>  IF
      dup temp1 td>cbptr l!-le              ( dlen addr )
      current-toggle 18 lshift              ( dlen addr curent-toggle~ )
      DATA0-TOGGLE                          ( dlen addr curent-toggle~ toggle )
      CC-FRESH-TD temp3 or or or            ( dlen addr or-result )
      temp1 td>tattr l!-le                  ( dlen addr )
      + 1- temp1 td>bfrend l!-le
   ELSE
      2drop
   THEN
;


\ COLON DEFINITION: (td-list-status )
\ FUNCTIONALITY:
\ To traverse the TD list to check for a TD carrying non-zero CC return the
\ respective TD address and CC ELSE 0
\ SCOPE:
\ Internal method

: (td-list-status) ( PointerToTDlist -- failingTD CCode TRUE | 0 )
   BEGIN 	 ( PointerToTDlist )
      dup 0<>	 ( PointerToTDlist TRUE|FALSE )
   IF 		 ( PointerToTDlist )
      dup td>tattr l@-le f0000000 and 1c rshift dup 0= TRUE swap
       ( PointerToTDlist CCode TRUE TRUE|FALSE )
   ELSE
      drop FALSE dup ( FALSE )
   THEN
   WHILE
      drop drop td>ntd l@-le
   REPEAT
;


\ ==================================================================
\ COLON DEFINITION: (wait-for-done-q)
\ FUNCTIONALITY:
\ To DO a timed polling OF the DOne queue and acknowledge and return
\ the address OF the last retired Td list
\ SCOPE:
\ Internal method
\ ==================================================================

: (wait-for-done-q)           ( timeout -- TD-list TRUE | FALSE )
   BEGIN                      ( timeout )
      dup 0<>                 ( timeout TRUE|FALSE )
      (HC-CHECK-WDH) NOT      ( timeout TRUE|FALSE TRUE|FALSE )
      AND                     \ not timed out AND WDH-bit not set
      WHILE
      1 ms                    \ wait
      1-                      ( timeout )
      dup ff and 0= IF show-proceed THEN
   REPEAT	                  ( timeout )
   drop
   hchccadneq  l@-le          \ read last HcDoneHead (RAM)
   (HC-CHECK-WDH)             \ HcDoneHead was updated ?
   IF
      (HC-ACK-WDH)	         \ clear register bit: WDH
      TRUE                    ( td-list TRUE )
   ELSE
      FALSE
   THEN
;


\ displays free tds


: debug-td ( -- )
   s" Num Free TDs = " num-free-tds usb-debug-print-val
;


\ display content of frame counter

\ : debug-frame-counter ( -- )
\   40 1 DO
\      ." Frame ct at HCCA at end OF enumeration = "
\      hchcca 80 + rl@-le .
\   LOOP
\ ;

\ ============================================================================
\ COLON DEFINITION: HC-reset
\ This routine should be the first to be executed.
\ This routine will reset the HC and will bring it to Operational
\ state.
\ PENDING:
\ Arrive at the right value OF FrameInterval. Currently we are hardcoding
\ it.
\ ==========================================================================
: HC-reset ( -- )

   hccomstat dup rl@-le 01 or swap rl!-le    \ issue HC reset
   BEGIN
      hccomstat rl@-le 01 and 0<>            \ wait for reset end
      WHILE
   REPEAT

   23f02edf hcintrval rl!-le                 \ frame-interval register
   hchcca   hchccareg rl!-le                 \ HC communication area
   0000     hcctrhead rl!-le                 \ control transfer head
   0000     hcbulkhead rl!-le                \ bulk transfer head
   0ffff    hcintdsbl rl!-le                 \ interrupt disable reg.

\ all devices are still in reset-state
\ next command starts sending SOFs
   83       hccontrol rl!-le                 \ set USBOPERATIONAL

\ these two repeated register settings are necessary for Bimini
\ Its OHCI controller (AM8111) behaves different to NEC's one
   23f02edf hcintrval rl!-le                 \ frame-interval register
   hchcca   hchccareg rl!-le                 \ HC communication area
   
   d# 50 ms

   hcrhdescA rl@-le ff and     ( total-rh-ports )
   to max-rh-ports

\ if no hardware-reset was issued (rescan)
\ switch off all ports first !
   hcrhpstat TO current-stat              \ start with first port status reg
   0                                      \ port status default
   max-rh-ports 0                         \ checking all ports
   DO
      current-stat rl@-le or              \ OR-ing all stats
      200 current-stat rl!-le             \ Clear Port Power (CPP)
      current-stat 4 + TO current-stat    \ check next RH-Port
   LOOP
   100 and 0<>                            \ any of the ports had power ?
   IF
      d# 750 wait-proceed                 \ wait for power discharge
   THEN

\ now power on all ports of this root-hub
   hcrhpstat TO current-stat              \ start with first port status reg
   max-rh-ports 0
   DO
      102 current-stat rl!-le             \ power on and enable
      hcrhdescA 3 + rb@ 2 * ms            \ startup delay 30 ms (2 * POTPGT)
      current-stat 4 + TO current-stat    \ check next RH-Port
   LOOP
   d# 500 wait-proceed                    \ STEC device needs 300 ms
;

: error-recovery ( -- )
   initialize-td-free-list
   initialize-ed-free-list
   HC-reset
;

\ ================================================================
: store-initial-usb-hub-address ( -- )
    usb-address TO initial-hub-address
;

: reset-to-initial-usb-hub-address ( -- )
    initial-hub-address TO usb-address
;

\ allocate-usb-address:
\ Function allocates an USB address.
\ See RISK below.


: allocate-usb-address ( -- usb-address )
   usb-address    7f <>		( TRUE|FALSE )
   IF
      usb-address 1+ TO usb-address \ RISK: Check to see IF it overflows 127
      usb-address		( usb-address )
   THEN				( usb-address )
;

s" usb-support.fs" INCLUDED



\ =====================================================================
\ COLON DEFINTION: control-std-set-address
\                  INTERFACE FUNCTION
\ Function allocates an USB addrss and uses it to send SET-ADDRESS packet
\ to the default USB address.
\ This is an interface function available to child nodes.

: control-std-set-address        ( speedbit -- usb-address TRUE | FALSE )
   >r                                                 ( R: speedbit )
   0005000000000000 setup-packet !
   allocate-usb-address dup setup-packet 2 + c!       ( usb-addr  R: speedbit )
   s" USB set-address: " 2 pick usb-debug-print-val   ( usb-addr  R: speedbit )
   0 0 0 setup-packet 8 r> controlxfer                ( usb-addr TRUE | FALSE )
   IF						      ( TRUE | FALSE )
      TRUE 					      ( TRUE )
   ELSE
      drop FALSE \ PENDING: Return the allocated address back. ( FALSE )
   THEN						      ( TRUE | FALSE )
;


\ Fetches the device decriptor of the usb-device


: control-std-get-device-descriptor
	            ( data-buffer data-len MPS fa -- TRUE|FALSE )

   8006000100000000 setup-packet !
   2 pick setup-packet 6 + w!-le
                     ( data-buffer data-len MPS fa )
   setup-packet -rot ( data-buffer data-len setup-packet MPS fa )
   >r >r >r >r >r 0 r> r> r> r> r>
   		     ( 0 data-buffer data-len setup-packet MPS fa )
   controlxfer	     ( TRUE | FALSE )
;


\ ==================================================================
\ To retrieve the configuration descriptor OF a device
\ with a valid USB address


: control-std-get-configuration-descriptor
   ( data-buffer data-len MPS FuncAddr -- TRUE|FALSE )
   TO temp1 ( data-buffer data-len MPS )
   TO temp2 ( data-buffer data-len )
   TO temp3 ( data-buffer )
   8006000200000000 setup-packet !
   temp3 setup-packet 6 + w!-le
   0 swap temp3 setup-packet temp2 temp1 controlxfer
;

\ Fetches num of logical units available for a device
: control-std-get-maxlun ( MPS fun-addr dir data-buff data-len -- TRUE | FALSE )
   GET-MAX-LUN setup-packet !  ( MPS fun-addr dir data-buff data-len )
   setup-packet 5 pick 5 pick
   ( MPS fun-addr dir data-buff data-len setup-packet MPS fun-addr )
   controlxfer ( MPS fun-addr  TRUE | FALSE )
   nip nip    ( TRUE | FALSE )
;

\ Bulk-Only Mass Storage Reset
\ fixed to interface #0
: control-bulk-reset ( MPS fun-addr dir data-buff data-len -- TRUE | FALSE )
   21FF000000000000 setup-packet !  ( MPS fun-addr dir data-buff data-len )
   setup-packet 5 pick 5 pick
               ( MPS fun-addr dir data-buff data-len setup-packet MPS fun-addr )
   controlxfer ( MPS fun-addr  TRUE | FALSE )
   nip nip    ( TRUE | FALSE )
;



\ get the string descriptor of the usb device


: control-std-get-string-descriptor
   ( StringIndex data-buffer data-len MPS FuncAddr -- TRUE | FALSE )
   TO temp1  ( StringIndex data-buffer data-len MPS )
   TO temp2  ( StringIndex data-buffer data-len )
   TO temp3  ( StringIndex )
   8006000300000000 setup-packet !
   temp3 setup-packet 6 + w!-le
   409 setup-packet 4 + w!-le \ US English Language code.
   swap      ( data buffer StringIndex )
   setup-packet 2 + c! ( data-buffer )
   0 swap temp3 setup-packet temp2 temp1 controlxfer ( TRUE | FALSE )
;

\ sets a valid usb configaration for a device

: control-std-set-configuration ( configvalue FuncAddr -- TRUE|FALSE )
   TO temp1                     ( configvalue )
   TO temp2
   0009000000000000 setup-packet ! \ RISK: Endian and 64-bit assumptions
   temp2 setup-packet 2 + w!-le
   0 0 0 setup-packet DEFAULT-CONTROL-MPS temp1 controlxfer

   \ NOTE: We could use DEFAULT-CONTROL-MPS because there is no data phase
   \ associated with this control xfer. Its a dont care.
;


\ To set the device address retrive the device descriptor and build the
\ usb device tree by passing device class


0 VALUE port-number

s" usb-enumerate.fs" INCLUDED

: rhport-enumerate ( port-num -- )
   TO port-number
   device-speed control-std-set-address        ( usb-addr TRUE | FALSE )
   IF
      device-speed or                          ( usb-addr+speedbit )
      TO new-device-address
      dd-buffer @ 8 erase

      \ Read Device Descriptor - First 8 bytes.

      dd-buffer @ DEFAULT-CONTROL-MPS DEFAULT-CONTROL-MPS      ( buffer mps mps )
      new-device-address control-std-get-device-descriptor   ( TRUE | FALSE )
      IF
      ELSE
         s" USB: Read Dev Descriptor failed"   usb-debug-print EXIT

         \ NOTE: Tomorrow, IF there is a LOOP here,we may need to UNLOOP before
         \ "EXIT"ing. Beware. Much depends on what LOOPing construct is used.

      THEN

      \ Read the Descriptor Type and check IF we have read correctly.

      dd-buffer @ DEVICE-DESCRIPTOR-TYPE-OFFSET + c@  ( Descriptor-type )
      DEVICE-DESCRIPTOR-TYPE <> IF
         s" USB: Error Reading Device Descriptor"   usb-debug-print
         s" Read descriptor is not OF the right type"  usb-debug-print
         s" Aborting enumeration"  usb-debug-print
         EXIT
         \ NOTE: Tomorrow, IF u have a LOOP here THEN we may need to
         \ UNLOOP before EXITing. Depends on what type OF LOOPing construct
         \ is used. Beware.

      THEN

      \ Read the MPS and store it.

      dd-buffer @ DEVICE-DESCRIPTOR-MPS-OFFSET + c@ TO mps

      \ NOTE: Probably, we could check MPS for only 8/16/32/64
      \       hmm.. not now...

      \ Read the device class to see what type OF device it is and create an
      \ appropriate child node here.
      create-usb-device-tree
   ELSE
      s" Set address failed on port " port-number usb-debug-print-val
      s" Aborting Enumeration."   usb-debug-print
      EXIT

      \ NOTE: Tomorrow , IF u have a LOOP here THEN we may need to
      \ UNLOOP before EXITing. Depends on what type OF LOOPing construct
      \ is used. Beware.

   THEN
;


\ =========================================================================
\ PROTOTYPE FUNCTION: "rhport-initialize"
\ Detect Device, reset and enable the respective port.
\ COLON Definition rhport-initialize accepts the total number OF root hub
\ ports as an argument and probes every available root hub port and initiates
\ the build OF the USB devie sub-tree so is effectively the mother OF all
\ USB device nodes that are to be detected and instantiated.
\ ==========================================================================
: rhport-initialize ( -- )

   hcrhpstat TO current-stat              \ start with first port status reg
   max-rh-ports 1+ 1
   DO
      \ any Device connected to that port ?
      current-stat rl@-le RHP-CCS and 0<> 	( TRUE|FALSE )
      IF
         current-stat hcrhpstat3 =        \ third port of NEC ?
         IF
            81 to uDOC-present            \ uDOC is present and now processed
         THEN

         s" Device connected to this port!" usb-debug-print
         RHP-PRS current-stat rl!-le      \ issue a port reset
         BEGIN
            current-stat rl@-le RHP-PRS AND    \ wait for reset end
            WHILE
         REPEAT
         hcrhdescA 3 + rb@ 2 * ms         \ startup delay 30 ms (POTPGT)
         d# 100 ms

         current-stat rl@-le 200 and 4 lshift
         to device-speed                  \ store speed bit

         RHP-CSC RHP-PRSC or current-stat rl!-le

         I ['] rhport-enumerate CATCH IF  \ Scan port
            s" USB scan failed on root hub port: " rot usb-debug-print-val
            reset-to-initial-usb-hub-address
         THEN

      ELSE
         s" No device detected at this port." usb-debug-print
         current-stat hcrhpstat3 =        \ third port of NEC ? (=ModFD)
         IF                               \ here a ModFD should be on ELBA
            current-stat rl@-le 80000 and 0<> 	\ is over-current detected ?
            IF
               uDOC-present 08 or to uDOC-present  \ set flag for uDOC-check
            THEN
         THEN
      THEN
      current-stat 4 + TO current-stat    \ check next RH-Port
      uDOC-present 0f and to uDOC-present \ remove processing flag
   LOOP
;


\ ===================================================
\ Enumeration at Host level
\ ===================================================

: enumerate ( -- )
   HC-reset
   ['] hc-suspend add-quiesce-xt     \ Assert that HC will be supsended
   store-initial-usb-hub-address
   rhport-initialize                 \ Probe all available RH ports
   reset-to-initial-usb-hub-address
;


\ Create an alias for this controller:
set-ohci-alias

