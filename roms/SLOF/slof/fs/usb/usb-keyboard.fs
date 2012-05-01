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


s" keyboard" device-name
s" keyboard" device-type

."   USB Keyboard" cr

3 encode-int s" assigned-addresses" property
1 encode-int s" reg" property
1 encode-int s" configuration#" property
s" EN" encode-string s" language" property

1 constant NumLk
2 constant CapsLk
4 constant ScrLk

00 value kbd-addr
to kbd-addr                                \ save speed bit
8 value mps-dcp
8 constant DEFAULT-CONTROL-MPS
8 chars alloc-mem value setup-packet
8 chars alloc-mem value kbd-report
4 chars alloc-mem value multi-key
0 value cfg-buffer
0 value led-state
0 value temp1
0 value temp2
0 value temp3
0 value ret
0 value scancode
0 value kbd-shift
0 value kbd-scan
0 value key-old
0 value expire-ms
0 value mps-int-in
0 value int-in-ep
0 value int-in-toggle

kbd-addr                                    \ give speed bit to include file 
s" usb-kbd-device-support.fs" included

: control-cls-set-report ( reportvalue FuncAddr -- TRUE|FALSE )
  to temp1
  to temp2
  2109000200000100 setup-packet ! 
  temp2 kbd-data l!-le  
  1 kbd-data 1 setup-packet DEFAULT-CONTROL-MPS temp1 controlxfer  
;

: control-cls-get-report ( data-buffer data-len MPS FuncAddr -- TRUE|FALSE )
  to temp1
  to temp2
  to temp3
  a101000100000000 setup-packet ! 
  temp3 setup-packet 6 + w!-le  
  0 swap temp3 setup-packet temp2 temp1 controlxfer  
;

: int-get-report ( -- )                                           \ get report for interrupt transfer
    0 2 int-in-toggle kbd-report 8 mps-int-in
    kbd-addr int-in-ep 7 lshift or rw-endpoint                    \ get report 
    swap to int-in-toggle if
	kbd-report @ ff00000000000000 and 38 rshift to kbd-shift  \ store shift status
	kbd-report @ 0000ffffffffffff and to kbd-scan             \ store scan codes
    else
	0 to kbd-shift                                            \ clear shift status 
	0 to kbd-scan                                             \ clear scan code buffer
    then
;

: ctl-get-report ( -- )                                           \ get report for control transfer      
    kbd-report 8 8 kbd-addr control-cls-get-report if             \ get report 
        kbd-report @ ff00000000000000 and 38 rshift to kbd-shift  \ store shift status
        kbd-report @ 0000ffffffffffff and to kbd-scan             \ store scan codes 
    else
	0 to kbd-shift                                            \ clear shift status 
	0 to kbd-scan                                             \ clear scan code buffer
    then
;

: set-led ( led -- ) 
  dup to led-state  
  kbd-addr control-cls-set-report drop
;

: is-shift ( -- true|false )
    kbd-shift 22 and if
	true
    else
	false
    then
;

: is-alt ( -- true|false )
    kbd-shift 44 and if
	true
    else
	false
    then
;

: is-ctrl ( -- true|false )
    kbd-shift 11 and if
	true
    else
	false
    then
;

: ctrl_alt_del_key ( char -- )
    is-ctrl if                                           \ ctrl is pressed?
	is-alt if                                        \ alt is pressed?
	    4c = if                                      \ del is pressed?
		s" reboot.... " usb-debug-print 
		\ reset-all                              \ reboot
		drop false                               \ invalidate del key on top of stack
	    then
	    false                                        \ dummy for last drop
	then
    then
    drop                                                 \ clear stack 
;

: get-ukbd-char ( ScanCode -- char|false )
    dup ctrl_alt_del_key                                 \ check ctrl+alt+del 
    dup to scancode                                      \ store scan code
    case                                                 \ translate scan code --> char
	 04 of [char] a endof 
	 05 of [char] b endof 
	 06 of [char] c endof 
	 07 of [char] d endof 
	 08 of [char] e endof 
	 09 of [char] f endof 
 	 0a of [char] g endof 
	 0b of [char] h endof 
	 0c of [char] i endof 
	 0d of [char] j endof 
	 0e of [char] k endof 
	 0f of [char] l endof 
	 10 of [char] m endof 
	 11 of [char] n endof 
	 12 of [char] o endof 
	 13 of [char] p endof 
	 14 of [char] q endof 
	 15 of [char] r endof 
	 16 of [char] s endof 
	 17 of [char] t endof 
	 18 of [char] u endof 
	 19 of [char] v endof 
	 1a of [char] w endof 
	 1b of [char] x endof 
	 1c of [char] y endof 
	 1d of [char] z endof 
	 1e of [char] 1 endof 
	 1f of [char] 2 endof 
	 20 of [char] 3 endof 
	 21 of [char] 4 endof 
	 22 of [char] 5 endof 
	 23 of [char] 6 endof 
	 24 of [char] 7 endof 
	 25 of [char] 8 endof 
	 26 of [char] 9 endof 
	 27 of [char] 0 endof 
	 28 of 0d endof                            \ Enter
	 29 of 1b endof                            \ ESC 
	 2a of 08 endof                            \ Backsace 
	 2b of 09 endof                            \ Tab
 	 2c of 20 endof                            \ Space
 	 2d of [char] - endof 
 	 2e of [char] = endof 
 	 2f of [char] [ endof 
 	 30 of [char] ] endof 
 	 31 of [char] \ endof 
 	 33 of [char] ; endof 
	 34 of [char] ' endof 
	 35 of [char] ` endof 
	 36 of [char] , endof 
	 37 of [char] . endof 
	 38 of [char] / endof
	 39 of led-state CapsLk xor set-led false endof  \ CapsLk
	 3a of 1b 7e31315b to multi-key endof      \ F1
	 3b of 1b 7e32315b to multi-key endof      \ F2
	 3c of 1b 7e33315b to multi-key endof      \ F3
	 3d of 1b 7e34315b to multi-key endof      \ F4
	 3e of 1b 7e35315b to multi-key endof      \ F5
	 3f of 1b 7e37315b to multi-key endof      \ F6
	 40 of 1b 7e38315b to multi-key endof      \ F7
	 41 of 1b 7e39315b to multi-key endof      \ F8
	 42 of 1b 7e30315b to multi-key endof      \ F9
	 43 of 1b 7e31315b to multi-key endof      \ F10
	 44 of 1b 7e33315b to multi-key endof      \ F11
	 45 of 1b 7e34315b to multi-key endof      \ F12
	 47 of led-state ScrLk xor set-led false endof   \ ScrLk
	 49 of 1b 7e315b to multi-key endof        \ Ins
	 4a of 1b 7e325b to multi-key endof        \ Home
	 4b of 1b 7e335b to multi-key endof        \ PgUp
	 4c of 1b 7e345b to multi-key endof        \ Del
	 4d of 1b 7e355b to multi-key endof        \ End
	 4e of 1b 7e365b to multi-key endof        \ PgDn
	 4f of 1b 435b to multi-key endof          \ R-arrow
	 50 of 1b 445b to multi-key endof          \ L-arrow
	 51 of 1b 425b to multi-key endof          \ D-arrow
	 52 of 1b 415b to multi-key endof          \ U-arrow
	 53 of led-state NumLk xor set-led false endof   \ NumLk
	 54 of [char] / endof                      \ keypad / 
	 55 of [char] * endof                      \ keypad *
	 56 of [char] - endof                      \ keypad -
	 57 of [char] + endof                      \ keypad +
	 58 of 0d endof                            \ keypad Enter
	 89 of [char] \ endof	                   \ japanese yen
	 dup of false endof                        \ other keys are false
     endcase
     to ret                                        \ store char
     led-state CapsLk and 0 <> if                  \ if CapsLk is on
	 scancode 03 > if                          \ from a to z ?
	     scancode 1e < if
		 ret 20 - to ret                   \ to Upper case
	     then
	 then
     then
     is-shift if                                   \ if shift is on
	 scancode 03 > if                          \ from a to z ?
	     scancode 1e < if
		 ret 20 - to ret                   \ to Upper case
	     else
		 scancode
		 case                              \ translate scan code --> char
		     1e of [char] ! endof
		     1f of [char] @ endof
		     20 of [char] # endof
		     21 of [char] $ endof
		     22 of [char] % endof
		     23 of [char] ^ endof
		     24 of [char] & endof
		     25 of [char] * endof
		     26 of [char] ( endof
		     27 of [char] ) endof
		     2d of [char] _ endof
		     2e of [char] + endof
		     2f of [char] { endof
		     30 of [char] } endof
		     31 of [char] | endof
		     33 of [char] : endof
		     34 of [char] " endof
		     35 of [char] ~ endof
		     36 of [char] < endof
		     37 of [char] > endof
		     38 of [char] ? endof
		     dup of ret endof              \ other keys are no change
		 endcase
		 to ret                            \ overwrite new char    
	     then
	 then
     then
     led-state NumLk and 0 <> if                   \ if NumLk is on
       scancode 
       case                                        \ translate scan code --> char
	 59 of [char] 1 endof
	 5a of [char] 2 endof
	 5b of [char] 3 endof
	 5c of [char] 4 endof
	 5d of [char] 5 endof
	 5e of [char] 6 endof
	 5f of [char] 7 endof
	 60 of [char] 8 endof
	 61 of [char] 9 endof
	 62 of [char] 0 endof
	 63 of [char] . endof                      \ keypad .
	 dup of ret endof                          \ other keys are no change
       endcase
       to ret                                      \ overwirte new char
     then
     ret                                           \ return char
;

: key-available? ( -- true|false )
   multi-key 0 <> IF 
      true \ multi scan code key was pressed... so key is available
      EXIT \ done
   THEN
   kbd-scan 0 = IF \ if no kbd-scan code is currently available 
      int-get-report \ check for one using int-get-report 
   THEN
   kbd-scan 0 <> \ if a kbd-scan is available, report true, else false
;

: usb-kread ( -- char|false )                            \ usb key read for control transfer
    multi-key 0 <> if                                    \ if multi scan code key is pressed
	multi-key ff and                                 \ read one byte from buffer
	multi-key 8 rshift to multi-key                  \ move to next byte 
    else                                                 \ normal key check
    \ check for new scan code only, if kbd-scan is not set, e.g.
    \ by a previous call to key-available?
   kbd-scan 0 = IF
	\ if interrupt transfer
	int-get-report                                   \ read report (interrupt transfer)
	\ else control transfer
	\ ctl-get-report                                 \ read report (control transfer)
	\ end of interrupt/control switch
   THEN
 	kbd-scan 0 <> if                                 \ scan code exist?
	    begin kbd-scan ff and dup 00 = while         \ get a last scancode in report buffer
		    kbd-scan 8 rshift to kbd-scan        \ This algorithm is wrong --> must be fixed!
		    drop                                 \ KBD doesn't set scancode in pressed order!!!
	    repeat
	    dup key-old <> if                            \ if the scancode is new
	    	dup to key-old                           \ save current scan code
	    	get-ukbd-char                            \ translate scan code --> char
	    	milliseconds fa + to expire-ms           \ set typematic delay 250ms	    
	    else                                         \ scan code is not changed
	    	milliseconds expire-ms > if              \ if timer is expired ... should be considered timer carry over
	    	    get-ukbd-char                        \ translate scan code --> char
	    	    milliseconds 21 + to expire-ms       \ set typematic rate 30cps
	    	else                                     \ timer is not expired 
	    	    drop false                           \ do nothing
	    	then
	    then
       kbd-scan 8 rshift to kbd-scan \ handled scan-code
 	else
	    0 to key-old                                 \ clear privious key
	    false                                        \ no scan code --> return false
 	then
    then
;


: key-read ( -- char )
    0 begin drop usb-kread dup 0 <> until                \ read key input (Interrupt transfer)
;


: read ( addr len -- actual )
   0= IF drop 0 EXIT THEN
   usb-kread ?dup  IF  swap c! 1  ELSE  0 swap c! -2  THEN
;


kbd-init                                                 \ keyboard initialize
milliseconds to expire-ms                                \ Timer initialize
0 to multi-key                                           \ multi key buffer clear
7 set-led                                                \ flash leds
250 ms
0 set-led

s" keyboard" get-node node>path set-alias

: open ( -- true )
   7 set-led
   100 ms
   3 set-led
   100 ms
   1 set-led
   100 ms
   \ read once from keyboard before actually using it
   usb-kread drop
   0 set-led
   true
;

: close ;
