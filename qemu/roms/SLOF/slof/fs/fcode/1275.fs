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

0 value function-type    ' function-type @ constant <value>
  variable function-type ' function-type @ constant <variable>
0 constant function-type ' function-type @ constant <constant>
: function-type ;        ' function-type @ constant <colon>
create function-type     ' function-type @ constant <create>
defer function-type      ' function-type @ constant <defer>

\ variable tmp-buf-current
\ variable orig-here
\ create tmp-buf 10000 allot

( ---------------------------------------------------- )

: fcode-revision ( -- n )
  00030000 \ major * 65536 + minor
  ;

: b(lit) ( -- n )
  next-ip read-fcode-num32
  ?compile-mode IF literal, THEN
  ;

: b(")
  next-ip read-fcode-string
  ?compile-mode IF fc-string, align postpone count THEN
  ;

: b(')
  next-ip read-fcode# get-token drop ?compile-mode IF literal, THEN
  ;

: ?jump-direction ( n -- )
  dup 8000 >= IF FFFF swap - negate 2- THEN
  ;

: ?negative
  8000 and
  ;

: dest-on-top
  0 >r BEGIN dup @ 0= WHILE >r REPEAT
       BEGIN r> dup WHILE swap REPEAT 
  drop
  ;

: ?branch
  true =
  ;

: read-fcode-offset \ ELSE needs to be fixed!
  ?offset16 IF next-ip read-fcode-num16 ELSE THEN
  ;

: b?branch ( flag -- )
  ?compile-mode IF  
                    read-fcode-offset ?negative IF   dest-on-top postpone until
                                                ELSE postpone if
												THEN
                ELSE
					?branch IF   2 jump-n-ip
							ELSE read-fcode-offset
								 ?jump-direction 2- jump-n-ip
							THEN
                THEN
  ; immediate

: bbranch ( -- )
  ?compile-mode IF 
                     read-fcode-offset
					 ?negative IF   dest-on-top postpone again
							   ELSE postpone else
                     get-ip next-ip fcode@ B2 = IF drop ELSE set-ip THEN
							   THEN
				ELSE  
                     read-fcode-offset ?jump-direction 2- jump-n-ip
                THEN
  ; immediate

: b(<mark) ( -- )
  ?compile-mode IF postpone begin THEN
  ; immediate

: b(>resolve) ( -- )
  ?compile-mode IF postpone then THEN
  ; immediate

: ffwto; ( -- )
	BEGIN fcode@ dup c2 <> WHILE
." ffwto: skipping " dup . ." @ " get-ip . cr
		CASE	10 OF ( lit ) read-fcode-num32 drop ENDOF
			11 OF ( ' ) read-fcode# drop ENDOF
			12 OF ( " ) read-fcode-string 2drop ENDOF
			13 OF ( bbranch ) read-fcode-offset drop ENDOF
			14 OF ( b?branch ) read-fcode-offset drop ENDOF
			15 OF ( loop ) read-fcode-offset drop ENDOF
			16 OF ( +loop ) read-fcode-offset drop ENDOF
			17 OF ( do ) read-fcode-offset drop ENDOF
			18 OF ( ?do ) read-fcode-offset drop ENDOF
			1C OF ( of ) read-fcode-offset drop ENDOF
			C6 OF ( endof ) read-fcode-offset drop ENDOF
			C3 OF ( to ) read-fcode# drop ENDOF
			dup OF next-ip ENDOF
		ENDCASE
	REPEAT next-ip
;

: rpush ( rparm -- ) \ push the rparm to be on top of return stack after exit
	r> swap >r >r
;

: rpop ( -- rparm ) \ pop the rparm that was on top of return stack before this
	r> r> swap >r
;

: b1(;) ( -- )
." b1(;)" cr
  rpop set-ip 
;

\ : b1(:) ( -- )
\ ." b1(:)" cr
\ <colon> compile, get-ip 1+ literal ] get-ip rpush set-ip [
\ ffwto;
\   ; immediate

: b(;) ( -- )
  postpone exit reveal postpone [ 
  ; immediate

: b(:) ( -- )
  <colon> compile, ]
  ; immediate

: b(case) ( sel -- sel )
  postpone case
  ; immediate

: b(endcase)
  postpone endcase
  ; immediate

: b(of)
  postpone of
  read-fcode-offset drop   \ read and discard offset
  ; immediate

: b(endof)
  postpone endof
  read-fcode-offset drop   
  ; immediate

: b(do)
  postpone do
  read-fcode-offset drop   
  ; immediate

: b(?do)
  postpone ?do
  read-fcode-offset drop   
  ; immediate

: b(loop)
  postpone loop
  read-fcode-offset drop   
  ; immediate

: b(+loop)
  postpone +loop
  read-fcode-offset drop   
  ; immediate

: b(leave)
  postpone leave
  ; immediate

: new-token  \ unnamed local fcode function
  align here next-ip read-fcode# 0 swap set-token
  ;

: external-token ( -- )  \ named local fcode function 
  next-ip read-fcode-string
  header         ( str len -- )  \ create a header in the current dictionary entry
  new-token
  ;

: new-token
	eva-debug? IF
		s" x" get-ip >r next-ip read-fcode# r> set-ip (u.) $cat strdup
		header
	THEN new-token
;

: named-token  \ decide wether or not to give a new token an own name in the dictionary
  fcode-debug? IF new-token ELSE external-token THEN
  ;

: b(to) ( x -- )
  next-ip read-fcode#
  get-token drop
  >body cell -
  ?compile-mode IF literal, postpone !  ELSE !  THEN
  ; immediate

: b(value)
  <value> , , reveal
  ;

: b(variable)
  <variable> , 0 , reveal
  ;

: b(constant)
  <constant> , , reveal
  ;

: undefined-defer
  cr cr ." Unititialized defer word has been executed!" cr cr 
  true fcode-end !
  ;

: b(defer)
  <defer> , reveal
  postpone undefined-defer
  ;

: b(create)
  <variable> , 
  postpone noop reveal
  ;

: b(field) ( E: addr -- addr+offset ) ( F: offset size -- offset+size )
  <colon> , over literal,
  postpone + postpone exit
  +
  ;

: b(buffer:) ( E: -- a-addr) ( F: size -- )
  <variable> , allot
  ;

: suspend-fcode ( -- )
  noop        \ has to be implemented more efficiently ;-)
  ;

: offset16 ( -- )
  16 to fcode-offset
  ;

: version1 ( -- )
  1 to fcode-spread
  8 to fcode-offset
  read-header
  ;

: start0 ( -- )
  0 to fcode-spread
  offset16
  read-header
  ;
  
: start1 ( -- )
  1 to fcode-spread
  offset16
  read-header
  ;
    
: start2 ( -- )
  2 to fcode-spread
  offset16
  read-header
  ;

: start4 ( -- )
  4 to fcode-spread
  offset16
  read-header
  ;

: end0 ( -- ) 
  true fcode-end ! 
  ;

: end1 ( -- ) 
  end0 
  ;

: ferror ( -- )
  clear end0
  cr ." FCode# " fcode-num @ . ." not assigned!"
  cr ." FCode evaluation aborted." cr
  ." ( -- S:" depth . ." R:" rdepth . ." ) " .s cr
  abort
  ;

: reset-local-fcodes
  FFF 800 DO ['] ferror 0 i set-token LOOP
  ;

: byte-load ( addr xt -- )
  >r >r 
  save-evaluator-state
  r> r>
  reset-fcode-end
  1 to fcode-spread
  dup 1 = IF drop ['] rb@ THEN to fcode-rb@
  set-ip
  reset-local-fcodes
  depth >r
  evaluate-fcode
  r> depth 1- <> IF   clear end0 
                      cr ." Ambiguous stack depth after byte-load!"
                      cr ." FCode evaluation aborted." cr cr
				 ELSE restore-evaluator-state 
				 THEN
  ['] c@ to fcode-rb@                
  ;

create byte-load-test-fcode
f1 c, 08 c, 18 c, 69 c, 00 c, 00 c, 00 c, 68 c,
12 c, 16 c, 62 c, 79 c, 74 c, 65 c, 2d c, 6c c, 
6f c, 61 c, 64 c, 2d c, 74 c, 65 c, 73 c, 74 c, 
2d c, 66 c, 63 c, 6f c, 64 c, 65 c, 21 c, 21 c, 
90 c, 92 c, ( a6 c, a7 c, 2e c, ) 00 c,

: byte-load-test
  byte-load-test-fcode ['] w@
  ; immediate

: fcode-ms
    s" ms" $find IF 0= IF compile, ELSE execute THEN THEN ; immediate

: fcode-$find
  $find
  IF
    drop true
  ELSE
    false
  THEN    
  ;

( ---------------------------------------------------- )
