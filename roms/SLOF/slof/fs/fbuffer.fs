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

#include "terminal.fs"
#include "display.fs"

\ \\\\\\\\\\\\\\ Global Data

0 VALUE frame-buffer-adr
0 VALUE screen-height
0 VALUE screen-width
0 VALUE window-top
0 VALUE window-left

0 VALUE .sc
: screen-#rows .sc IF 18 ELSE true to .sc s" screen-#rows" eval false to .sc THEN ;
: screen-#columns .sc IF 50 ELSE true to .sc s" screen-#columns" eval false to .sc THEN ;

\ \\\\\\\\\\\\\\ Structure/Implementation Dependent Methods


\ \\\\\\\\\\\\\\ Implementation Independent Methods (Depend on Previous)
\ *
\ *

: fb8-background inverse-screen? ;
: fb8-foreground inverse? invert ;

: fb8-lines2bytes ( #lines -- #bytes ) char-height * screen-width * ;
: fb8-columns2bytes ( #columns -- #bytes ) char-width * ;
: fb8-line2addr ( line# -- addr )
	char-height * window-top + screen-width *
	frame-buffer-adr + window-left +
;

: fb8-erase-block ( addr len ) fb8-background rfill ;


0 VALUE .ab
CREATE bitmap-buffer 400 allot

: active-bits ( -- new ) .ab dup 8 > IF 8 - to .ab 8 ELSE
		char-width to .ab ?dup 0= IF recurse THEN
	THEN ;

: fb8-char2bitmap ( font-height font-addr -- bitmap-buffer )
	bitmap-buffer >r
	char-height rot 0> IF r> char-width 2dup fb8-erase-block + >r 1- THEN

	r> -rot char-width to .ab
	( fb-addr font-addr font-height )
	fontbytes * bounds ?DO
		i c@ active-bits 0 ?DO
			dup 80 and IF fb8-foreground ELSE fb8-background THEN
			( fb-addr fbyte colr ) 2 pick ! 1 lshift swap 1+ swap
		LOOP drop
	LOOP drop
	bitmap-buffer
;

\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ * IEEE 1275: Frame buffer support routines
\ *

: fb8-draw-logo ( line# addr width height -- ) ." fb8-draw-logo ( " .s ."  )" cr
	2drop 2drop
;

: fb8-toggle-cursor ( -- )
	line# fb8-line2addr column# fb8-columns2bytes +
	char-height 0 ?DO
		char-width 0 ?DO dup dup rb@ -1 xor swap rb! 1+ LOOP
		screen-width + char-width -
	LOOP drop
;

: fb8-draw-character ( char -- )
    >r default-font over + r@ -rot between IF
	2swap 3drop r> >font fb8-char2bitmap ( bitmap-buf )
	line# fb8-line2addr column# fb8-columns2bytes + ( bitmap-buf fb-addr )
	char-height 0 ?DO
		2dup char-width mrmove
		screen-width + >r char-width + r>
	LOOP 2drop
    ELSE 2drop r> 3drop THEN
;

: fb8-insert-lines ( n -- )
	fb8-lines2bytes >r line# fb8-line2addr dup dup r@ +
	#lines line# - fb8-lines2bytes r@ - rmove
	r> fb8-erase-block
;

: fb8-delete-lines ( n -- )
	fb8-lines2bytes >r line# fb8-line2addr dup dup r@ + swap
	#lines fb8-lines2bytes r@ - dup >r rmove
	r> + r> fb8-erase-block
;

: fb8-insert-characters ( n -- )
	line# fb8-line2addr column# fb8-columns2bytes + >r
	#columns column# - 2dup >= IF
		nip dup 0> IF fb8-columns2bytes r> ELSE r> 2drop EXIT THEN
	ELSE
		fb8-columns2bytes swap fb8-columns2bytes tuck -
		over r@ tuck + rot char-height 0 ?DO
			3dup rmove
			-rot screen-width tuck + -rot + swap rot
		LOOP
		3drop r>
	THEN
	char-height 0 ?DO dup 2 pick fb8-erase-block screen-width + LOOP 2drop
;

: fb8-delete-characters ( n -- )
	line# fb8-line2addr column# fb8-columns2bytes + >r
	#columns column# - 2dup >= IF
		nip dup 0> IF fb8-columns2bytes r> ELSE r> 2drop EXIT THEN
	ELSE
		fb8-columns2bytes swap fb8-columns2bytes tuck -
		over r@ + 2dup + r> swap >r rot char-height 0 ?DO
			3dup rmove
			-rot screen-width tuck + -rot + swap rot
		LOOP
		3drop r> over -
	THEN
	char-height 0 ?DO dup 2 pick fb8-erase-block screen-width + LOOP 2drop
;

: fb8-reset-screen ( -- ) ( Left as no-op by design ) ;

: fb8-erase-screen ( -- )
	frame-buffer-adr screen-height screen-width * fb8-erase-block
;

: fb8-invert-screen ( -- )
	frame-buffer-adr screen-height screen-width * 2dup /x / 0 ?DO
		dup rx@ -1 xor over rx! xa1+
	LOOP 3drop
;

: fb8-blink-screen ( -- ) fb8-invert-screen fb8-invert-screen ;

: fb8-install ( width height #columns #lines -- )
	screen-#rows min to #lines
	screen-#columns min to #columns
	dup to screen-height char-height #lines * - 2/ to window-top
	dup to screen-width char-width #columns * - 2/ to window-left
	['] fb8-toggle-cursor to toggle-cursor
	['] fb8-draw-character to draw-character
	['] fb8-insert-lines to insert-lines
	['] fb8-delete-lines to delete-lines
	['] fb8-insert-characters to insert-characters
	['] fb8-delete-characters to delete-characters
	['] fb8-erase-screen to erase-screen
	['] fb8-blink-screen to blink-screen
	['] fb8-invert-screen to invert-screen
	['] fb8-reset-screen to reset-screen
	['] fb8-draw-logo to draw-logo
;

\ \\\\\\\\\\\\ Debug Stuff \\\\\\\\\\\\\\\\

: fb8-dump-bitmap cr char-height 0 ?do char-width 0 ?do dup c@ if ." @" else ." ." then 1+ loop cr loop drop ;

: fb8-dump-char >font -b swap fb8-char2bitmap fb8-dump-bitmap ;


