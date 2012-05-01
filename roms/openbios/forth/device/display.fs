\ tag: Display device management
\ 
\ this code implements IEEE 1275-1994 ch. 5.3.6
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

hex 

\ 
\ 5.3.6.1 Terminal emulator routines
\ 

\ The following values are used and set by the terminal emulator
\ defined and described in 3.8.4.2
0 value line# ( -- line# )
0 value column# ( -- column# )
0 value inverse? ( -- white-on-black? )
0 value inverse-screen? ( -- black? )
0 value #lines ( -- rows )
0 value #columns ( -- columns )

\ The following values are used internally by both the 1-bit and the 
\ 8-bit frame-buffer support routines.
  
0 value frame-buffer-adr ( -- addr )
0 value screen-height    ( -- height )
0 value screen-width     ( -- width )
0 value window-top       ( -- border-height )
0 value window-left      ( -- border-width )
0 value char-height      ( -- height )
0 value char-width       ( -- width )
0 value fontbytes        ( -- bytes )

\ these values are used internally and do not represent any
\ official open firmware words
0 value char-min
0 value char-num
0 value font

0 value foreground-color
0 value background-color


\ The following wordset is called the "defer word interface" of the 
\ terminal-emulator support package. It gets overloaded by fb1-install
\ or fb8-install (initiated by the framebuffer fcode driver)

defer draw-character    ( char -- )
defer reset-screen      ( -- )
defer toggle-cursor     ( -- )
defer erase-screen      ( -- )
defer blink-screen      ( -- )
defer invert-screen     ( -- )
defer insert-characters ( n -- )
defer delete-characters ( n -- )
defer insert-lines ( n -- )
defer delete-lines ( n -- )
defer draw-logo ( line# addr width height -- )

defer fb-emit ( x -- )

\ 
\ 5.3.6.2 Frame-buffer support routines
\ 

: default-font ( -- addr width height advance min-char #glyphs )
  \ (romfont-8x16) 8 10 10 0 100
  ;

: set-font ( addr width height advance min-char #glyphs -- )
  to char-num
  to char-min
  to fontbytes
  to char-height
  to char-width
  to font
  ;

: >font ( char -- addr )
  char-min - 
  char-num min
  fontbytes *
  font +
  ;

\ 
\ 5.3.6.3 Display device support
\ 

\ 
\ 5.3.6.3.1 Frame-buffer package interface
\ 

: is-install    ( xt -- )
  external
  \ Create open and other methods for this display device.
  \ Methods to be created: open, write, draw-logo, restore
  s" open" header 
  1 , \ colon definition
  ,
  ['] (semis) ,
  reveal
  s" : write dup >r bounds do i c@ fb-emit loop r> ; " evaluate
  s" : draw-logo draw-logo ; " evaluate
  s" : restore reset-screen ; " evaluate
  ;

: is-remove    ( xt -- )
  external
  \ Create close method for this display device.
  s" close" header 
  1 , \ colon definition
  ,
  ['] (semis) ,
  reveal
  ;
  
: is-selftest    ( xt -- )
  external
  \ Create selftest method for this display device.
  s" selftest" header 
  1 , \ colon definition
  ,
  ['] (semis) ,
  reveal
  ;


\ 5.3.6.3.2 Generic one-bit frame-buffer support (optional)

: fb1-nonimplemented
  ." Monochrome framebuffer support is not implemented." cr
  end0
  ;

: fb1-draw-character	fb1-nonimplemented ; \ historical
: fb1-reset-screen	fb1-nonimplemented ;
: fb1-toggle-cursor	fb1-nonimplemented ;
: fb1-erase-screen	fb1-nonimplemented ;
: fb1-blink-screen	fb1-nonimplemented ;
: fb1-invert-screen	fb1-nonimplemented ;
: fb1-insert-characters fb1-nonimplemented ;
: fb1-delete-characters	fb1-nonimplemented ;
: fb1-insert-lines	fb1-nonimplemented ;
: fb1-delete-lines	fb1-nonimplemented ;
: fb1-slide-up		fb1-nonimplemented ;
: fb1-draw-logo		fb1-nonimplemented ;
: fb1-install		fb1-nonimplemented ;

  
\ 5.3.6.3.3 Generic eight-bit frame-buffer support

\ The following two functions are unrolled for speed.


\ blit 8 continuous pixels described by the 8bit
\ value in bitmask8. The most significant bit is
\ painted first. 

\ this function should honour fg and bg colors

: fb8-write-mask8 ( bitmask8 faddr -- )
  over 1  and 0<> over 7 + c!
  over 2  and 0<> over 6 + c!
  over 4  and 0<> over 5 + c!
  over 8  and 0<> over 4 + c!
  over 10 and 0<> over 3 + c!
  over 20 and 0<> over 2 + c!
  over 40 and 0<> over 1 + c!
  over 80 and 0<> over 0 + c!
  2drop
  ; 

: fb8-blitmask ( fbaddr mask-addr width height --  )
  over >r          \ save width ( -- R: width )
  * 3 >>           \ fbaddr mask-addr width*height/8
  bounds           \ fbaddr mask-end mask
  r> 0 2swap       \ fbaddr width 0 mask-end mask
  ?do              \ ( fbaddr width l-cnt )
    2 pick over +  \ fbaddr-current
    i c@           \ bitmask8 
    swap fb8-write-mask8
    ( fbaddr width l-cnt )
    8 + 2dup = if
      drop swap screen-width + 
      swap 0
    then
    ( fbaddr width l-cnt )
  loop
  2drop drop
  ;

: fb8-line2addr ( line -- addr )
  window-top +
  screen-width * 
  frame-buffer-adr + 
  window-left +
;
  
: fb8-copy-line ( from to -- )
  fb8-line2addr swap 
  fb8-line2addr swap 
  #columns char-width * move
;

: fb8-clear-line ( line -- )
  fb8-line2addr 
  #columns char-width * 
  background-color fill
\ 0 fill
;
  
: fb8-draw-character ( char -- )
  \ draw the character:
  >font  
  line# char-height * window-top + screen-width *
  column# char-width * window-left + + frame-buffer-adr +
  swap char-width char-height
  fb8-blitmask
  \ now advance the position
  column# 1+
  dup #columns = if
    drop 0 to column#
    line# 1+ 
    dup #lines = if
      drop 
      \ FIXME move up screen (and keep position)
    else
      to #lines 
    then
  else
    to column#
  then
  ;

: fb8-reset-screen ( -- )
  false to inverse?
  false to inverse-screen?
  0 to foreground-color 
  d# 15 to background-color
  ;

: fb8-toggle-cursor ( -- )
  line# char-height * window-top + screen-width *
  column# char-width * window-left + + frame-buffer-adr +
  char-height 0 ?do
    char-width 0 ?do
      dup i + dup c@ invert ff and swap c!
    loop
    screen-width +
  loop
  drop
  ;

: fb8-erase-screen ( -- )
  frame-buffer-adr 
  screen-height screen-width * 
  inverse-screen? if
    foreground-color
  else
    background-color
  then
  fill
  ;

: fb8-invert-screen ( -- )
  frame-buffer-adr
  screen-height screen-width * 
  bounds ?do
    i c@ case
      foreground-color of background-color endof
      background-color of foreground-color endof
      dup
    endcase
    i c!
  loop
  ;

: fb8-blink-screen ( -- )
  fb8-invert-screen fb8-invert-screen
  ;
  
: fb8-insert-characters ( n -- )
  ;
  
: fb8-delete-characters ( n -- )
  ;

: fb8-insert-lines ( n -- )
  ;
  
: fb8-delete-lines ( n -- )
  \ numcopy = ( #lines - ( line# + n )) * char-height
  #lines over #line + - char-height *

  ( numcopy ) 0 ?do
    dup line# + char-height * i +
    line# char-height * i +
    swap fb8-copy-line
  loop

  #lines over - char-height *
  over char-height *
  0 ?do
    dup i + fb8-clear-line
  loop
  
  2drop
;


: fb8-draw-logo ( line# addr width height -- )
  2swap swap
  char-height  * window-top  + 
  screen-width * window-left +
  frame-buffer-adr + 
  swap 2swap
  \ in-fb-start-adr logo-adr logo-width logo-height 

  fb8-blitmask ( fbaddr mask-addr width height --  )
;


: fb8-install ( width height #columns #lines -- )

  \ set state variables
  to #lines
  to #columns
  to screen-height
  to screen-width

  screen-width #columns char-width * - 2/ to window-left
  screen-height #lines char-height * - 2/ to window-top
  
  0 to column#
  0 to line#
  0 to inverse? 
  0 to inverse-screen?

  \ set defer functions to 8bit versions

  ['] fb8-draw-character to draw-character
  ['] fb8-toggle-cursor to toggle-cursor
  ['] fb8-erase-screen to erase-screen
  ['] fb8-blink-screen to blink-screen
  ['] fb8-invert-screen to invert-screen
  ['] fb8-insert-characters to insert-characters
  ['] fb8-delete-characters to delete-characters
  ['] fb8-insert-lines to insert-lines
  ['] fb8-delete-lines to delete-lines
  ['] fb8-draw-logo to draw-logo
  ['] fb8-reset-screen to reset-screen

  \ recommended practice
  s" iso6429-1983-colors" get-my-property if
    0 ff
  else
    2drop d# 15 0
  then
  to foreground-color to background-color

;
