\ tag: Other FCode functions
\ 
\ this code implements IEEE 1275-1994 ch. 5.3.7
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ The current diagnostic setting
defer _diag-switch?


\ 
\ 5.3.7 Other FCode functions
\ 

hex

\ 5.3.7.1 Peek/poke 

: cpeek    ( addr -- false | byte true )
  c@ true
  ;

: wpeek    ( waddr -- false | w true )
  w@ true
  ;

: lpeek    ( qaddr -- false | quad true )
  l@ true
  ;
  
: cpoke    ( byte addr -- okay? )
  c! true
  ;
  
: wpoke    ( w waddr -- okay? )
  w! true
  ;
  
: lpoke    ( quad qaddr -- okay? )
  l! true
  ;


\ 5.3.7.2 Device-register access

: rb@    ( addr -- byte )
  ;
  
: rw@    ( waddr -- w )
  ;
  
: rl@    ( qaddr -- quad )
  ;
  
: rb!    ( byte addr -- )
  ;
  
: rw!    ( w waddr -- )
  ;
  
: rl!    ( quad qaddr -- )
  ;

: rx@ ( oaddr - o )
  state @ if
    h# 22e get-token if , else execute then
  else
    h# 22e get-token drop execute
  then
  ; immediate

: rx! ( o oaddr -- )
  state @ if
    h# 22f get-token if , else execute then
  else
    h# 22f get-token drop execute
  then
  ; immediate
 
\ 5.3.7.3 Time

0 value dummy-msecs

: get-msecs    ( -- n )
  dummy-msecs dup 1+ to dummy-msecs
  ;
  
: ms    ( n -- )
  get-msecs +
  begin dup get-msecs < until
  drop
  ;
  
: alarm    ( xt n -- )
  2drop
  ;
  
: user-abort    ( ... -- )  ( R: ... -- )
  ;


\ 5.3.7.4 System information
0003.0000 value fcode-revision    ( -- n )
  
: mac-address    ( -- mac-str mac-len )
  ;


\ 5.3.7.5 FCode self-test
: display-status    ( n -- )
  ;
  
: memory-test-suite ( addr len -- fail? )
  ;
  
: mask    ( -- a-addr )
  ;
  
: diagnostic-mode?     ( -- diag? )
  \ Return the NVRAM diag-switch? setting
  _diag-switch?
  ;
  
\ 5.3.7.6 Start and end.

\ Begin program with spread 0 followed by FCode-header.
: start0 ( -- )
  0 fcode-spread !
  offset16
  fcode-header 
  ;

\ Begin program with spread 1 followed by FCode-header.  
: start1 ( -- )
  1 to fcode-spread
  offset16
  fcode-header 
  ;
  
\ Begin program with spread 2 followed by FCode-header.
: start2 ( -- )
  2 to fcode-spread
  offset16
  fcode-header 
  ;

\ Begin program with spread 4 followed by FCode-header.
: start4 ( -- )
  4 to fcode-spread
  offset16
  fcode-header 
  ;
 
\ Begin program with spread 1 followed by FCode-header. 
: version1 ( -- )
  1 to fcode-spread
  fcode-header 
  ;

\ Cease evaluating this FCode program.
: end0 ( -- )
  true fcode-end !  
  ;

\ Cease evaluating this FCode program.
: end1 ( -- )
  end0 
  ;

\ Standard FCode number for undefined FCode functions.
: ferror ( -- )
  ." undefined fcode# encountered." cr 
  true fcode-end !
  ;

\ Pause FCode evaluation if desired; can resume later.
: suspend-fcode ( -- )
  \ NOT YET IMPLEMENTED.
  ;


\ Evaluate FCode beginning at location addr.

\ : byte-load ( addr xt -- )
\   \ this word is implemented in feval.fs
\   ;

\ Set address and arguments of new device node.
: set-args ( arg-str arg-len unit-str unit-len -- ) 
  ?my-self drop

  depth 1- >r
  " decode-unit" ['] $call-parent catch if
    2drop 2drop
  then
  
  my-self ihandle>phandle >dn.probe-addr \ offset
  begin depth r@ > while
    dup na1+ >r ! r>
  repeat
  r> 2drop

  my-self >in.arguments 2@ free-mem
  strdup my-self >in.arguments 2!
;

: dma-alloc
  s" dma-alloc" $call-parent
  ;
