\ *****************************************************************************
\ * Copyright (c) 2004, 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/


\ Support for device node instances.

0 VALUE my-self

: >instance
   my-self 0= ABORT" No instance!"
   my-self +
;

: (create-instance-var) ( initial-value -- )
   get-node ?dup 0= ABORT" Instance word outside device context!"
   dup node>extending? @ 0=
   my-self 0<> AND ABORT" INSTANCE word can not be used while node is opened!"
   dup node>instance @      ( iv phandle tmp-ihandle )
   swap node>instance-size dup @     ( iv tmp-ih *instance-size instance-size )
   dup ,                             \ compile current instance ptr
   swap 1 cells swap +!              ( iv tmp-ih instance-size )
   + !
;

: create-instance-var ( "name" initial-value -- )
  CREATE (create-instance-var) PREVIOUS ;

VOCABULARY instance-words  ALSO instance-words DEFINITIONS

: VARIABLE  0 create-instance-var DOES> [ here ] @ >instance ;
: VALUE       create-instance-var DOES> [ here ] @ >instance @ ;
: DEFER     0 create-instance-var DOES> [ here ] @ >instance @ execute ;
\ No support for BUFFER: yet.

PREVIOUS DEFINITIONS

\ Save XTs of the above instance-words (put on the stack with "[ here ]")
CONSTANT <instancedefer>
CONSTANT <instancevalue>
CONSTANT <instancevariable>

\ check whether a value or a defer word is an
\ instance word: It must be a CREATE word and
\ the DOES> part must do >instance as first thing

: (instance?) ( xt -- xt true|false )
   dup @ <create> = IF
      dup cell+ @ cell+ @ ['] >instance =
   ELSE
      false
   THEN
;

\ This word does instance values in compile mode.
\ It corresponds to DOTO from engine.in
: (doito) ( value R:*CFA -- )
   r> cell+ dup >r
   @ cell+ cell+ @ >instance !
;

: to ( value wordname<> -- )
   ' (instance?)
   state @ IF
      \ compile mode handling normal or instance value
      IF ['] (doito) ELSE ['] DOTO THEN
      , , EXIT
   THEN
   IF
      cell+ cell+ @ >instance ! \ interp mode instance value
   ELSE
      cell+ !                   \ interp mode normal value
   THEN
; IMMEDIATE

: INSTANCE  ALSO instance-words ;


STRUCT
/n FIELD instance>node
/n FIELD instance>parent
/n FIELD instance>args
/n FIELD instance>args-len
CONSTANT /instance-header

: my-parent  my-self instance>parent @ ;
: my-args    my-self instance>args 2@ ;

\ copy args from original instance to new created
: set-my-args   ( old-addr len -- )
   dup IF                             \ IF len > 0                    ( old-addr len )
      dup alloc-mem                   \ | allocate space for new args ( old-addr len new-addr )
      swap 2dup                       \ | write the new address       ( old-addr new-addr len new-addr len )
      my-self instance>args 2!        \ | into the instance table     ( old-addr new-addr len )
      move                            \ | and copy the args           ( -- )
   ELSE                               \ ELSE                          ( old-addr len )
      my-self instance>args 2!        \ | set new args to zero, too   ( )
   THEN                               \ FI
;

\ Current node has already been set, when this is called.
: create-instance-data ( -- instance )
   get-node dup node>instance @ swap node>instance-size @  ( instance instance-size )
   dup alloc-mem dup >r swap move r>
;
: create-instance ( -- )
   my-self create-instance-data
   dup to my-self instance>parent !
   get-node my-self instance>node !
;

: destroy-instance ( instance -- )
   dup @ node>instance-size @ free-mem
;

: ihandle>phandle ( ihandle -- phandle )
   dup 0= ABORT" no current instance" instance>node @
;

: push-my-self ( ihandle -- )  r> my-self >r >r to my-self ;
: pop-my-self ( -- )  r> r> to my-self >r ;
: call-package  push-my-self execute pop-my-self ;
: $call-static ( ... str len node -- ??? )
\  cr ." call for " 3dup -rot type ."  on node " .
   find-method IF execute ELSE -1 throw THEN
;
: $call-my-method  ( str len -- ) my-self ihandle>phandle $call-static ;
: $call-method  push-my-self $call-my-method pop-my-self ;
: $call-parent  my-parent $call-method ;
