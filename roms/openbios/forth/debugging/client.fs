\ 7.6 Client Program Debugging command group


\ 7.6.1    Registers display

: ctrace    ( -- )
  ;
  
: .registers    ( -- )
  ;

: .fregisters    ( -- )
  ;

\ to    ( param [old-name< >] -- )


\ 7.6.2    Program download and execute

struct ( saved-program-state )
  /n field >sps.entry
  /n field >sps.file-size
  /n field >sps.file-type
constant saved-program-state.size
create saved-program-state saved-program-state.size allot

variable state-valid
0 state-valid !

variable file-size

: !load-size file-size ! ;

: load-size file-size @ ;


\ File types identified by (init-program)

0  constant elf-boot
1  constant elf
2  constant bootinfo
3  constant xcoff
4  constant pe
5  constant aout
10 constant fcode
11 constant forth


: init-program    ( -- )
  \ Call down to the lower level for relocation etc.
  s" (init-program)" $find if
    execute
  else
    s" Unable to locate (init-program)!" type cr
  then
  ;

: (encode-bootpath) ( param-str param-len -- bootpath-str bootpath-len)
  \ Parse the <param> string from a load/boot command and set both
  \ the bootargs and bootpath properties as appropriate.

  \ bootpath
  bl left-split 	\ argstr argstr-len bootdevstr bootdevstr-len
  dup 0= if

    \ None specified. As per IEEE-1275 specification, search through each value
    \ in boot-device and use the first that returns a valid ihandle on open.

    2drop		\ drop the empty device string as we're going to use our own

    s" boot-device" $find drop execute 
    bl left-split
    begin 
      dup 
    while
      2dup s" Trying " type type s" ..." type cr
      2dup open-dev ?dup if
        close-dev
	2swap drop 0	\ Fake end of string so we exit loop
      else
        2drop
        bl left-split
      then
    repeat
    2drop
  then

  \ Set the bootpath property
  2dup encode-string
  " /chosen" (find-dev) if
    " bootpath" rot (property)
  then

  \ bootargs
  2swap dup 0= if
    \ None specified, use default from nvram
    2drop s" boot-file" $find drop execute
  then

  \ Set the bootargs property
  encode-string
  " /chosen" (find-dev) if
    " bootargs" rot (property)
  then
;

: $load ( devstr len )
  open-dev ( ihandle )
  dup 0= if
    drop
    exit
  then
  dup >r
  " load-base" evaluate swap ( load-base ihandle )
  dup ihandle>phandle " load" rot find-method ( xt 0|1 )
  if swap call-package !load-size else cr ." Cannot find load for this package" 2drop then
  r> close-dev
  init-program
  ;

: load    ( "{params}<cr>" -- )
  linefeed parse
  (encode-bootpath)
  $load
;

: dir ( "{paths}<cr>" -- )
  linefeed parse
  split-path-device
  open-dev dup 0= if
    drop
    exit
  then
  -rot 2 pick
  " dir" rot ['] $call-method catch
  if
    3drop
    cr ." Cannot find dir for this package"
  then
  close-dev
;

: go    ( -- )
  state-valid @ not if
    s" No valid state has been set by load or init-program" type cr
    exit 
  then

  \ Call the architecture-specific code to launch the client image
  s" (go)" $find if
    execute
  else
    ." go is not yet implemented"
    2drop
  then
  ;


\ 7.6.3    Abort and resume

\ already defined !?
\ : go    ( -- )
\   ;

  
\ 7.6.4    Disassembler

: dis    ( addr -- )
  ;
  
: +dis    ( -- )
  ;

\ 7.6.5    Breakpoints
: .bp    ( -- )
  ;

: +bp    ( addr -- )
  ;

: -bp    ( addr -- )
  ;

: --bp    ( -- )
  ;

: bpoff    ( -- )
  ;

: step    ( -- )
  ;

: steps    ( n -- )
  ;

: hop    ( -- )
  ;

: hops    ( n -- )
  ;

\ already defined
\ : go    ( -- )
\   ;

: gos    ( n -- )
  ;

: till    ( addr -- )
  ;

: return    ( -- )
  ;

: .breakpoint    ( -- )
  ;

: .step    ( -- )
  ;

: .instruction    ( -- )
  ;


\ 7.6.6    Symbolic debugging
: .adr    ( addr -- )
  ;

: sym    ( "name< >" -- n )
  ;

: sym>value    ( addr len -- addr len false | n true )
  ;

: value>sym    ( n1 -- n1 false | n2 addr len true )
  ;
