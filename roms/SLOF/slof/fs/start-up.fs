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

: (boot) ( -- )
   s" Executing following boot-command: "
   boot-command $cat nvramlog-write-string-cr
   s" boot-command" evaluate      \ get boot command
   ['] evaluate catch ?dup IF     \ and execute it
      ." boot attempt returned: "
      abort"-str @ count type cr
      nip nip                     \ drop string from 1st evaluate
      throw
   THEN
;

\ Note: The following ESC sequences has to be handled:
\     1B 4F 50
\     1B 5B 31 31 7E

\ Reads and converts the function key.
\ key = F1 -- n = 1
: (function-key) ( -- n )
   key? IF
      key CASE
	 50  OF 1 ENDOF
	 7e  OF 1 ENDOF
	 dup OF 0 ENDOF
      ENDCASE
   THEN
;

\ Checks if an ESC sequence occurs.
: (esc-sequence) ( -- n )
   key? IF
      key CASE
	  4f  OF (function-key) ENDOF
	  5b  OF
	     key key drop (function-key) ENDOF
	  dup OF 0 ENDOF
       ENDCASE
   THEN
;

: (s-pressed) ( -- )
   s" An 's' has been pressed. Entering Open Firmware Prompt"
   nvramlog-write-string-cr
;

: (boot?) ( -- )
   of-prompt? not auto-boot? and IF
      (boot)
   THEN
;


#include "sms/sms-load.fs"


\ Watchdog will be rearmed during load if use-load-watchdog variable is TRUE
TRUE VALUE use-load-watchdog?


: start-it ( -- )
   key? IF
      key CASE
	 [char] s  OF (s-pressed) ENDOF
	 1b        OF

	    (esc-sequence) CASE
	       1   OF console-clean-fifo sms-start (boot) ENDOF
	       dup OF (boot?) ENDOF
	    ENDCASE

	 ENDOF
	 dup OF (boot?) ENDOF
      ENDCASE
   ELSE
      (boot?)
   THEN

   disable-watchdog  FALSE to use-load-watchdog?
   .banner
;
