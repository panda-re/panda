\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ PAPR hvterm console.  Enabled very early.

: hvterm-emit  hv-putchar ;
: hvterm-key?  hv-haschar ;
: hvterm-key   BEGIN hvterm-key? UNTIL hv-getchar ;

' hvterm-emit to emit
' hvterm-key  to key
' hvterm-key? to key?

\ Override serial methods to make term-io.fs happy
: serial-emit hvterm-emit ;
: serial-key? hvterm-key? ;
: serial-key  hvterm-key  ;
