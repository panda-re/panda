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

\ big-endian

( ---------------------------------------------------- )

: read-fcode-num16 ( -- n )
  0 fcode-num !
  ?arch64 IF
                       read-byte fcode-num 6 + C!
               next-ip read-byte fcode-num 7 + C!
          ELSE
                       read-byte fcode-num 2 + C!
               next-ip read-byte fcode-num 3 + C!
		  THEN
  fcode-num @
  ;

: read-fcode-num32 ( -- n )
  0 fcode-num !
  ?arch64 IF
					  read-byte fcode-num 4 + C!
			  next-ip read-byte fcode-num 5 + C!
			  next-ip read-byte fcode-num 6 + C!
			  next-ip read-byte fcode-num 7 + C!
          ELSE
					  read-byte fcode-num 0 + C!
			  next-ip read-byte fcode-num 1 + C!
			  next-ip read-byte fcode-num 2 + C!
			  next-ip read-byte fcode-num 3 + C!
		  THEN
  fcode-num @
  ;

( ---------------------------------------------------- )
