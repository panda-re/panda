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


s" mouse" device-name
s" mouse" device-type

."   USB Mouse" cr

1 encode-int s" configuration#" property
2 encode-int s" #buttons" property
4 encode-int s" assigned-addresses" property
2 encode-int s" reg" property

: open true ;
: close ;
: get-event ( msec -- pos.x pos.y buttons true|false )
;

