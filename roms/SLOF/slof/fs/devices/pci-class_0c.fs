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

s" serial bus [ " type my-space pci-class-name type s"  ]" type cr

my-space pci-device-generic-setup


\ Handle USB OHCI controllers:
: handle-usb-ohci-class  ( -- )
   \ set Memory Write and Invalidate Enable, SERR# Enable
   \ (see PCI 3.0 Spec Chapter 6.2.2 device control):
   4 config-w@ 110 or 4 config-w!
   pci-master-enable               \ set PCI Bus master bit and
   pci-mem-enable                  \ memory space enable for USB scan
   10 config-l@                    \ get base address on stack for usb-ohci.fs
                                   \ TODO: Use translate-address here
   s" usb-ohci.fs" included
;

\ Check PCI sub-class and interface type of Serial Bus Controller
\ to include the appropriate driver:
: handle-sbc-subclass  ( -- )
   my-space pci-class@ ffff and CASE         \ get PCI sub-class and interface
      0310 OF handle-usb-ohci-class ENDOF    \ USB OHCI controller
   ENDCASE
;

handle-sbc-subclass

