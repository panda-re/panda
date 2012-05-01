[IFDEF] CONFIG_DRIVER_PCI

: pci-addr-encode ( addr.lo addr.mi addr.hi )
  rot >r swap >r 
  encode-int 
  r> encode-int encode+ 
  r> encode-int encode+
  ;
 
: pci-len-encode ( len.lo len.hi )
  encode-int 
  rot encode-int encode+ 
  ;

[THEN]
