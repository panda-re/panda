
" /" find-device
  2 encode-int " #address-cells" property
  1 encode-int " #size-cells" property

  " sun4m" encode-string " compatible" property
  h# 0a21fe80 encode-int " clock-frequency" property

  : encode-unit encode-unit-sbus ;
  : decode-unit decode-unit-sbus ;

new-device
  " memory" device-name
  external
  : open true ;
  : close ;
  \ claim ( phys size align -- base )
  \ release ( phys size -- )
finish-device

new-device
  " virtual-memory" device-name
  external
  : open true ;
  : close ;
  \ claim ( phys size align -- base )
  \ release ( phys size -- )
finish-device

new-device
  " iommu" device-name
  2 encode-int " #address-cells" property
  1 encode-int " #size-cells" property
  h# 1000 encode-int " page-size" property
  0 encode-int " cache-coherence?" property
  external
  : open ( cr ." opening iommu" cr) true ;
  : close ;
  : encode-unit encode-unit-sbus ;
  : decode-unit decode-unit-sbus ;
finish-device

" /iommu" find-device
new-device
  " sbus" device-name
  " hierarchical" device-type
  2 encode-int " #address-cells" property
  1 encode-int " #size-cells" property
  h# 01443fd0 encode-int " clock-frequency" property
  h# 1c encode-int " slot-address-bits" property
  h# 3f encode-int " burst-sizes" property
  external
  : open ( cr ." opening SBus" cr) true ;
  : close ;
  : encode-unit encode-unit-sbus ;
  : decode-unit decode-unit-sbus ;
finish-device

[IFDEF] CONFIG_BPP
" /iommu/sbus" find-device
new-device
  " SUNW,bpp" device-name
  h# 4 encode-int h# 0c800000 encode-int encode+ h# 0000001c encode-int encode+ " reg" property
  h# 33 encode-int 0 encode-int encode+ " intr" property
finish-device
[THEN]

" /iommu/sbus" find-device
new-device
  " SUNW,tcx" device-name
  " display" device-type
  h# 1d encode-int " vbporch" property
  h# a0 encode-int " hbporch" property
  h# 06 encode-int " vsync" property
  h# 88 encode-int " hsync" property
  h# 03 encode-int " vfporch" property
  h# 18 encode-int " hfporch" property
  h# 03dfd240 encode-int " pixfreq" property
  h# 3c encode-int " vfreq" property
  h# 300 encode-int " height" property
  h# 400 encode-int " width" property
  h# 400 encode-int " linebytes" property
  5 encode-int 0 encode-int encode+ " intr" property
  5 encode-int " interrupts" property
finish-device

" /iommu/sbus" find-device
new-device
  " espdma" device-name
  external
  : encode-unit encode-unit-sbus ;
  : decode-unit decode-unit-sbus ;
finish-device

" /iommu/sbus" find-device
new-device
  " ledma" device-name
  h# 3f encode-int " burst-sizes" property
  external
  : encode-unit encode-unit-sbus ;
  : decode-unit decode-unit-sbus ;
finish-device

" /iommu/sbus/ledma" find-device
new-device
  " le" device-name
  " network" device-type
  h# 7 encode-int " busmaster-regval" property
  h# 26 encode-int 0 encode-int encode+ " intr" property
finish-device

\ obio (on-board IO)
" /" find-device
new-device
  " obio" device-name
  " hierarchical" device-type
  2 encode-int " #address-cells" property
  1 encode-int " #size-cells" property
  external
  : open ( cr ." opening obio" cr) true ;
  : close ;
  : encode-unit encode-unit-sbus ;
  : decode-unit decode-unit-sbus ;
finish-device

" /options" find-device
  " disk" encode-string " boot-from" property

" /openprom" find-device
  0 0 " aligned-allocator" property
