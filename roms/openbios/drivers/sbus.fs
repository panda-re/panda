\ -------------------------------------------------------------------------
\ SBus encode/decode unit
\ -------------------------------------------------------------------------

: decode-unit-sbus ( str len -- id lun )
  ascii , left-split
  ( addr-R len-R addr-L len-L )
  parse-hex
  -rot parse-hex
  swap
;

: encode-unit-sbus ( id lun -- str len)
  swap
  pocket tohexstr
  " ," pocket tmpstrcat >r
  rot pocket tohexstr r> tmpstrcat drop
;
