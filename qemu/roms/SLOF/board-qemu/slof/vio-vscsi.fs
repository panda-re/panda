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

." Populating " pwd

0 CONSTANT vscsi-debug

0 VALUE vscsi-unit

\ -----------------------------------------------------------
\ Direct DMA conversion hack
\ -----------------------------------------------------------
: l2dma ( laddr - dma_addr)      
;

\ -----------------------------------------------------------
\ CRQ related functions
\ -----------------------------------------------------------

0    VALUE     crq-base
0    VALUE     crq-dma
0    VALUE     crq-offset
1000 CONSTANT  CRQ-SIZE

CREATE crq 10 allot

: crq-alloc ( -- )
    \ XXX We rely on SLOF alloc-mem being aligned
    CRQ-SIZE alloc-mem to crq-base 0 to crq-offset
    crq-base l2dma to crq-dma
;

: crq-free ( -- )
    vscsi-unit hv-free-crq
    crq-base CRQ-SIZE free-mem 0 to crq-base
;

: crq-init ( -- res )
    \ Allocate CRQ. XXX deal with fail
    crq-alloc

    vscsi-debug IF
        ." VSCSI: allocated crq at " crq-base . cr
    THEN

    \ Clear buffer
    crq-base CRQ-SIZE erase

    \ Register with HV
    vscsi-unit crq-dma CRQ-SIZE hv-reg-crq

    \ Fail case
    dup 0 <> IF
        ." VSCSI: Error " . ."  registering CRQ !" cr
	crq-free
    THEN
;

: crq-cleanup ( -- )
    crq-base 0 = IF EXIT THEN

    vscsi-debug IF
        ." VSCSI: freeing crq at " crq-base . cr
    THEN
    crq-free
;

: crq-send ( msgaddr -- true | false )
    vscsi-unit swap hv-send-crq 0 =
;

: crq-poll ( -- true | false)
    crq-offset crq-base + dup
    vscsi-debug IF
        ." VSCSI: crq poll " dup .
    THEN
    c@
    vscsi-debug IF
        ."  value=" dup . cr
    THEN
    80 and 0 <> IF
        dup crq 10 move
	0 swap c!
	crq-offset 10 + dup CRQ-SIZE >= IF drop 0 THEN to crq-offset
	true
    ELSE drop false THEN
;

: crq-wait ( -- true | false)
    \ FIXME: Add timeout
    0 BEGIN drop crq-poll dup not WHILE d# 1 ms REPEAT
    dup not IF
        ." VSCSI: Timeout waiting response !" cr EXIT
    ELSE
        vscsi-debug IF
            ." VSCSI: got crq: " crq dup l@ . ."  " 4 + dup l@ . ."  "
	    4 + dup l@ . ."  " 4 + l@ . cr
        THEN
    THEN
;

\ -----------------------------------------------------------
\ CRQ encapsulated SRP definitions
\ -----------------------------------------------------------

01 CONSTANT VIOSRP_SRP_FORMAT
02 CONSTANT VIOSRP_MAD_FORMAT
03 CONSTANT VIOSRP_OS400_FORMAT
04 CONSTANT VIOSRP_AIX_FORMAT
06 CONSTANT VIOSRP_LINUX_FORMAT
07 CONSTANT VIOSRP_INLINE_FORMAT

struct
   1 field >crq-valid
   1 field >crq-format
   1 field >crq-reserved
   1 field >crq-status
   2 field >crq-timeout
   2 field >crq-iu-len
   8 field >crq-iu-data-ptr
constant /crq

: srp-send-crq ( addr len -- )
    80                crq >crq-valid c!
    VIOSRP_SRP_FORMAT crq >crq-format c!
    0                 crq >crq-reserved c!
    0                 crq >crq-status c!
    0                 crq >crq-timeout w!
    ( len )           crq >crq-iu-len w!
    ( addr ) l2dma    crq >crq-iu-data-ptr x!
    crq crq-send
    not IF
        ." VSCSI: Error sending CRQ !" cr
    THEN
;

: srp-wait-crq ( -- [tag true] | false )
    crq-wait not IF false EXIT THEN

    crq >crq-format c@ VIOSRP_SRP_FORMAT <> IF
    	." VSCSI: Unsupported SRP response: "
	crq >crq-format c@ . cr
	false EXIT
    THEN

    crq >crq-iu-data-ptr x@ true
;

\ Add scsi functions to dictionary
scsi-open


\ -----------------------------------------------------------
\ SRP definitions
\ -----------------------------------------------------------

0 VALUE >srp_opcode

00 CONSTANT SRP_LOGIN_REQ
01 CONSTANT SRP_TSK_MGMT
02 CONSTANT SRP_CMD
03 CONSTANT SRP_I_LOGOUT
c0 CONSTANT SRP_LOGIN_RSP
c1 CONSTANT SRP_RSP
c2 CONSTANT SRP_LOGIN_REJ
80 CONSTANT SRP_T_LOGOUT
81 CONSTANT SRP_CRED_REQ
82 CONSTANT SRP_AER_REQ
41 CONSTANT SRP_CRED_RSP
42 CONSTANT SRP_AER_RSP

02 CONSTANT SRP_BUF_FORMAT_DIRECT
04 CONSTANT SRP_BUF_FORMAT_INDIRECT

struct
   1 field >srp-login-opcode
   3 +
   8 field >srp-login-tag
   4 field >srp-login-req-it-iu-len
   4 +
   2 field >srp-login-req-buf-fmt
   1 field >srp-login-req-flags
   5 +
  10 field >srp-login-init-port-ids
  10 field >srp-login-trgt-port-ids
constant /srp-login

struct
   1 field >srp-lresp-opcode
   3 +
   4 field >srp-lresp-req-lim-delta
   8 field >srp-lresp-tag
   4 field >srp-lresp-max-it-iu-len
   4 field >srp-lresp-max-ti-iu-len
   2 field >srp-lresp-buf-fmt
   1 field >srp-lresp-flags
constant /srp-login-resp

struct
   1 field >srp-lrej-opcode
   3 +
   4 field >srp-lrej-reason
   8 field >srp-lrej-tag
   8 +
   2 field >srp-lrej-buf-fmt
constant /srp-login-rej

00 CONSTANT SRP_NO_DATA_DESC
01 CONSTANT SRP_DATA_DESC_DIRECT
02 CONSTANT SRP_DATA_DESC_INDIRECT

struct
    1 field >srp-cmd-opcode
    1 field >srp-cmd-sol-not
    3 +
    1 field >srp-cmd-buf-fmt
    1 field >srp-cmd-dout-desc-cnt
    1 field >srp-cmd-din-desc-cnt
    8 field >srp-cmd-tag
    4 +
    8 field >srp-cmd-lun
    1 +
    1 field >srp-cmd-task-attr
    1 +
    1 field >srp-cmd-add-cdb-len
   10 field >srp-cmd-cdb
    0 field >srp-cmd-cdb-add
constant /srp-cmd

struct
    1 field >srp-rsp-opcode
    1 field >srp-rsp-sol-not
    2 +
    4 field >srp-rsp-req-lim-delta
    8 field >srp-rsp-tag
    2 +
    1 field >srp-rsp-flags
    1 field >srp-rsp-status
    4 field >srp-rsp-dout-res-cnt
    4 field >srp-rsp-din-res-cnt
    4 field >srp-rsp-sense-len
    4 field >srp-rsp-resp-len
    0 field >srp-rsp-data
constant /srp-rsp

\ Storage for up to 256 bytes SRP request */
CREATE srp 100 allot
0 VALUE srp-len

: srp-prep-cmd-nodata ( id lun -- )
    srp /srp-cmd erase
    SRP_CMD srp >srp-cmd-opcode c!
    1 srp >srp-cmd-tag x!
    srp >srp-cmd-lun 1 + c!     \ lun
    80 or                       \ select logical unit addressing method
    srp >srp-cmd-lun c!         \ id
    /srp-cmd to srp-len   
;

: srp-prep-cmd-io ( addr len id lun -- )
    srp-prep-cmd-nodata		( addr len )
    swap l2dma			( len dmaaddr )
    srp srp-len +    		( len dmaaddr descaddr )
    dup >r x! r> 8 +		( len descaddr+8 )
    dup 0 swap l! 4 +		( len descaddr+c )
    l!    
    srp-len 10 + to srp-len
;

: srp-prep-cmd-read ( addr len id lun -- )
    srp-prep-cmd-io
    01 srp >srp-cmd-buf-fmt c!	\ in direct buffer
    1 srp >srp-cmd-din-desc-cnt c!
;

: srp-prep-cmd-write ( addr len id lun -- )
    srp-prep-cmd-io
    10 srp >srp-cmd-buf-fmt c!	\ out direct buffer
    1 srp >srp-cmd-dout-desc-cnt c!
;

: srp-send-cmd ( -- )
    vscsi-debug IF
        ." VSCSI: Sending SCSI cmd " srp >srp-cmd-cdb c@ . cr
    THEN
    srp srp-len srp-send-crq
;

: srp-rsp-find-sense ( -- addr )
    \ XXX FIXME: Always in same position
    srp >srp-rsp-data
;

: srp-wait-rsp ( -- true | [ ascq asc sense-key false ] )
    srp-wait-crq not IF false EXIT THEN
    dup 1 <> IF
        ." VSCSI: Invalid CRQ response tag, want 1 got " . cr
	false EXIT
    THEN drop
    
    srp >srp-rsp-tag x@ dup 1 <> IF
        ." VSCSI: Invalid SRP response tag, want 1 got " . cr
	false EXIT
    THEN drop
    
    srp >srp-rsp-status c@
    vscsi-debug IF
        ." VSCSI: Got response status: "
	dup .status-text cr
    THEN

    0 <> IF
       srp-rsp-find-sense
       scsi-get-sense-data
       vscsi-debug IF
           ." VSCSI: Sense key: " dup .sense-text cr	   
       THEN
       false EXIT
    THEN
    true
;


\ -----------------------------------------------------------
\ Core VSCSI
\ -----------------------------------------------------------

CREATE sector d# 512 allot

0 INSTANCE VALUE current-id
0 INSTANCE VALUE current-lun

\ SCSI test-unit-read
: test-unit-ready ( -- true | [ ascq asc sense-key false ] )
    current-id current-lun srp-prep-cmd-nodata
    srp >srp-cmd-cdb scsi-build-test-unit-ready
    srp-send-cmd
    srp-wait-rsp
;

: inquiry ( -- true | false )
    \ WARNING: ATAPI devices with libata seem to ignore the MSB of
    \ the allocation length... let's only ask for ff bytes
    sector ff current-id current-lun srp-prep-cmd-read
    ff srp >srp-cmd-cdb scsi-build-inquiry
    srp-send-cmd
    srp-wait-rsp
    dup not IF nip nip nip EXIT THEN \ swallow sense
;

: read-capacity ( -- true | false )
    sector scsi-length-read-cap-10 current-id current-lun srp-prep-cmd-read
    srp >srp-cmd-cdb scsi-build-read-cap-10
    srp-send-cmd
    srp-wait-rsp
    dup not IF nip nip nip EXIT THEN \ swallow sense    
;

: start-stop-unit ( state# -- true | false )
    current-id current-lun srp-prep-cmd-nodata
    srp >srp-cmd-cdb scsi-build-start-stop-unit
    srp-send-cmd
    srp-wait-rsp
    dup not IF nip nip nip EXIT THEN \ swallow sense    
;

: get-media-event ( -- true | false )
    sector scsi-length-media-event current-id current-lun srp-prep-cmd-read
    srp >srp-cmd-cdb scsi-build-get-media-event
    srp-send-cmd
    srp-wait-rsp
    dup not IF nip nip nip EXIT THEN \ swallow sense    
;

: read-blocks ( -- addr block# #blocks blksz -- [ #read-blocks true ] | false )
    over * 					( addr block# #blocks len )    
    >r rot r> 			                ( block# #blocks addr len )
    5 0 DO
      	2dup current-id current-lun
	srp-prep-cmd-read                       ( block# #blocks addr len )
        2swap					( addr len block# #blocks )
        2dup srp >srp-cmd-cdb scsi-build-read-10 ( addr len block# #blocks )
	2swap                                   ( block# #blocks addr len )
        srp-send-cmd
 	srp-wait-rsp
	IF 2drop nip true UNLOOP EXIT THEN
	srp >srp-rsp-status c@ 8 <> IF
	    nip nip nip 2drop 2drop false EXIT
	THEN
	3drop
	100 ms
    LOOP
    2drop 2drop false
;

\ Cleanup behind us
: vscsi-cleanup
    ." VSCSI: Cleaning up" cr

    crq-cleanup

    \ Disable TCE bypass
    vscsi-unit 0 rtas-set-tce-bypass
;

\ Initialize our vscsi instance
: vscsi-init ( -- true | false )
    ." VSCSI: Initializing" cr

    \ Can't use my-unit bcs we aren't instanciating (fix this ?)
    " reg" get-node get-package-property IF
        ." VSCSI: Not reg property !!!" 0
    THEN
    decode-int to vscsi-unit 2drop

    \ Enable TCE bypass special qemu feature
    vscsi-unit 1 rtas-set-tce-bypass

    \ Initialize CRQ
    crq-init 0 <> IF false EXIT THEN

    \ Send init command
    " "(C0 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00)" drop
    crq-send not IF
        ." VSCSI: Error sending init command"
        crq-cleanup false EXIT
    THEN

    \ Wait reply
    crq-wait not IF
        crq-cleanup false EXIT
    THEN

    \ Check init reply
    crq c@ c0 <> crq 1 + c@ 02 <> or IF
        ." VSCSI: Initial handshake failed"
	crq-cleanup false EXIT
    THEN

    \ We should now login etc.. but we really don't need to
    \ with our qemu model

    \ Ensure we cleanup after booting
    ['] vscsi-cleanup add-quiesce-xt

    true
;

\ -----------------------------------------------------------
\ SCSI scan at boot and child device support
\ -----------------------------------------------------------

: set-address ( lun id -- )
    to current-id to current-lun 
;

: dev-max-transfer ( -- n )
    10000 \ Larger value seem to have problems with some CDROMs
;

: dev-get-capacity ( -- blocksize #blocks )
    \ Make sure that there are zeros in the buffer in case something goes wrong:
    sector 10 erase
    \ Now issue the read-capacity command
    read-capacity not IF
        0 0 EXIT
    THEN
    sector scsi-get-capacity-10
;

: dev-read-blocks ( -- addr block# #blocks blksize -- #read-blocks )
    read-blocks    
;

: initial-test-unit-ready ( -- true | [ ascq asc sense-key false ] )
    0 0 0 false
    3 0 DO
        2drop 2drop
        test-unit-ready dup IF UNLOOP EXIT THEN
    LOOP    
;

: compare-sense ( ascq asc key ascq2 asc2 key2 -- true | false )
    3 pick =	    ( ascq asc key ascq2 asc2 keycmp )
    swap 4 pick =   ( ascq asc key ascq2 keycmp asccmp )
    rot 5 pick =    ( ascq asc key keycmp asccmp ascqcmp )
    and and nip nip nip
;

0 CONSTANT CDROM-READY
1 CONSTANT CDROM-NOT-READY
2 CONSTANT CDROM-NO-DISK
3 CONSTANT CDROM-TRAY-OPEN
4 CONSTANT CDROM-INIT-REQUIRED
5 CONSTANT CDROM-TRAY-MAYBE-OPEN

: cdrom-status ( -- status )
    initial-test-unit-ready
    IF CDROM-READY EXIT THEN

    vscsi-debug IF
        ." TestUnitReady sense: " 3dup . . . cr
    THEN

    3dup 1 4 2 compare-sense IF
        3drop CDROM-NOT-READY EXIT
    THEN

    get-media-event IF
        sector w@ 4 >= IF
	    sector 2 + c@ 04 = IF
	        sector 5 + c@
		dup 02 and 0<> IF drop 3drop CDROM-READY EXIT THEN
		dup 01 and 0<> IF drop 3drop CDROM-TRAY-OPEN EXIT THEN
		drop 3drop CDROM-NO-DISK EXIT
	    THEN
	THEN
    THEN

    3dup 2 4 2 compare-sense IF
        3drop CDROM-INIT-REQUIRED EXIT
    THEN
    over 4 = over 2 = and IF
        \ Format in progress... what do we do ? Just ignore
	3drop CDROM-READY EXIT
    THEN
    over 3a = IF
        3drop CDROM-NO-DISK EXIT
    THEN

    \ Other error...
    3drop CDROM-TRAY-MAYBE-OPEN    
;

: cdrom-try-close-tray ( -- )
    scsi-const-load start-stop-unit drop
;

: cdrom-must-close-tray ( -- )
    scsi-const-load start-stop-unit not IF
        ." Tray open !" cr -65 throw
    THEN
;

: dev-prep-cdrom ( -- )
    5 0 DO
        cdrom-status CASE
	    CDROM-READY           OF UNLOOP EXIT ENDOF
	    CDROM-NO-DISK         OF ." No medium !" cr -65 THROW ENDOF
	    CDROM-TRAY-OPEN       OF cdrom-must-close-tray ENDOF
	    CDROM-INIT-REQUIRED   OF cdrom-try-close-tray ENDOF
	    CDROM-TRAY-MAYBE-OPEN OF cdrom-try-close-tray ENDOF
	ENDCASE
	d# 1000 ms
    LOOP
    ." Drive not ready !" cr -65 THROW
;

: dev-prep-disk ( -- )
    initial-test-unit-ready 0= IF
        ." Disk not ready!" cr
        3drop
    THEN
;

: vscsi-create-disk	( lun id -- )
    " disk" 0 " vio-vscsi-device.fs" included
;

: vscsi-create-cdrom	( lun id -- )
    " cdrom" 1 " vio-vscsi-device.fs" included
;

: wrapped-inquiry ( -- true | false )
    inquiry not IF false EXIT THEN
    \ Skip devices with PQ != 0
    sector inquiry-data>peripheral c@ e0 and 0 =
;

8 CONSTANT #dev
: vscsi-find-disks      ( -- )   
    ." VSCSI: Looking for disks" cr
    #dev 0 DO                                      \ check 8 devices (no LUNs)
        0 i set-address
	wrapped-inquiry IF	
	    ."   SCSI ID " i .
	    \ XXX FIXME: Check top bits to ignore unsupported units
	    \            and maybe provide better printout & more cases
	    sector inquiry-data>peripheral c@ CASE
                0   OF ." DISK     : " 0 i vscsi-create-disk  ENDOF
                5   OF ." CD-ROM   : " 0 i vscsi-create-cdrom ENDOF
                7   OF ." OPTICAL  : " 0 i vscsi-create-cdrom ENDOF
                e   OF ." RED-BLOCK: " 0 i vscsi-create-disk  ENDOF
                dup dup OF ." ? (" . 8 emit 29 emit 5 spaces ENDOF
            ENDCASE
	    sector .inquiry-text cr
	THEN
    LOOP
;

\ Remove scsi functions from word list
scsi-close

: setup-alias
    " scsi" find-alias 0= IF
        " scsi" get-node node>path set-alias
    ELSE THEN 
;

: vscsi-init-and-scan  ( -- )
    \ Create instance for scanning:
    0 0 get-node open-node ?dup 0= IF EXIT THEN
    my-self >r
    dup to my-self
    \ Scan the VSCSI bus:
    vscsi-init IF
        vscsi-find-disks
        setup-alias
    THEN
    \ Close the temporary instance:
    close-node
    r> to my-self
;

vscsi-init-and-scan
