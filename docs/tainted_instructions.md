
Taint Tutorial #1
=================

Introduction
------------

Say you have a replay and you want to taint some data and then
determine which instructions operate on that tainted data.  That is,
you want to know what instructions in what processes delete, copy and
comute taint sets.  This is a little like a forward slice, but on a
specific, concrete execution.  Remember that PANDA's taint is
whole-system.  So shared memory or disk bytes can get tainted, and
taint flows between processes and to and from kernel.

This sort of thing can be interesting and useful if, e.g., you want
to know what code computes a hash function or performs encryption
or is engaged in computing a function argument deep in a program.

In this tutorial, we will use a replay of someone using ssh-keygen.
We will apply taint labels to the passphrase entered and then ask
PANDA to tell us all the code that processes that tainted data.


NOTE:  This tutorial is known to work with git checkout

    52c73e19f47784e2322ecd5e755a857702a88b24


Obtain Replay 
-------------

Download the replay from here. 

    http://www.rrshare.org/detail/30 

And unpack it with 

    python scripts/rrunpack.py sshkeygen.rr 

This produces two files sshkeygen-rr-nondet.log, which is
the replay log, and sshkeygen-rr-snp, which is the snapshot
from which to begin replay.


Use TZB to find the interesting part of the replay
--------------------------------------------------

The passphrase entered, as the rrshare page explains, is
`"tygertygerburningbrightintheforestofthenight"`.  We are going to use
TZB's  stringsearch  plugin to tell us what instructions
(or tap points) process that string. Here's how to do that. 

1. Create a file called 

    sshkeygen_search_strings.txt 

    and put it in the qemu directory of PANDA.  That file should contain
    the string "tygertygerburningbrightintheforestofthenight".  Yes, you
    need the quotes. 

2. Run PANDA with the following command (assuming you unpacked replay into
qemu dir)

        ./x86_64-softmmu/qemu-system-x86_64 -replay sshkeygen -panda stringsearch:name=sshkeygen

On my computer this takes about 15 seconds.  
This should produce output chugging through the replay until `stringsearch` sees the passphrase:

     ...
     sshkeygen:   368898074 ( 84.16%) instrs.   12.90 sec.  0.14 GB ram.                                   
     sshkeygen:   373086326 ( 85.11%) instrs.   13.02 sec.  0.14 GB ram.                                   
     sshkeygen:   377154763 ( 86.04%) instrs.   13.13 sec.  0.14 GB ram.                                   
     sshkeygen:   382130152 ( 87.18%) instrs.   13.26 sec.  0.14 GB ram.                                   
     sshkeygen:   386299122 ( 88.13%) instrs.   13.38 sec.  0.14 GB ram.                                   
     sshkeygen:   390265367 ( 89.03%) instrs.   13.49 sec.  0.14 GB ram.                                   
     sshkeygen:   395207399 ( 90.16%) instrs.   13.62 sec.  0.14 GB ram.                                   
     sshkeygen:   399390427 ( 91.12%) instrs.   13.74 sec.  0.14 GB ram.                                   
     sshkeygen:   403518432 ( 92.06%) instrs.   13.85 sec.  0.14 GB ram.                                   
     sshkeygen:   408425942 ( 93.18%) instrs.   13.99 sec.  0.14 GB ram.                                   
     sshkeygen:   412507606 ( 94.11%) instrs.   14.10 sec.  0.14 GB ram.                                   
     sshkeygen:   416547149 ( 95.03%) instrs.   14.21 sec.  0.14 GB ram.                                   
     sshkeygen:   421487980 ( 96.16%) instrs.   14.35 sec.  0.14 GB ram.                                   
     sshkeygen:   425620638 ( 97.10%) instrs.   14.46 sec.  0.14 GB ram.                                   
     sshkeygen:   429671621 ( 98.02%) instrs.   14.57 sec.  0.14 GB ram.                                   
     sshkeygen:   434054149 ( 99.02%) instrs.   14.82 sec.  0.14 GB ram.                                   
     WRITE Match of str 0 at: instr_count=434856967 :  00000000b7551cd7 00000000b76dc0c0 000000000503d000  
     READ Match of str 0 at: instr_count=434857701 :  00000000b74cb385 00000000b722c9b6 000000000503d000   
     WRITE Match of str 0 at: instr_count=434857701 :  00000000b74cb385 00000000b722c9b6 000000000503d000  
     READ Match of str 0 at: instr_count=434861370 :  00000000b76d1fee 00000000b722c9d1 000000000503d000   
     WRITE Match of str 0 at: instr_count=434861370 :  00000000b76d1fee 00000000b722c9d1 000000000503d000  
     READ Match of str 0 at: instr_count=434866607 :  00000000c11ce65e 00000000c11660ac 0000000000000000   
     WRITE Match of str 0 at: instr_count=434866607 :  00000000c11ce65e 00000000c11660ac 0000000000000000  
     READ Match of str 0 at: instr_count=434866903 :  00000000c11d4ee2 00000000c11d43b6 0000000000000000   
     WRITE Match of str 0 at: instr_count=434866903 :  00000000c11d4ee2 00000000c11d43b6 0000000000000000  
     READ Match of str 0 at: instr_count=434911491 :  00000000c11d40d0 00000000c11d1288 0000000000000000   
     WRITE Match of str 0 at: instr_count=434911572 :  00000000c11d1b7e 00000000c11d0274 0000000000000000  
     READ Match of str 0 at: instr_count=435098574 :  00000000c11ce1a1 00000000c11d2279 0000000000000000   
     WRITE Match of str 0 at: instr_count=435098624 :  00000000c11ce1a1 00000000c11d22d0 0000000000000000  
     READ Match of str 0 at: instr_count=435098710 :  00000000c11ce1a1 00000000c11d22f0 0000000000000000   
     WRITE Match of str 0 at: instr_count=435098717 :  00000000c11d22fd 00000000c1165944 0000000000000000  
     READ Match of str 0 at: instr_count=435099352 :  00000000b77095e1 00000000b7717621 0000000005234000   
     ...

So it isn't until about 430M instructions into the trace that we see "tygertygerburningbrightintheforestofthenight".
`WRITE Match` means PANDA saw that data written to memory. 
`READ Match` means PANDA saw it read from memory.

For more info on TZB see publications in https://github.com/moyix/panda


Use taint to find out what instructions process the passphrase
-----------------------------------------------------------------

Finally, we'll use the tstringsearch plugin to apply taint labels to
that passphrase and ask the taint system to figure out what
instructions are tainted, meaning they copy or compute on data derived from that key.  
Here's how to do that.

      ./x86_64-softmmu/qemu-system-x86_64 -replay sshkeygen -pandalog tainted_instr.plog -panda 'stringsearch:name=sshkeygen;tstringsearch;tainted_instr'

On my computer, this takes about 2 min.
This time, in addition to all the WRITE and READ match info, you should also see PANDA saying it is applying
taint labels to those matched strings, e.g.,

     ...
     READ Match of str 0 at: instr_count=434866903 :  00000000c11d4ee2 00000000c11d43b6 0000000000000000                                                     
     tstringsearch: thestring = [tygertygerburningbrightintheforestofthenight]                                                                            
     tstringsearch: 74 79 67 65 72 74 79 67 65 72 62 75 72 6e 69 6e 67 62 72 69 67 68 74 69 6e 74 68 65 66 6f 72 65 73 74 6f 66 74 68 65 6e 69 67 68 74   
     tstringsearch: string in memory @ 0xc53be000                                                                                                         
                                                                                                                                                         
     ****************************************************************************                                                                         
     applying taint labels to search string of length 44  @ p=0x00000000c53be000                                                                          
     ******************************************************************************                                                                       
     ...

The output of the `tainted_instr` plugin is written to the pandalog `tainted_instr.plog`.
Pandalog is a protocol buffers log written by plugins.  
To read this particular log, you should compile and run the program `panda/tainted_instr.cpp` (instructions are at the top of that file).
That program takes two arguments, the first is the pandalog file to process and the second
controls how much and what kind of output you get. 

In `full` mode, 

    tainted_instr tainted_instr.plog full

you will see taint query results for tainted instructions, callstack info, and asid changes.
Here is a sample

     ...
     instr=434857690 pc=0xb722c9b6 : asid changed to 0x503d000                                                                                                  
     instr=434857690 pc=0xb722c9b6 :                                                                                                                            
     instr=434857690 pc=0xb722c9b6 : taint query unqiue label set: ptr=7f16142b9000 labels: 10                                                                  
     instr=434857690 pc=0xb722c9b6 : taint query: labels ptr 7f16142b9000 tcn=0                                                                                 
     instr=434857690 pc=0xb722c9b6 : callstack=(9,[ 0xb74cb385, 0xb754d3ce, 0xb754519d, 0xb74d280e, 0xb76ec565, 0xb76e252c, 0xb76eae75, 0xb76ae5bd, 0xb76af985])
     instr=434857690 pc=0xb722c9b6 :                                                                                                                            
     instr=434857690 pc=0xb722c9b6 : taint query unqiue label set: ptr=7f16142b9030 labels: 10                                                                  
     instr=434857690 pc=0xb722c9b6 : taint query: labels ptr 7f16142b9030 tcn=0                                                                                 
     instr=434857690 pc=0xb722c9b6 : callstack=(9,[ 0xb74cb385, 0xb754d3ce, 0xb754519d, 0xb74d280e, 0xb76ec565, 0xb76e252c, 0xb76eae75, 0xb76ae5bd, 0xb76af985])
     instr=434857690 pc=0xb722c9b6 :                                                                                                                            
     instr=434857690 pc=0xb722c9b6 : taint query: labels ptr 7f16142b9000 tcn=0                                                                                 
     instr=434857690 pc=0xb722c9b6 : callstack=(9,[ 0xb74cb385, 0xb754d3ce, 0xb754519d, 0xb74d280e, 0xb76ec565, 0xb76e252c, 0xb76eae75, 0xb76ae5bd, 0xb76af985])
     instr=434857690 pc=0xb722c9b6 :                                                                                                                            
     instr=434857690 pc=0xb722c9b6 : taint query: labels ptr 7f16142b9030 tcn=0                                                                                 
     instr=434857690 pc=0xb722c9b6 : callstack=(9,[ 0xb74cb385, 0xb754d3ce, 0xb754519d, 0xb74d280e, 0xb76ec565, 0xb76e252c, 0xb76eae75, 0xb76ae5bd, 0xb76af985])
     instr=434857691 pc=0xb722c9b6 :                                                                                                                            
     instr=434857691 pc=0xb722c9b6 : taint query unqiue label set: ptr=7f16142b9060 labels: 10                                                                  
     instr=434857691 pc=0xb722c9b6 : taint query: labels ptr 7f16142b9060 tcn=0                                                                                 
     instr=434857691 pc=0xb722c9b6 : callstack=(9,[ 0xb74cb385, 0xb754d3ce, 0xb754519d, 0xb74d280e, 0xb76ec565, 0xb76e252c, 0xb76eae75, 0xb76ae5bd, 0xb76af985])
     ...

In `summary` mode, 

     tainted_instr tainted_instr.plog summary

you will get a listing by asid, of the set of tainted instructions.
This is probably what you really want.  
Here is that output.
Note that this program takes about 30 seconds to run on my computer. 

     asid=0x503d000	pc=b71c9470     
     asid=0x503d000	pc=b71c9475     
     asid=0x503d000	pc=b71c947b     
     asid=0x503d000	pc=b71c947c     
     asid=0x503d000	pc=b71c947e     
     asid=0x503d000	pc=b71c947f     
     asid=0x503d000	pc=b71c9485     
     asid=0x503d000	pc=b71c948c     
     asid=0x503d000	pc=b71dcb60     
     asid=0x503d000	pc=b71dcb61     
     asid=0x503d000	pc=b71dcb63     
     asid=0x503d000	pc=b71dcb69     
     asid=0x503d000	pc=b71dcb6c     
     asid=0x503d000	pc=b71dcb6f     
