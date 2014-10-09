
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


    3601eb928a379f27a236ae15cfe8f00ab6fee2f2    

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

        search_strings.txt 

    and put it in the qemu directory of PANDA.  That file should contain
    the string "tygertygerburningbrightintheforestofthenight".  Yes, you
    need the quotes. 

2. Run PANDA with the following command (assuming you unpacked replay into
qemu dir)

        ./x86_64-softmmu/qemu-system-x86_64 -m 128 -replay sshkeygen -display none  -panda callstack_instr -panda stringsearch 


On my computer this takes about 1 min 3 sec.  
This should produce output chugging through the replay until `stringsearch` sees the passphrase:

    ...
    /data/laredo/tleek/rr-logs/sshkeygen-rr-nondet.log:  740611 of 1010779 (73.27%) bytes, 421487980 of 438334408 (96.16%) instructions processed.
    /data/laredo/tleek/rr-logs/sshkeygen-rr-nondet.log:  742261 of 1010779 (73.43%) bytes, 425620638 of 438334408 (97.10%) instructions processed.
    /data/laredo/tleek/rr-logs/sshkeygen-rr-nondet.log:  744037 of 1010779 (73.61%) bytes, 429671621 of 438334408 (98.02%) instructions processed.
    /data/laredo/tleek/rr-logs/sshkeygen-rr-nondet.log:  747064 of 1010779 (73.91%) bytes, 434054149 of 438334408 (99.02%) instructions processed.
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
    ...

So it isn't until about 430M instructions into the trace that we see "tygertygerburningbrightintheforestofthenight".

For more info on TZB see publications in https://github.com/moyix/panda


Use scissors to pull out the interesting 
----------------------------------------

We dont really care about the part of the replay before we see the
passphrase.  So we'll use PANDA's `scissors` plugin to pull out just the
interesting part of the trace.  Here's how to do that.


    ./x86_64-softmmu/qemu-system-x86_64 -m 128 -replay sshkeygen -display none -panda scissors:start=420000000,end=438334408,name=sshksci

On my computer, this takes about 13 seconds. 
This creates a new recording that starts at 420M instructions in and ends
with the last instruction in the trace. This new replay is called 
`sshksci`.


Use taint to find out what instructions process the passphrase
-----------------------------------------------------------------

Finally, we'll use the tstringsearch plugin to apply taint labels to
that passphrase and ask the taint system to figure out what
instructions are tainted.  Here's how to do that.

      ./x86_64-softmmu/qemu-system-x86_64 -m 128 -replay sshksci -display none -panda callstack_instr -panda stringsearch -panda taint:tainted_instructions=1 -panda tstringsearch

On my computer, this takes about 10 min 38 sec. 
This time, in addition to all the WRITE and READ match info, you should also see PANDA saying it is tainting those matched strings, e.g.,


     WRITE Match of str 0 at: instr_count=4812751 :  00000000c11d4ee2 00000000c11d43b6 0000000000000000 
     thestring = [tygertygerburningbrightintheforestofthenigh]                                          
     search string is sitting in memory starting at 0xc53bec50                                          
                                                                                                        
     ****************************************************************************                       
     applying taint labels to search string of length 44  @ p=0x00000000c53bec50                        
     ******************************************************************************                     

And, at the end of the run, you will see the tainted instructions:

    uninit taint plugin                                
    asid = 503d000                                     
    instr is tainted :  asid=0x503d000 : pc=0xb722c988 
    instr is tainted :  asid=0x503d000 : pc=0xb722c9b6 
    instr is tainted :  asid=0x503d000 : pc=0xb722c9ba 
    instr is tainted :  asid=0x503d000 : pc=0xb722c9bd 
    instr is tainted :  asid=0x503d000 : pc=0xb722c9bf 
    instr is tainted :  asid=0x503d000 : pc=0xb722c9ca 
    instr is tainted :  asid=0x503d000 : pc=0xb722c9d1 
    ...                                                

This tells us that the process with CR3 0x503d000 processed tainted
data in instructions at pc=0xb722c988,0xb722c9b6, etc.  

Note that one needn't apply taint labels via tstringsearch (although
it is convenient).  Instead, you might taint data at the linux
`read` system call.  Or somewhere else.

The complete expected output from list last run of panda is reproduced below.

    adding /home/tleek/git/panda/qemu/x86_64-softmmu/panda_plugins/panda_callstack_instr.so to panda_plugin_files 0                
    adding /home/tleek/git/panda/qemu/x86_64-softmmu/panda_plugins/panda_stringsearch.so to panda_plugin_files 1                   
    Adding PANDA arg taint:tainted_instructions=1.                                                                                             
    adding /home/tleek/git/panda/qemu/x86_64-softmmu/panda_plugins/panda_taint.so to panda_plugin_files 2                          
    Adding PANDA arg tstringsearch:instr_count=4618917.                                                                            
    adding /home/tleek/git/panda/qemu/x86_64-softmmu/panda_plugins/panda_tstringsearch.so to panda_plugin_files 3                  
    loading /home/tleek/git/panda/qemu/x86_64-softmmu/panda_plugins/panda_callstack_instr.so                                       
    Initializing plugin callstack_instr                                                                                            
    loading /home/tleek/git/panda/qemu/x86_64-softmmu/panda_plugins/panda_stringsearch.so                                          
    Initializing plugin stringsearch                                                                                               
    stringsearch: added string of length 44 to search set                                                                          
    loading /home/tleek/git/panda/qemu/x86_64-softmmu/panda_plugins/panda_taint.so                                                 
    Initializing taint plugin                                                                                                      
    Taint: running in byte labeling mode.                                                                                          
    max_taintset_card = 0                                                                                                          
    max_taintset_compute_number = 0                                                                                                
    taint_label_incoming_network_traffic = 0                                                                                       
    taint_query_outgoing_network_traffic = 0                                                                                       
    tainted_pointer = 1                                                                                                            
    done initializing taint plugin                                                                                                 
    loading /home/tleek/git/panda/qemu/x86_64-softmmu/panda_plugins/panda_tstringsearch.so                                         
    Initializing tstringsearch                                                                                                     
    taint will be enabled around instr count 467aa5                                                                                
    loading snapshot                                                                                                               
    ... done.                                                                                                                      
                                                                                                                                   
    Logging all cpu states                                                                                                         
    CPU #0:                                                                                                                        
    opening nondet log for read :	./sshksci-rr-nondet.log                                                                        
    ./sshksci-rr-nondet.log:  382 of 237186 (0.16%) bytes, 357301 of 8080262 (4.42%) instructions processed.                       
    ./sshksci-rr-nondet.log:  712 of 237186 (0.30%) bytes, 1078800 of 8080262 (13.35%) instructions processed.                     
    ./sshksci-rr-nondet.log:  1042 of 237186 (0.44%) bytes, 1905129 of 8080262 (23.58%) instructions processed.                    
    ./sshksci-rr-nondet.log:  1372 of 237186 (0.58%) bytes, 2114960 of 8080262 (26.17%) instructions processed.                    
    ./sshksci-rr-nondet.log:  1702 of 237186 (0.72%) bytes, 2729540 of 8080262 (33.78%) instructions processed.                    
    ./sshksci-rr-nondet.log:  2032 of 237186 (0.86%) bytes, 3295208 of 8080262 (40.78%) instructions processed.                    
    ./sshksci-rr-nondet.log:  2765 of 237186 (1.17%) bytes, 3813573 of 8080262 (47.20%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3079 of 237186 (1.30%) bytes, 3999997 of 8080262 (49.50%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3107 of 237186 (1.31%) bytes, 4010001 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3135 of 237186 (1.32%) bytes, 4010019 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3163 of 237186 (1.33%) bytes, 4010019 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3191 of 237186 (1.35%) bytes, 4010031 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3219 of 237186 (1.36%) bytes, 4010031 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3247 of 237186 (1.37%) bytes, 4010043 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3275 of 237186 (1.38%) bytes, 4010043 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3303 of 237186 (1.39%) bytes, 4010069 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3331 of 237186 (1.40%) bytes, 4010069 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3359 of 237186 (1.42%) bytes, 4010084 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3387 of 237186 (1.43%) bytes, 4010084 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3415 of 237186 (1.44%) bytes, 4010112 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3443 of 237186 (1.45%) bytes, 4010112 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3471 of 237186 (1.46%) bytes, 4010164 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3499 of 237186 (1.48%) bytes, 4010164 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3527 of 237186 (1.49%) bytes, 4010181 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3555 of 237186 (1.50%) bytes, 4010181 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3583 of 237186 (1.51%) bytes, 4010214 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3611 of 237186 (1.52%) bytes, 4010214 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3639 of 237186 (1.53%) bytes, 4010231 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3667 of 237186 (1.55%) bytes, 4010231 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3695 of 237186 (1.56%) bytes, 4010234 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3723 of 237186 (1.57%) bytes, 4010234 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3751 of 237186 (1.58%) bytes, 4010245 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3779 of 237186 (1.59%) bytes, 4010245 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3807 of 237186 (1.61%) bytes, 4010251 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3835 of 237186 (1.62%) bytes, 4010251 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3863 of 237186 (1.63%) bytes, 4010268 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3891 of 237186 (1.64%) bytes, 4010268 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3919 of 237186 (1.65%) bytes, 4010271 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3947 of 237186 (1.66%) bytes, 4010271 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  3975 of 237186 (1.68%) bytes, 4010297 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4003 of 237186 (1.69%) bytes, 4010297 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4031 of 237186 (1.70%) bytes, 4010301 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4059 of 237186 (1.71%) bytes, 4010301 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4087 of 237186 (1.72%) bytes, 4010353 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4115 of 237186 (1.73%) bytes, 4010353 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4143 of 237186 (1.75%) bytes, 4010355 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4171 of 237186 (1.76%) bytes, 4010355 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4199 of 237186 (1.77%) bytes, 4010369 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  4227 of 237186 (1.78%) bytes, 4010369 of 8080262 (49.63%) instructions processed.                    
    ./sshksci-rr-nondet.log:  9473 of 237186 (3.99%) bytes, 4041905 of 8080262 (50.02%) instructions processed.                    
    ./sshksci-rr-nondet.log:  14581 of 237186 (6.15%) bytes, 4131511 of 8080262 (51.13%) instructions processed.                   
    ./sshksci-rr-nondet.log:  32395 of 237186 (13.66%) bytes, 4230164 of 8080262 (52.35%) instructions processed.                  
    ./sshksci-rr-nondet.log:  33420 of 237186 (14.09%) bytes, 4297761 of 8080262 (53.19%) instructions processed.                  
    ./sshksci-rr-nondet.log:  39355 of 237186 (16.59%) bytes, 4367674 of 8080262 (54.05%) instructions processed.                  
    ./sshksci-rr-nondet.log:  46127 of 237186 (19.45%) bytes, 4444802 of 8080262 (55.01%) instructions processed.                  
    ./sshksci-rr-nondet.log:  52001 of 237186 (21.92%) bytes, 4556646 of 8080262 (56.39%) instructions processed.                  
    ./sshksci-rr-nondet.log:  65853 of 237186 (27.76%) bytes, 4618917 of 8080262 (57.16%) instructions processed.                  
    enabling taint at instr count 477737                                                                                           
    __taint_enable_taint                                                                                                           
    Note: dyn log ignoring memset greater than 100 bytes                                                                           
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_x86_dump_seg_cache_llvm.                                    
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: skipping taint analysis of statically unknowable call in cpu_dump_state_llvm.                                            
    Note: taint ignoring memset greater than 100 bytes                                                                             
    Note: skipping taint analysis of statically unknowable call in cpu_x86_update_cr3_llvm.                                        
    Note: skipping taint analysis of statically unknowable call in breakpoint_handler_llvm.                                        
    Note: skipping taint analysis of statically unknowable call in do_inject_x86_mce_llvm.                                         
    Note: unsupported intrinsic llvm.lifetime.start in cpu_x86_inject_mce_llvm.                                                    
    Note: unsupported intrinsic llvm.lifetime.end in cpu_x86_inject_mce_llvm.                                                      
    Note: skipping taint analysis of statically unknowable call in cpu_x86_set_a20_llvm.                                           
    Note: skipping taint analysis of statically unknowable call in helper_pcmpistri_xmm_llvm.                                      
    Note: skipping taint analysis of statically unknowable call in helper_pcmpestri_xmm_llvm.                                      
    Note: skipping taint analysis of statically unknowable call in helper_cpuid_llvm.                                              
    Note: skipping taint analysis of statically unknowable call in helper_panda_insn_exec_llvm.                                    
    ./sshksci-rr-nondet.log:  77621 of 237186 (32.73%) bytes, 4705764 of 8080262 (58.24%) instructions processed.                  
    ./sshksci-rr-nondet.log:  87406 of 237186 (36.85%) bytes, 4767965 of 8080262 (59.01%) instructions processed.                  
    WRITE Match of str 0 at: instr_count=4802815 :  00000000b7551cd7 00000000b76dc0c0 000000000503d000                             
    thestring = [tygertygerburningbrightintheforestofthenigh]                                                                      
    search string is sitting in memory starting at 0xb897c136                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000b897c136                                                    
    ******************************************************************************                                                 
    READ Match of str 0 at: instr_count=4803549 :  00000000b74cb385 00000000b722c9b6 000000000503d000                              
    thestring = [,tygertygerburningbrightintheforestofthenigh]                                                                     
    WRITE Match of str 0 at: instr_count=4803549 :  00000000b74cb385 00000000b722c9b6 000000000503d000                             
    thestring = [,tygertygerburningbrightintheforestofthenig]                                                                      
    READ Match of str 0 at: instr_count=4807218 :  00000000b76d1fee 00000000b722c9d1 000000000503d000                              
    thestring = []                                                                                                                 
    WRITE Match of str 0 at: instr_count=4807218 :  00000000b76d1fee 00000000b722c9d1 000000000503d000                             
    thestring = []                                                                                                               
    READ Match of str 0 at: instr_count=4812455 :  00000000c11ce65e 00000000c11660ac 0000000000000000                              
    thestring = []                                                                                                               
    WRITE Match of str 0 at: instr_count=4812455 :  00000000c11ce65e 00000000c11660ac 0000000000000000                             
    thestring = []                                                                                                                 
    READ Match of str 0 at: instr_count=4812751 :  00000000c11d4ee2 00000000c11d43b6 0000000000000000                              
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xc53be000                                                                      
    WRITE Match of str 0 at: instr_count=4812751 :  00000000c11d4ee2 00000000c11d43b6 0000000000000000                             
    thestring = [tygertygerburningbrightintheforestofthenigh]                                                                      
    search string is sitting in memory starting at 0xc53bec50                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000c53bec50                                                    
    ******************************************************************************                                                 
    READ Match of str 0 at: instr_count=4857339 :  00000000c11d40d0 00000000c11d1288 0000000000000000                              
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xc53bec50                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000c53bec50                                                    
    ******************************************************************************                                                 
    WRITE Match of str 0 at: instr_count=4857420 :  00000000c11d1b7e 00000000c11d0274 0000000000000000                             
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xc6e5f000                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000c6e5f000                                                    
    ******************************************************************************                                                 
    ./sshksci-rr-nondet.log:  89991 of 237186 (37.94%) bytes, 4861006 of 8080262 (60.16%) instructions processed.                  
    ./sshksci-rr-nondet.log:  97269 of 237186 (41.01%) bytes, 4938739 of 8080262 (61.12%) instructions processed.                  
    ./sshksci-rr-nondet.log:  97979 of 237186 (41.31%) bytes, 5035553 of 8080262 (62.32%) instructions processed.                  
    READ Match of str 0 at: instr_count=5044422 :  00000000c11ce1a1 00000000c11d2279 0000000000000000                              
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xc6e5f000                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000c6e5f000                                                    
    ******************************************************************************                                                 
    WRITE Match of str 0 at: instr_count=5044472 :  00000000c11ce1a1 00000000c11d22d0 0000000000000000                             
    thestring = [/ÅõÚÁÌ/Å\/Å 6<Å]                                                                                          
    READ Match of str 0 at: instr_count=5044558 :  00000000c11ce1a1 00000000c11d22f0 0000000000000000                              
    thestring = [/ÅÍ¿Ì/Å\/Å 6<Å]                                                                                         
    WRITE Match of str 0 at: instr_count=5044565 :  00000000c11d22fd 00000000c1165944 0000000000000000                             
    thestring = [4Í¿¨Í¿]                                                                                                     
    READ Match of str 0 at: instr_count=5045200 :  00000000b77095e1 00000000b7717621 0000000005234000                              
    thestring = [4Í¿¨Í¿]                                                                                                     
    WRITE Match of str 0 at: instr_count=5045210 :  00000000b77095e1 00000000b771764d 0000000005234000                             
    thestring = [Í¿]                                                                                                           
    READ Match of str 0 at: instr_count=5045226 :  00000000b77095e1 00000000b7717656 0000000005234000                              
    thestring = [Í¿]                                                                                                           
    WRITE Match of str 0 at: instr_count=5045235 :  00000000b77095e1 00000000b77176a4 0000000005234000                             
    thestring = [tygertygerburningbrightintheforestofthenigh·]                                                                     
    search string is sitting in memory starting at 0xbfcd075c                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000bfcd075c                                                    
    ******************************************************************************                                                 
    READ Match of str 0 at: instr_count=5063614 :  00000000b770a107 00000000b7717cdc 0000000005234000                              
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xbfcd075c                                                                      
    WRITE Match of str 0 at: instr_count=5063614 :  00000000b770a107 00000000b7717ce2 0000000005234000                             
    thestring = [tygertygerburningbrightintheforestofthenigh]                                                                      
    search string is sitting in memory starting at 0xb8869ad8                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000b8869ad8                                                    
    ******************************************************************************                                                 
    ./sshksci-rr-nondet.log:  100205 of 237186 (42.25%) bytes, 5111201 of 8080262 (63.26%) instructions processed.                 
    ./sshksci-rr-nondet.log:  104216 of 237186 (43.94%) bytes, 5171570 of 8080262 (64.00%) instructions processed.                 
    ./sshksci-rr-nondet.log:  121076 of 237186 (51.05%) bytes, 5259820 of 8080262 (65.09%) instructions processed.                 
    ./sshksci-rr-nondet.log:  126788 of 237186 (53.46%) bytes, 5333453 of 8080262 (66.01%) instructions processed.                 
    WRITE Match of str 0 at: instr_count=5415598 :  00000000b7551cd7 00000000b76dc0c0 000000000503d000                             
    thestring = [tygertygerburningbrightintheforestofthenight®]                                                                  
    search string is sitting in memory starting at 0xb897c136                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000b897c136                                                    
    ******************************************************************************                                                 
    READ Match of str 0 at: instr_count=5416332 :  00000000b74cb385 00000000b722c9b6 000000000503d000                              
    thestring = [,tygertygerburningbrightintheforestofthenigh®]                                                                  
    WRITE Match of str 0 at: instr_count=5416332 :  00000000b74cb385 00000000b722c9b6 000000000503d000                             
    thestring = [,tygertygerburningbrightintheforestofthenig]                                                                      
    READ Match of str 0 at: instr_count=5420001 :  00000000b76d1fee 00000000b722c9d1 000000000503d000                              
    thestring = []                                                                                                                 
    WRITE Match of str 0 at: instr_count=5420001 :  00000000b76d1fee 00000000b722c9d1 000000000503d000                             
    thestring = []                                                                                                               
    READ Match of str 0 at: instr_count=5425238 :  00000000c11ce65e 00000000c11660ac 0000000000000000                              
    thestring = []                                                                                                               
    WRITE Match of str 0 at: instr_count=5425238 :  00000000c11ce65e 00000000c11660ac 0000000000000000                             
    thestring = []                                                                                                                 
    READ Match of str 0 at: instr_count=5425534 :  00000000c11d4ee2 00000000c11d43b6 0000000000000000                              
    thestring = [tygertygerburningbrightintheforestofthenight®]                                                                  
    search string is sitting in memory starting at 0xc53be000                                                                      
    WRITE Match of str 0 at: instr_count=5425534 :  00000000c11d4ee2 00000000c11d43b6 0000000000000000                             
    thestring = [tygertygerburningbrightintheforestofthenigh]                                                                      
    search string is sitting in memory starting at 0xc53bec7d                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000c53bec7d                                                    
    ******************************************************************************                                                 
    READ Match of str 0 at: instr_count=5434051 :  00000000c11d40d0 00000000c11d1288 0000000000000000                              
    thestring = [tygertygerburningbrightintheforestofthenight®]                                                                  
    search string is sitting in memory starting at 0xc53bec7d                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000c53bec7d                                                    
    ******************************************************************************                                                 
    WRITE Match of str 0 at: instr_count=5434132 :  00000000c11d1b7e 00000000c11d0274 0000000000000000                             
    thestring = [tygertygerburningbrightintheforestofthenight®]                                                                  
    search string is sitting in memory starting at 0xc6e5f000                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000c6e5f000                                                    
    ******************************************************************************                                                 
    ./sshksci-rr-nondet.log:  132903 of 237186 (56.03%) bytes, 5462176 of 8080262 (67.60%) instructions processed.                 
    ./sshksci-rr-nondet.log:  136095 of 237186 (57.38%) bytes, 5497746 of 8080262 (68.04%) instructions processed.                 
    ./sshksci-rr-nondet.log:  140585 of 237186 (59.27%) bytes, 5609256 of 8080262 (69.42%) instructions processed.                 
    READ Match of str 0 at: instr_count=5679677 :  00000000c11ce1a1 00000000c11d2279 0000000000000000                              
    thestring = [tygertygerburningbrightintheforestofthenight®]                                                                  
    search string is sitting in memory starting at 0xc6e5f000                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000c6e5f000                                                    
    ******************************************************************************                                                 
    WRITE Match of str 0 at: instr_count=5679727 :  00000000c11ce1a1 00000000c11d22d0 0000000000000000                             
    thestring = [/ÅõÚÁÌ/Å\/Å 6<Å]                                                                                          
    READ Match of str 0 at: instr_count=5679813 :  00000000c11ce1a1 00000000c11d22f0 0000000000000000                              
    thestring = [/ÅÍ¿Ì/Å\/Å 6<Å]                                                                                         
    WRITE Match of str 0 at: instr_count=5679820 :  00000000c11d22fd 00000000c1165944 0000000000000000                             
    thestring = [4Í¿¨Í¿]                                                                                                     
    READ Match of str 0 at: instr_count=5680455 :  00000000b77095e1 00000000b7717621 0000000005234000                              
    thestring = [4Í¿¨Í¿]                                                                                                     
    WRITE Match of str 0 at: instr_count=5680465 :  00000000b77095e1 00000000b771764d 0000000005234000                             
    thestring = [Í¿]                                                                                                           
    READ Match of str 0 at: instr_count=5680481 :  00000000b77095e1 00000000b7717656 0000000005234000                              
    thestring = [Í¿]                                                                                                           
    WRITE Match of str 0 at: instr_count=5680490 :  00000000b77095e1 00000000b77176a4 0000000005234000                             
    thestring = [tygertygerburningbrightintheforestofthenighx®]                                                                  
    search string is sitting in memory starting at 0xbfcd075c                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000bfcd075c                                                    
    ******************************************************************************                                                 
    READ Match of str 0 at: instr_count=5697749 :  00000000b770a107 00000000b7717cdc 0000000005234000                              
    thestring = [tygertygerburningbrightintheforestofthenight®]                                                                  
    search string is sitting in memory starting at 0xbfcd075c                                                                      
    WRITE Match of str 0 at: instr_count=5697749 :  00000000b770a107 00000000b7717ce2 0000000005234000                             
    thestring = [tygertygerburningbrightintheforestofthenigh]                                                                      
    search string is sitting in memory starting at 0xb8869b10                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000b8869b10                                                    
    ******************************************************************************                                                 
    READ Match of str 0 at: instr_count=5698353 :  00000000b76ff8ec 00000000b740cbf8 0000000005234000                              
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xb8869ad8                                                                      
    READ Match of str 0 at: instr_count=5698353 :  00000000b76ff8ec 00000000b740cbfa 0000000005234000                              
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xb8869b10                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000b8869b10                                                    
    ******************************************************************************                                                 
    READ Match of str 0 at: instr_count=5698417 :  00000000b73aae46 00000000b76ff900 0000000005234000                              
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xb8869b10                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000b8869b10                                                    
    ******************************************************************************                                                 
    ./sshksci-rr-nondet.log:  140915 of 237186 (59.41%) bytes, 5724375 of 8080262 (70.84%) instructions processed.                 
    READ Match of str 0 at: instr_count=5998123 :  00000000b754d331 00000000b740e9b6 0000000005234000                              
    thestring = []                                                                                                                 
    WRITE Match of str 0 at: instr_count=5998123 :  00000000b754d331 00000000b740e9b6 0000000005234000                             
    thestring = []                                                                                                                 
    ./sshksci-rr-nondet.log:  141402 of 237186 (59.62%) bytes, 5999187 of 8080262 (74.24%) instructions processed.                 
    ./sshksci-rr-nondet.log:  141648 of 237186 (59.72%) bytes, 6026730 of 8080262 (74.59%) instructions processed.                 
    READ Match of str 0 at: instr_count=6034309 :  00000000b754d446 00000000b740e9b6 0000000005234000                              
    thestring = []                                                                                                                 
    WRITE Match of str 0 at: instr_count=6034309 :  00000000b754d446 00000000b740e9b6 0000000005234000                             
    thestring = [)¹`tygertygerburningbrightintheforestofthen]                                                                      
    ./sshksci-rr-nondet.log:  142061 of 237186 (59.89%) bytes, 6055949 of 8080262 (74.95%) instructions processed.                 
    ./sshksci-rr-nondet.log:  142128 of 237186 (59.92%) bytes, 6117281 of 8080262 (75.71%) instructions processed.                 
    ./sshksci-rr-nondet.log:  142156 of 237186 (59.93%) bytes, 6117281 of 8080262 (75.71%) instructions processed.                 
    ./sshksci-rr-nondet.log:  143170 of 237186 (60.36%) bytes, 6169177 of 8080262 (76.35%) instructions processed.                 
    ./sshksci-rr-nondet.log:  159770 of 237186 (67.36%) bytes, 6223649 of 8080262 (77.02%) instructions processed.                 
    READ Match of str 0 at: instr_count=6242040 :  00000000b73aae46 00000000b76fd492 0000000005234000                              
    thestring = [tygertygerburningbrightintheforestofthenight]                                                                     
    search string is sitting in memory starting at 0xb8869ad8                                                                      
                                                                                                                                   
    ****************************************************************************                                                   
    applying taint labels to search string of length 44  @ p=0x00000000b8869ad8                                                    
    ******************************************************************************                                                 
    ./sshksci-rr-nondet.log:  161550 of 237186 (68.11%) bytes, 6303076 of 8080262 (78.01%) instructions processed.                 
    ./sshksci-rr-nondet.log:  162927 of 237186 (68.69%) bytes, 6432973 of 8080262 (79.61%) instructions processed.                 
    ./sshksci-rr-nondet.log:  163143 of 237186 (68.78%) bytes, 6514410 of 8080262 (80.62%) instructions processed.                 
    ./sshksci-rr-nondet.log:  164691 of 237186 (69.44%) bytes, 6556189 of 8080262 (81.14%) instructions processed.                 
    ./sshksci-rr-nondet.log:  166125 of 237186 (70.04%) bytes, 6634239 of 8080262 (82.10%) instructions processed.                 
    ./sshksci-rr-nondet.log:  169152 of 237186 (71.32%) bytes, 6779775 of 8080262 (83.91%) instructions processed.                 
    ./sshksci-rr-nondet.log:  169482 of 237186 (71.46%) bytes, 6886494 of 8080262 (85.23%) instructions processed.                 
    ./sshksci-rr-nondet.log:  170147 of 237186 (71.74%) bytes, 7024997 of 8080262 (86.94%) instructions processed.                 
    ./sshksci-rr-nondet.log:  170461 of 237186 (71.87%) bytes, 7067973 of 8080262 (87.47%) instructions processed.                 
    ./sshksci-rr-nondet.log:  170859 of 237186 (72.04%) bytes, 7151214 of 8080262 (88.50%) instructions processed.                 
    ./sshksci-rr-nondet.log:  170887 of 237186 (72.05%) bytes, 7157730 of 8080262 (88.58%) instructions processed.                 
    ./sshksci-rr-nondet.log:  183741 of 237186 (77.47%) bytes, 7201829 of 8080262 (89.13%) instructions processed.                 
    ./sshksci-rr-nondet.log:  184765 of 237186 (77.90%) bytes, 7290879 of 8080262 (90.23%) instructions processed.                 
    ./sshksci-rr-nondet.log:  185095 of 237186 (78.04%) bytes, 7368415 of 8080262 (91.19%) instructions processed.                 
    ./sshksci-rr-nondet.log:  185828 of 237186 (78.35%) bytes, 7613158 of 8080262 (94.22%) instructions processed.                 
    ./sshksci-rr-nondet.log:  186142 of 237186 (78.48%) bytes, 7658246 of 8080262 (94.78%) instructions processed.                 
    ./sshksci-rr-nondet.log:  187186 of 237186 (78.92%) bytes, 7670238 of 8080262 (94.93%) instructions processed.                 
    ./sshksci-rr-nondet.log:  187852 of 237186 (79.20%) bytes, 7688194 of 8080262 (95.15%) instructions processed.                 
    ./sshksci-rr-nondet.log:  198332 of 237186 (83.62%) bytes, 7759702 of 8080262 (96.03%) instructions processed.                 
    ./sshksci-rr-nondet.log:  204546 of 237186 (86.24%) bytes, 7841277 of 8080262 (97.04%) instructions processed.                 
    ./sshksci-rr-nondet.log:  210784 of 237186 (88.87%) bytes, 7929622 of 8080262 (98.14%) instructions processed.                 
    ./sshksci-rr-nondet.log:  231610 of 237186 (97.65%) bytes, 8001856 of 8080262 (99.03%) instructions processed.                 
    ./sshksci-rr-nondet.log:  log is empty.                                                                                        
    Replay completed successfully.                                                                                                 
    Time taken was: 201 seconds.                                                                                                   
    Stats:                                                                                                                         
    RR_INPUT_1 number = 0, size = 0 bytes                                                                                          
    RR_INPUT_2 number = 0, size = 0 bytes                                                                                          
    RR_INPUT_4 number = 785, size = 23550 bytes                                                                                    
    RR_INPUT_8 number = 4974, size = 169116 bytes                                                                                  
    RR_INTERRUPT_REQUEST number = 1255, size = 35140 bytes                                                                         
    RR_EXIT_REQUEST number = 0, size = 0 bytes                                                                                     
    RR_SKIPPED_CALL number = 64, size = 9330 bytes                                                                                 
    RR_DEBUG number = 0, size = 0 bytes                                                                                            
    max_queue_len = 473                                                                                                            
    472 items on recycle list, 41536 bytes total                                                                                   
    Replay completed successfully.                                                                                                 
    Logging all cpu states                                                                                                         
    CPU #0:                                                                                                                        
    uninit taint plugin                                                                                                            
    asid = 503d000                                                                                                                 
    instr is tainted :  asid=0x503d000 : pc=0xb722c988                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb722c9b6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb722c9ba                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb722c9bd                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb722c9bf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb722c9ca                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb722c9d1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb72cae6e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb72cae71                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb72cae73                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb72cae77                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb72caf41                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb72caf66                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb346                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb399                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb39d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb3b1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb3b7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb3bb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb3d7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb3d9                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb4d2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb520                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb53e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb548                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb54a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb55c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb566                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb569                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb56c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb56f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb572                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb575                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb578                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb57c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb57f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb588                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb728                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb72b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb72e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb731                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb734                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb736                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb738                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb73a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb73c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb743                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb745                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb747                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb749                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb74c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb74f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb751                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb753                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb755                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb75c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb75e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb760                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb762                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb765                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb768                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb76a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb76c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb76e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb775                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb777                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb779                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb77b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb77e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb781                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb783                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb785                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb787                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb78e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb790                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb792                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb794                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb797                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb79a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb79c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb79e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7a0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7a7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7a9                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7ab                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7ad                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7b0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7b3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7b5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7b7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7b9                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7c0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7c2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7c4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7c6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7c9                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7cc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7ce                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7d0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7d2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7d9                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7db                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7dd                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7df                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7e2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7e5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7e7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7e9                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7eb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7f2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7f4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7f6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7f8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7fb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb7fe                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb800                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb802                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb804                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb80b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb80d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb80f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb811                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb814                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb817                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb819                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb81b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb81d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb824                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb826                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb828                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb82a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb82d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb830                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb832                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb834                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb836                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb83d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb83f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb841                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb843                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb846                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb849                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb84b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb84d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb84f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb856                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb858                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb85a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb85c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb85f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb862                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb864                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb866                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb868                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb86f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb871                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb873                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb875                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb878                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb87b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb87d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb87f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb881                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb888                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb88a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb88c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb88e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb891                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb894                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb896                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb898                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb89a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8a1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8a3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8a5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8a7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8aa                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8ad                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8af                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8b1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8b3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8ba                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8bc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8be                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8c0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8c3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8c6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8c8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8cf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8d1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8d3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8d6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8d8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8da                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8dc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8df                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8e1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8e8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8ea                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8ec                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8ef                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8f1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8f3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8f5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8f8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb8fa                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb901                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb903                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb905                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb907                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb909                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb90b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb90d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb910                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb912                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb919                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb91b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb91d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb920                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb922                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb924                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb926                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb929                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb92b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb932                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb934                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb936                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb939                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb93b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb93d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb93f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb942                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb944                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb94b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb94d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb94f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb952                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb954                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb956                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb958                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb95b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb95d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb964                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb966                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb968                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb96b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb96d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb96f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb971                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb974                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb976                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb97d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb97f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb981                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb984                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb986                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb988                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb98a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb98d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb98f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb996                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb998                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb99a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb99d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb99f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9a1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9a3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9a6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9a8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9af                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9b1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9b3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9b6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9b8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9ba                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9bc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9bf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9c1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9c8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9ca                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9cc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9cf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9d1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9d3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9d5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9d8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9da                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9e1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9e3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9e5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9e8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9ea                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9ec                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9ee                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9f1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9f3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9fa                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9fc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cb9fe                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba01                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba03                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba05                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba07                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba0a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba0c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba13                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba15                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba17                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba1a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba1c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba1e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba20                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba23                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba25                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba2c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba2e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba30                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba33                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba35                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba37                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba39                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba3c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba3e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba45                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba47                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba49                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba4c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba4e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba50                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba52                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba55                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba57                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba59                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba5b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba62                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba64                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba67                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba6a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba6c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba73                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba75                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba77                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba79                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba7c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba7e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba80                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba83                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba85                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba87                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba89                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba90                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba92                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba95                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba98                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cba9a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaa1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaa3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaa5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaa7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaaa                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaac                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaae                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbab1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbab3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbab5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbab7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbabe                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbac0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbac3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbac6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbac8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbacf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbad1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbad3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbad5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbad8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbada                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbadc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbadf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbae1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbae3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbae5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaec                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaee                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaf1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaf4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaf6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbafd                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbaff                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb01                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb03                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb06                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb08                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb0a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb0d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb0f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb11                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb13                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb1a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb1c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb1f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb21                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb23                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb2a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb2c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb2e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb30                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb33                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb35                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb37                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb3a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb3c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb3e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb40                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb47                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb49                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb4c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb4f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb51                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb58                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb5a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb5c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb5e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb61                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb63                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb65                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb68                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb6a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb6c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb6e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb75                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb77                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb7a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb7d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb7f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb86                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb88                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb8a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb8c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb8f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb91                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb93                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb96                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb98                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb9a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbb9c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbba3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbba5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbba8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbab                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbad                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbb4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbb6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbb8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbba                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbbc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbc3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbc6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbc8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbca                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbcc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbd3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbd5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbd8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbda                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbdf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbe2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbe4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbe6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbe8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbef                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbf1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbf4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbf6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbfb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbbfe                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc00                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc02                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc04                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc0b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc0d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc10                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc12                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc17                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc1a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc1c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc1e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc20                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc27                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc29                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc2c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc2e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc33                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc36                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc38                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc3a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc3c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc43                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc45                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc48                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc4a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc4f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc52                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc54                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc56                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc58                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc5f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc61                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc64                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc66                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc6b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc6e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc70                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc72                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc74                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc7b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc7d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc80                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc82                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc87                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc8a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc8c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc8e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc90                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc97                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc99                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc9c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbc9e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbca3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbca6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbca8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcaa                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcac                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcb3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcb5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcb8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcba                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcbf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcc2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcc4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcc6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcc8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbccf                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcd1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcd4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcd6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcdb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcde                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbce0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbce2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbce4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbceb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbced                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcf0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcf2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcf7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcfa                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcfc                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbcfe                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd00                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd07                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd09                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd0c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd0e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd13                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd16                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd18                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd1a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd1c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd23                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd25                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd28                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd2a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd2f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd32                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd34                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd36                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd38                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd3f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd41                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd44                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd46                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd4b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd4e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd50                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd52                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd54                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd5b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd5d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd60                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd62                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd67                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd6a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd6c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd6e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd70                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd77                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd79                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd7d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd7f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd82                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd85                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd88                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd8a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd8c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd8f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd91                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd94                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd96                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd99                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd9b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbd9e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbda1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbda4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbda7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbdaa                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbdac                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbdb2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbdb3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbdb4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbdb5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbdb6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74cbdb7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74d286f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74d2876                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74d287e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74d2885                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb74d290d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb75451f2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb7545225                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb7545228                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb754522c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb754d396                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb754d3a8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb754d3b3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb754d3bb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb754d3c6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb754d3c9                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d10e8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d2083                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d208b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d208f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d5472                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d6f43                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d6f46                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d6f48                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d6f4c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76d8943                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76dc0c0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76dc0cb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76e21e7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76e21ed                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76e2204                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76e2562                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76e2656                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76e265d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f7888                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f788e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f7893                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f7896                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f7898                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f789a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f789e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f78a0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f78a3                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f78a4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xb76f78a5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc100abb1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc100c0f2                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc100c110                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc100f401                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc100f405                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc100f443                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc100f444                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc100f4ad                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc1029eda                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc102e279                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc103d1e5                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc103d27b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc103d286                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc105dad8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc105dae1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc105dae7                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc105dae9                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc105daed                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc105daf8                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc10d97eb                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc115df02                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc116608a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc116608e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11660ac                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11660b0                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d0246                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d0247                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d024a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d024c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d0253                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d026c                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d0274                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d0290                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d0295                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d0296                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d0298                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d127d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1288                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d128a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1298                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d129a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d129f                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d12d4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d131b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1348                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d134b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1364                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1366                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1368                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d136b                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1373                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1390                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d13df                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d1d3e                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d43b6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d43ba                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d43c4                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc11d43c6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c3043                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c3045                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c4579                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c458a                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c458d                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c45ad                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c45b1                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c8de6                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c8e01                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c8e02                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c8e04                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c8e05                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c8e06                                                                             
    instr is tainted :  asid=0x503d000 : pc=0xc12c8e0b                                                                             
    asid = 5234000                                                                                                                 
    instr is tainted :  asid=0x5234000 : pc=0xb73b848c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb73b8494                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74045e2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7407362                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7407365                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74074ac                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74074af                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74074b2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7407506                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7407839                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740783b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740783e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7407840                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7407d24                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740989d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740cbf8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740cbfa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740cbfc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740cbfe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740cbff                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740cc00                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740cc02                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740cc04                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740e980                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740e9b6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740e9ba                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740e9bd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740e9bf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740e9ca                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb740e9d1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74141ed                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74141f6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74141fa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74141fe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414202                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414204                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414206                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414212                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741421b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741421d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741421f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414223                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414225                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414227                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741422b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741422f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414233                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414239                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414240                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414245                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414249                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741424b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741424d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414252                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414256                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414258                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741425a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741425f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414263                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414265                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414267                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741426c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414270                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414273                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414279                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414290                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414293                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414295                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414298                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7414299                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741429a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741429b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb741429d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74142a0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74142a2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74142a5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74142a6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74142a7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb745ba0b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb745ba17                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ace6e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ace71                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ace73                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ace77                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ace7a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acf30                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acf41                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acf66                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfbc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfc0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfc5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfca                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfcf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfd4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfd9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfde                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acff1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acff5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acffa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74acfff                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad004                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad009                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad00e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad013                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad229                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad22e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad233                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad3e9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad3ee                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad3f3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb74ad3f8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754745c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754a3f4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754a412                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d346                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d399                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d39d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d3b1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d3b7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d3bb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d3d7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d3d9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d4d7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d520                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d53e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d548                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d54a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d55c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d566                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d569                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d56c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d56f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d572                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d575                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d57c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d57f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d584                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d588                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d728                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d72a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d72b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d72e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d731                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d734                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d736                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d738                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d73a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d73c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d743                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d745                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d747                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d749                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d74c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d74f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d751                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d753                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d755                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d75c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d75e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d760                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d762                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d765                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d768                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d76a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d76c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d76e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d775                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d777                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d779                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d77b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d77e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d781                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d783                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d785                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d787                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d78e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d790                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d792                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d794                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d797                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d79a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d79c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d79e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7a0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7a7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7a9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7ab                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7ad                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7b0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7b3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7b5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7b7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7b9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7c0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7c2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7c4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7c6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7c9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7cc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7ce                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7d0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7d2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7d9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7db                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7dd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7df                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7e2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7e5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7e7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7e9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7eb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7f2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7f4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7f6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7f8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7fb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d7fe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d800                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d802                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d804                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d80b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d80d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d80f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d811                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d814                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d817                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d819                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d81b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d81d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d824                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d826                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d828                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d82a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d82d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d830                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d832                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d834                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d836                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d83d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d83f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d841                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d843                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d846                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d849                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d84b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d84d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d84f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d856                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d858                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d85a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d85c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d85f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d862                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d864                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d866                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d868                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d86f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d871                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d873                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d875                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d878                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d87b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d87d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d87f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d881                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d888                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d88a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d88c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d88e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d891                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d894                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d896                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d898                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d89a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8a1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8a3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8a5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8a7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8aa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8ad                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8af                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8b1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8b3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8ba                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8bc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8be                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8c0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8c3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8c6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8c8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8cf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8d1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8d3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8d6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8d8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8da                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8dc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8df                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8e1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8e8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8ea                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8ec                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8ef                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8f1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8f3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8f5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8f8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d8fa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d901                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d903                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d905                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d907                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d909                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d90b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d90d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d910                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d912                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d919                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d91b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d91d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d920                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d922                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d924                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d926                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d929                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d92b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d932                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d934                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d936                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d939                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d93b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d93d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d93f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d942                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d944                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d94b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d94d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d94f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d952                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d954                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d956                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d958                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d95b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d95d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d964                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d966                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d968                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d96b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d96d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d96f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d971                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d974                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d976                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d97d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d97f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d981                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d984                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d986                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d988                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d98a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d98d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d98f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d996                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d998                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d99a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d99d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d99f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9a1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9a3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9a6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9a8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9af                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9b1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9b3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9b6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9b8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9ba                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9bc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9bf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9c1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9c8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9ca                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9cc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9cf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9d1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9d3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9d5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9d8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9da                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9e1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9e3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9e5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9e8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9ea                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9ec                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9ee                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9f1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9f3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9fa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9fc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754d9fe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da01                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da03                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da05                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da07                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da0a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da0c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da13                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da15                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da17                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da1a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da1c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da1e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da20                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da23                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da25                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da2c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da2e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da30                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da33                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da35                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da37                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da39                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da3c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da3e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da45                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da47                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da49                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da4c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da4e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da50                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da52                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da55                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da57                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da59                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da5b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da62                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da64                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da67                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da6a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da6c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da73                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da75                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da77                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da79                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da7c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da7e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da80                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da83                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da85                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da87                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da89                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da90                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da92                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da95                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da98                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754da9a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daa1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daa3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daa5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daa7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daaa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daac                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daae                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dab1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dab3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dab5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dab7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dabe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dac0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dac3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dac6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dac8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dacf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dad1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dad3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dad5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dad8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dada                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dadc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dadf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dae1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dae3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dae5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daec                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daee                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daf1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daf4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daf6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dafd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754daff                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db01                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db03                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db06                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db08                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db0a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db0d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db0f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db11                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db13                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db1a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db1c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db1f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db21                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db23                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db2a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db2c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db2e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db30                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db33                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db35                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db37                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db3a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db3c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db3e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db40                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db47                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db49                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db4c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db4f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db51                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db58                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db5a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db5c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db5e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db61                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db63                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db65                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db68                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db6a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db6c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db6e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db75                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db77                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db7a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db7d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db7f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db86                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db88                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db8a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db8c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db8f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db91                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db93                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db96                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db98                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db9a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754db9c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dba3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dba5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dba8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbab                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbad                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbb4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbb6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbb8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbba                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbbc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbbe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbc3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbc6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbc8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbca                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbcc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbd3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbd5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbd8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbda                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbdf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbe2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbe4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbe6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbe8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbef                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbf1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbf4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbf6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbfb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dbfe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc00                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc02                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc04                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc0b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc0d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc10                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc12                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc17                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc1a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc1c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc1e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc20                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc27                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc29                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc2c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc2e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc33                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc36                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc38                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc3a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc3c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc43                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc45                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc48                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc4a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc4f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc52                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc54                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc56                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc58                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc5f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc61                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc64                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc6b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc6e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc70                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc72                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc74                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc7b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc7d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc80                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc82                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc87                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc8a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc8c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc8e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc90                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc97                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc99                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc9c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dc9e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dca3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dca6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dca8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcaa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcac                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcb3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcb5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcb8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcba                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcbf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcc2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcc4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcc6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcc8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dccf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcd1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcd4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcd6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcdb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcde                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dce0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dce2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dce4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dceb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dced                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcf0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcf2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcf7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcfa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcfc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dcfe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd00                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd07                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd09                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd0c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd0e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd13                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd16                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd18                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd1a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd1c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd23                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd25                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd28                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd2a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd2f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd32                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd34                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd36                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd38                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd3f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd41                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd44                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd46                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd4b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd4e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd50                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd52                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd54                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd5b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd5d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd60                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd62                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd67                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd6a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd6c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd6e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd70                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd77                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd79                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd7d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd7f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd82                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd85                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd88                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd8a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd8c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd8f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd91                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd94                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd96                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd99                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd9b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dd9e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dda1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dda4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754dda7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754ddaa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754ddac                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754ddb2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754ddb3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb754ddb6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627a0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627a3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627ad                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627e0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627e4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627e8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627eb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627ee                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627f1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627f6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627fa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75627fd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562802                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562805                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562808                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756280b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562810                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562813                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562815                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562819                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756281c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562821                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562824                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562826                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562829                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756282c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562831                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562834                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562836                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562839                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756283e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562841                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562843                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562846                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562849                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756284e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562851                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562854                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562859                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756285c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756285e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562861                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562864                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562869                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756286c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756286e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562871                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562876                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562879                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756287b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756287e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562881                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562886                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562889                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756288c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562891                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562894                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562896                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562899                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756289c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756289f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628a4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628a7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628a9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628ae                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628b3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628b6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628b8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628bb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628c0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628c3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628c5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628c8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628ce                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628d3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628d5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628d8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628db                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628de                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628e2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628e8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628ed                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628f0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628f3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628f6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628f9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628fc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75628ff                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562902                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562905                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562909                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756290d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562910                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562913                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562916                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562919                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756291d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562921                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562924                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562927                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756292a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756292d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562930                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562933                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562937                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756293b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756293f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562943                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562946                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562949                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756294c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756294f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562952                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562955                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562958                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756295c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562960                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562964                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562967                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756296b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756296f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562972                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562975                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562978                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756297b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756297e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562981                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562984                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562987                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562990                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562993                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629a0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629a4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629a6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629a9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629ac                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629af                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629c0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629c2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629c8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629cc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629cf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629d3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629d5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629d8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629de                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629e2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629e4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629e7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629eb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629ef                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629f1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629f7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629fa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75629fe                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a01                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a05                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a07                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a0a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a10                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a14                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a16                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a19                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a1d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a21                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a23                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a29                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a2c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a30                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a33                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a37                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a39                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a3c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a42                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a48                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a4c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a4f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a53                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a57                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a5b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a5e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a62                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a66                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a6c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a70                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a74                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a78                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a7a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a7d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a7f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a82                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a85                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a88                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a8c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a90                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a96                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a98                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562a9e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562aa2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562aa8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562aab                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562aaf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ab5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ab7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ab9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562abc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ac2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ac6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562acc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ace                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ad0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ad3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ad7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562add                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562adf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ae3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ae5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562aeb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562aee                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562af2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562af8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562afb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562aff                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b05                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b07                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b09                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b0c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b12                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b16                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b1c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b1e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b20                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b23                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b27                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b2d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b2f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b33                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b35                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b3b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b3e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b42                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b48                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b4b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b4f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b55                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b57                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b59                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b5c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b62                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b68                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b6c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b72                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b74                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b77                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b7b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b81                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b83                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b87                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b8d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b91                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b97                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b9a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562b9e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ba3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ba5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562ba9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562baf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bb3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bb9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bbb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bbf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bc3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bc9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bcb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bcd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bd0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bd2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bd5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bd8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7562bdb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565036                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565080                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565083                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565086                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565088                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756508b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756508e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756509a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756509e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650a2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650a4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650a7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650aa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650ad                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650b0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650b4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650b8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650c6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650cc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650cf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650d2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650d4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650d7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650da                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650eb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650f0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650f2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650f4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650f6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75650ff                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565100                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652d8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652db                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652e0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652e3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652f0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652f4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652f8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652fc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75652ff                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565303                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756530a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565311                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565314                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565317                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756531b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756532d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565330                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565334                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565336                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756533c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756533d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756560c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756560e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565611                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565614                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565617                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565619                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756561c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756561f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565622                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565628                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756562a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756562d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565630                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565635                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565638                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756563b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756563d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565642                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565645                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565648                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756564a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756564f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565652                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565655                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565657                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756565c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756565f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565661                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565668                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756566b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756566e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565671                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565674                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565677                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756567a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756567d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756567e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565681                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565684                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7565686                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756568d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756568f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756582a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756582b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75695dc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75695e2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7569634                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb756963a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c2fe8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c32a2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c32aa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c64f0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c64f4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c64f8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c64fb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c64fd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6501                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6503                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6505                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6508                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6510                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6512                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6515                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6518                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c651b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6523                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6525                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6528                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c652b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c652e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6536                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6539                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6541                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6544                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c654a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c654d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6554                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6556                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c655c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c655f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6562                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6565                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c65e0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c65ed                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c65ee                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c65ef                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c65f0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c65f1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c66ec                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6700                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6708                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c670c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6710                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6713                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c6715                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c71f2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c7228                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c722c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c7965                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c79c2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c8173                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c8175                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c853e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c853f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c8540                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c8541                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c9100                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c9104                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c910a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c910f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c911c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c9120                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75c912c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75cd0d9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75cd0f5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75cd0f7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75cd0fc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75cd71f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75cd7e1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75cf396                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75f9c11                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75f9c1f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb75fa9aa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76d7419                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e0eea                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e0f02                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e0f05                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e0f08                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e0f0a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e0f11                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e5b75                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e5b78                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e5b7b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e5b7e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e5b80                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e5b83                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e5b86                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76e5b89                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76fa810                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76fd492                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76fd4a4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76fd4a8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76ff802                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76ff8fd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76ff900                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76ff916                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb76ff91d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7702a09                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7702a0b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb77095f3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb77095ff                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb770a0ed                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb770a0f0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717600                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717613                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717621                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717626                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717629                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb771762f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717632                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717638                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb771763c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717644                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb771764d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717651                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717656                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb771765b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717660                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717665                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717667                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb771766f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb77176a4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb77176a7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb77176aa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb77176d1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717b6e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717b72                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717cd8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717cdc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717ce2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717ce7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717ce9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717d06                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717d10                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xb7717d11                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100abb1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100af3e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100c0f2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100c110                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100ca2f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100ca30                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100ca44                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100ca5d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100caae                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100f3a3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100f3aa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100f4ac                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100f4bf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100f4ce                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc100fa01                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101dfdb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101dfe8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101e462                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101e463                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101e468                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101e469                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101e4ad                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101e4c4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc101e4c5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1020ca5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1024498                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102a211                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102ae00                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102ae01                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102ae1d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102ae21                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102ae2c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102ae32                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102aed9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102aee5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102b779                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102bb98                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102bb9b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102bb9c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102bba7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102bbc3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102bbeb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102bbf1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102d06c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102d06e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e279                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e27a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e27e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e28e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e322                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e6d3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e804                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e80f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e820                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e836                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e842                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc102e844                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc103d239                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc103d23e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc104fc9c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc104ffb0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1050025                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc105085f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc105087c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10508cc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10508df                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1050917                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1050a41                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1051852                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1051889                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc105188a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc105188c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc105188d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10519ce                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1051a34                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1051a8c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1051b54                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053be2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053bf3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053bf8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053bfd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c0d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c0f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c14                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c18                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c1e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c20                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c21                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c24                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c26                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c29                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1053c31                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1054758                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1054787                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10547d6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1054e44                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1054e5d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1054e69                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1054e78                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1054e80                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1054ed0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc105dae6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc105dae9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc105db23                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc107af28                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc107af35                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc107af3d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc107b0db                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc107be77                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc107beb0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10cd589                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10cd58a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10cd5a2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10cd656                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10cd65f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10ce582                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10ce5a1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc10ce5b5                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc116119c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc116209a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc116209d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc116209e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11620a3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1162133                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc116214c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1162151                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1162baf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1165938                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc116593d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1165944                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1165946                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1165948                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11660ac                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc1166136                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d02aa                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d2279                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d2281                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d2286                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d22d0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d22e6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d22f0                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d22f8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d22fd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d43b6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d5728                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d572b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d5896                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d58ab                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc11d597a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c3043                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c3045                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c3051                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c3069                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c3363                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c336f                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c337b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c35dc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c35de                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4578                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4579                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4597                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4599                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c459a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c45b1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4705                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4707                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c470b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4714                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c471d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4721                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c479e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47a6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47b6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47b7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47b8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47b9                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47ba                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47bb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47bc                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47be                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47bf                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47c1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47c3                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c47c6                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4823                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4829                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c482c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c4832                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5118                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c511d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c511e                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5120                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5122                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5123                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5124                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5125                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5126                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5127                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5128                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5129                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c512a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c512b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5130                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5142                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5308                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5310                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5312                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5313                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5314                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5315                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5316                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5317                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5318                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5319                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c531a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c531b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c531c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5321                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5323                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5329                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c5368                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c536a                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71b1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71b2                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71b4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71ba                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71c4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71e1                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71e4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71e7                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71eb                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71ed                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71f4                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71f8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c71fd                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c726c                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c750d                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c8df8                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c8e01                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c8e0b                                                                             
    instr is tainted :  asid=0x5234000 : pc=0xc12c8e88                                                                             
    asid = 6d3f000                                                                                                                 
    instr is tainted :  asid=0x6d3f000 : pc=0xc100af67                                                                             
    instr is tainted :  asid=0x6d3f000 : pc=0xc12c3581                                                                             
    asid = 6e68000                                                                                                                 
    instr is tainted :  asid=0x6e68000 : pc=0xc100abb1                                                                             
    instr is tainted :  asid=0x6e68000 : pc=0xc100af67                                                                             
    instr is tainted :  asid=0x6e68000 : pc=0xc100c110                                                                             
    instr is tainted :  asid=0x6e68000 : pc=0xc12c3581                                                                             
    instr is tainted :  asid=0x6e68000 : pc=0xc12c5130                                                                             
    asid = 7a2f000                                                                                                                 
    instr is tainted :  asid=0x7a2f000 : pc=0x804d7af                                                                              
    instr is tainted :  asid=0x7a2f000 : pc=0xc100af67                                                                             
    instr is tainted :  asid=0x7a2f000 : pc=0xc12c3581                                                                             



