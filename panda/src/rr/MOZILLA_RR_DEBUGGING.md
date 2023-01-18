# How to use Mozilla RR to debug PANDA's record/replay.  

## Introduction

Some notes on how to use Mozilla's RR to debug PANDA's RR.

This example is worked for MIPS.  
But you can extrapolate to other arch.  
You need to be able to boot / do things in the guest.  
So the various Qemu cmdline args needed for that are your problem. 

Note that you also will need various files like qcows and kernels perhaps.  
A good way to get these is with PyPanda.

    python
    from pandare import Panda
    from pandare.qcows import Qcows
    panda = Panda(generic="mips")

If you don't already have the needed files to boot and work with a fairly generic MIPS linux guest, that should download them to your `~/.panda` directory.
Further, if you need to know the cmdline for panda to boot that guest, this python one-liner will tell you what that is.

    python3 -m pandare.qcows mips

When I run this, I get back the following.

    Run the generic mips PANDA guest interactively with the following command:
    ~/git/panda/build/mips-softmmu/panda-system-mips -L ~/git/panda/build/mips-softmmu/pc-bios -os linux-32-debian:3.2.0-4-4kc-malta ~/.panda/debian_7.3_mips.qcow -m 1g -M malta -kernel ~/.panda/vmlinux-3.2.0-4-4kc-malta -append root=/dev/sda1 -nographic -loadvm root


In this example, we will create a recording of guest running the command `ls` and then try to replay the PANDA recording and observe that this fails.  
Then we'll use Mozilla rr to debug.

## Take Mozilla RR recording of PANDA record

First, create Mozilla rr recording of PANDA taking a recording called 'ls'.  
Note that this cmdline will store Mozilla RR files in the `recrep` directory.  

    cd ~/git/panda/build
    rr record -o recrep \
      ./mips-softmmu/panda-system-mips \
      ~/.panda/debian_7.3_mips.qcow \
      -m 1g -M malta \
      -kernel ~/.panda/vmlinux-3.2.0-4-4kc-malta \
      -append root=/dev/sda1 \
      -nographic

Now you should operate PANDA as usual to create a recording.  Switch to monitor and `loadvm root` if you dont want to wait for boot.  Take a recording named `ls` in which you type something like `/bin/ls /etc` in the guest.    

You should at this point probably verify that replaying the PANDA recording you just created fails.

    ./mips-softmmu/panda-system-mips \
      -m 1g -M malta \
      -kernel ~/.panda/vmlinux-3.2.0-4-4kc-malta \
      -replay ls

If you now have a failing replay, take note of the max instr count reached during replay since you'll need it later.


## Take Mozilla RR recording of PANDA failing to replay its own recording

Here's how to create Mozilla rr recording of PANDA trying and failing to replay its own recording.

Note: Mozilla rr files will be in the reprep directory

    rr record -o reprep \
      ./mips-softmmu/panda-system-mips \
      -m 1g -M malta \
      -kernel ~/.panda/vmlinux-3.2.0-4-4kc-malta \
      -replay ls

## Replaying either of those Mozilla RRs

When you replay a Mozilla rr recording, you do so from a gdb shell. 

    rr replay recrep
    rr replay reprep

Either of these will launch the shell which looks like

    (rr)

And from which you can set break points in the program that will eventually execute.  
Those break points also work under the magic new gdb command "rc" for reverse-continue. 
So you can run the replay forward and backward to debug.


## Running `diverge.py`

This is a cool script that, implausibly, tries to do the following.  
  
1. Start replaying the mozilla recording of Panda record.

2. Start replaying the mozilla recording of Panda replay.

3. Set breakpoint for the former in `rr_do_begin_record`, i.e., just when we request that a recording be taken.

4. Set breakpoint for the latter in `rr_do_begin_replay`, i.e., just when panda begins to replay a recording.
   
5. Allow both to continue to their respective break points.

6. Set breakpoints in both at cpu_loop_exec_tb, which is the function that executes a single guest emulated basic block

7. Make those breakpoints in 6 conditional upon instruction count.

8. Perform a binary search over instruction counts, with initial bracketing being something like [low_instr_count, max_instr_count] where that upper bounds comes from where the PANDA replay failed.

9. The binary search is looking for the point at which there is a memory+regs+cpu_hidden_state divergence between the two mozilla replays.  
Divergence is judged via panda functions that compute checksums over memory, regs, hidden state.


**NB: 6 implies that diverge.py is assuming that basic block chaining is *disabled* during recording and replaying.**

The result of `diverge.py` is usually a fairly tight bracket of instruction counts between which you need to figure out why divergence occurs. 

Here's how to actually run `diverge.py`.  
First, you need to do this in tmux so get yourself inside a tmux session. 

    python ../panda/scripts/diverge.py --rr /usr/local/bin/rr recrep reprep    --instr-max=XX

Use the last instruction replay got to from before, here, in place of XX.
And if your `rr` is somewhere else, fix that too. 

## Further debugging with rr

You can also use rr by hand if you want to poke around and examine values.  

    rr replay recrep
    rr replay reprep

RR exposes a gdb-like interface with the prompt `(rr)`.
Use one of these to get to start of record/replay.

    break rr_do_begin_record
    break rr_do_begin_replay

Now use this conditional breakpoint to get you to right point in the rr recording.
    break cpu_loop_exec_tb if cpus->tqh_first->rr_guest_instr_count > 1718780

And then you can disable that bp and add this one to go one bb at a time
    break cpu_loop_exec_tb


Other things you might need.

1. Here's how to print disassembly of bb about to execute.

    call target_disas(stdout, cpu, tb->pc, tb->size, 0)

2. Here's how to print out lots of register values.

    call cpu_dump_state((CPUState*) cpus->tqh_first, stderr, fprintf, CPU_DUMP_FPU)

3. This has something to do with pending exceptions?

    p/x ((CPUMIPSState *) (cpus->tqh_first->env_ptr))->CP0_EPC

4. This is the MIPS asid, kinda

    p/x ((CPUMIPSState *) (cpus->tqh_first->env_ptr))->CP0_EntryHi

5. This is the instruction count

    p cpus->tqh_first->rr_guest_instr_count

6. This is the PC

    p/x ((CPUMIPSState*)cpus->tqh_first->env_ptr)->active_tc.PC

7. Checksums:

    call rr_checksum_regs()
    call rr_checksum_ram()
    call rr_checksum_tlb() 

8. Here's how to determine if a virtual address is currently mapped to a physical one. 

    call panda_virt_to_phys(cpus->tqh_first, 0x7f81cac0)

In mips, we've seen situations in which this will succeed in the rr record but fail in the rr replay. 
This is due to tlb being flushed differently in the two. Note that MIPS has to run guest code to figure out virtual to physical mappings when they aren't in the tlb. 


    