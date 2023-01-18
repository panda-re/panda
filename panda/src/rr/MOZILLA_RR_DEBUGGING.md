How to use Mozilla RR to debug Panda's record/replay.  This example is worked for MIPS.  But you can extrapolate to other arch.  You need to be able to boot / do things in the guest.  So the various Qemu cmdline args needed for that are your problem. 

In this example, we will create a recording of guest running the command `ls` and then try to replay the panda recording and observe that this fails.  Then we'll use Mozilla rr to debug.

First, create mozilla rr recording of panda taking a recording called 'ls':
RR files will be in the recrep directory.  

    cd ~/git/panda/build
    rr record -o recrep \
      ./mips-softmmu/panda-system-mips \
      ~/.panda/debian_7.3_mips.qcow \
      -m 1g -M malta \
      -kernel ~/.panda/vmlinux-3.2.0-4-4kc-malta \
      -append root=/dev/sda1 \
      -nographic

Now you should operate panda as usual to create a recording.  Switch to monitor and `loadvm root`.  Take a recording named `ls` in which you type something like `/bin/ls /etc` in the guest.    

You should at this point probably verify that replay just plain fails:

    ./mips-softmmu/panda-system-mips \
      -m 1g -M malta \
      -kernel ~/.panda/vmlinux-3.2.0-4-4kc-malta \
      -replay ls

If you now have a failing replay, you can use Mozilla RR to create a recording of panda failing at that replay.  
RR files will be in the reprep directory

    rr record -o reprep \
      ./mips-softmmu/panda-system-mips \
      -m 1g -M malta \
      -kernel ~/.panda/vmlinux-3.2.0-4-4kc-malta \
      -replay ls

Given that, you should be able to use `diverge.py`


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

2. Here's how to print out lots of registers.
    call cpu_dump_state((CPUState*) cpus->tqh_first, stderr, fprintf, CPU_DUMP_FPU)

3. This has something to do with pending exceptions?
    p/x ((CPUMIPSState *) (cpus->tqh_first->env_ptr))->CP0_EPC

4. This is the MIPS asid, kinda
    p/x ((CPUMIPSState *) (cpus->tqh_first->env_ptr))->CP0_EntryHi

5. This is the instruction count
    p cpus->tqh_first->rr_guest_instr_count

6. This is the PC
    p/x ((CPUMIPSState*)cpus->tqh_first->env_ptr)->active_tc.PC

7. Checksum for regs
    call rr_checksum_regs()

    call panda_virt_to_phys(cpus->tqh_first, 0x7f81cac0)


    