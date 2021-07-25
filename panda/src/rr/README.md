Record Replay
===

This documentation was created while debugging RR for arm virt machine, not by the original RR devlopers. It's better than nothing but not great.


## Reading your XYZ-rr-nondet.log files
In build directory under architecture - `rr_print_[arch] [infile]`
dumps data like:

```
opened ./dd-rr-nondet.log for read.  len=288558 bytes.
RR Log with 136917553 instructions
{guest_instr_count=0}
        RR_INTERRUPT_REQUEST_2 from RR_CALLSITE_CPU_HANDLE_INTERRUPT_BEFORE
{guest_instr_count=2}
        RR_INTERRUPT_REQUEST_6 from RR_CALLSITE_CPU_HANDLE_INTERRUPT_AFTER
{guest_instr_count=3}
        RR_INTERRUPT_REQUEST_2 from RR_CALLSITE_CPU_HANDLE_INTERRUPT_BEFORE
{guest_instr_count=57}
        RR_INPUT_8 27 from RR_CALLSITE_IO_READ_ALL
{guest_instr_count=61}
        RR_INTERRUPT_REQUEST_0 from RR_CALLSITE_CPU_HANDLE_INTERRUPT_BEFORE
{guest_instr_count=7730}
        RR_INPUT_8 1023 from RR_CALLSITE_IO_READ_ALL
{guest_instr_count=19796}
        RR_INTERRUPT_REQUEST_2 from RR_CALLSITE_CPU_HANDLE_INTERRUPT_BEFORE
```


## Skipped calls
`rr_record_skipped_call` - special case for when guest needs to be explicitly modified. E.g., `rr_record_hd_transfer` which records data transfered to/from hd.


## diverge.py
*Incredible* python script to use mozilla RR + PANDA to root cause a divergence between record and replay. Not perfect for non x86.

The script auto calculates the ram base pointer by using an physical pointer to RAM to find the memory region. This varies per arch/machine so you might need to reconfigure it (you'll get an assertion if so).
Once you get the base ram pointer (you'll see it in a bunch of the calculations) you can use that to read guest RAM as follows:

### Read guest memory from debugger.
Short version: Guest virt addr -> guest physaddr -> host virtaddr -> gdb read with `x`

First convert the guest virtual address (ZZZ) to a physical one:
```
panda_virt_to_phys(current_cpu, ZZZ)
```

Then identify the memory region containing that address and get a HOST pointer to it:

```
p memory_region_find(get_system_memory(), GUEST_PHYS_ADDR, 0).mr->name
p/x memory_region_find(get_system_memory(), GUEST_PHYS_ADDR, 0).mr->ram_block.host
```

Then find the offset from that host pointer to your memory
```
p/x memory_region_find(get_system_memory(), GUEST_PHYS_ADDR, 0).offset_within_region
```

Finally, read host memory at the (memory region + the offset to the address) and that will give you guest memory.

```
p/10x [ram_block.host] + [offset_within_region]
```
