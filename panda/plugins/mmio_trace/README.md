Plugin: mmio_trace
===========

Summary
-------

Log MMIO interactions within the guest.
Each interaction is annotated with the corresponding device name.
Interaction data (access type, address, value, etc) will be accurate, but device name may not be (only tested on a few ARM boards).

Arguments
---------

* out_log (string): JSON file to log MMIO R/Ws to (optional)

Dependencies
------------

None

APIs and Callbacks
------------------

As an alternative to the optional log file output in `uninit_plugin`, API for retrieval of sequential MMIO event tuples (`access_type`, `pc`, `phys_addr`, `virt_addr`, `size`, `value`, `dev_name`).


```c
// Get heap-allocated array of contiguous mmio_event_t structs and their count
mmio_event_t* get_mmio_events(int* struct_cnt_ret);
```

Example
-------

Testing with the Debian ARM image used by PANDA's `run_debian.py --arch arm`, log all MMIO accesses to `mmio.log`:

```
arm-softmmu/panda-system-arm -M versatilepb -kernel ~/.panda/vmlinuz-3.2.0-4-versatile \
    -initrd ~/.panda/initrd.img-3.2.0-4-versatile -hda ~/.panda/arm_wheezy.qcow \
    -monitor stdio -loadvm root \
    -panda mmio_trace:out_log="mmio.json"
```

Fidelity Note for Cortex-M
-------

Running a Cortex-M test firmware with `qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb ... -panda mmio_trace:out_log="mmio.json"`, excerpt from this plugin's output
showing interactions with `SysTick` CPU private peripheral:

```json
...
{ "type": "R", "guest_pc": "0x0000043e", "phys_addr": "0x00000010", "virt_addr": "0xe000e010", "size": "0x00000004", "value": "0x00000000", "device": "systick" },
{ "type": "W", "guest_pc": "0x00000444", "phys_addr": "0x00000010", "virt_addr": "0xe000e010", "size": "0x00000004", "value": "0x00000004", "device": "systick" },
{ "type": "W", "guest_pc": "0x0000044a", "phys_addr": "0x00000014", "virt_addr": "0xe000e014", "size": "0x00000004", "value": "0x00001000", "device": "systick" },
{ "type": "W", "guest_pc": "0x0000044c", "phys_addr": "0x00000018", "virt_addr": "0xe000e018", "size": "0x00000004", "value": "0x00000000", "device": "systick" },
{ "type": "R", "guest_pc": "0x0000044e", "phys_addr": "0x00000010", "virt_addr": "0xe000e010", "size": "0x00000004", "value": "0x00000004", "device": "systick" },
{ "type": "W", "guest_pc": "0x00000454", "phys_addr": "0x00000010", "virt_addr": "0xe000e010", "size": "0x00000004", "value": "0x00000005", "device": "systick" },
{ "type": "R", "guest_pc": "0x00000478", "phys_addr": "0x00000010", "virt_addr": "0xe000e010", "size": "0x00000004", "value": "0x00000005", "device": "systick" },
{ "type": "R", "guest_pc": "0x00000480", "phys_addr": "0x00000018", "virt_addr": "0xe000e018", "size": "0x00000004", "value": "0x00000e41", "device": "systick" },
{ "type": "R", "guest_pc": "0x00000478", "phys_addr": "0x00000010", "virt_addr": "0xe000e010", "size": "0x00000004", "value": "0x00000005", "device": "systick" },
{ "type": "R", "guest_pc": "0x00000480", "phys_addr": "0x00000018", "virt_addr": "0xe000e018", "size": "0x00000004", "value": "0x00000df1", "device": "systick" },
...
```

Because of QEMU's `iotlb` implementation there is both a physical and virtual address logged, but virtual addresses do not exist on Cortex-M CPUs (which may have MPUs but not MMUs).
According to [pg. 95 of the datasheet](http://www.ti.com/lit/ds/spms144i/spms144i.pdf) for this board, `0xe000e010-0xe000e01f`, is the correct physical address range
for the `SysTick` peripheral. Corresponding excerpt from QEMU's memory map (notice the end address doesn't exactly match the datasheet):

```
address-space: cpu-memory
  0000000000000000-ffffffffffffffff (prio 0, i/o): armv7m-container
    ... (entries omitted)
    00000000e000e000-00000000e000efff (prio 0, i/o): nvic
      00000000e000e000-00000000e000efff (prio 0, i/o): nvic_sysregs
      00000000e000e010-00000000e000e0ef (prio 1, i/o): systick
```

This particular board is also missing peripherals, the below is an excerpt from `hw/arm/stellaris.c` , the only board that uses the QEMU API `create_unimplemented_device()` (although other boards may be missing peripherals):

```
/* Add dummy regions for the devices we don't implement yet,
 * so guest accesses don't cause unlogged crashes.
 */
create_unimplemented_device("wdtimer", 0x40000000, 0x1000);
create_unimplemented_device("i2c-0", 0x40002000, 0x1000);
create_unimplemented_device("i2c-2", 0x40021000, 0x1000);
create_unimplemented_device("PWM", 0x40028000, 0x1000);
create_unimplemented_device("QEI-0", 0x4002c000, 0x1000);
create_unimplemented_device("QEI-1", 0x4002d000, 0x1000);
create_unimplemented_device("analogue-comparator", 0x4003c000, 0x1000);
create_unimplemented_device("hibernation", 0x400fc000, 0x1000);
create_unimplemented_device("flash-control", 0x400fd000, 0x1000);
```

So, when using this plugin, keep in mind:
1. QEMU's "virtual address" may actually be the physical address.
2. QEMU's board definitions may not implement all MMIO peripherals, so logged MMIO interactions may reflect real-world behavior.