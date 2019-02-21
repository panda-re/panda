Plugin: NAME
===========

Summary
-------

Call a function in the guest (currently ARM only)

Arguments
---------

* when (ulong): PC at which to call our function
* func (ulong): Function to call
* args (string): Hexidecimal, dash delimited arguments for the function to call (optional)
* mm_file (string): File to memory map (optional)
* mm_dst (ulong): Memory location to map file (optional)
* rev_push (bool): Push stack arguments in reverse order, if any (optional)

Dependencies
------------

None

APIs and Callbacks
------------------

None

Example 1
---------

Call the function `kmalloc` to allocate 64KB of kernel memory whenever `do_execve` is called. Note that these addresses are specific to the Debian ARM image used by PANDA's `run_debian.py --arch arm`; you will have to adjust them if you want to use them on another target.

```
arm-softmmu/qemu-system-arm -M versatilepb -kernel ~/.panda/vmlinuz-3.2.0-4-versatile \
    -initrd ~/.panda/initrd.img-3.2.0-4-versatile -hda ~/.panda/arm_wheezy.qcow \
    -serial stdio -loadvm root -display none \
    -panda callfunc:when=0xc00ca05c,func=0xc00bb0cc,args="0x10000-0xd0"
```

Example 2
---------

Write a `null` terminated string to a file, map that file into guest memory to use it's contents as the format string for a call to the kernel's `printk` function, again triggered whenever `do_execve` is called.

```
echo -ne "Hello from kernel's printk! %d %d %d %d %d %d %d\n\0" > fmt_str.txt

arm-softmmu/qemu-system-arm -M versatilepb -kernel ~/.panda/vmlinuz-3.2.0-4-versatile \
    -initrd ~/.panda/initrd.img-3.2.0-4-versatile -hda ~/.panda/arm_wheezy.qcow \
    -serial stdio -loadvm root -display none \
    -panda callfunc:when=0xc00ca05c,func=0xc026feb4,mm_file="fmt_str.txt",mm_dst=0xc0000000,args="0xc0000000-0x1-0x2-0x3-0x4-0x5-0x6-0x7"

```
