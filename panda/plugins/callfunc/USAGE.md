Plugin: NAME
===========

Summary
-------

Call a function in the guest (currently ARM only)

Arguments
---------

* when: the PC at which to call our function
* func: the function to call
* arg1: the first function argument (optional)
* arg2: the second function argument (optional)
* arg3: the third function argument (optional)
* arg4: the fourth function argument (optional)

Dependencies
------------

None

APIs and Callbacks
------------------

None

Example
-------

Call the function `kmalloc` to allocate 64KB of kernel memory whenever `do_execve` is called. Note that these addresses are specific to the Debian ARM image used by PANDA's `run_debian.py --arch arm`; you will have to adjust them if you want to use them on another target.

```
arm-softmmu/qemu-system-arm -M versatilepb -kernel ~/.panda/vmlinuz-3.2.0-4-versatile \
    -initrd ~/.panda/initrd.img-3.2.0-4-versatile -hda ~/.panda/arm_wheezy.qcow \
    -serial stdio -loadvm root -display none \
    -panda callfunc:when=0xc00ca05c,func=0xc00bb0cc,args="0x10000-0xd0"
```
