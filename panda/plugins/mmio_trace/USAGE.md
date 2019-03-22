Plugin: mmio_trace
===========

Summary
-------

Log MMIO interactions within the guest.

Arguments
---------

* out_log (string): File to log MMIO R/Ws to (optional)

Dependencies
------------

None

APIs and Callbacks
------------------

None

Example
-------

Testing with the Debian ARM image used by PANDA's `run_debian.py --arch arm`, log all MMIO accesses to `mmio.log`:

```
arm-softmmu/qemu-system-arm -M versatilepb -kernel ~/.panda/vmlinuz-3.2.0-4-versatile \
    -initrd ~/.panda/initrd.img-3.2.0-4-versatile -hda ~/.panda/arm_wheezy.qcow \
    -serial stdio -loadvm root -display none \
    -panda mmio_trace:out_log="mmio.log"
```