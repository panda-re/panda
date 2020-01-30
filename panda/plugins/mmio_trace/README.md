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

As an alternative to the optional log file output in `uninit_plugin`, API for retrieval of sequential MMIO event tuples (`access_type`, `pc`, `phys_addr`, `virt_addr`, `size`, `value`, `dev_name`).


```c
// Get heap-allocated array of mmio_event_t structs and it's size
mmio_event_t* get_mmio_events(int* arr_size_ret);
```

Example
-------

Testing with the Debian ARM image used by PANDA's `run_debian.py --arch arm`, log all MMIO accesses to `mmio.log`:

```
arm-softmmu/panda-system-arm -M versatilepb -kernel ~/.panda/vmlinuz-3.2.0-4-versatile \
    -initrd ~/.panda/initrd.img-3.2.0-4-versatile -hda ~/.panda/arm_wheezy.qcow \
    -serial stdio -loadvm root -display none \
    -panda mmio_trace:out_log="mmio.log"
```
