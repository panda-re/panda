# osi_test plugin

This plugin is meant to test the functionality of the [PANDA OS introspection framework][osi]. To run, it requires to first load the `osi` framework plugin and a proper guest-os-specific plugin. e.g.

```
./i386-softmmu/qemu-system-i386 -vnc :1 -panda 'osi;osi_linux;osi_test' -replay mytrace
```

By default, the `osi_test` plugin invokes the OSI code every time that the Page Directory register is written to.

Invocation frequency can be increased by commenting out the definition of the `INVOKE_FREQ_PGD` macro in the code. Then, OSI code will be invoked before the execution of each basic block. Be warned that this may be too frequent and even small traces will take a long time to be replayed.

## Output normalizer
Script [osi_test_normalize.py][osi_test_normalize] can be used to make regression testing easier.
The script will strip out any cruft coming from debug printing and print process and library lists in a normalized format.

[osi]: ../osi
[osi_test_normalize]: osi_test_normalize.py
