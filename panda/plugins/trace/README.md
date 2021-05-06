Plugin: Trace
===========

Summary
-------
Dump all memory and register changes to disk.
When run in single-process mode, this output is compatable with the TENET trace exploration tool.

Arguments
---------
`log`: file name to store results in. Defaults to `trace.txt`

`target`: if set, the name of a process to collect traces from. Note when this is unset, we log in whole-system mode which produces a different output format.

Dependencies
------------
If `target` argument is set, `OSI` is required to identify process name.

APIs and Callbacks
------------------

Log format: Single Process
-----
Each line is a list of register value changes, memory reads, and memory writes. This format is compatable with the TENET trace exploration tool.
```
rax=0x4,rbx=0x1e288060,rcx=0x1e288060,rdx=0x403b870,rbp=0x1,rsp=0xbae438,rsi=0x2e1c0030,rdi=0x403b840,r8=0x0,r9=0x230,r10=0x403b870,r11=0x0,r12=0xffffffff,r13=0x2c7cb684b38,r14=0x141281d08,r15=0x1,rip=0x1401f6530
rip=0x1401f6535,mw=0xbae450:6080281E00000000
rip=0x1401f653a,mw=0xbae458:0100000000000000
rsp=0xbae430,rip=0x1401f653b,mw=0xbae430:40B8030400000000
rsp=0xbae000,rip=0x1401f6542
rdi=0x403b870,rip=0x1401f6545
rip=0x1401f6549,mw=0x1e288062:00
```
mw = memory write, mr = memory read

Log format: Whole System
-----
Line starts with `asid=[current asid],kernel=[kernel_mode]` then a list of register value changes, memory reads, and memory writes.
```
asid=0x34c0ad20,kernel=1,eip=0xc17efb88,eax=0xc10343f0,ecx=0x00000001,edx=0xc1b16000,esp=0xc1b17f6c,ebp=0xc1b17f78,mw=0xc1b17f68:44000,esp=0xc1b17f68
asid=0x34c0ad20,kernel=1,eip=0xc17f0140,mr=0xc1b17f68:44000,mw=0xc1b17f68:c4ffffff,mw=0xc1b17f64:e0000,esp=0xc1b17f64,mw=0xc1b17f60:d8000,esp=0xc1b17f60,mw=0xc1b17f5c:7b000,esp=0xc1b17f5c,mw=0xc1b17f58:7b000,esp=0xc1b17f58,mw=0xc1b17f54:f0433c1,esp=0xc1b17f54,mw=0xc1b17f50:787fb1c1,esp=0xc1b17f50,mw=0xc1b17f4c:0000,esp=0xc1b17f4c,mw=0xc1b17f48:0000,esp=0xc1b17f48,mw=0xc1b17f44:060b1c1,esp=0xc1b17f44,mw=0xc1b17f40:1000,esp=0xc1b17f40,mw=0xc1b17f3c:0000,esp=0xc1b17f3c,edx=0x0000007b
asid=0x34c0ad20,kernel=1,eip=0xc17f015c
asid=0x34c0ad20,kernel=1,eip=0xc17f015e,edx=0x000000d8,edx=0x000000e0,eax=0xc1b17f3c,mw=0xc1b17f38:7317fc1
asid=0x34c0ad20,kernel=1,eip=0xc17f0cd0,esp=0xc1b17f38,mw=0xc1b17f34:787fb1c1,esp=0xc1b17f34,ebp=0xc1b17f34,mw=0xc1b17f30:0000,esp=0xc1b17f30,mw=0xc1b17f2c:0000,esp=0xc1b17f2c,mw=0xc1b17f28:0000,esp=0xc1b17f28,esp=0xc1b17f14,mr=0xf63aec80:0000,mr=0xc1b17f68:c4ffffff,ebx=0xffffffc4,mw=0xc1b17f24:3c7fb1c1,mw=0xf63aec80:3c7fb1c1,mw=0xc1b17f10:f6c7fc1
```
mw = memory write, mr = memory read


Example
-------

In the subdirectory `test` generate a recording of `whoami` and then generate a log by running `test.py`. Or generate a recording and run PANDA with arguments:

```
-replay my_replay -panda trace:log=log.txt
```
