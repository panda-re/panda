Plugin: memorymap
===========

Summary
-------

The `memorymap` plugin dumps the current process mapping at a given instruction, enabling the user to determine if an address is in code, data or the heap.  The instruction of interest can be identifed by its count or by its guest address.  It is possible to identify some instructions by address and others by count.  If neither addresses nor counts are provided, then the information for every instruction is written to standard output.

Following are selected lines from sample output:

	...
	pc=0x80441d6d instr_count=9260452 process=win_mt_sf_moref pid=412 tid=644 in_kernel=true image_name=ntoskrnl.exe image_path=\WINNT\System32\ntoskrnl.exe image_base=0x80400000
	pc=0x80441d6f instr_count=9260453 process=win_mt_sf_moref pid=412 tid=644 in_kernel=true image_name=ntoskrnl.exe image_path=\WINNT\System32\ntoskrnl.exe image_base=0x80400000
	pc=0x80441d71 instr_count=9260454 process=win_mt_sf_moref pid=412 tid=644 in_kernel=true image_name=ntoskrnl.exe image_path=\WINNT\System32\ntoskrnl.exe image_base=0x80400000
	pc=0x80064bd4 instr_count=9260455 process=win_mt_sf_moref pid=412 tid=644 in_kernel=true image_name=hal.dll image_path=\WINNT\System32\hal.dll image_base=0x80062000
	pc=0x80064bd6 instr_count=9260456 process=win_mt_sf_moref pid=412 tid=644 in_kernel=true image_name=hal.dll image_path=\WINNT\System32\hal.dll image_base=0x80062000
	...
	pc=0x77fcc3a1 instr_count=9738384 process=win_mt_sf_moref pid=412 tid=644 in_kernel=false image_name=ntdll.dll image_path=C:\WINNT\system32\ntdll.dll image_base=0x77f80000
	pc=0x77f89103 instr_count=9738385 process=win_mt_sf_moref pid=412 tid=644 in_kernel=false image_name=ntdll.dll image_path=C:\WINNT\system32\ntdll.dll image_base=0x77f80000
	pc=0x77f8910a instr_count=9738386 process=win_mt_sf_moref pid=412 tid=644 in_kernel=false image_name=ntdll.dll image_path=C:\WINNT\system32\ntdll.dll image_base=0x77f80000
	...
	pc=0x800caa20 instr_count=10961074 process=win_mt_sf_moref pid=412 tid=848 in_kernel=false image_name=(unknown) image_path=(unknown) image_base=(unknown)
	pc=0x80064be6 instr_count=10961075 process=win_mt_sf_moref pid=412 tid=848 in_kernel=true image_name=hal.dll image_path=\WINNT\System32\hal.dll image_base=0x80062000
	pc=0x800ca99b instr_count=10961076 process=win_mt_sf_moref pid=412 tid=848 in_kernel=false image_name=(unknown) image_path=(unknown) image_base=(unknown)
	...

The information reported on each instruction is, in order from left to right:

- `pc` : the guest address of the instruction, in hexadecimal
- `instr_count` : the number of the instruction within the replay
- `process` : the name of the process currently executing in the guest, if it can be determined
- `pid` : the process identifier of the currently executing process
- `tid` : the thread identifier of the currently executing thread within the process
- `in_kernel` : whether or not in the kernel
- `image_name` : the name of the kernel module or dynamic library within which the instruction exists, if it can be determined
- `image_path` : the path to the identified `image_name`
- `image_base` : the base address of the identified kernel module or dynamic library

Arguments
---------

* `pcs`: a dash delimited list of guest instruction addresses to be reported upon (use prefix 0x or 0X to specify in hexadecimal, 0 to specify in octal, or no prefix for decimal)
* `instr_counts` : a dash delimited list of instruction counts to be reported upon

Dependencies
------------

Depends on the **osi** plugin to provide OS introspection information. See the documentation for the OSI plugin for more details.

APIs and Callbacks
------------------

None.

Example
-------

To run `memorymap` on a Windows 2000 32-bit recording and report on two instructions specified by their addresses:

`$PANDA_PATH/i386-softmmu/qemu-system-i386 -replay foo -os windows-32-2000 -panda memorymap:pcs=0xbfeee8bd-0x80069a0f`
