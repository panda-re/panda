Plugin: osi\_test
========================

Summary
------------------------
This plugin is meant to test the functionality of the [PANDA OS introspection framework][osi].

By default, the `osi_test` plugin invokes the OSI code every time that the
address space identifier (ASID) changes.
Invocation frequency can be increased by commenting out the definition of the
`OSI_TEST_ON_ASID_CHANGED` macro in the code. Then, OSI code will be invoked before the
execution of each basic block. Be warned that this may be too frequent and even
small traces will take a long time to be replayed.

Arguments
------------------------
None.

Dependencies
------------------------
Depends on the `osi` plugin to access the introspection API, and also a
particular introspection provider (e.g., `osi_linux` or `wintrospection`).

APIs and Callbacks
------------------------
None.

Example
------------------------
To run, it requires to first load the `osi` framework plugin and a proper
guest-os-specific plugin.

### command
E.g. to run `osi_test` on an Windows 7 32-bit replay:

```sh
  $PANDA_PATH/i386-softmmu/panda-system-i386 -replay mytrace \
    -os windows-32-7sp1 -panda osi_test
```
The os-specific plugin is loaded implicitly by specifying `-os windows-32-7sp1`.

### output

```
Current process: csrss.exe PID:348 PPID:328

Process list (27 procs):
  smss.exe        	200	4
  csrss.exe       	288	280
  wininit.exe     	336	280
  csrss.exe       	348	328
  winlogon.exe    	376	328
  services.exe    	436	336
  lsass.exe       	448	336
  lsm.exe         	456	336
  svchost.exe     	544	436
[...]
  conhost.exe     	760	348
  System          	4	0

-------------------------------------------------

Dynamic libraries list (18 libs):
	0x49cb0000	20480	csrss.exe                C:\Windows\system32\csrss.exe
	0x76f50000	1318912	ntdll.dll                C:\Windows\SYSTEM32\ntdll.dll
	0x74e50000	53248	CSRSRV.dll               C:\Windows\system32\CSRSRV.dll
	0x74e40000	57344	basesrv.DLL              C:\Windows\system32\basesrv.DLL
[...]
	0x770a0000	659456	ADVAPI32.dll             C:\Windows\system32\ADVAPI32.dll
	0x75fb0000	102400	sechost.dll              C:\Windows\SYSTEM32\sechost.dll

Kernel module list (136 modules):
	0x82818000	4251648	ntoskrnl.exe             \SystemRoot\system32\ntoskrnl.exe
	0x82c26000	225280	hal.dll                  \SystemRoot\system32\halmacpi.dll
	0x80b9b000	32768	kdcom.dll                \SystemRoot\system32\kdcom.dll
	0x8b405000	544768	mcupdate.dll             \SystemRoot\system32\mcupdate_GenuineIntel.dll
	0x8b48a000	69632	PSHED.dll                \SystemRoot\system32\PSHED.dll
	0x8b49b000	32768	BOOTVID.dll              \SystemRoot\system32\BOOTVID.dll
	[...]
	0x98e2a000	57344	tssecsrv.sys             \SystemRoot\System32\DRIVERS\tssecsrv.sys
	0x98e38000	204800	RDPWD.SYS                \SystemRoot\System32\Drivers\RDPWD.SYS
	0x00000000	0	                         

-------------------------------------------------
[...]	
```

### output normalizer
Script [osi_test_normalize.py][osi_test_normalize] can be used to make
regression testing easier. The script will strip out any cruft coming from
debug printing and print process and library lists in a normalized format.

[osi]: ../osi
[osi_test_normalize]: osi_test_normalize.py


