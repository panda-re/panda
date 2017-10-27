# Plugin: osi_test

## Summary

This plugin is meant to test the functionality of the [PANDA OS introspection framework](../osi).

By default, the `osi_test` plugin invokes the OSI code every time that the Page Directory register is written to.

Invocation frequency can be increased by commenting out the definition of the `INVOKE_FREQ_PGD` macro in the code. Then, OSI code will be invoked before the execution of each basic block. Be warned that this may be too frequent and even small traces will take a long time to be replayed.

### Output Normalizer

The [osi_test_normalize.py](osi_test_normalize.py) script can be used to make regression testing easier.  The script will strip out any cruft coming from debug printing and print process and library lists in a normalized format.

### Example Output

    Current process: svchost.exe PID:876 PPID:452
    Dynamic libraries list (68 libs):
            0x00000000003d0000      32768   svchost.exe              C:\Windows\System32\svchost.exe
            0x0000000077a80000      1294336 ntdll.dll                C:\Windows\SYSTEM32\ntdll.dll
            0x0000000076810000      868352  kernel32.dll             C:\Windows\system32\kernel32.dll
            0x0000000075cd0000      303104  KERNELBASE.dll           C:\Windows\system32\KERNELBASE.dll
            0x0000000076300000      704512  msvcrt.dll               C:\Windows\system32\msvcrt.dll
            0x0000000077a60000      102400  sechost.dll              C:\Windows\SYSTEM32\sechost.dll
            0x0000000076250000      659456  RPCRT4.dll               C:\Windows\system32\RPCRT4.dll
    [...]
    Process list (29 procs):
      svchost.exe           876     452
      svchost.exe           964     452
      svchost.exe           1076    452
      spoolsv.exe           1172    452
      svchost.exe           1208    452
      svchost.exe           1308    452
      sppsvc.exe            264     452
      svchost.exe           284     452
      GoogleCrashHan        532     260
      SearchIndexer.        912     452
      taskhost.exe          524     452
      dwm.exe               1136    832
    [...]

## Arguments

None.

## Dependencies

Depends on the `osi` plugin to access the introspection API, and also a particular introspection provider (e.g., `osi_linux` or `win7x86intro`).

## APIs and Callbacks

None.

## Example

Running `osi_test` on an Windows 7 32-bit replay:

```sh
    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda osi -panda win7x86intro -panda osi_test
```