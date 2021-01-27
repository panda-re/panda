Plugin: lighthouse\_coverage
=======

Summary
-------

This PANDA plugin emits a file, `lighthouse.out`, for usage by the lighthouse coverage plugin for IDA pro and Binary Ninja. This is especially useful for the analysis of binaries that have advanced anti-debug and anti-tracing features and are heavily obfuscated with overlapping code. Binary Ninja is capable of displaying this.


Arguments
---------
you can restrict the output of this plugin to a particular process by specifying the process parameter, e.g.
-panda lighthouse\_coverage:process=lsass.exe
you can restrict the output of this plugin to a particular dll by specifying both process and dll parameters, e.g.
-panda lighthouse\_coverage:process=lsass.exe,dll=ntdll.dll

Dependencies
------------

This module needs OSI.


Example
-------

```$ ./panda-system-x86_64 -m 4096 -replay theRecording -os linux-64-ubuntu -panda osi -panda osi_linux:kconf_group=ubuntu:5.3.0-28-generic:64 -panda lighthouse_coverage```

produces a file in the current directory, `lighthouse.out', which contains coverage information lighthouse can use.
