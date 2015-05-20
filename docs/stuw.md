STUW aims to give an overview of interprocess communication for system calls. It relies on data collected by win7proc output into a pandalog. This pandalog is then read in by stuw.cpp which outputs a text adjancency matrix.

Stuw is compiled in a similar manner to pandalog_reader.cpp, a simple pandalog to text output program. Here's the compile line for it, but check the top of stuw.cpp to make sure that a newer one hasn't changed.

     g++ -g -o stuw stuw.cpp pandalog.c pandalog_print.c pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c -I .. -lz -D PANDALOG_READER  -std=c++11

To use stuw, first run the replay using win7proc. Win7proc relies on syscalls2, which needs a profile, so your -panda argument should look something like this:

    -panda "syscalls2;profile=windows7_x86;win7proc"

STUW also requires pandalogged output, so the -pandalog arguement is also important:

    -pandalog mypandalogfile

After the replay runs, you should use stuw to read in the pandalog:

      ./stuw mypandalogfile

Currently STUW outputs the matches in the form of an adjacency matrix, with a sender node listing the receiver nodes. Note that the sender may be a source that is pulled from, by NTReadVirtualMemory for instance. In the following example, (1404,avp.exe) uses frequent calls to NTReadVirtualMemory on explorer.exe.

```
proc(3448,WmiPrvSE.exe) : 92
  proc(1404,avp.exe) : {[section, 19]}
proc(1404,avp.exe) : 55
  proc(3448,WmiPrvSE.exe) : {[section, 19]}
  proc(440,csrss.exe) : {[ALPC, 14][section, 2][virtualmemory, 8]}
  proc(2344,explorer.exe) : {[section, 7][virtualmemory, 2]}
  proc(588,lsass.exe) : {[section, 2]}
  proc(696,svchost.exe) : {[section, 1]}
proc(2448,avp.exe) : 39
  proc(2448,avp.exe) : {[virtualmemory, 15]}
  proc(496,csrss.exe) : {[ALPC, 4][section, 1]}
  proc(2344,explorer.exe) : {[virtualmemory, 6]}
  proc(3556,rundll32.exe) : {[section, 2][virtualmemory, 5]}
  proc(1180,svchost.exe) : {[file, 6]}
proc(440,csrss.exe) : 72
  proc(1404,avp.exe) : {[ALPC, 14][section, 2][virtualmemory, 5]}
proc(496,csrss.exe) : 138
  proc(2448,avp.exe) : {[ALPC, 4][section, 1]}
proc(2344,explorer.exe) : 816
  proc(1404,avp.exe) : {[section, 7][virtualmemory, 684]}
proc(588,lsass.exe) : 6
  proc(1404,avp.exe) : {[section, 2]}
proc(3556,rundll32.exe) : 122
  proc(2448,avp.exe) : {[section, 2]}
proc(696,svchost.exe) : 9
  proc(1404,avp.exe) : {[section, 1]}
proc(1180,svchost.exe) : 5
  proc(2448,avp.exe) : {[file, 5]}
```
