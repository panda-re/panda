PANDROID
====
PANDA supports Android/ARM guests.
This required porting code from the Android emulator, starting with some
devices ported by Georgia Tech student Patrick Jackson as a Google Summer of Code
project.
We have also ported some introspection tools that were part of the DECAF/DroidScope
project out of Syracuse University.

Building
----
Build PANDA as normal, with two changes:

1. Only build the arm_softmmu architecture
2. Pass the "--enable-android" flag to configure

Pandroid can only be built on a 64-bit OS.

Preparing an image
----
The easiest way to make an Android guest is to create an Android Virtual Device with
the Android SDK, and then use the pandroidConverter.py script in /scripts to create
QCOW2 files of the filesystems, as well as copying the correct kernel and initramfs.

Running
----
The runandroid.py script in /scripts runs PANDROID with simplified arguments, as long
as the 4 partitions' QCOW files are located in the same directory. The only required parameters
to the script are the QCOW file directory and the API version number of the Android guest.
Additional parameters are available; run runandroid.py -h for more information. The script
will also forward arguments it doesn't parse directly to PANDA.

PANDROID requires a long command line.
Android 3.2 (Honeycomb) and newer use ARMv7 in the SDK image, requiring the CPU to be
set to cortex-a8 or cortex-a9
The first serial device is the console. They second is the GSM radio interface.
Example command line: -M android_arm -cpu cortex-a9  -kernel /androidstuff/kernel-qemu -initrd /androidstuff/ramdisk.img  -global goldfish_nand.system_path=/androidstuff/system.img.qcow2 -global goldfish_nand.user_data_path=/androidstuff/userdata-qemu.img.qcow2  -global goldfish_nand.cache_path=/androidstuff/cache.img.qcow2 -append  "console=ttyS0 ndns=2 qemu=1 no_console_suspend=1 qemu.gles=0 android.qemud=ttyS1" -m 2G -no-reboot -monitor telnet:localhost:4321,server,nowait -show-cursor -serial stdio -serial telnet:localhost:4421,server,nowait -display sdl -net nic,vlan=1 -net user,vlan=1,hostfwd=tcp::5555-:5555,hostfwd=tcp::5039-:5039 -global goldfish_mmc.sd_path=/androidstuff/sdcard.qcow2  -android

Images using ext4 partitions instead of YAFFS require the argument "-global goldfish_nand.ext4=on"

VNC is supported but an attached VNC client will cause significantly more overhead than SDL.

Sensors
----
Telnet to localhost 5554 and you'll have a console with interactive help. This
is the same as the Android emulator. It enables text messages, phone calls,
GPS, etc. 

Introspection (DroidScope)
----
Code from the [DroidScope/DECAF project](http://code.google.com/p/decaf-platform/) has been integrated into Panda. Some of it is functional. It has not yet been migrated to loadable plugins.

###Linux-level introspection
Currently, the DroidScope code for the Linux layer works (with the Linux kernel structure definitions hard-coded to the ones for the stable Android Goldfish kernel).
Every time the current page table base changes, the DroidScope code updates its shadow process list, if necessary. This process list can also track threads and loaded modules, and can use symbols extracted by the [tools](http://code.google.com/p/decaf-platform/source/browse/?r=181#svn%2Fbranches%2FDroidScope%2Fqemu%2Fobjs) provided by the DroidScope team.

If Panda’s system call tracer plugin is loaded, the DroidScope code will also be notified explicitly of fork(), clone(), and exec() calls, and will parse the process's module list after exec().

To actually use this data, you’ll need to modify context.c, or duplicate much of its code in a copy of the system call tracer plugin.
You can also run Panda in GDB, break in, and execute “call printProcessList(0)” to print the process list to Panda’s stdout. The module and thread lists are similar.

###Dalvik-level introspection
DroidScope’s Dalvik/Android specific code is currently tied to Android 2.3. It appears that Dalvik has changed significantly since then. We plan on implementing support for 4.x at some point, but we don’t know when that will happen.
