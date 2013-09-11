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

Preparing an image
----
The easiest way to make an Android guest is to create an Android Virtual Device with
the Android SDK, and then use the pandroidConverter.py script in /scripts to create
QCOW2 files of the filesystems, as well as copying the correct kernel and initramfs.

Running
----
PANDROID requires a long command line.
Android 3.1 (Honeycomb) and newer use ARMv7 in the SDK image, requiring the CPU to be
set to cortex-a8 or cortex-a9
The first serial device is the console. They second is the GSM radio interface.
Example command line: -M android_arm -cpu cortex-a9  -kernel /androidstuff/kernel-qemu -initrd /androidstuff/ramdisk.img  -global goldfish_nand.system_path=/androidstuff/system.img.qcow2 -global goldfish_nand.user_data_path=/androidstuff/userdata-qemu.img.qcow2  -global goldfish_nand.cache_path=/androidstuff/cache.img.qcow2 -append  "console=ttyS0 ndns=1 qemu=1 no_console_suspend=1 qemu.gles=0 android.qemud=ttyS1" -m 2G -no-reboot -monitor telnet:localhost:4321,server,nowait -show-cursor -serial stdio -serial telnet:localhost:4421,server,nowait -display sdl -net nic,vlan=1 -net user,vlan=1,hostfwd=tcp::5555-:5555,hostfwd=tcp::5039-:5039 -global goldfish_mmc.sd_path=/androidstuff/sdcard.qcow2  -android

VNC is supported but an attached VNC client will cause significantly more overhead than SDL.

Sensors
----
Telnet to localhost 5554 and you'll have a console with interactive help. This
is the same as the Android emulator. It enables text messages, phone calls,
GPS, etc. 


