# DECAF Kernel Information Module

For DECAF to be able to examine the structure of the running kernel,
it needs to know several offsets within the data structures used by the
kernel.  E.g. what is the offset of ``pid`` within ``struct task_struct``?

These offsets are dependent on the kernel version *and* the flags used to
compile it. Some of them could be guessed using heuristics. But a more
robust approach is query the running kernel from within the guest VM,
when this is possible.

The scripts in this directory implement this approach.

<!-- Comments from DECAF_linux_vmi.c. To be added in markdown format.

//This tool depends on the kernelinfo.conf file that is obtained by either populating the values
// manually, or getting it by inserting a kernel module
//The source is included at the end of this file. There are two ways of doing this
//1. Paste the source into a file called procinfo.c in the drivers/misc directory of the kernel source tree
// Then add the following line to the Makefile and just made the kernel as normal
//obj-y                           += procinfo.o
//2. Paste the source into a different kernel module, such as goldfish_audio.c, inside the init function
// No other changes are necessary.
//The difference between the two methods is that in the first, you have to insmod the module and then do a dmesg.
// You should get an error from insmod, but the necessary data is printed to the log. In the second method, you
// just run dmesg and its done. That is because goldfish-audio is automatically loaded.
//The second is more intrusive ofcourse, but it still works fine.
-->
