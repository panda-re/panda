Plugin: osi_linux
===========

Summary
-------

`osi_linux` provides Linux introspection information and makes it available through the OSI interface. It does so by knowing about the offsets for various Linux kernel data structures and then providing algorithms that traverse these data structures in the guest virtual machine.

Because the offsets of fields in Linux kernel data structures change frequently (and can even depend on the specific compilation flags used), `osi_linux` uses a configuration file to specify the offsets of critical data structures. An portion of such a configuration file, which is in the [GLib key-value format](https://developer.gnome.org/glib/stable/glib-Key-value-file-parser.html) (similar to .ini files), is given below:

    [debian-3.2.63-i686]
    name = #1 Debian 3.2.63-2+deb7u1 i686
    task.size = 1000
    #task.init_addr = 0xC1397480
    task.init_addr = 3241768064
    task.task_offset = 0
    task.tasks_offset = 204
    task.pid_offset = 248

    [... omitted ...]

    [debian_wheezy_i386_desktop]
    name = #1 SMP Debian 3.2.51-1 i686
    task.size = 1060
    #task.init_addr = 0xC13E0FE0
    task.init_addr = 3242069984
    task.task_offset = 0
    task.tasks_offset = 212
    task.pid_offset = 292
    task.tgid_offset = 296
    task.group_leader_offset = 328

    [... omitted ...]

Of course, generating this file by hand would be extremely painful. So instead we can generate it automatically by building and loading a kernel module in the guest OS.

To do so, you will need the kernel headers and a compiler installed in the guest. On a Debian guest, you can do:

```sh
    apt-get install build-essential linux-headers-`uname -r`
```

Then copy the `panda_plugins/osi_linux/utils/kernelinfo` directory into the guest (e.g., using `scp` from inside the guest or simply by cloning the PANDA repository), and run `make` to build `kernelinfo.ko`. Finally, insert the kernel module and run `dmesg` to get the values. Note that although `insmod` will return an "Operation not permitted" error, it will still print the right information to the log:

    # insmod kernelinfo.ko
    Error: could not insert module kernelinfo.ko: Operation not permitted
    # dmesg

You should see output in the `dmesg` log like:

    [166368.803659] --KERNELINFO-BEGIN--
    [166368.804324] name = #1 SMP Debian 3.2.51-1 i686
    [166368.804390] task.size = 1060
    [166368.804509] #task.init_addr = 0xC13E0FE0
    [166368.804530] task.init_addr = 3242069984
    [166368.804594] task.task_offset = 0
    [166368.804639] task.tasks_offset = 212
    [166368.804685] task.pid_offset = 292
    [166368.804719] task.tgid_offset = 296
    [166368.804748] task.group_leader_offset = 328
    [166368.804781] task.thread_group_offset = 384
    [166368.804808] task.real_parent_offset = 304
    [166368.804836] task.parent_offset = 308
    [166368.804861] task.mm_offset = 240
    [166368.804885] task.stack_offset = 4
    [166368.804912] task.real_cred_offset = 504
    [166368.804936] task.cred_offset = 508
    [166368.804966] task.comm_offset = 516
    [...]
    [166368.805736] fs.d_iname_offset = 36
    [166368.805761] fs.d_parent_offset = 16
    [166368.805778] ---KERNELINFO-END---

Copy this information (without the KERNELINFO-BEGIN and KERNELINFO-END lines) into the `kernelinfo.conf`. Be sure to put it in its own configuration section, i.e.:

    [my_kernel_info]
    name = #1 SMP Debian 3.2.51-1 i686
    task.size = 1060
    [...]

The name you give (`my_kernel_info` in this case) should then be passed as the `kconf_group` argument to the plugin.

Arguments
---------

* `kconf_file`: string, defaults to "kernelinfo.conf". The location of the configuration file that gives the required offsets for different versions of Linux.
* `kconf_group`: string, defaults to "debian-3.2.65-i686". The specific configuration desired from the kernelinfo file (multiple configurations can be stored in a single `kernelinfo.conf`).

Dependencies
------------

`osi_linux` is an introspection provider for the `osi` plugin.

APIs and Callbacks
------------------

In addition to providing the standard APIs used by OSI, `osi_linux` also provides two Linux-specific API calls that resolve file descriptors to filenames and tell you the current file position:

```C
    // returns fd for a filename or a NULL if failed
    char *osi_linux_fd_to_filename(CPUState *env, OsiProc *p, int fd);

    // returns pos in a file
    unsigned long long  osi_linux_fd_to_pos(CPUState *env, OsiProc *p, int fd);
```

Example
-------

Assuming you have a `kernelinfo.conf` in the current directory with a configuration named `my_kernel_info`, you can run the OSI test plugin on a Linux replay as follows:

```bash
    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda osi -panda osi_linux:kconf_file=kernelinfo.conf,kconf_group=my_kernel_info \
        -panda osi_test
```