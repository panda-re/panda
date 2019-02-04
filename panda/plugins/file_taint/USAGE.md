Plugin: file_taint
===========

Summary
-------

The `file_taint` plugin taints the bytes of some file that is read in the guest as they are read in from disk. This is useful in many scenarios where taint is used:

* Tainting a file with private data to see if it is later sent out on the network.
* Tainting some encrypted file to see where the decryption algorithm is (using `tainted_instr`)
* Tracking the liveness of each byte of some input file using `dead_data`

To effectively use taint, you will also need some mechanism for *querying* taint on some data at some point in the replay. Some plugins available for this are `tainted_instr`, `tainted_branch`, and `dead_data`.

Arguments
---------

* `filename`: string, defaults to "abc123". The filename we want to taint.
* `pos`: boolean, defaults to false. Enables use of positional labels. I.e. the file offset where the data were read from is used as their initial taint label.
* `notaint`: boolean: whether to actually do any tainting. This option is useful because we can run `file_taint` without taint to find out when the first use of the file in the replay is, and then re-run it with the `first_instr` option to turn on taint just before the file is opened. This can dramatically speed up the process, since running with taint enabled (even if nothing is tainted) can be very slow.
* `max_num_labels` ulong, defaults to 1000000. How many labels to apply to input bytes. The default value corresponds to a roughly 1MB chunk of the file.
* `start`: ulong, the first offset in the file to label.
* `end`: ulong, the last offset in the file to label.
* `first_instr`: uint64, defaults to 0. The instruction count at which we should enable taint. To find out what instruction count that is, you can run with `notaint` as described above.

Dependencies
------------

`file_taint` depends on the **osi** plugin to get information about file objects from their file descriptors. This allows it to track, for example, the current file offset, without having to track calls to `seek`. It also depends on **syscalls2** to intercept the appropriate file-related APIs (`open`, `read`, etc.).

APIs and Callbacks
------------------

None.

Example
-------

A typical run might first try to find out where the file `foo.txt` is first used:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 -panda file_taint:filename=foo.txt,notaint=y

By looking at the output, we may discover that the file is first opened at instruction `1215124234`. Now we can actually run the replay with taint enabled:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 \
        -panda file_taint:filename=foo.txt,pos=y,first_instr=1215124234

Bugs
----

* `file_taint` unconditionally requires the `osi_linux` plugin, which means it can't be run on Windows replays without modifying the source.
* File position information is currently somewhat broken on Windows.
