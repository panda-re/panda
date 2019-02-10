Plugin: file_taint
===========

Summary
-------

The `file_taint` plugin taints the bytes of some file that is read in the guest as they are read in from disk. This is useful in many scenarios where taint is used:

* Tainting a file with private data to see if it is later sent out on the network.
* Tainting some encrypted file to see where the decryption algorithm is (using `tainted_instr`)
* Tracking the liveness of each byte of some input file using `dead_data`

To effectively use taint, you will also need some mechanism for *querying* taint on some data at some point in the replay. Some plugins available for this are `tainted_instr` and `tainted_branch`.

Arguments
---------

* `filename`: string, required. The filename we want to taint. Full paths are supported, but on Windows there are some limitations.

   The matching algorithm looks for the last instance of this parameter in the filename of files that are being read. If an instance is found, it must fill out the rest of the string to be considered a match. The following are examples. Say I want to taint "/home/panda/test". Then the following filenames can be searched for to match "/home/panda/test":

    * "test"
    * "panda/test"
    * "/home/panda/test"
    * "nda/test"
    * ... and more

    For Windows paths, be sure to escape backslashes if you're using bash. Alternatively, you may surround the entire path in single quotes.

* `pos`: boolean, defaults to false. Enables use of positional labels. I.e. the file offset where the data were read from is used as their initial taint label.
* `max_num_labels` ulong, defaults to 1000000. How many labels to apply to input bytes. The default value corresponds to a roughly 1MB chunk of the file.
* `start`: ulong, the first offset in the file to label.
* `end`: ulong, the last offset in the file to label.
* `label`: the uniform label to use if positional taint is off (defaults to 0xF11E).
* `verbose`: enables some extra output for debugging, sanity checks.
* `pread_bits_64`: Treat the offset passed to pread as a 64-bit signed integer (Linux specific). If the binary under analysis was compiled with _FILE_OFFSET_BITS=64, then its possible that this flag needs to be set. See: https://www.gnu.org/software/libc/manual/html_node/I_002fO-Primitives.html

Dependencies
------------

`file_taint` depends on the **osi** plugin to get information about file objects from their file descriptors. This allows it to track, for example, the current file offset, without having to track calls to `seek`. It also depends on **syscalls2** to intercept the appropriate file-related APIs (`open`, `read`, etc.).

APIs and Callbacks
------------------

None.

Example
-------

A typical run might first try to find out where the file `foo.txt` is first used:

    $PANDA_PATH/i386-softmmu/qemu-system-i386 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 -panda file_taint:filename=foo.txt

Limitations
----

* In Windows, matching file names that include a drive letter is not supported. The OSI calls used to support file taint in Windows return Kernel object paths which do not include drive letters. This means that the filename is checked against a path without a drive letter. Also, the exact filename that is stored in the kernel object depends on how the file was opened. If the file was opened with a full path, it will have a full path in the file object. Otherwise, the path is relative to the process working directory.

   For example, say I want to taint C:\Users\panda\test.txt. If I provide "C:\Users\panda\test.txt" as the filename, file_taint will miss the file. However, if I provide "\Users\panda\test.txt", file_taint will pick up the file read properly.
