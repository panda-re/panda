Plugin: file\_taint
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

* `filename`: string, required. The filename pattern to taint.
  This plugin now uses **Shell-style Wildcards (globbing)** for matching.
  The matching algorithm compares the **full path** of the file being read against
  the provided pattern.

  **Supported Wildcards:**
    * `*` : Matches everything (any number of characters)
    * `?` : Matches any single character
    * `[...]` : Matches any character inside the brackets

  **Examples:**
  * To taint everything in a directory:
    * `/home/panda/inputs/*`
  * To taint only `.bin` files in a directory:
    * `/home/panda/inputs/*.bin`
  * To taint a specific file (Exact Match):
    * `/home/panda/inputs/exploit.bin`
  * To simulate the old "Suffix Match" behavior (ends with):
    * `*panda/test`

  **Windows Note:**
  1. **Backslashes:** Windows paths use backslashes (`\`). You must use backslashes in your pattern (e.g., `*\dir\file`). Forward slashes will fail.
  2. **Drive Letters:** Windows Kernel paths do not include drive letters (e.g., PANDA sees `\Device\HarddiskVolume1\test.txt` instead of `C:\test.txt`).
     * **Recommendation:** Always start your Windows patterns with `*` (e.g., `*\Users\panda\test.txt`) to match the file regardless of the drive letter or volume prefix.
* `pos`: boolean, defaults to false. Enables use of positional labels. I.e. the file offset where the data were read from is used as their initial taint label.
* `max_num_labels` ulong, defaults to 1000000. How many labels to apply to input bytes. The default value corresponds to a roughly 1MB chunk of the file.
* `start`: ulong, the first offset in the file to label.
* `end`: ulong, the last offset in the file to label.
* `label`: the uniform label to use if positional taint is off (defaults to 0xF11E).
* `verbose`: enables some extra output for debugging, sanity checks.
* `pread_bits_64`: Treat the offset passed to pread as a 64-bit signed integer (Linux specific). If the binary under analysis was compiled with \_FILE\_OFFSET\_BITS=64, then its possible that this flag needs to be set. See: https://www.gnu.org/software/libc/manual/html\_node/I\_002fO-Primitives.html

Dependencies
------------

`file_taint` depends on the **osi** plugin to get information about file objects from their file descriptors. This allows it to track, for example, the current file offset, without having to track calls to `seek`. It also depends on **syscalls2** to intercept the appropriate file-related APIs (`open`, `read`, etc.).

APIs and Callbacks
------------------

None.

Example
-------

A typical run might first try to find out where the file `foo.txt` is first used:

```
    $PANDA_PATH/i386-softmmu/panda-system-i386 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 -panda file_taint:filename=foo.txt
```

