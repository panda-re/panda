Plugin: memstrings
===========

Summary
-------

The `memstrings` plugin attempts to extract all printable strings read and written in memory throughout the course of a replay. It supports, for this purpose, ASCII and UTF-16 encodings, and assumes English printable characters.

The output is a list of strings seen during the replay, one per line. Each line also has the instruction count where the string match occurred, and an indicator of whether the match was a Unicode or ASCII string, e.g.:

    123141222:U:C:\Documents and Settings\qemu\thething.dll

To save space, the strings file is compressed with gzip.

Each string must be at least 4 consecutive printable characters to be considered valid (though this is configurable), and strings are capped at 256 characters.

Arguments
---------

* `name`: string, defaults to "memstrings". The prefix for the output filename. The output will be named according to `${name}_strings.txt.gz`.
* `len`: ulong, defaults to 4. The minimum number of consecutive characters needed to be considered a valid string.

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

To save the strings to `malware_strings.txt.gz` and only allow strings with at least 8 characters:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda memstats:name=malware,len=8
