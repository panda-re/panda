Plugin: stringsearch
===========

Summary
-------

The `stringsearch` plugin searches for strings being read or written at different tap points. This is immensely useful for quickly locating what code deals with a particular piece of data.

By default, `stringsearch` reads strings to search for from a text file named `${NAME}_search_strings.txt`, one per line; `${NAME}` is a configurable parameter. Each pattern can be expressed as a sequence of hex bytes separated ":" or, in the case of printable strings, as a simple string enclosed in quotes. For example:

    "has stopped working"
    01:02:03:04

Will search for the string `has stopped working` and the byte sequence `0x01 0x02 0x03 0x04` being written to or read from memory.

When a match is found, it is saved into `${NAME}_string_matches.txt` in a file listing the callstack, program counter, address space, and number of hits. The number of entries in the callstack is a configurable parameter. For example, with just two levels of callstack information, example output might look like:

    826954f7 8269669d 23d1a0e2 3eb5b3c0  1
    3140cd87 330f54a0 23d1a11f 3eb5b3c0  1
    826954f7 8269669d 23d1a11f 3eb5b3c0  1
    188b2992 1c9196fc 23d7f60a 3eb5b3c0  3
    1fd615c5 1fd621d8 23d80d9e 3eb5b3c0  8

Arguments
---------

* `str`: string, optional. An ASCII string to search for. This can be useful if you just want to quickly search for a simple string with no non-printable characters in a replay.
* `callers`: uint64, defaults to 16. The amount of callstack information to write to the log file on each string match.
* `name`: string, defaults to "stringsearch". The base name to use for the input and output file. For example, for the name `foo` the plugin will read from `foo_search_strings.txt` and write to `foo_string_matches.txt`.

Dependencies
------------

`stringsearch` relies on `callstack_instr` to group memory accesses into tap points, as well as to print callstack information whenever a match is found.

APIs and Callbacks
------------------

`stringsearch` provides a single callback that can be used by other plugins to take actions when a string match is found:

Name: **on_ssm**

Signature:

```C
typedef void (* on_ssm_t)(CPUState *env, target_ulong pc, target_ulong addr,
                uint8_t *matched_string, uint32_t matched_string_length,
                bool is_write)
```

Description: Called whenever a string match is observed. The callback is passed the CPU state, the value of the program counter when the match occurred, the actual string data that was matched (in case multiple search strings were used), the number of bytes in the matched string, and a flag indicating whether the match was seen during a read or a write.

Example
-------

To search for JPEG files being read or written in memory, create a file named `jpeg_search_strings.txt` with:

    ff:d8:ff:e0

Then run PANDA with stringsearch:

```sh
    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr -panda stringsearch:name=jpeg
```

Output will be placed in `jpeg_string_matches.txt` as well as being printed to the screen.
