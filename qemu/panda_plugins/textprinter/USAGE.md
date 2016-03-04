Plugin: textprinter
===========

Summary
-------

The somewhat misnamed `textprinter` plugin writes the contents of any data flowing through a set of tap points out to a log file. These log files can then be examined and processed to look for interesting information.

The plugin is usually used after identifying some tap points of interest, using something like the `stringsearch` plugin.

`textprinter` reads a list of tap points to monitor from a file named `tap_points.txt`, one per line. Each tap point consists of a caller, program counter, and address space.

`textprinter` saves output to two files named `read_tap_buffers.txt.gz` and `write_tap_buffers.txt.gz`. These logs are gzipped text files that have entries of the form:

    [Callstack] [PC] [ASID] [Virtual Address] [Access Count] [Byte Value]

The virtual address is the location in memory where the data was read from or written to. The access count is a number indicating how many memory operations have occurred; the idea is that for a multi-byte write (e.g., `mov DWORD PTR [0x1234], eax`) all four bytes will have the same access count.

Once you have a tap point log, you can split it up into its constitutent tap points with `scripts/split_taps.py`:

    $ scripts/split_taps.py --help
    usage: split_taps.py [-h] [-c CALLERS] logfile prefix

    Split a logfile containing tap point data into its constitutent taps.

    positional arguments:
      logfile               log file containing tap point data (can be gzipped)
      prefix                prefix for output files

    optional arguments:
      -h, --help            show this help message and exit
      -c CALLERS, --callers CALLERS
                            levels of calling context to use when splitting

The resulting files will contain the raw data seen at each tap point.

Arguments
---------

None.

Dependencies
------------

`textprinter` uses the `callstack_instr` plugin to get callstack information for each memory access.

APIs and Callbacks
------------------

None.

Example
-------

First create a file called `tap_points.txt` with your tap points:

    683158d0 686a375c 3eb5b180
    680c54e2 686dd7e3 3eb5b180

Then run PANDA with `textprinter`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr -panda textprinter

You will get output in `read_tap_buffers.txt.gz` and `write_tap_buffers.txt.gz`. This snippet of such a log file shows four bytes (`0x8d 0x64 0x24 0x04`) being written to address `0x001aebe8`:

    692483d1 [...] 683158d0 686a375c 3eb5b180 001aebe8 3331087336 8d
    692483d1 [...] 683158d0 686a375c 3eb5b180 001aebe9 3331087336 64
    692483d1 [...] 683158d0 686a375c 3eb5b180 001aebea 3331087336 24
    692483d1 [...] 683158d0 686a375c 3eb5b180 001aebeb 3331087336 04

