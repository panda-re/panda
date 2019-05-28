Plugin: textprinter
===========

Summary
-------

The somewhat misnamed `textprinter` plugin writes the contents of any data flowing through a set of tap points out to a log file. These log files can then be examined and processed to look for interesting information.

The plugin is usually used after identifying some tap points of interest, using something like the `stringsearch` plugin.

`textprinter` reads a list of tap points to monitor from a file named `tap_points.txt`. The first line of the file is the number of the Stack Type used to specify the address space portion of each tap point.
- 0 (asid) each address space is a single number, the ASID
- 1 (heuristic) each address space is specified by an ASID and an SP
- 2 (threaded) each address space is specified by a process ID and a thread ID
(Please see the `callstack_instr` plugin for more information.)
After the stack type, the tap points are listed, one per line. Each tap point consists of a caller, program counter, and address space.

`textprinter` saves output to two files named `read_tap_buffers.txt.gz` and `write_tap_buffers.txt.gz`. These logs are gzipped text files that have entries of the form:

    [Callstack] [PC] [Stack Type] [Address Space] [Virtual Address] [Access Count] [Byte Value]

The address space in the output file is always specified by two numbers. (If the stack type is 0 (asid), then the second number is always 0.) The virtual address is the location in memory where the data was read from or written to. The access count is a number indicating how many memory operations have occurred; the idea is that for a multi-byte write (e.g., `mov DWORD PTR [0x1234], eax`) all four bytes will have the same access count.

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

`textprinter` uses the `callstack_instr` plugin to get callstack information for each memory access. Be sure to specify the same `stack_type` as is specified in the `tap_points.txt` file.

APIs and Callbacks
------------------

None.

Example
-------

First create a file called `tap_points.txt` with your tap points. The following example uses the threaded stack type:

    2
    7800f6a8 7800fc97 0000019c 00000210
    7800f6a8 7800fc97 0000019c 00000244
    7800f6a8 7800fc9a 0000019c 00000210
    7800f6a8 7800fc9a 0000019c 00000244

Then run PANDA with `textprinter`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr,stack_type=threaded -panda textprinter

You will get output in `read_tap_buffers.txt.gz` and `write_tap_buffers.txt.gz`. This snippet of such a log file shows four bytes (`0x62 0x72 0x61 0x6e`) being written to address `0x003f3830`:

    77fa15db [...] 7800f6a8 7800fc9a 2 0000019c 00000210 003f3830 6520348 62
    77fa15db [...] 7800f6a8 7800fc9a 2 0000019c 00000210 003f3831 6520348 72
    77fa15db [...] 7800f6a8 7800fc9a 2 0000019c 00000210 003f3832 6520348 61
    77fa15db [...] 7800f6a8 7800fc9a 2 0000019c 00000210 003f3833 6520348 6e

