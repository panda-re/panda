Reproducing the LINE Censorship Results
=======================================

Preliminaries
-------------

Start by downloading and unpacking the LINE recording from rrshare.org:

    $ wget http://www.rrshare.org/content/rrlogs/line2.rr
    $ scripts/rrunpack.py line2.rr
    Verifying checksum... Success.
    line2-rr-snp
    line2-rr-nondet.log
    Unacking RR log line2.rr with 10367712943 instructions... Done.

Get the version of PANDA used in the paper:

    $ git clone https://github.com/moyix/panda.git
    $ git checkout b8d3dbb

Modify the `build.sh` script to build with Android support. It will end
up looking like:

    #!/bin/sh

    python ../scripts/apigen.py

    ./configure --target-list=arm-softmmu \
    --cc=gcc-4.7 \
    --cxx=g++-4.7 \
    --prefix=`pwd`/install \
    --enable-android \
    --disable-pie \
    --enable-llvm \
    --with-llvm=../llvm-3.3/Release \
    --extra-cflags="-O2" \
    --extra-cxxflags="-O2" \
    && make -j $(nproc)

Build PANDA (see the documentation for details on dependencies).

Due to a bug in the Android support, the replay requires that a QCOW2
file exists for the system and user data devices of the Android
emulator. It doesn't have to have any real data though, so we can just
create a small dummy QCOW2:

    $ ./qemu-img create -f qcow2 dummy.qcow2 1M

Now we can move on to the actual analysis.

Analysis
--------

Now, we suspect that the censorship list will include Tiananmen (天安门)
and Falun (法轮). So we will use TZB to search all memory reads and
writes for the UTF-8 encoded versions of these strings. Create a file
`search_strings.txt` that looks like:

    e5:a4:a9:e5:ae:89:e9:97:a8
    e6:b3:95:e8:bd:ae

Now, run the replay. Note that we have to pass in the dummy QCOW2 we
created:

    ../arm-softmmu/qemu-system-arm -m 2048 -replay line2 -M android_arm -cpu cortex-a9 -kernel /dev/null -vnc :0 \
      -global goldfish_mmc.sd_path=/dev/null -global goldfish_nand.system_path=dummy.qcow2 \
      -global goldfish_nand.user_data_path=dummy.qcow2 \
      -panda 'callstack_instr;stringsearch'

About 19% of the way through the replay, we begin seeing matches:

    ./line2-rr-nondet.log:  10362284 of 66356457 (15.62%) bytes, 1866218128 of 10367712943 (18.00%) instructions processed.
    ./line2-rr-nondet.log:  11056439 of 66356457 (16.66%) bytes, 1969919380 of 10367712943 (19.00%) instructions processed.
    WRITE Match of str 0 at: instr_count=1997783382 :  40796784 4074f7f8 28210000
    WRITE Match of str 0 at: instr_count=1999952799 :  40796784 4074f7f8 28210000
    WRITE Match of str 0 at: instr_count=2008500449 :  407a7ada 4b50817c 28210000
    WRITE Match of str 0 at: instr_count=2011053513 :  407a7ada 4b50817c 28210000
    WRITE Match of str 0 at: instr_count=2011442343 :  407a7ada 4b50817c 28210000
    WRITE Match of str 1 at: instr_count=2011820449 :  407a7ada 4b50817c 28210000
    WRITE Match of str 0 at: instr_count=2012833451 :  407a7ada 4b50817c 28210000
    WRITE Match of str 0 at: instr_count=2012867057 :  407a7ada 4b50817c 28210000
    WRITE Match of str 1 at: instr_count=2013214014 :  407a7ada 4b50817c 28210000
    WRITE Match of str 1 at: instr_count=2013231331 :  407a7ada 4b50817c 28210000

Once the replay is finished, we will have a file `string_matches.txt` 
that summarizes these matches:

    4b536c00 4b536c00 4b536c00 4b536c00 4b536c00 407a7ada 40796784 4075222c 40796784 400417a8 40041e6a 407a7ada 40796784 4075222c 40796784 40796784 40038678 28210000  16 12
    4b536c00 4b536c00 4b536c00 4b536c00 4b536c00 407a7ada 40796784 4075222c 40796784 400417a8 40041e6a 407a7ada 40796784 4075222c 40796784 40796784 40038684 28210000  0 1
    4b536c00 4b536c00 4b536c00 4b536c00 4b536c00 407a7ada 40796784 4075222c 40796784 400417a8 40041e6a 407a7ada 40796784 4075222c 40796784 40796784 40038688 28210000  16 12
    407a7ada 400417a8 40041e6a 407a7ada 400417a8 40041e6a 407a7ada 400417a8 40041e6a 407a7ada 407a7ada 400417a8 40041e6a 407a7ada 407a7ada 407a7ada 4074f630 28210000  8 5
    4b53490a 407a7ada 407a7ada 407a7ada 40796784 407a7ada 40796784 40796784 4b519eea 4b51c19a 4b53490a 407a7ada 407a7ada 407a7ada 407a7ada 40796784 4074f7f8 28210000  2 0
    4b536c00 4b536c00 4b536c00 4b536c00 407a7ada 4b50902c 40796784 4b519eea 4b51c19a 4b53490a 4b536c00 4b536c00 4b536c00 4b536c00 4b536c00 407a7ada 4b50817c 28210000  13 11

On the far right are the number of times each string matched.

We don't know *a priori* which of these will contain the full list, but
we can simply dump out all data passing through them using `textprinter`.
Create a file `tap_points.txt` with the caller, pc, and address space
information where both strings matched:

    40796784 40038678 28210000
    40796784 40038688 28210000
    407a7ada 4074f630 28210000
    407a7ada 4b50817c 28210000

And run another replay with `textprinter` turned on:

    ../arm-softmmu/qemu-system-arm -m 2048 -replay line2 -M android_arm -cpu cortex-a9 -kernel /dev/null -vnc :0 \
      -global goldfish_mmc.sd_path=/dev/null -global goldfish_nand.system_path=dummy.qcow2 \
      -global goldfish_nand.user_data_path=dummy.qcow2 \
      -panda 'callstack_instr;textprinter'

This will create two gzipped files, `read_tap_buffers.txt.gz` and
`write_tap_buffers.txt.gz`. Their contents are rather verbose and show
the callstack, memory address, and value of each byte passing through
the specified tap points. For example:

    40782c3a 40782c3a 40782c3a 40782c3a 407698fe 40782c3a 40782c3a 407698fe 40782c3a 40782c3a 40769d40 40782c3a 407698fe 400417a8 40041e6a 407a7ada 4074f630 28210000 415bc3a8 156197121 3c
    407698fe 40782c3a 40782c3a 40782c3a 40782c3a 40782c3a 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4078213e 40796784 40038678 28210000 415bc3f0 156603914 61
    407698fe 40782c3a 40782c3a 40782c3a 40782c3a 40782c3a 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4078213e 40796784 40038678 28210000 415bc3f1 156603914 6d
    407698fe 40782c3a 40782c3a 40782c3a 40782c3a 40782c3a 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4078213e 40796784 40038678 28210000 415bc3f2 156603914 65
    407698fe 40782c3a 40782c3a 40782c3a 40782c3a 40782c3a 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4078213e 40796784 40038678 28210000 415bc3f3 156603914 3d
    407698fe 40782c3a 40782c3a 40782c3a 40782c3a 40782c3a 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4078213e 40796784 40038678 28210000 415bc3f4 156603915 22
    407698fe 40782c3a 40782c3a 40782c3a 40782c3a 40782c3a 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4075222c 4078213e 40796784 40038678 28210000 415bc3f5 156603915 44

We can make this more readable by splitting these files out into their
constituent tap points and converting the hex data to binary. The
script that does this is called `split_taps.py`:

    $ mkdir -p taps/reads taps/writes
    $ ../scripts/split_taps.py ../scripts/split_taps.py read_tap_buffers.txt.gz taps/reads/line
    $ ../scripts/split_taps.py ../scripts/split_taps.py write_tap_buffers.txt.gz taps/writes/line

And then examining the files in `taps/reads` and `taps/writes`. Looking
in particular at `taps/writes/line.40796784.40038688.28210000.dat`, we
see partway through the file lines that look promising:

    GCD
    GFW
    18大
    38军
    八九
    半羽
    鲍彤
    暴政
    柴玲
    赤匪
    共党
    共匪

These translate to words like "tyranny", "communist", etc.

We now wish to ensure we get the full list. If part of the list is
processed at a different program counter, that part will not show up in
our dump. However, we can reasonably surmise that the entire file is
being read into a contiguous buffer in memory. If we go back to the
point in the tap buffer file where the characters we're interested in
appear, we can look at the addresses and then monitor all writes to
that contiguous buffer (plus some extra at the end to make sure we
see everything).

We start by getting the byte offset of one of the strings we saw:

    $ grep -a -b -o GCD taps/writes/line.40796784.40038688.28210000.dat
    64587:GCD
    80715:GCD

We can then look at that line in the original tap dump:

    $ zgrep '40796784 40038688 28210000' write_tap_buffers.txt.gz | less

And then type `64587G` into `less` to jump to line `64587`. Here we see
(full callstack abbreviated and annotated for the sake of readability):

    40796784 40038688 28210000 41544f7e 714950631 75  ; u
    40796784 40038688 28210000 41544f7f 714950631 a7  ; \xa7
    40796784 40038688 28210000 41792080 726257350 31  ; 1
    40796784 40038688 28210000 41792081 726257350 39  ; 9
    40796784 40038688 28210000 41792082 726257350 38  ; 8
    40796784 40038688 28210000 41792083 726257350 39  ; 9
    40796784 40038688 28210000 41792084 726257351 36  ; 6
    40796784 40038688 28210000 41792085 726257351 34  ; 4
    40796784 40038688 28210000 41792086 726257351 0a  ; \n
    40796784 40038688 28210000 41792087 726257351 46  ; F
    40796784 40038688 28210000 41792088 726257352 4c  ; L
    40796784 40038688 28210000 41792089 726257352 47  ; G
    40796784 40038688 28210000 4179208a 726257352 0a  ; \n
    40796784 40038688 28210000 4179208b 726257352 47  ; G
    40796784 40038688 28210000 4179208c 726257353 43  ; C
    40796784 40038688 28210000 4179208d 726257353 44  ; D
    40796784 40038688 28210000 4179208e 726257353 0a  ; \n

The third-to-last column is the address being written to. We see that
a contiguous buffer containing our candidate censorship list starts at
`41792080` with the string "198964". This refers to June 4, 1989, the
date of the Tiananmen Square massacre.

Now we can pick a reasonable size for the buffer. It looks like what
we've seen of our censorship list ends at `41793e3f`, so we'll consider
the slightly larger range `[41792080,41794080)` -- a `0x2000`  byte
region. We can also update this guess if it looks like we still haven't
found the whole thing after monitoring writes to this region.

Now we can use `bufmon`, which monitors accesses to a buffer. We create
a file `search_buffers.txt` with the range we want to monitor and its
address space identifier:

    0x41792080 0x2000 28210000

Now we run `bufmon`:

    ../arm-softmmu/qemu-system-arm -m 2048 -replay line2 -M android_arm -cpu cortex-a9 -kernel /dev/null -vnc :0 \
      -global goldfish_mmc.sd_path=/dev/null -global goldfish_nand.system_path=dummy.qcow2 \
      -global goldfish_nand.user_data_path=dummy.qcow2 \
      -panda 'callstack_instr;bufmon'

Output is placed in `buffer_taps.txt`. Looking at the tap point we saw
earlier, we see that the buffer is zeroed out just before the
censorship list is written to it:

    WRITE 40759e88 40038998 28210000 41793e38 00000004 00 00 00 00
    WRITE 40759e88 40038998 28210000 41793e3c 00000004 00 00 00 00
    WRITE 40759e88 400389ac 28210000 41793e40 00000004 00 00 00 00
    WRITE 40759e88 400389ac 28210000 41793e44 00000004 00 00 00 00
    WRITE 40796784 40038688 28210000 41792080 00000004 31 39 38 39
    WRITE 40796784 40038688 28210000 41792084 00000004 36 34 0a 46
    WRITE 40796784 40038688 28210000 41792088 00000004 4c 47 0a 47
    WRITE 40796784 40038688 28210000 4179208c 00000004 43 44 0a 47

We can see that most of the list is indeed written from the original
tap point we found, `40796784 40038688 28210000`. At the end, however,
we see 8 additional bytes written from `40796784 400386ac 28210000`:

    WRITE 40796784 40038688 28210000 41793e38 00000004 e5 85 b1 e6
    WRITE 40796784 40038688 28210000 41793e3c 00000004 9d 83 e6 96
    WRITE 40796784 400386ac 28210000 41793e40 00000004 97 0a e4 b9
    WRITE 40796784 400386ac 28210000 41793e44 00000004 b0 e6 9e aa
    WRITE 4079ff5a 4079e8aa 28210000 41793e4c 00000004 91 51 00 00

After this, the next write is to a non-contiguous region. We can thus
assume that the entire censorship list is written to the buffer from
`0x41792080` to `0x41793e48`. Finally we can extract the bytes written
to that location by hand (i.e. copy/paste) and obtain our full list
of censored words, which we can analyze at our leisure.

For reference, the full list is available at:

http://www.cc.gatech.edu/~brendan/line.txt
