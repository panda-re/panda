Introduction
----

PANDA supports whole system deterministic record and replay in whole
system mode on the i386, x86_64, and arm targets. We hope to add more
soon; for example, partial SPARC support exists but is not yet reliable.

Background
----

Deterministic record and replay is a technique for capturing the
*non-deterministic inputs* to a system -- that is, the things that would
cause a system to be have differently if it were re-started from the
same point with the same inputs. This includes things like network
packets, hard drive reads, mouse and keyboard input, etc.

Our implementation of record and replay focuses on reproducing code
execution. That is, the non-deterministic inputs we record are changes
made to the CPU state and memory -- DMA, interrupts, `in` instructions,
and so on. Unlike many record and replay implementations, we do *not*
record the inputs to devices; this means that one cannot "go live"
during a recording, but it greatly simplifies the implementation. To get
an idea of what is recorded, imagine drawing a line around the CPU and
RAM; things going from the outside world to the CPU and RAM, crossing
this line, must be recorded.

Record and replay is extremely useful because it enables many
sophisticated analysis that are too slow to run in real-time; for
example, trying to do taint flow analysis makes the guest system so slow
that it cannot make network connections (because remote systems time out
before the guest can process the packets and respond). By creating a
recording, which has fairly modest overhead, and performing analyses on
the replayed execution, one can do analyses that simply aren't possible
to do live.

Usage
----

Record and replay is controlled with four QEMU monitor commands:
begin_record, end_record, begin_replay, end_replay:

* `begin_record <name>`

    Starts a recording session, saved as `<name>`. Note that there is
    currently no safeguard to prevent overwriting previous recordings,
    so be careful to choose a unique name.

    The recording log consists of two parts: the snapshot, which is
    named `<name>-rr-snp`, and the recording log, which is named
    `<name>-rr-nondet.log`.

* `end_record`

    Ends an active recording session. The guest will be paused, but can
    be resumed and another recording can be made once the guest is
    resumed.

* `begin_replay <name>`

    Begin a replay of the session named `<name>`. Note that QEMU not must
    be halted for this to work.

* `end_replay`

    End an active replay. Normally the replay will just finish on its
    own, but if you want to end it early you can use this command.

    Quitting QEMU (either by pressing ^C or typing "quit" in the
    monitor) will also end the replay.

Alternatively, one can start replays from the command line using the
`-replay <name>` option. 

Of course, just running a replay isn't very useful by itself, so you
will probably want to run the replay with some plugins enabled that
perform some analysis on the replayed execution. See docs/PANDA.md for
more details.

Migrating Recordings from Older Versions of PANDA
----

Prior to commit 9139261d70, snapshot data was stored in the QCOW itself.
To enable sharing of record/replay logs without sharing the QCOW, this
has changed so that the snapshot is stored in a separate file, named
`<name>-rr-snp`.

Of course, this means that recordings made before commit 9139261d70
cannot be directly used with the current version of PANDA. Luckily, it's
easy to convert existing snapshots to the new format. Assuming your
recording is named `foo`, stored in `hd.qcow2`, and was created using
QEMU architecture `$ARCH` with memory size `$MEM` the command is:

    echo -e 'migrate exec:cat>foo-rr-snp\nq" | qemu-system-$ARCH -m $MEM -hda hd.qcow2 -monitor stdio -vnc :0 -S -loadvm foo-rr-snp

Naturally, you should adjust `foo`, `$ARCH`, `$MEM`, and `hd.qcow2` to
match your particular situation. Once the command finishes, `foo-rr-snp`
should exist in the current directory. Assuming that `foo-rr-nondet.log`
is also in the current directory, you can then run the replay with:

    qemu-system-$ARCH -m $MEM -vnc :0 -replay foo

Note that the QCOW is no longer required.

Sharing Recordings
----

To make it easier to share record/replay logs, PANDA has two scripts,
`rrpack.py` and `rrunpack.py`, that bundle up and compress a recording.
These can be found in the `scripts` directory. To pack up a recording,
just use:

    scripts/rrpack.py <name>

This will bundle up `<name>-rr-snp` and `<name>-rr-nondet.log` and put
them into PANDA's packed record/replay format in a file named
`<name>.rr`. This file can be unpacked and verified using:

    scripts/rrunpack.py <name>.rr

A central repository for sharing record/replay logs is available at the [PANDA Share](http://www.rrshare.org/) website.
