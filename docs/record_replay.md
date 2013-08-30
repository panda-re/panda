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

* begin_record <name>
    Starts a recording session, saved as <name>. Note that there is
    currently no safeguard to prevent overwriting previous recordings,
    so be careful to choose a unique name.

    The recording log consists of two parts: the snapshot, which is
    stored in the QCOW under the name <name>-rr-snp, and the recording
    log, which is named <name>-rr-nondet.log.

* end_record
    Ends an active recording session. The guest will be paused, but can
    be resumed and another recording can be made once the guest is
    resumed.

* begin_replay <name>
    Begin a replay of the session named <name>. Note that QEMU not must
    be halted for this to work. You may find it convenient to use the
    following trick to get a replay started:

      (echo "begin_replay <name>" ; cat) | qemu-system-arm -monitor stdio
    
    This will start up QEMU and place the monitor on stdin, and
    immediately tell QEMU to start replay.

* end_replay
    End an active replay. Normally the replay will just finish on its
    own, but if you want to end it early you can use this command.

    Quitting QEMU (either by pressing ^C or typing "quit" in the
    monitor) will also end the replay.

Note that you *must* have at least one QCOW disk for record and replay
to work, because QEMU snapshots are used to create the starting state
for the recording session. If the system you are trying to emulate
doesn't have a hard disk, you can just create an empty QCOW and pass it
to QEMU with -hda; the guest system won't see it, but this will give
QEMU a place to store snapshots.

Of course, just running a replay isn't very useful by itself, so you
will probably want to run the replay with some plugins enabled that
perform some analysis on the replayed execution. See docs/PANDA.md for
more details.
