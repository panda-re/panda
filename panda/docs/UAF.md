This is an example of using PANDA for rapid vulnerability diagnosis.
To start, clone a copy of the PANDA repository:

	git clone https://github.com/moyix/panda.git

We're using revision 46bf2ea for this tutorial, so run:

	git checkout 46bf2ea

To build PANDA, cd into `panda/qemu`. Edit `build.sh` to remove the lines
about LLVM; we won't need them for our purposes. Then run `build.sh`.

Now download the [bug replay on rrshare.org](http://www.rrshare.org/detail/38/)
and unpack it:

    panda/scripts/rrunpack.py cve-2011-1255-crash.rr

One of PANDA's advantages is that it enables you to zero in on the
relevant code very quickly. First, we need to zoom in on the part of the
replay that's relevant to us. We aren't quite sure what's happening, so
let's use the replaymovie plugin to make a video of replay execution.
Run:

	panda/qemu/x86_64-softmmu/qemu-system-x86_64 -m 1024 -replay cve-2011-1255-crash \
        -display none -panda 'replaymovie'

This will dump out a bunch of raw image files. Luckily, the replaymovie
plugin has a script to actually make a movie. Run

	panda/qemu/panda_plugins/replaymovie/movie.sh

(make sure you have parallel and imagemagick installed). This will
create replay.mp4, which you can watch in your favorite video player.
The movie tells you that Internet Explorer crashes after a page is
loaded, so let's find out what page it is. First, though, we need to cut
the replay to a manageable size. The relevant part should start with the
page load--so we should see the string `<html` in memory, and it should
end with "has stopped working" being in memory. Place the following
three lines into `search_strings.txt`:

	"<html"
	"<HTML"
	"has stopped working"

Now run the stringsearch plugin:
	
	panda/qemu/x86_64-softmmu/qemu-system-x86_64 -m 1024 -replay cve-2011-1255-crash \
        -display none -panda 'callstack_instr;stringsearch'

The output (abberviated here) will look something like:

    opening nondet log for read :   ./cve-2011-1255-crash-rr-nondet.log
    ./cve-2011-1255-crash-rr-nondet.log:  324672 of 13204683 (2.46%) bytes, 14286548 of 1425929663 (1.00%) instructions processed.
    [...]
    ./cve-2011-1255-crash-rr-nondet.log:  3224618 of 13204683 (24.42%) bytes, 370747250 of 1425929663 (26.00%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  3314428 of 13204683 (25.10%) bytes, 385204921 of 1425929663 (27.01%) instructions processed.
    READ Match of str 0 at: instr_count=398546927 :  0000000086ebece0 0000000082888856 0000000000000000
    WRITE Match of str 0 at: instr_count=398546927 :  0000000086ebece0 0000000082888856 0000000000000000
    ./cve-2011-1255-crash-rr-nondet.log:  3360953 of 13204683 (25.45%) bytes, 399378040 of 1425929663 (28.01%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  3423622 of 13204683 (25.93%) bytes, 414167226 of 1425929663 (29.05%) instructions processed.
    READ Match of str 0 at: instr_count=422577965 :  000000007679371a 0000000076319b60 000000003f98b320
    WRITE Match of str 0 at: instr_count=422577965 :  000000007679371a 0000000076319b60 000000003f98b320
    [...]
    ./cve-2011-1255-crash-rr-nondet.log:  4261845 of 13204683 (32.28%) bytes, 641754362 of 1425929663 (45.01%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  4367057 of 13204683 (33.07%) bytes, 656083288 of 1425929663 (46.01%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  4491501 of 13204683 (34.01%) bytes, 670258577 of 1425929663 (47.01%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  4675020 of 13204683 (35.40%) bytes, 684462870 of 1425929663 (48.00%) instructions processed.
    READ Match of str 1 at: instr_count=693024260 :  0000000086c37b91 00000000828887d3 0000000000000000
    WRITE Match of str 1 at: instr_count=693024260 :  0000000086c37b91 00000000828887d3 0000000000000000
    ./cve-2011-1255-crash-rr-nondet.log:  4881606 of 13204683 (36.97%) bytes, 698721619 of 1425929663 (49.00%) instructions processed.
    READ Match of str 1 at: instr_count=705861108 :  000000007679371a 0000000076319b60 000000003f98b320
    WRITE Match of str 1 at: instr_count=705861108 :  000000007679371a 0000000076319b60 000000003f98b320
    READ Match of str 1 at: instr_count=705874377 :  00000000828aca66 00000000828887d3 0000000000000000
    WRITE Match of str 1 at: instr_count=705874377 :  00000000828aca66 00000000828887d3 0000000000000000
    READ Match of str 1 at: instr_count=706855458 :  00000000761e6ab5 0000000076319b60 000000003f98b320
    WRITE Match of str 1 at: instr_count=706855458 :  00000000761e6ab5 0000000076319b60 000000003f98b320
    READ Match of str 1 at: instr_count=708771845 :  00000000761f6fd3 0000000076319b60 000000003f98b320
    WRITE Match of str 1 at: instr_count=708771845 :  00000000761f6fd3 0000000076319b60 000000003f98b320
    READ Match of str 1 at: instr_count=708779961 :  000000006da56ee2 0000000076319b60 000000003f98b320
    WRITE Match of str 1 at: instr_count=708779961 :  000000006da56ee2 0000000076319b60 000000003f98b320
    READ Match of str 1 at: instr_count=708780509 :  000000006da6902c 0000000076319b60 000000003f98b320
    WRITE Match of str 1 at: instr_count=708780509 :  000000006da6902c 0000000076319b60 000000003f98b320
    READ Match of str 1 at: instr_count=708782056 :  000000006d9cfd1f 0000000075ab9f11 000000003f98b320
    ./cve-2011-1255-crash-rr-nondet.log:  5035997 of 13204683 (38.14%) bytes, 713178025 of 1425929663 (50.01%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  5895169 of 13204683 (44.64%) bytes, 727498781 of 1425929663 (51.02%) instructions processed.
    [...]
    ./cve-2011-1255-crash-rr-nondet.log:  12506363 of 13204683 (94.71%) bytes, 1098178736 of 1425929663 (77.01%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  12600539 of 13204683 (95.42%) bytes, 1112292842 of 1425929663 (78.00%) instructions processed.
    READ Match of str 2 at: instr_count=1122107469 :  0000000076453d79 0000000076447933 000000003f98b2e0
    READ Match of str 2 at: instr_count=1122110674 :  0000000076487a32 000000007646ffea 000000003f98b2e0
    READ Match of str 2 at: instr_count=1122167975 :  0000000076453d79 0000000076447933 000000003f98b2e0
    READ Match of str 2 at: instr_count=1122171180 :  0000000076487a32 000000007646ffea 000000003f98b2e0
    [...]
    ./cve-2011-1255-crash-rr-nondet.log:  13179500 of 13204683 (99.81%) bytes, 1397901771 of 1425929663 (98.03%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  13193969 of 13204683 (99.92%) bytes, 1411828978 of 1425929663 (99.01%) instructions processed.
    ./cve-2011-1255-crash-rr-nondet.log:  log is empty.
    Replay completed successfully.
    Time taken was: 686 seconds.

Now we can cut the replay down to size using the `scissors` plugin.
Our reduced log will start at instruction `398546927` (which was
reported as the first match for `<html`) and end at `1122107469`, the
first match for `"has stopped working`.

	panda/qemu/x86_64-softmmu/qemu-system-x86_64 -m 1024 -replay cve-2011-1255-crash \
        -display none -panda 'scissors:start=398546927,end=1122107469,name=crash_reduced`

Once this runs, we'll have a replay of around 700 million instructions
-- about half the size of the original.

Now we want to get more information on the cause of the crash. To do so,
we'll want to examine the full text of the HTML seen by the browser.
Part of the output of `stringsearch` is a text file named
`string_matches.txt` that contains the callstack of the memory accesses
that matched our search strings. It looks like (again abbreviated):

    00000000761f6994 [...] 000000006da68ba1 000000006da803e0 000000003f98b320  1 0 0
    00000000761f680e [...] 000000006d9cfd1f 0000000075ab9f11 000000003f98b320  0 1 0
    000000006da9f0e3 [...] 000000006da56ee2 0000000076319b60 000000003f98b320  2 2 0
    00000000761f680e [...] 000000006da6902c 0000000076319b60 000000003f98b320  0 2 0
    00000000760c739f [...] 00000000761e6ab5 0000000076319b60 000000003f98b320  2 2 0
    00000000761f68a1 [...] 00000000761f6fd3 0000000076319b60 000000003f98b320  2 2 0
    000000007678e4dd [...] 000000007679371a 0000000076319b60 000000003f98b320  2 2 0
    0000000074a88305 [...] 0000000076453d79 0000000076447933 000000003f98b2e0  0 0 20
    00000000760c4d7b [...] 0000000076487a32 000000007646ffea 000000003f98b2e0  0 0 20
    000000007678331e [...] 00000000828aca66 00000000828887d3 0000000000000000  2 2 0
    00000000828e2893 [...] 0000000086c37b91 00000000828887d3 0000000000000000  0 2 0
    000000007678fd00 [...] 0000000086ebece0 0000000082888856 0000000000000000  2 0 0

The last three columns give the number of matches seen at that point for
each string. In this case, the first two lines seem promising since they
each contain one copy of the `<html` string.

We can dump out their contents by creating a file called
`tap_points.txt` with the contents:

    000000006da68ba1 000000006da803e0 000000003f98b320
    000000006d9cfd1f 0000000075ab9f11 000000003f98b320

And then running the `textprinter` plugin:

    panda/qemu/x86_64-softmmu/qemu-system-x86_64 -display none -m 1024 -replay crash_reduced \
        -panda 'callstack_instr;textprinter'

This creates two files containing all the data read and written at those
points into `read_tap_buffers.txt.gz` and `write_tap_buffers.txt.gz`. We
can then look at the data in this log file by doing:

    panda/scripts/split_taps.py read_tap_buffers.txt.gz crash.read
    panda/scripts/split_taps.py write_tap_buffers.txt.gz crash.write

Since there were no writes in this case, we'll just end up with two
files that we can examine,
`crash.read.000000006d9cfd1f.0000000075ab9f11.000000003f98b320.dat` and
`crash.read.000000006da68ba1.000000006da803e0.000000003f98b320.dat`. 

Although the latter is just the directory listing, the former contains
the HTML that triggers the crash:

    <HTML XMLNS:t="urn:schemas-microsoft-com:time">
    <?IMPORT namespace="t" implementation="#default#time2">
    <body>
    <div id="x" contenteditable="true">
    HELLOWORLD
    <t:TRANSITIONFILTER></t:TRANSITIONFILTER>
    <script>
       document.getElementById("x").innerHTML = "";
       CollectGarbage();
       window.onclick;
       document.location.reload();
    </script>
    </div>
    </body>
    </HTML>

Judging by the use of `CollectGarbage()`, the bug is likely some kind of
use after free. We tested this suspicion by writing a simple use after
free detection plugin. The basic idea behind it is simple: once provided
with the addresses of `malloc`, `free`, and `realloc`, the plugin keeps
a map of allocated heap objects and then alerts when a freed object is
accessed. PANDA's makes this easy since we can watch every memory access
through the memory read and write callbacks. This strategy is not
foolproof, since it is possible another object will be allocated in the
same space before the stale pointer is dereferenced, but in this case it
is sufficient to detect the bug.

The revision we're using already has the correct addresses for `malloc`,
`free`, and `realloc` as defaults, as well as the CR3 of the Internet
Explorer process. These were derived by dumping memory during the replay
and then using
[Volatility](https://github.com/volatilityfoundation/volatility) to find
the relevant process and look up the addresses of the memory allocation
functions.

Now we can run the use after free detector:

    panda/qemu/x86_64-softmmu/qemu-system-x86_64 -display none -m 1024 -replay crash_reduced \
        -panda 'callstack_instr;useafterfree'

Its output contains many warnings of the form `READING INVALID POINTER`;
these are generally harmless. An actual use after free will be reported
as `USE AFTER FREE`. And, indeed, around halfway through the reduced
replay we see:

    USE AFTER FREE READ @ {3f98b320, 5556f0}! PC 6dc996f5

This indicates that code at `0x6dc996f5` attempted to read from a freed
object at `0x5556f0`, confirming our suspicion that the underlying cause
of the crash is a use after free. The information provided allows us to
pinpoint exactly where the freed object is used, and (if we had access
to source code) would tell us precisely where to apply a fix.
