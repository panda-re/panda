First, download the replay at
http://www.rrshare.org/content/rrlogs/starcraft4.rr, and clone a copy of
the PANDA repository:

> git clone https://github.com/moyix/panda.git

This tutorial is based on revision 186fcec, so run:

> git checkout 186fcec

To build PANDA, cd into panda/qemu. Edit build.sh to remove the lines
about LLVM; we won't need them for this tutorial. Then run build.sh.

The first thing we need to do is reduce the size of the replay, as it's
too big to run complicated analyses. While recording the replay, we
entered the CD-key "N68KTD-HEKM-HEV89N-74GKE-DNYKC" into the installer and
hit OK. This string gives us the opportunity to use the `stringsearch`
plugin to zero in on the verification code.

Write the following to search_strings.txt, including quotes:

> "N68KTD"

Now `stringsearch` will watch every memory read/write for this string.
Let's run PANDA with stringsearch turned on. It requires the
`callstack_instr` plugin, too.

> panda/qemu/i386-softmmu/qemu-system-i386 -replay starcraft4 -display none -panda 'callstack_instr;stringsearch'

Now `stringsearch` will give us a bunch of matches, the first of which
are:

> WRITE Match of str 0 at: instr_count=10643329 :  004374c3 00494678 06cba000
> READ Match of str 0 at: instr_count=10647796 :  004374ec 00411698 06cba000
> WRITE Match of str 0 at: instr_count=10647796 :  004374ec 00411698 06cba000
> READ Match of str 0 at: instr_count=10648447 :  0045b42d 00437e54 06cba000
> WRITE Match of str 0 at: instr_count=10648539 :  0045b42d 00437e77 06cba000
> WRITE Match of str 0 at: instr_count=10651042 :  0045b42d 00437eee 06cba000
> READ Match of str 0 at: instr_count=10651584 :  0045b42d 00437f34 06cba000
> READ Match of str 0 at: instr_count=10652239 :  00437f4d 00411698 06cba000
> WRITE Match of str 0 at: instr_count=10652239 :  00437f4d 00411698 06cba000

The first number is the return address on the stack (i.e. the value
pointed at by EBP), the second is the EIP at which the string was seen,
and the third is the CR3. Certainly, the second and third matches appear
to be a memcpy, which is probably not the code of interest. Cursory
inspection of the fourth and fifth seems to indicate that that code is
uppercasing and checking to make sure the CD-Key is alphanumeric. The
sixth match (`instr_count` 10651042) is adding dashes (0x2D) to the string,
which means it's probably a UI function of some form and unlikely to be
the actual processing, and the seventh match is similar.
