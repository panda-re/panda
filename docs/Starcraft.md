First, download the replay at
http://www.rrshare.org/content/rrlogs/starcraft4.rr, and clone a copy of
the PANDA repository:

	git clone https://github.com/moyix/panda.git

This tutorial is based on revision 186fcec, so run:

	git checkout 186fcec

To build PANDA, cd into panda/qemu. Edit build.sh to remove the lines
about LLVM; we won't need them for this tutorial. Then run build.sh.

The first thing we need to do is find the code that's checking the
CD-Key. While recording the replay, we entered the CD-key
"N68KTD-HEKM-HEV89N-74GKE-DNYKC" into the installer and hit OK. This
string gives us the opportunity to use the `stringsearch` plugin to zero
in on the verification code. We'll search for the first two blocks of
the CD-Key without dashes, as we make the reasonable assumption that the
verification code ignores the dashes.

Write the following to search_strings.txt, including quotes:

	"N68KTDHEKM"

Now `stringsearch` will watch every memory read/write for this string.
Let's run PANDA with stringsearch turned on. It requires the
`callstack_instr` plugin, too.

	panda/qemu/i386-softmmu/qemu-system-i386 -replay starcraft4 -display none -panda 'callstack_instr;stringsearch'

Now `stringsearch` will give us a bunch of matches, the first of which
are:

	WRITE Match of str 0 at: instr_count=10649029 :  0045b42d 00437e77 06cba000
	WRITE Match of str 0 at: instr_count=10651144 :  0045b42d 00437eee 06cba000
	WRITE Match of str 0 at: instr_count=10848983 :  0045b42d 00437e77 06cba000
	WRITE Match of str 0 at: instr_count=10851098 :  0045b42d 00437eee 06cba000
	READ Match of str 0 at: instr_count=10860768 :  00437a2b 0049aad4 06cba000
	READ Match of str 0 at: instr_count=10861024 :  00437a2b 0049aad4 06cba000
	READ Match of str 0 at: instr_count=10861317 :  00437a2b 0049aad4 06cba000
	READ Match of str 0 at: instr_count=10861638 :  00437a2b 0049aad4 06cba000
	READ Match of str 0 at: instr_count=10862350 :  00437a68 00411362 06cba000
	WRITE Match of str 0 at: instr_count=10862350 :  00437a68 00411362 06cba000
	READ Match of str 0 at: instr_count=10862853 :  0045b73a 00411362 06cba000
	WRITE Match of str 0 at: instr_count=10862853 :  0045b73a 00411362 06cba000

The first number is the return address on the stack (i.e. the value
pointed at by EBP), the second is the EIP at which the string was seen,
and the third is the CR3.

The first four matches appear to be doing basic validation of the
CD-Key—they are checking to see that all characters are alphanumeric and
converting to uppercase. The next four (PC 49aad4) might be looking for
dashes, as that PC is inside a `strnchr` function. The last four are
copying the CD-Key twice but don't appear to be doing any computation
nearby.

So let's move on to the next group:

	READ Match of str 0 at: instr_count=30991180 :  0040331b 00411362 06cba000
	WRITE Match of str 0 at: instr_count=30991180 :  0040331b 00411362 06cba000
	READ Match of str 0 at: instr_count=31015372 :  0047d949 0047d4cb 06cba000
	READ Match of str 0 at: instr_count=31045765 :  004286ff 0044c951 06cba000
	READ Match of str 0 at: instr_count=31046388 :  0044c964 00411698 06cba000
	WRITE Match of str 0 at: instr_count=31046388 :  0044c964 00411698 06cba000

The first two are copies again. But the third looks a little more
interesting:

	47d4cb:       0f b6 04 17             movzbl (%edi,%edx,1),%eax 
	47d4cf:       0f b6 80 70 ea 51 00    movzbl 0x51ea70(%eax),%eax

It's using the character from the CD-Key, read at 47d4cb, to do a table
lookup into a table at 0x51ea70. This seems like the beginning of a
decryption algorithm. Starting at 47d949, the caller appears to
initialize 16 bytes on the stack to 0. It then passes the address of
this 16-byte region to three different functions, moves different
portions of that region into some locations in memory, and returns.

`stringsearch` uses the `callstack` plugin to record the full callstack
for each match, so we can look up the caller for 47d949. The callstacks
are stored in string_matches.txt. The line we're looking for will end
with PC/caller/CR3 as above, so we can locate it:

	0045c252 00428867 004286ff 0044c83b 0047d949 0047d4cb 06cba000

The return address is 44c83b, where the program grabs part of the stored
16-byte region from before, calls a function (44c120, which appears to
be some form of strnchr), and then jumps away if the result is true—if
the strnchr finds the desired value. From here, we can write a custom
plugin to confirm our intuition, or manually RE the code enough to
figure out that we're correct.

The one remaining issue is to find the strnchr value which is being
searched for. The best way to do this is to write a custom plugin to
print out the dynamic value. We'll leave that as an exercise for the
reader.
