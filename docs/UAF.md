This is an example of using PANDA for rapid vulnerability diagnosis.
Start by downloading the CVE replay from URL, and clone a copy of the
PANDA repository:

	git clone https://github.com/moyix/panda.git

We're using revision 46bf2ea for this tutorial, so run:

	git checkout 46bf2ea

To build PANDA, cd into panda/qemu. Edit build.sh to remove the lines
about LLVM; we won't need them for our purposes. Then run build.sh.

One of PANDA's advantages is that it enables you to zero in on the
relevant code very quickly. First, we need to zoom in on the part of the
replay that's relevant to us. We aren't quite sure what's happening, so
let's use the replaymovie plugin to make a video of replay execution.
Run:

	panda/qemu/i386-softmmu/qemu-system-i386 -m 1024 -replay REPLAY -display none -panda 'replaymovie'

This will dump out a bunch of raw image files. Luckily, the replaymovie
plugin has a script to actually make a movie. Run

	panda/qemu/panda_plugins/replaymovie/movie.sh

(make sure you have parallel and imagemagick installed). This will
create replay.mp4, which you can watch in your favorite video player.
The movie tells you that Internet Explorer crashes after a page is
loaded, so let's find out what page it is. First, though, we need to cut
the replay to a manageable size. The relevant part should start with the
page load--so we should see the string <html in memory, and it should
end with "has stopped working" being in memory. Place the following
three lines into search_strings.txt:

	"<html"
	"<HTML"
	"has stopped working"

Now run the stringsearch plugin:
	
	panda/qemu/i386-softmmu/qemu-system-i386 -m 1024 -replay REPLAY -display none -panda 'callstack_instr;stringsearch'


