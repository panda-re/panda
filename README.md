# PANDA

[![Build Status](https://travis-ci.org/panda-re/panda.svg?branch=master)](https://travis-ci.org/panda-re/panda)

PANDA is an open-source Platform for Architecture-Neutral Dynamic Analysis. It
is built upon the QEMU whole system emulator, and so analyses have access to all
code executing in the guest and all data. PANDA adds the ability to record and
replay executions, enabling iterative, deep, whole system analyses. Further, the
replay log files are compact and shareable, allowing for repeatable experiments.
A nine billion instruction boot of FreeBSD, e.g., is represented by only a few
hundred MB. PANDA leverages QEMU's support of thirteen different CPU
architectures to make analyses of those diverse instruction sets possible within
the LLVM IR. In this way, PANDA can have a single dynamic taint analysis, for
example, that precisely supports many CPUs. PANDA analyses are written in a
simple plugin architecture which includes a mechanism to share functionality
between plugins, increasing analysis code re-use and simplifying complex
analysis development.

It is currently being developed in collaboration with MIT Lincoln
Laboratory, NYU, and Northeastern University. PANDA is released under
the [GPLv2 license](LICENSE).

---------------------------------------------------------------------

## Building

###  Debian, Ubuntu
Because PANDA has a few dependencies, we've encoded the build instructions into
the [install\_ubuntu.sh](panda/scripts/install\_ubuntu.sh). The script should
work on the latest Debian stable/Ubuntu LTS versions.
For other distributions, it should be straightforward to translate the `apt-get`
commands into whatever package manager your distribution uses.
We currently only vouch for buildability on the latest Debian stable/Ubuntu LTS,
but we welcome pull requests to fix issues with other distros.

Note that if you want to use our LLVM features (mainly the dynamic taint
system), you will need to install LLVM 3.3 from OS packages or compiled from
source. On Ubuntu this should happen automatically via `install_ubuntu.sh`.
Additionally, it is **strongly** recommended that you only build PANDA as 64bit
binary. Creating a 32bit build should be possible, but best avoided.
See the limitations section for details.

Alternatively, you can manually add the Ubuntu PPA we have created at
`ppa:phulin/panda` and use the following commands to install PANDA
dependencies:

```sh
# install qemu pre-requisites
sudo add-apt-repository ppa:phulin/panda
sudo apt-get update
sudo apt-get build-dep qemu

# install generic dependencies
sudo apt-get install git python-pip libc++-dev libelf-dev libdwarf-dev \
  libelf-dev libdwarf-dev libwiretap-dev wireshark-dev python-pycparser

# install llvm dependencies from ppa:phulin/panda
sudo apt-get install llvm-3.3 clang-3.3

# install protobuf dependencies
sudo apt-get install protobuf-compiler protobuf-c-compiler python-protobuf \
  libprotoc-dev libprotobuf-dev libprotobuf-c-dev

# clone and build PANDA
git clone https://github.com/panda-re/panda
mkdir -p build-panda && cd build-panda
../panda/build.sh
```

### Arch-linux
Because PANDA has a few dependencies, we've encoded the build instructions into
a script, [panda/scripts/install\_arch.sh](panda/scripts/install\_arch.sh).
The script has only been tested on Arch Linux 4.17.5-1-MANJARO

#### Dependencies
```
aur_install_pkg () {
	local FNAME=$1
	local FNAME_WEB=$(python2 -c "import urllib; print urllib.quote('''$FNAME''')")
	wget -O /tmp/$FNAME.tar.gz https://aur.archlinux.org/cgit/aur.git/snapshot/$FNAME_WEB.tar.gz
	cd /tmp
	tar -xvf $FNAME.tar.gz
	cd /tmp/$FNAME
	makepkg -s
	makepkg --install
}

gpg --receive-keys A2C794A986419D8A
aur_install_pkg "libc++"
aur_install_pkg "llvm33"
aur_install_pkg "libprotobuf2"

# Protobuf for C language
cd /tmp
git clone https://github.com/protobuf-c/protobuf-c.git protobuf-c
cd protobuf-c
./autogen.sh
./configure --prefix=/usr
make
sudo make install

# We need to use an older version of wireshark, since 2.5.1 breaks the network plugin
sudo pacman -U https://archive.archlinux.org/packages/w/wireshark-common/wireshark-common-2.4.4-1-x86_64.pkg.tar.xz
sudo pacman -U https://archive.archlinux.org/packages/w/wireshark-cli/wireshark-cli-2.4.4-1-x86_64.pkg.tar.xz

# Other dependencies
sudo pacman -S python2-protobuf libelf dtc capstone libdwarf python2-pycparser
```
#### Build

```
export PANDA_LLVM_ROOT=/opt/llvm33
export CFLAGS=-Wno-error
./build.sh
```

### Building on Mac

Building on Mac is less well-tested, but has been known to work. There is a script,
[panda/scripts/install\_osx.sh](panda/scripts/install\_osx.sh) to build under OS X.

### Docker Image

Finally, if you want to skip the build process altogether, there is a
[Docker image](https://hub.docker.com/r/pandare/panda). You can get it by running:

    docker pull pandare/panda

Alternatively, you can pull the [latest build from an unofficial](https://hub.docker.com/r/thawsystems/panda) third party.

    docker pull thawsystems/panda

### Installation

PANDA can be installed with `make install`. Assuming you have the dependencies
installed from earlier steps, you can use configure and make to install PANDA.

```
mkdir build
cd build/
../configure --prefix=/opt/panda --with-llvm=/opt/llvm33 --enable-llvm
make
sudo make install
```

Note if you install PANDA, you need to make sure the bin directory where the
PANDA binaries live is on your PATH.

After installation, you can run PANDA similarly to QEMU:

```
panda-system-i386 -m 2G -hda guest.img -monitor stdio
```

---------------------------------------------------------------------

## Limitations

### LLVM Support
PANDA uses the LLVM architecture from the [S2E project](https://github.com/dslab-epfl/s2e).
This allows translating the TCG intermediate code representation used by QEMU,
to LLVM IR. The latter has the advantages of being easier to work with, as well
as platform independent. This enables the implementation of complex analyses
like the `taint2` plugin.
However, S2E is not actively updated to work with the latest LLVM toolchain.
As a consequence, PANDA still requires specifically LLVM 3.3 in order to be
built with taint analysis support.
of the plugins.

### Cross-architecture record/replay
Great effort is put to maintain the PANDA trace format stable so that existing
traces remain replayable in the future. Changes that will break existing traces
are avoided.
However, currently, record/replay is only guaranteed between PANDA builds of the
same address length. E.g. you can't replay a trace captured on a 32bit build of
PANDA on a 64bit of PANDA. The reason for this is that some raw pointers managed
to creep into the trace format (see headers in `panda/rr`).

Given the memory limitations of 32bit builds, almost all PANDA users use 64bit.
As a result, this issue should affect only a tiny minority of users.
This is also supported by the fact that the issue remained unreported for a
long time (>3 years). Therefore, when a fix is to be implemented, it may be
assessed that migrating existing recordings captured by 32bit builds is not
worth the effort.

For this, it is **strongly** recommended that you only create and use 64bit
builds of PANDA. If you happen to already have a dataset of traces captured
by a 32bit build of PANDA, you should contact the community ASAP to discuss
possible options.

---------------------------------------------------------------------

## Support

If you need help with PANDA, or want to discuss the project, you can join our
IRC channel at #panda-re on Freenode, or join the [PANDA mailing
list](http://mailman.mit.edu/mailman/listinfo/panda-users).

We have a basic manual [here](panda/docs/manual.md).

## PANDA Plugins

Details about the architecture-neutral plugin interface can be found in
[panda/docs/PANDA.md](panda/docs/PANDA.md). Existing plugins and tools can be found in
[panda/plugins](panda/plugins) and [panda](panda).

## Record/Replay

PANDA currently supports whole-system record/replay execution, as well as time-travel debugging, of x86, x86\_64, and ARM guests. Documentation can be found in
[the manual](panda/docs/manual.md#recordreplay-details).

---------------------------------------------------------------------

## Publications

* [1] B. Dolan-Gavitt, T. Leek, J. Hodosh, W. Lee.  Tappan Zee (North) Bridge:
Mining Memory Accesses for Introspection. 20th ACM Conference on Computer and
Communications Security (CCS), Berlin, Germany, November 2013.

* [2] R. Whelan, T. Leek, D. Kaeli.  Architecture-Independent Dynamic
Information Flow Tracking. 22nd International Conference on Compiler
Construction (CC), Rome, Italy, March 2013.

* [3] B. Dolan-Gavitt, J. Hodosh, P. Hulin, T. Leek, R. Whelan.
Repeatable Reverse Engineering with PANDA. 5th Program Protection and Reverse
Engineering Workshop, Los Angeles, California, December 2015.

* [4] M. Stamatogiannakis, P. Groth, H. Bos. Decoupling Provenance
Capture and Analysis from Execution. 7th USENIX Workshop on the Theory
and Practice of Provenance, Edinburgh, Scotland, July 2015.

* [5] B. Dolan-Gavitt, P. Hulin, T. Leek, E. Kirda, A. Mambretti,
W. Robertson, F. Ulrich, R. Whelan. LAVA: Large-scale Automated Vulnerability
Addition. 37th IEEE Symposium on Security and Privacy, San Jose,
California, May 2016.

---------------------------------------------------------------------

## Acknowledgements

This material is based upon work supported under Air Force Contract No.
FA8721-05-C-0002 and/or FA8702-15-D-0001. Any opinions, findings,
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the U.S. Air
Force.
