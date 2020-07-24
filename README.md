# PANDA

![Core Emulation Tests](https://github.com/panda-re/panda/workflows/QEMU%20Checks/badge.svg)
![Taint System Tests](https://github.com/panda-re/panda/workflows/Taint%20Unit%20Tests/badge.svg)
![Publish Docker Container](https://github.com/panda-re/panda/workflows/Build%20and%20Publish%20Docker%20Container/badge.svg)


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
### Quickstart: Docker
The latest version of PANDA's master branch is automatically built as a docker image
from both Ubuntu Bionic (18.04) and Xenial (16.04). These images are available [here](https://hub.docker.com/r/pandare/panda).

To pull the latest docker container and run PANDA
```
$ docker pull pandare/panda
$ docker run --rm pandare/panda -- /bin/panda-system-i386 --help
```

###  Debian, Ubuntu
Because PANDA has a few dependencies, we've encoded the build instructions into
the [install\_ubuntu.sh](panda/scripts/install\_ubuntu.sh). The script should
work on the latest Debian stable/Ubuntu LTS versions.
If you wish to build PANDA manually, you can also check the
[step-by-step instructions](panda/docs/build\_ubuntu.md) in the documentation
directory.

We currently only vouch for buildability on the latest Debian stable/Ubuntu LTS,
but we welcome pull requests to fix issues with other distros.
For other distributions, it should be straightforward to translate the `apt-get`
commands into whatever package manager your distribution uses.

Note that if you want to use our LLVM features (mainly the dynamic taint
system), you will need to install LLVM 3.3 from OS packages or compiled from
source. On Ubuntu this should happen automatically via `install_ubuntu.sh`.
Additionally, it is **strongly** recommended that you only build PANDA as 64bit
binary. Creating a 32bit build should be possible, but best avoided.
See the limitations section for details.

### Arch
The [install\_arch.sh](panda/scripts/install\_arch.sh) has been contributed
for building PANDA on Arch Linux.
Currently, the script has only been tested on Arch Linux 4.17.5-1-MANJARO.
You can also find
[step-by-step instructions for building on Arch](panda/docs/build\_arch.md)
in the documentation directory.

### MacOS
Building on Mac is less well-tested, but has been known to work. There is a script,
[install\_osx.sh](panda/scripts/install\_osx.sh) to build under OS X.
The script uses [homebrew](https://brew.sh) to install the PANDA dependencies.
As homebrew is known to be very fast in deprecating support for older versions
of OS X and supported packages, expect this to be broken.

### Installation
After successfully building PANDA, you can copy the build to a system-wide
location by running `make install`. The default installation path is `/usr/local`.
You can specify an alternate installation path through the `prefix` configuration
option. E.g. `--prefix=/opt/panda`.  Note that your system must have `chrpath`
installed in order for `make install` to succeed.

If the `bin` directory containing the PANDA binaries is in your `PATH` environment
variable, then you can run PANDA similarly to QEMU:

    panda-system-i386 -m 2G -hda guest.img -monitor stdio

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

## Documentation and Support

### PANDA manual
PANDA currently supports whole-system record/replay execution, as well as
time-travel debugging, of x86, x86\_64, and ARM guests.
Details about the implementation and use of PANDA can be found in the
[PANDA manual](panda/docs/manual.md). Some of the topics covered are:

  * [details about record/replay](panda/docs/manual.md#recordreplay-details)
  * the [architecture-neutral plugin interface](panda/docs/manual.md#plugin-architecture)
  * the [callbacks provided by PANDA](panda/docs/manual.md#appendix-a-callback-list)
  * [plugin zoo](panda/docs/manual.md#plugin-zoo)

Documentation for individual plugins is provided by the `README.md` file
in the plugin directory. See [panda/plugins](panda/plugins) directory.

### Support
If you need help with PANDA, or want to discuss the project, you can join our
IRC channel at #panda-re on Freenode, or join the [PANDA mailing
list](http://mailman.mit.edu/mailman/listinfo/panda-users).

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
