# Compiling PANDA
In order to build PANDA, you should use the ``build.sh`` script in the
QEMU directory. The script comes with some default options. But first,
the prerequisites need to be taken care of.

It is recommended building LLVM and QEMU with the same compiler.
In order to build some of the PANDA plugins inside of the QEMU directory,
a compiler that supports C++11 is required.

PANDA is known to build on debian wheezy and jessie with the following steps.

## Prepackaged prerequisites

Use the following commands to install the prerequisites that
can be used as-is from the Debian repositories.

```
$ apt-get install build-essential 
$ apt-get build-dep qemu
$ apt-get install nasm
$ apt-get install libssl-dev
```

<!--
This is required for building libiscsi.
But iSCSI support has been disabled in build.sh in the meantime.
apt-get install autoconf libtool
-->

## Self-compiled prerequisites

### LLVM
Download LLVM 3.3. Also, download Clang 3.3 and extract it in the LLVM
tools directory. Make sure the resulting directory is named `clang`. The
final releases can be directly fetched from the svn repositories of the
project.

```
$ cd panda
$ svn checkout http://llvm.org/svn/llvm-project/llvm/tags/RELEASE_33/final/ llvm
$ cd llvm/tools
$ svn checkout http://llvm.org/svn/llvm-project/cfe/tags/RELEASE_33/final/ clang
$ cd -
$ cd llvm/tools/clang/tools
$ svn checkout http://llvm.org/svn/llvm-project/clang-tools-extra/tags/RELEASE_33/final/ extra
$ cd -
```

Now, compile LLVM. If building a **debug build**, use the following command (note: the debug build is REALLY slow):

```
$ cd llvm
$ CC=gcc-4.7 CXX=g++-4.7 ./configure --disable-optimized --enable-assertions --enable-debug-symbols --enable-debug-runtime --enable-targets=x86 && REQUIRES_RTTI=1 make -j $(nproc)
$ cd -
```

If building a **release build**, use the following commands:

```
$ cd llvm
$ CC=gcc-4.7 CXX=g++-4.7 ./configure --enable-optimized --disable-assertions --enable-targets=x86 && REQUIRES_RTTI=1 make -j $(nproc)
$ cd -
```

### diStorm

[diStorm](https://code.google.com/p/distorm/) is a binary disassembler library.
It is used by some of the PANDA plugins, and may also come handy when writing your
own plugin.
The following commands will download, build and install diStorm on your system.

```
$ svn checkout http://distorm.googlecode.com/svn/trunk/ distorm
$ cd distorm/make/linux
$ make
$ sudo make install
$ cd -
$ cd distorm/include
$ sudo cp * /usr/local/include
$ cd -
```

<!--
Note: Commented because iSCSI support has been disabled in build.sh.

### libiSCSI
If you are running on Debian jessie and need iSCSI support, you will
need to download and compile libiSCSI 1.4.
This is because the (newer) version of libiSCSI that comes with Debian
jessie is not compatible with QEMU 1.x on which PANDA is based on.

```
$ git clone -b 1.4 https://github.com/sahlberg/libiscsi.git
$ cd libiscsi
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
$ cd -
```
-->

## Building the QEMU part
After successfully installing all the prerequisites, you can go on and
build the QEMU part of PANDA.
Note that if you want to use LLVM, you may need to specify the
location where your LLVM build is located at the ``--with-llvm`` option
in qemu/build.sh.

```
$ cd qemu
$ sh ./build.sh
```

Moreover, you can override the default compiler by setting the ``CC``/``CXX``
environment variables. E.g.

```
$ cd qemu
$ CC=gcc-4.8 CXX=g++-4.8 sh ./build.sh
```

