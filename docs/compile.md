# Compiling PANDA
In order to build PANDA, you should use the `build.sh` script
in the QEMU directory. The script comes with some default
options. But first, the prerequisites need to be taken care of.
It is recommended to build LLVM and QEMU with the same compiler.
In order to build some of the PANDA plugins inside of the QEMU
directory, a compiler that supports C++11 is required.

PANDA is known to build on debian wheezy and jessie with the
following steps.
Some parts of the installation require root privileges. We assume
that sudo has been setup and enabled for the user installing
PANDA.
If you prefer to have these instructions printed, you can 
use [gitprint](https://gitprint.com/) to render them into
a printable PDF file.

## Prepackaged prerequisites
Use the following commands to install the prerequisites that can
be used as-is from the Debian repositories.
Some of the prerequisite libraries are not directly used by
PANDA, but are required by the plugins shipping with it.
Subversion is used to retrieve the source of LLVM.

```
sudo apt-get install build-essential 
sudo apt-get build-dep qemu
sudo apt-get install nasm
sudo apt-get install libssl-dev
sudo apt-get install libpacap-dev
sudo apt-get install subversion
sudo apt-get -y install curl
sudo apt-get -y install autoconf
sudo apt-get -y install libtool

```

## Compiled prerequisites

### LLVM
Download the source for LLVM 3.3 and Clang 3.3. **Make sure you
get these specific versions!** Clang source must be extracted in
directory `tools/clang` directory of the LLVM source tree.
The required source trees can be directly checked out from the
[LLVM subversion repositories](http://llvm.org/svn/llvm-project/).

```
cd panda
svn checkout http://llvm.org/svn/llvm-project/llvm/tags/RELEASE_33/final/ llvm
cd llvm/tools
svn checkout http://llvm.org/svn/llvm-project/cfe/tags/RELEASE_33/final/ clang
cd -
cd llvm/tools/clang/tools
svn checkout http://llvm.org/svn/llvm-project/clang-tools-extra/tags/RELEASE_33/final/ extra
cd -
```

Now, compile LLVM. For a **debug build** (REALLY slow), use the following command:

```
cd llvm
CC=gcc-4.7 CXX=g++-4.7 ./configure --disable-optimized --enable-assertions --enable-debug-symbols --enable-debug-runtime --enable-targets=x86 && REQUIRES_RTTI=1 make -j $(nproc)
$ cd -
```

For a **release build**, use the following commands:

```
cd llvm
CC=gcc-4.7 CXX=g++-4.7 ./configure --enable-optimized --disable-assertions --enable-targets=x86 && REQUIRES_RTTI=1 make -j $(nproc)
cd -
```

### diStorm
[diStorm](https://code.google.com/p/distorm/) is a binary
disassembler library. It is used by some of the PANDA plugins,
and may also come handy when writing your own plugins.
The following commands will download, build and install diStorm
on your system.

```
svn checkout http://distorm.googlecode.com/svn/trunk/ distorm
cd distorm/make/linux
make
sudo make install
cd -
cd distorm/include
sudo cp * /usr/local/include
cd -
```

### Protocol buffers C style

Protocol buffers are used by pandalog.  You want it.
This is how I built things and installed them.

```
cd ~/software
git clone https://github.com/google/protobuf.git
cd protobuf
sh ./autogen.sh
./configure --disable-shared
make
make install

cd ~/software
git clone https://github.com/protobuf-c/protobuf-c.git
cd protobuf-c
sh ./autogen.sh
./configure --disable-shared
make
make install
```

### Pycparser

The new version of PPP, which permits api functions that have fn pointers as arguments,
uses a c parser written in python: pycparser.

```
cd ~/software
git clone https://github.com/eliben/pycparser.git
cd pycparser
sudo python setup.py install
```


## Building the QEMU part
After successfully installing all the prerequisites, you can go
on and build the QEMU part of PANDA.

Before launching the `build.sh` script, make sure you have
updated it to reflect the location of your LLVM build.
You should pass `--with-llvm=../llvm/Debug+Asserts` or
`--with-llvm=../llvm/Release` to the configure script, depending
on which LLVM build you compiled earlier.


```
$ cd qemu
$ ./build.sh
```

By default `gcc-4.7` and `g++-4.7` will be used for the
compilation. The `build.sh` script respects the ``CC``/``CXX``
environment variables in case you want to use a different
compiler. E.g.

```
$ cd qemu
$ CC=gcc-4.8 CXX=g++-4.8 ./build.sh
```


