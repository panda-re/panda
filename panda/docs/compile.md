# Compiling PANDA

PANDA depends on LLVM-10, python3, and the qemu dependencies.
It is known to build on Ubuntu 18.04 and the Dockerfile in the root directory
will produce a container with panda and it's python interface setup.

## Compiled prerequisites

### libdwarf

[libdwarf](https://www.prevanders.net/dwarf.html) is a DWARF
producer and consumer. It is used by `dwarfp` in order to
provide source level introspection to PANDA plugins.

```sh
wget http://www.prevanders.net/libdwarf-20160507.tar.gz --no-check-certificate
tar -xzvf libdwarf-20151114.tar.gz
cd dwarf-20160507
progress "Installing libdwarf..."
./configure --enable-shared
make
sudo mkdir -p /usr/local/include/libdwarf
sudo cp libdwarf/libdwarf.h /usr/local/include/libdwarf
sudo cp libdwarf/dwarf.h /usr/local/include/libdwarf
sudo cp libdwarf/libdwarf.so /usr/local/lib/
cd ../
```

### Pycparser

The new version of PPP, which permits api functions that have fn pointers as arguments,
uses a c parser written in python: [pycparser](https://github.com/eliben/pycparser).
You can directly install pycparser using [pip](https://pip.pypa.io/):

```sh
sudo pip install git+https://github.com/eliben/pycparser.git@master
```

<!--
Manual installation is also possible:

```
cd ~/software
git clone https://github.com/eliben/pycparser.git
cd pycparser
sudo python setup.py install
```

-->
