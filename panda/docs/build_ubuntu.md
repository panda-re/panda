# Manually building on Ubuntu 18.04

The following commands install the qemu build dependencies, the panda build dependencies, then clone and build PANDA.

```sh
sudo apt-get update
sudo apt-get build-dep qemu

# install generic dependencies
sudo apt install --no-install-recommends apt-transport-https automake bison build-essential build-essential ca-certificates chrpath clang-10 flex gcc gcc-multilib gcc-multilib genisoimage git git gnupg libaio1 libbluetooth3 libbrlapi0.6 libc++-dev libc6-dev-i386 libcacard0 libcap-ng0 libcapstone-dev libcapstone3 libcurl3-gnutls libdwarf-dev libdwarf1 libelf-dev libelf1 libfdt1 libffi-dev libglib2.0-0 libgnutls30 libiscsi7 libjpeg-turbo8 libjpeg8 libllvm10 libnettle6 libnuma1 libpixman-1-0 libpng16-16 libprotobuf-c0-dev libprotobuf-c1 libprotobuf10 libprotoc-dev libpython3-dev librados2 librbd1 librdmacm1 libsasl2-2 libsasl2-modules-db libsdl1.2debian libspice-server1 libtool-bin libusb-1.0-0 libusbredirparser1 libwireshark-dev libwiretap-dev libwiretap8 libxen-4.9 libxenstore3.0 llvm-10-dev lsb-core nasm nasm pkg-config protobuf-c-compiler protobuf-compiler python3 python3-dev python3-pip python3-pip software-properties-common wget zip

# clone and build PANDA
git clone https://github.com/panda-re/panda
cd panda
mkdir -p build && cd build
../build.sh

# Pypanda dependencies
pip3 install pycparser "protobuf==3.0.0" "https://foss.heptapod.net/pypy/cffi/-/archive/branch/default/cffi-branch-default.zip" colorama


# Install pypanda
cd ../panda/python/core
python3 setup.py install
```
