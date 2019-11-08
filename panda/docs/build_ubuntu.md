# Manually building on Ubuntu Linux

You can can manually add the Ubuntu PPA we have created at `ppa:phulin/panda`
and use the following commands to build PANDA without using the Ubuntu
installation script.

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

