#!/bin/bash


# This script installs all of PANDA after first taking care of current dependencies. 
# Known to work on Arch Linux (Manjaro) 4.17.5-1-MANJARO

progress() {
  echo
  echo -e "\e[32m[panda_install]\e[0m \e[1m$1\e[0m"
}

aur_install_pkg () {
	local FNAME=$1
	wget -O /tmp/$FNAME https://aur.archlinux.org/cgit/aur.git/snapshot/$FNAME.tar.gz
	cd /tmp
	tar -xvf $FNAME.tar.gz
	cd /tmp/$FNAME
	makepkg -s
	makepkg --install
}

# Exit on error.
set -e

progress "Installing PANDA dependencies..."

gpg --receive-keys A2C794A986419D8A #

progress "Installing PANDA dependencies...libc++"
aur_install_pkg "libc++"
progress "Installing PANDA dependencies...llvm33"
aur_install_pkg "llvm33"
progress "Installing PANDA dependencies...libprotobuf2"
aur_install_pkg "libprotobuf2"

progress "Installing PANDA dependencies...protobuf-c"

cd /tmp
git clone https://github.com/protobuf-c/protobuf-c.git protobuf-c
cd protobuf-c
./autogen.sh
./configure --prefix=/usr
make
sudo make install

progress "Building PANDA..."


mkdir build
cd build

export PANDA_LLVM_ROOT=/opt/llvm33
export CFLAGS=-Wno-error

../build.sh "$@"
