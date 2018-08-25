#!/bin/bash


# This script installs all of PANDA after first taking care of current dependencies. 
# Known to work on Arch Linux (Manjaro) 4.17.5-1-MANJARO

progress() {
  echo
  echo -e "\e[32m[panda_install]\e[0m \e[1m$1\e[0m"
}

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


check_libcxx () {
	printf "#include <ciso646>\nint main () {}" | clang -E -stdlib=libc++ -x c++ -dM - | grep _LIBCPP_VERSION
}



check_llvm () {
	/opt/llvm33/bin/llc --version | grep "LLVM version 3\.3"
}

check_protobuf2 () {
	pkg-config --modversion protobuf | grep 2\.[[:digit:]]\\+\.[[:digit:]]\\+
}

check_protobufc () {
	pkg-config --modversion libprotobuf-c | grep [[:digit:]]\.[[:digit:]]\\+\.[[:digit:]]\\+
}

check_wireshark () {
	pkg-config --modversion wireshark | grep 2\.4\.4
}


# Exit on error.
set -e

progress "Installing PANDA dependencies..."


if check_libcxx; then
    echo "Libc++ is already installed"
else
    progress "Installing PANDA dependencies...libc++"
    gpg --receive-keys A2C794A986419D8A #
    aur_install_pkg "libc++"
fi


if check_llvm; then
    echo "LLVM33 is already installed"
else
    progress "Installing PANDA dependencies...llvm33"
    aur_install_pkg "llvm33"
fi

if check_protobuf2; then
    echo "libprotobuf2 is already installed"
else
	progress "Installing PANDA dependencies...libprotobuf2"
	aur_install_pkg "libprotobuf2"
fi


if check_protobufc; then
    echo "protobuf-c is already installed"
else

	progress "Installing PANDA dependencies...protobuf-c"

	cd /tmp
	git clone https://github.com/protobuf-c/protobuf-c.git protobuf-c
	cd protobuf-c
	./autogen.sh
	./configure --prefix=/usr
	make
	sudo make install

fi


if check_wireshark; then
    echo "wireshark 2.4.4 is already installed"
else
	# We need to use an older version of wireshark, since 2.5.1 breaks the network plugin
	sudo pacman -U https://archive.archlinux.org/packages/w/wireshark-common/wireshark-common-2.4.4-1-x86_64.pkg.tar.xz
	sudo pacman -U https://archive.archlinux.org/packages/w/wireshark-cli/wireshark-cli-2.4.4-1-x86_64.pkg.tar.xz
fi


sudo pacman -S libelf dtc capstone libdwarf python2-pycparser




progress "Building PANDA..."


mkdir build || true
cd build

export PANDA_LLVM_ROOT=/opt/llvm33
export CFLAGS=-Wno-error

../build.sh "$@"
