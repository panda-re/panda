# Manually building on Arch Linux

Warning this file is very out of date. PRs welcome.

## Dependencies
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

#### Building
```
export PANDA_LLVM_ROOT=/opt/llvm33
export CFLAGS=-Wno-error
./build.sh
```

