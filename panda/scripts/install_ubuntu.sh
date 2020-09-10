#!/bin/bash
# This script installs all of PANDA after first taking care of current
# dependencies. Known to work on Debian 7 install.

# some globals
PANDA_GIT="https://github.com/panda-re/panda.git"
PANDA_PPA="ppa:phulin/panda"
LIBDWARF_GIT="git://git.code.sf.net/p/libdwarf/code"
UBUNTU_FALLBACK="xenial"

# system information
vendor=$(lsb_release --id | awk -F':[\t ]+' '{print $2}')
codename=$(lsb_release --codename | awk -F':[\t ]+' '{print $2}')
version=$(lsb_release -r| awk '{print $2}' | awk -F'.' '{print $1}')
arch=$(uname -m)

progress() {
  echo
  echo -e "\e[32m[panda_install]\e[0m \e[1m$1\e[0m"
}

ppa_list_file() {
  local SOURCES_LIST_D="/etc/apt/sources.list.d"
  local PPA_OWNER=$(echo "$1" | awk -F'[:/]' '{print $2}')
  local PPA_NAME=$(echo "$1" | awk -F'[:/]' '{print $3}')
  printf "%s/%s-%s-%s-%s.list" \
    "$SOURCES_LIST_D" "$PPA_OWNER" "$(echo "$2" | tr A-Z a-z)" \
    "$PPA_NAME" "$3"
}

apt_enable_src() {
  local SOURCES_LIST="/etc/apt/sources.list"
  if grep -q "^[^#]*deb-src .* $codename .*main" "$SOURCES_LIST"; then
    progress "deb-src already enabled in $SOURCES_LIST."
    return 0
  fi
  progress "Enabling deb-src in $SOURCES_LIST."
  sudo sed -E -i 's/^([^#]*) *# *deb-src (.*)/\1 deb-src \2/' "$SOURCES_LIST"
}

# Exit on error.
set -e

apt_enable_src

progress "Installing qemu dependencies..."
sudo apt-get update || true
if [ "$version" -le "19" ]; then
  sudo apt-get -y build-dep qemu
fi

progress "Installing PANDA dependencies..."
if [ "$version" -ge "20" ]; then
  progress "Ubuntu 20 or higher"
  sudo apt-get -y install wget git protobuf-compiler protobuf-c-compiler \
    libprotobuf-c-dev libprotoc-dev python3-protobuf libelf-dev pkg-config \
    libwiretap-dev libwireshark-dev flex bison python3-pip python3 \
    libglib2.0-dev libpixman-1-dev libsdl2-dev libcurl4-gnutls-dev zip

    # Enable 16.04/xenial repos for dependencies for the LLVM 3.3 packages in ppa:phulin/panda
    sudo add-apt-repository "deb http://mirrors.kernel.org/ubuntu/ xenial main"

    # Additional LLVM 3.3 deps we have to do manually
    if [ "$arch" == "x86_64" ]; then
      is_x86=true
      libcloog_deb="libcloog-isl4_0.18.4-1_amd64.deb"
      llvm_libc_deb="libc++1_3.7.0-1_amd64.deb"
      llvm_libc_dev_deb="libc++-dev_3.7.0-1_amd64.deb"
    elif [ "$arch" == "i386" ]; then
      libcloog_deb="libcloog-isl4_0.18.4-1_i386.deb"
      llvm_libc_deb="libc++1_3.7.0-1_i386.deb"
      llvm_libc_dev_deb="libc++-dev_3.7.0-1_i386.deb"
    else
      progress "Can't do LLVM 3.3 dependecy patching on non-x86 Ubuntu 20.04 system. Proceeding without..."
    fi

    if [[ "$arch" == "x86_64" || "$arch" == "i386" ]]; then
      llvm_libc_helpers_deb="libc++-helpers_3.7.0-1_all.deb"
      wget -q -nc --show-progress http://archive.ubuntu.com/ubuntu/pool/universe/c/cloog/$libcloog_deb
      wget -q -nc --show-progress http://archive.ubuntu.com/ubuntu/pool/universe/libc/libc++/$llvm_libc_deb
      wget -q -nc --show-progress http://archive.ubuntu.com/ubuntu/pool/universe/libc/libc++/$llvm_libc_helpers_deb
      wget -q -nc --show-progress http://archive.ubuntu.com/ubuntu/pool/universe/libc/libc++/$llvm_libc_dev_deb
      sudo apt -y install ./$libcloog_deb ./$llvm_libc_deb ./$llvm_libc_helpers_deb ./$llvm_libc_dev_deb
      rm ./$libcloog_deb ./$llvm_libc_deb ./$llvm_libc_helpers_deb ./$llvm_libc_dev_deb
    fi

elif [ "$version" -eq "19" ]; then
  sudo apt-get -y install python3-pip git protobuf-compiler protobuf-c-compiler \
    libprotobuf-c-dev libprotoc-dev python3-protobuf libelf-dev libc++-dev pkg-config \
    libwiretap-dev libwireshark-dev flex bison python3-pip python3 zip
else
  sudo apt-get -y install python3-pip git protobuf-compiler protobuf-c-compiler \
    libprotobuf-c0-dev libprotoc-dev python3-protobuf libelf-dev libc++-dev pkg-config \
    libwiretap-dev libwireshark-dev flex bison python3-pip python3 zip
fi
pushd /tmp

if [ "$vendor" = "Ubuntu" ]; then
  sudo apt-get -y install software-properties-common
  panda_ppa_file=$(ppa_list_file "$PANDA_PPA" "$vendor" "$codename")
  panda_ppa_file_fallback=$(ppa_list_file "$PANDA_PPA" "$vendor" "$UBUNTU_FALLBACK")

  # add custom ppa
  case $codename in
    trusty)  ;&
    xenial)  ;&
    yakkety)
      # directly supported release
      sudo add-apt-repository -y "$PANDA_PPA"
      ;;
    *)
      # use fallback release
      sudo rm -f "$panda_ppa_file" "$panda_ppa_file_fallback"
      sudo add-apt-repository -y "$PANDA_PPA" || true
      sudo sed -i "s/$codename/$UBUNTU_FALLBACK/g" "$panda_ppa_file"
      sudo mv -f "$panda_ppa_file" "$panda_ppa_file_fallback"
      ;;
  esac

  # For Ubuntu 18.04 the vendor packages are more recent than those in the PPA
  # and will be preferred.
  sudo apt-get update
  sudo apt-get -y install libcapstone-dev libdwarf-dev chrpath
else
  if [ ! \( -e "/usr/local/lib/libdwarf.so" -o -e "/usr/lib/libdwarf.so" \) ]
  then
    git clone "$LIBDWARF_GIT" libdwarf-code
    pushd libdwarf-code
    progress "Installing libdwarf..."
    ./configure --prefix=/usr/local --includedir=/usr/local/include/libdwarf --enable-shared
    make -j$(nproc)
    sudo make install
    popd
  else
    progress "Skipping libdwarf..."
  fi

  if python3 -c 'import pycparser' 2>/dev/null
  then
    if python3 <<EOF
import sys
import pycparser
version = [int(x) for x in pycparser.__version__.split(".")]
if version[0] < 2 or (version[0] == 2 and version[1] <= 18):
  print "pycparser too old. Please upgrade it!"
  sys.exit(1)
else:
  print "pycparser version good."
  sys.exit(0)
EOF
    then
      progress "Skipping pycparser..."
    else
      progress "Your pycparser is too old. Please upgrade from pip"
      exit 1
    fi
  else
    progress "Installing pycparser..."
    sudo -H pip install pycparser
  fi
fi

# Upgrading protocol buffers python support
if [ "$version" -le "19" ]; then
  sudo pip install --upgrade protobuf
fi
progress "Trying to install LLVM 3.3..."
if ! sudo apt-get -y install llvm-3.3-dev clang-3.3
then
  progress "Couldn't find OS package for LLVM 3.3. Proceeding without..."
fi

popd

if [ -e "build.sh" ]; then
  progress "Already in PANDA directory."
elif [ -e "panda/build.sh" ]; then
  progress "Switching to PANDA directory."
  cd panda
elif ! [ -d "panda" ]; then
  progress "Cloning PANDA into $(pwd)/panda..."
  git clone "$PANDA_GIT" panda
  cd panda
else
  progress "Aborting. Can't find build.sh in $(pwd)/panda."
  exit 1
fi

progress "Trying to update DTC submodule (if necessary)..."
git submodule update --init dtc || true

if [ -d "build" ]; then
  progress "Removing build directory."
  rm -rf "build"
fi

progress "Building PANDA..."
mkdir build
cd build
if [ "$version" -eq "20" ]; then
  if [ -z "$@" ]; then
    ../build.sh "x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu --disable-werror --disable-pyperipheral3"
  else
    ../build.sh "$@"
  fi
elif [ "$version" -eq "19" ]; then
  if [ -z "$@" ]; then
    ../build.sh "x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu --disable-werror"
  else
    ../build.sh "$@"
  fi
else
../build.sh "$@"
fi
progress "PANDA is built and ready to use in panda/build/[arch]-softmmu/panda-system-[arch]."
