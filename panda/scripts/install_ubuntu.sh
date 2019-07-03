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

# Exit on error.
set -e

progress "Installing qemu dependencies..."
sudo apt-get update || true
sudo apt-get -y build-dep qemu

progress "Installing PANDA dependencies..."
sudo apt-get -y install python-pip git protobuf-compiler protobuf-c-compiler \
  libprotobuf-c0-dev libprotoc-dev python-protobuf libelf-dev libc++-dev pkg-config \
  libwiretap-dev libwireshark-dev

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
  sudo apt-get -y install libcapstone-dev libdwarf-dev python-pycparser
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

  if python -c 'import pycparser' 2>/dev/null
  then
    if python <<EOF
import sys
import pycparser
version = [int(x) for x in pycparser.__version__.split(".")]
if version[0] < 2 or (version[0] == 2 and version[1] < 10):
  print "pycparser too old. Please upgrade it!"
  sys.exit(1)
else:
  print "pycparser version good."
  sys.exit(0)
EOF
    then
      progress "Skipping pycparser..."
    else
      progress "Your pycparser is too old. Please upgrade using your method of choice."
      exit 1
    fi
  else
    progress "Installing pycparser..."
    sudo -H pip install pycparser
  fi
fi

# Install libclang for apigen.py
# sudo apt-get -y install libclang-3.8 python-clang-3.8

# Upgrading protocol buffers python support
sudo pip install --upgrade protobuf

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
../build.sh "$@"

progress "PANDA is built and ready to use in panda/build/[arch]-softmmu/qemu-system-[arch]."
