#!/bin/bash
# This script installs dependencies then builds panda.
# Note that it doesn't actually *install* panda, it just install dependencies and *builds* panda.
# If you want to install run `make install` in the build directory after this runs

set -ex

# Tested for architectures listed in panda/panda/dependencies/

if grep -q Ubuntu /etc/issue; then
  echo "Ubuntu detected";
else
  echo "ERROR: This script only supports Ubuntu";
  exit 1
fi

sudo=""
if [ $EUID -ne 0 ]; then
  SUDO=sudo
fi

# Install lsb_release and git before anything else if either are missing
# Note package names should be consistent across Ubuntu versions.
lsb_release --help &>/dev/null || $SUDO apt-get update -qq && $SUDO apt-get -qq install -y --no-install-recommends lsb-release
git --help &>/dev/null || $SUDO apt-get -qq update && $SUDO apt-get -qq install -y --no-install-recommends git

# some globals
LIBOSI_VERSION="0.1.7"
UBUNTU_VERSION=$(lsb_release -r | awk '{print $2}')
CAPSTONE_VERSION="5.0.5"
PANDA_GIT="https://github.com/panda-re/panda.git"

# system information
#vendor=$(lsb_release --id | awk -F':[\t ]+' '{print $2}')
#codename=$(lsb_release --codename | awk -F':[\t ]+' '{print $2}')
version=$(lsb_release -r | awk '{print $2}' | awk -F'.' '{print $1}')

progress() {
  echo
  echo -e "\e[32m[panda_install]\e[0m \e[1m$1\e[0m"
}

# Exit on error.
set -e

# If this script is run from foo/panda/panda/scripts/install_ubuntu.sh
# we want to check in foo
possible_root=$(dirname $(dirname $(dirname $0)))

# Get panda (if necessary) and cd into panda directory
if [ -e "build.sh" ]; then
  progress "Already in PANDA directory."
elif [ -e "panda/build.sh" ]; then
  progress "Switching to PANDA directory at ./panda."
  cd panda
elif [ -e "$possible_root/build.sh" ]; then
  progress "Switching to PANDA directory at $possible_root."
  cd $possible_root
elif ! [ -d "panda" ]; then
  progress "Cloning PANDA into $(pwd)/panda..."
  git clone "$PANDA_GIT" panda
  cd panda
else
  progress "Aborting. Can't find build.sh in $(pwd)/panda."
  exit 1
fi

progress "Installing PANDA dependencies..." 
# Read file in dependencies directory and install those. If no dependency file present, error
$SUDO apt-get update


# Dependencies are for a major version, but the filenames include minor versions
# So take our major version, find the first match in dependencies directory and run with it.
# This will give us "./panda/dependencies/ubuntu:20.04" where ubuntu:20.04_build.txt or 20.04_base.txt exists
dep_base=$(find ./panda/dependencies/ubuntu_${version}.* -print -quit | sed  -e "s/_build\.txt\|_base\.txt//")

if [ -e ${dep_base}_build.txt ] || [ -e ${dep_base}_base.txt ]; then
  echo "Found dependency file(s) at ${dep_base}*.txt"
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get -y install --no-install-recommends $(cat ${dep_base}*.txt | grep -o '^[^#]*')  
else
  echo "Unsupported Ubuntu version: $version. Create a list of build dependencies in ${dep_base}_{base,build}.txt and try again."
  exit 1
fi

progress "Installing Rust..."
curl https://sh.rustup.rs -sSf | sh -s -- -y

# Expose cargo to the running shell/env
. $HOME/.cargo/env

# Install libcapstone v5 release if it's not present
if [[ !$(ldconfig -p | grep -q libcapstone.so.5) ]]; then
  echo "Installing libcapstone v5"
  pushd /tmp
  curl -LJO https://github.com/capstone-engine/capstone/releases/download/${CAPSTONE_VERSION}/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb
  if ! $SUDO dpkg -i /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb; then
    echo "dpkg failed, attempting to fix missing dependencies with apt-get install -f"
    $SUDO apt-get install -f -y
    # Try installing again after fixing dependencies
    if ! $SUDO dpkg -i /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb; then
      echo "ERROR: Failed to install libcapstone after fixing dependencies."
      popd
      exit 1
    fi
  fi
  rm -rf /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb
  popd
fi

# if the windows introspection library is not installed, clone and install
if [[ !$(dpkg -l | grep -q libosi) ]]; then
  pushd /tmp
  curl -LJO https://github.com/panda-re/libosi/releases/download/v${LIBOSI_VERSION}/libosi_${UBUNTU_VERSION}.deb 
  $SUDO dpkg -i /tmp/libosi_${UBUNTU_VERSION}.deb
  rm -rf /tmp/libosi_${UBUNTU_VERSION}.deb
  popd
fi

progress "Trying to update DTC submodule"
git submodule update --init dtc || true

if [ -d "build" ]; then
  progress "Removing build directory."
  rm -rf "build"
fi

progress "Building PANDA..."
mkdir build
pushd build
../build.sh "$@"
./i386-softmmu/panda-system-i386 --version | head # Make sure it worked
progress "PANDA is built and ready to use in panda/build/[arch]-softmmu/panda-system-[arch]."

cd ../panda/python/core
python3 create_panda_datatypes.py --install

# Ubuntu 24 gets most upset if you try to install PyPANDA to the system
# might as well do Ubuntu 22 in a virtual environment too, to be consistent
cd ../../../../
virtualenv pypanda_env
. ./pypanda_env/bin/activate
cd panda/panda/python/core
pip install -e .
python3 -c "import pandare; panda = pandare.Panda(generic='i386')" # Make sure it worked
progress "Pypanda successfully installed"
deactivate
popd
