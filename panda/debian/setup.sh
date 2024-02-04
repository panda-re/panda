#!/bin/bash
set -eu

# Function to get the current Ubuntu version
get_ubuntu_version() {
    lsb_release -i -s 2>/dev/null
}

if [[ $# -eq 0 ]]; then
	# No argument given, try building a package for current Ubuntu version

	# Check if we're running Ubuntu, exit otherwise
	OS=$(get_ubuntu_version)
else
	OS=$1
fi

if [[ $(get_ubuntu_version) != "Ubuntu" ]]; then
	echo "ERROR: OS of $OS is not Ubuntu and unsupported"
	exit 1
fi

if [[ $# -eq 1 ]]; then
	echo "USAGE:"
	echo "	To build a package for current Ubuntu version:"
	echo "	  $0"
	echo "	To build a package for a specific OS/version (only Ubuntu supported for now):"
	echo "	  $0 <OS> <version>"
	exit 1
fi

if [[ $# -eq 2 ]]; then
	version=$2

else
	version=$(lsb_release -r | awk '{print $2}')
fi

# Check if the given version is supported
if [[ ! -f "../dependencies/ubuntu_${version}_base.txt" ]]; then
	echo "ERROR: Ubuntu ${version} is not supported, no dependencies file found"
	exit 1
fi

# First build main panda container for the target ubuntu version
DOCKER_BUILDKIT=1 docker build --target panda -t panda --build-arg BASE_IMAGE="ubuntu:${version}" ../..

# Also build the installer, since that's where the whl file is built
DOCKER_BUILDKIT=1 docker build --target installer -t panda_installer --build-arg BASE_IMAGE="ubuntu:${version}" ../..

# Now build the packager container from that
docker build -t packager .

# Copy deb file out of container to host
docker run --rm -v $(pwd):/out packager bash -c "cp /pandare.deb /out"

# Copy whl file out of container to host, this also preserves wheel name, which is important as pip install WILL fail if you arbitarily change the generated wheel file name
docker run --rm -v $(pwd):/out panda_installer bash -c "cp /panda/panda/python/core/dist/*.whl /out"
