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
	echo "	  $0 <OS> <ubuntu-version> <tag-version>"
	exit 1
fi

if [[ $# -eq 2 ]]; then
	version=$2
else
	version=$(lsb_release -r | awk '{print $2}')
fi

if [[ $# -eq 3 ]]; then
	tag_version=$3
else
	tag_version='v3.1.0'
fi

# Remove leading 'v' if present, e. g. v1.5.1 -> 1.5.1
if [[ "$tag_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    tag_version=${tag_version:1}
fi

# Check if the version follows the format X.Y.Z, e. g. 1.5.1 or 1.9.1
if [[ ! "$tag_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Version must be in the format X.Y.Z, provided tag version: $tag_version"
    exit 1
fi

# Check if the given version is supported
if [[ ! -f "../dependencies/ubuntu_${version}_base.txt" ]]; then
	echo "ERROR: Ubuntu ${version} is not supported, no dependencies file found"
	exit 1
fi

# Check if HTTP_PROXY and HTTPS_PROXY are set, if not set them to blank
# You need this if you are in a proxy environment
HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

# Finish building main panda container for the target ubuntu version
DOCKER_BUILDKIT=1 docker build \
    --target whlpackager \
    -t packager \
    --build-arg HTTP_PROXY="${HTTP_PROXY}" \
    --build-arg HTTPS_PROXY="${HTTPS_PROXY}" \
    --build-arg BASE_IMAGE="ubuntu:${version}" \
    --build-arg PACKAGE_VERSION="${tag_version}" \
    ../..

# Copy deb file out of container to host
docker run --rm -v $(pwd):/out packager bash -c "cp /*.whl /pandare.deb /out"
mv pandare.deb pandare_${version}.deb