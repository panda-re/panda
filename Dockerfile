FROM ubuntu:18.04
# Base packages required before we do anything else
RUN apt-get update && apt install -y lsb-core

# apt_enable_src: Enable src repos
ENV SOURCES_LIST="/etc/apt/sources.list"
RUN if grep -q "^[^#]*deb-src .* $codename .*main" "$SOURCES_LIST"; then \
       echo "deb-src already enabled in $SOURCES_LIST."; \
   else \
       echo "Enabling deb-src in $SOURCES_LIST."; \
       sed -E -i 's/^([^#]*) *# *deb-src (.*)/\1deb-src \2/' "$SOURCES_LIST"; \
   fi

# Install QEMU build-deps, plus panda dependencies
RUN apt update && apt-get -y build-dep qemu && \
    apt -y install git protobuf-compiler protobuf-c-compiler \
    libprotobuf-c0-dev libprotoc-dev python3-protobuf libelf-dev libc++-dev pkg-config \
    libwiretap-dev libwireshark-dev flex bison python3-pip python3 software-properties-common \
    chrpath zip libcapstone-dev libdwarf-dev llvm-10 clang-10

# PYPANDA Dependencies
RUN apt-get install -y genisoimage wget libc6-dev-i386 gcc-multilib nasm libffi-dev
RUN pip3 install colorama 'protobuf==3.0.0' # Protobuf version should match system (apt) version
# Need cffi with patch for issue #478
RUN pip3 install https://foss.heptapod.net/pypy/cffi/-/archive/branch/default/cffi-branch-default.zip

# Core PANDA python3 dependencies to install via pip
RUN pip3 install --upgrade protobuf # Upgrade because it's already installed with apt
RUN pip3 install pycparser

# There's no python2 in this container - make python->python3 for convenience
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10

# Copy repo root directory to /panda, note we explicitly copy in .git directory
# Note .dockerignore file keeps us from copying everything
COPY . /panda/
COPY .git /panda/
WORKDIR "/panda"

# Update submodules
RUN git submodule init && git submodule update --recursive

# Build all targets (simplified logic from build.sh)
RUN mkdir /panda/build
WORKDIR "/panda/build"
ENV TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu"
RUN rm -f ./qemu-options.def

# NUMA disabled in docker because I can't get it to work in the container
# If we extend this to build to produce binaries to run outside of docker, we should
# re-enable (or make another build) with numa
RUN ../configure \
    --target-list=$TARGET_LIST \
    --prefix=/ \
    --enable-llvm \
    --disable-numa \
    --with-llvm=/usr/lib/llvm-10 \
    --disable-vhost-net \
    --extra-cflags=-DXC_WANT_COMPAT_DEVICEMODEL_API

RUN make -j

RUN make install

# Install pypanda
WORKDIR "/panda/panda/python/core"
RUN python3 setup.py install

WORKDIR "/panda"
