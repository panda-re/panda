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
    chrpath zip libcapstone-dev libdwarf-dev
# TODO: for llvm10 upgrade add llvm-10 clang-10 to the above list

# PYPANDA Dependencies
RUN apt-get install -y genisoimage wget libc6-dev-i386 gcc-multilib nasm
RUN pip3 install colorama cffi 'protobuf==3.0.0' # Protobuf version should match system (apt) version

# Core PANDA python3 dependencies to install via pip
RUN pip3 install --upgrade protobuf # Upgrade because it's already installed with apt
RUN pip3 install pycparser

# There's no python2 in this container - make python->python3 for convenience
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10


###### LLVM 3.3 TODO: remove when upgrading to LLVM10 ####
# Setup apt sources of llvm 3.3
ENV panda_ppa_file=/etc/apt/sources.list.d/phulin-ubuntu-panda-bionic.list
ENV panda_ppa_file_fallback=/etc/apt/sources.list.d/phulin-ubuntu-panda-xenial.list
ENV PANDA_PPA="ppa:phulin/panda"
ENV PANDA_GIT="https://github.com/panda-re/panda.git"
ENV PANDA_PPA="ppa:phulin/panda"
ENV LIBDWARF_GIT="git://git.code.sf.net/p/libdwarf/code"
ENV UBUNTU_FALLBACK="xenial"
ENV codename="bionic"

# We're on bionic so just add the PPA
RUN rm -f "$panda_ppa_file" "$panda_ppa_file_fallback"
RUN add-apt-repository -y "$PANDA_PPA" || true
RUN sed -i "s/$codename/$UBUNTU_FALLBACK/g" "$panda_ppa_file"
RUN mv -f "$panda_ppa_file" "$panda_ppa_file_fallback"

# Update so we can see the new PPA
RUN apt-get update

# Install LLVM 3.3...
RUN apt-get -y install llvm-3.3-dev clang-3.3
###### End of LLVM 3.3 logic ####

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
# TODO: update llvm-3.3 to llvm-10 for imminent upgrade in this command
RUN ../configure \
    --target-list=$TARGET_LIST \
    --prefix=/ \
    --enable-llvm \
    --disable-numa \
    --with-llvm=/usr/lib/llvm-3.3 \
    --disable-vhost-net \
    --extra-cflags=-DXC_WANT_COMPAT_DEVICEMODEL_API

RUN make -j

RUN make install

# Install pypanda
WORKDIR "/panda/panda/python/core"
RUN python3 setup.py install

WORKDIR "/panda"
