ARG BASE_IMAGE="ubuntu:20.04"
ARG TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu"
ARG PROTOBUF_VER="3.0.0"
ARG CFFI_PIP="https://foss.heptapod.net/pypy/cffi/-/archive/branch/default/cffi-branch-default.zip"

### BASE IMAGE
FROM $BASE_IMAGE as base
ARG TOOLCHAIN_R_KEY
ARG TOOLCHAIN_R_PPA


# Note nasm, gcc-multilib and libc6-dev-i386 are only necessary for pypanda tests
# Base image just needs runtime dependencies
RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
      gcc-multilib \
      genisoimage \
      git \
      libc6-dev-i386 \
      libcurl4-gnutls-dev \
      libelf-dev \
      libglib2.0-dev \
      libllvm10 \
      libpixman-1-dev \
      libsdl2-dev \
      libwireshark-dev \
      libwiretap-dev \
      pkg-config \
      protobuf-c-compiler \
      protobuf-compiler \
      python3 \
      python3-pip \
      python3-protobuf \
      wget \
      zip \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*


### BUILD IMAGE - STAGE 2
FROM base AS builder
ARG TARGET_LIST
ARG PROTOBUF_VER
ARG CFFI_PIP

RUN sed -i 's/# deb-src /deb-src /g' /etc/apt/sources.list && \
    apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq build-dep -y qemu && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
      automake \
      bison \
      build-essential \
      chrpath \
      clang-10 \
      flex \
      gcc-multilib \
      git \
      libc++-dev \
      libcapstone-dev \
      libdwarf-dev \
      libelf-dev \
      libprotobuf-c-dev \
      libprotoc-dev \
      libpython3-dev \
      libtool-bin \
      libwireshark-dev \
      libwiretap-dev \
      llvm-10-dev \
      lsb-core \
      nasm \
      pkg-config \
      protobuf-c-compiler \
      protobuf-compiler \
      python3 \
      python3-dev \
      python3-pip \
      software-properties-common \
      zip \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m pip install --upgrade --no-cache-dir pip && \
    python3 -m pip install --upgrade --no-cache-dir setuptools wheel && \
    python3 -m pip install --upgrade --no-cache-dir pycparser "protobuf==${PROTOBUF_VER}" "${CFFI_PIP}" colorama

# Build and install panda
# Copy repo root directory to /panda, note we explicitly copy in .git directory
# Note .dockerignore file keeps us from copying things we don't need
COPY . /panda/
COPY .git /panda/

RUN git -C /panda submodule update --init dtc && \
    git -C /panda rev-parse HEAD > /usr/local/panda_commit_hash && \
    mkdir  /panda/build && cd /panda/build && \
    /panda/configure \
        --target-list="${TARGET_LIST}" \
        --prefix=/usr/local \
        --enable-llvm && \
    make -C /panda/build -j "$(nproc)"

#### Develop setup: panda built + pypanda installed - Stage 3
FROM builder as developer
RUN cd /panda/panda/python/core && \
    python3 setup.py develop

#### Install PANDA + pypanda from builder - Stage 4
FROM builder as installer
RUN  make -C /panda/build install
# Install pypanda
RUN cd /panda/panda/python/core && \
    python3 setup.py install

### Copy files for panda+pypanda from installer  - Stage 5
FROM base as panda

COPY --from=installer /usr/local /usr/local

RUN ldconfig && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 10
