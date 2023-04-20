ARG BASE_IMAGE="ubuntu:20.04"
# Note PANDA supports ubuntu:22.04, but docker versions <= 20.10.7 can't run 22.04 containers

ARG TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu,aarch64-softmmu"

### BASE IMAGE
FROM $BASE_IMAGE as base
ARG BASE_IMAGE

# Copy dependencies lists into container. Note this
#  will rarely change so caching should still work well
COPY ./panda/dependencies/${BASE_IMAGE}*.txt /tmp/ 

# Base image just needs runtime dependencies
RUN [ -e /tmp/${BASE_IMAGE}_base.txt ] && \
    apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends curl $(cat /tmp/${BASE_IMAGE}_base.txt | grep -o '^[^#]*') && \
    apt-get clean

### BUILD IMAGE - STAGE 2
FROM base AS builder
ARG BASE_IMAGE
ARG TARGET_LIST

RUN [ -e /tmp/${BASE_IMAGE}_build.txt ] && \
    apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $(cat /tmp/${BASE_IMAGE}_build.txt | grep -o '^[^#]*') && \
    apt-get clean && \
    python3 -m pip install --upgrade --no-cache-dir pip && \
    python3 -m pip install --upgrade --no-cache-dir "cffi>1.14.3" && \
    python3 -m pip install --upgrade --no-cache-dir "capstone" && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal

# Then install capstone from source
RUN cd /tmp && \
    git clone https://github.com/capstone-engine/capstone/ -b 4.0.2 && \
    cd capstone/ && ./make.sh && make install && cd /tmp && \
    rm -rf /tmp/capstone && ldconfig

ENV PATH="/root/.cargo/bin:${PATH}"

# Sanity check to ensure cargo is installed
RUN cargo --help

# install libosi
RUN cd /tmp && \
    git clone https://github.com/panda-re/libosi && \
    mkdir /tmp/libosi/build && cd /tmp/libosi/build && \
    cmake -GNinja .. && ninja && ninja package && dpkg -i libosi*.deb && \
    cd /tmp && rm -rf libosi/ && ldconfig 

# Build and install panda
# Copy repo root directory to /panda, note we explicitly copy in .git directory
# Note .dockerignore file keeps us from copying things we don't need
COPY . /panda/
COPY .git /panda/

# Note we diable NUMA for docker builds because it causes make check to fail in docker
RUN git -C /panda submodule update --init dtc && \
    git -C /panda rev-parse HEAD > /usr/local/panda_commit_hash && \
    mkdir  /panda/build && cd /panda/build && \
    /panda/configure \
        --target-list="${TARGET_LIST}" \
        --prefix=/usr/local \
        --disable-numa \
        --enable-llvm && \
    make -C /panda/build -j "$(nproc)"

#### Develop setup: panda built + pypanda installed (in develop mode) - Stage 3
FROM builder as developer
RUN cd /panda/panda/python/core && \
    python3 setup.py develop && \
    ldconfig && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 10
WORKDIR /panda/

#### Install PANDA + pypanda from builder - Stage 4
FROM builder as installer
RUN  make -C /panda/build install
# Install pypanda
RUN cd /panda/panda/python/core && \
    python3 setup.py install
RUN python3 -m pip install --ignore-install pycparser && python3 -m pip install --force-reinstall --no-binary :all: cffi

# BUG: PANDA sometimes fails to generate all the necessary files for PyPANDA. This is a temporary fix to detect and fail when this occurs
RUN ls -alt $(pip show pandare | grep Location: | awk '{print $2}')/pandare/autogen/
RUN bash -c "ls $(pip show pandare | grep Location: | awk '{print $2}')/pandare/autogen/panda_{aarch64_64,arm_32,mips64_64,mips_32,mipsel_32,ppc_32,ppc_64,x86_64_64,i386_32}.py"

### Copy files for panda+pypanda from installer  - Stage 5
FROM base as panda

# Copy panda + libcapstone.so* + libosi libraries
COPY --from=installer /usr/local /usr/local
COPY --from=installer /usr/lib/libcapstone* /usr/lib/
COPY --from=installer /lib/libosi.so /lib/libiohal.so /lib/liboffset.so /lib/

# Workaround issue #901 - ensure LD_LIBRARY_PATH contains the panda plugins directories
#ARG TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu"
ENV LD_LIBRARY_PATH /usr/local/lib/python3.8/dist-packages/pandare/data/x86_64-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/i386-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/arm-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/ppc-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/mips-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/mipsel-softmmu/panda/plugins/
#PANDA_PATH is used by rust plugins
ENV PANDA_PATH /usr/local/lib/python3.8/dist-packages/pandare/data


# Ensure runtime dependencies are installed for our libpanda objects and panda plugins
RUN ldconfig && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 10 && \
    if (ldd /usr/local/lib/python*/dist-packages/pandare/data/*-softmmu/libpanda-*.so | grep 'not found'); then exit 1; fi && \
    if (ldd /usr/local/lib/python*/dist-packages/pandare/data/*-softmmu/panda/plugins/*.so | grep 'not found'); then exit 1; fi
