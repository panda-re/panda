ARG BASE_IMAGE="ubuntu:22.04"
ARG TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,aarch64-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu,mips64-softmmu,mips64el-softmmu"
ARG INSTALL_PREFIX="/usr/local/"

### BASE IMAGE
FROM $BASE_IMAGE AS base
ARG BASE_IMAGE
ARG INSTALL_PREFIX

# Copy dependencies lists into container. We copy them all and then do a mv because
# we need to transform base_image into a windows compatible filename which we can't
# do in a COPY command.
COPY ./panda/dependencies/* /tmp
RUN mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_build.txt /tmp/build_dep.txt && \
    mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_base.txt /tmp/base_dep.txt

# Base image just needs runtime dependencies
RUN [ -e /tmp/base_dep.txt ] && \
    apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends curl jq $(cat /tmp/base_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

### BUILD IMAGE - STAGE 2
FROM base AS builder
ARG BASE_IMAGE
ARG TARGET_LIST
ARG INSTALL_PREFIX

RUN [ -e /tmp/build_dep.txt ] && \
    apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $(cat /tmp/build_dep.txt | grep -o '^[^#]*') && \
    apt-get clean && \
    python3 -m pip install --upgrade --no-cache-dir pip && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal

# Then install capstone from source
RUN cd /tmp && \
    git clone https://github.com/capstone-engine/capstone/ -b v5 && \
    cd capstone/ && ./make.sh && make install && cd /tmp && \
    rm -rf /tmp/capstone && ldconfig

ENV PATH="/root/.cargo/bin:${PATH}"

# install libosi
RUN cd /tmp && \
    BASE_IMAGE_VERSION=$(echo "$BASE_IMAGE" | awk -F':' '{print $2}') && \
    LIBOSI_VERSION=$(curl -s https://api.github.com/repos/panda-re/libosi/releases/latest | jq -r .tag_name) && \
    curl -LJO https://github.com/panda-re/libosi/releases/download/${LIBOSI_VERSION}/libosi_${BASE_IMAGE_VERSION}.deb && \
    dpkg -i /tmp/libosi_${BASE_IMAGE_VERSION}.deb && \
    rm -rf /tmp/libosi_${BASE_IMAGE_VERSION}.deb

# Build and install panda
# Copy repo root directory to /panda, note we explicitly copy in .git directory
# Note .dockerignore file keeps us from copying things we don't need
# PyPANDA needs CFFI from pip (the version in apt is too old)
COPY . /panda/
COPY .git /panda/
RUN pip install -r /panda/panda/python/core/requirements.txt

# Note we diable NUMA for docker builds because it causes make check to fail in docker
RUN git -C /panda submodule update --init dtc && \
    git -C /panda rev-parse HEAD > ${INSTALL_PREFIX}panda_commit_hash && \
    mkdir  /panda/build && cd /panda/build && \
    python3 -m pip install setuptools_scm && \
    python3 -m pip install build && \
    python3 -m setuptools_scm -r .. --strip-dev 2>/dev/null >/tmp/savedversion && \
    /panda/configure \
        --target-list="${TARGET_LIST}" \
        --prefix=${INSTALL_PREFIX} \
        --disable-numa \
        --enable-llvm && \
    rm -rf /panda/.git

RUN PRETEND_VERSION=$(cat /tmp/savedversion) make -C /panda/build -j "$(nproc)"

#### Develop setup: panda built + pypanda installed (in develop mode) - Stage 3
FROM builder AS developer
ARG INSTALL_PREFIX
RUN cd /panda/panda/python/core && \
    python3 create_panda_datatypes.py && \
    PRETEND_VERSION=$(cat /tmp/savedversion) pip install -e . && \
    ldconfig && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 10 && \
    cd /panda && \
    ( git config --get-regexp http > /dev/null && \
    git config --remove-section http.https://github.com/ || true ) && \
    git remote set-url origin https://github.com/panda-re/panda
WORKDIR /panda/

#### Install PANDA + pypanda from builder - Stage 4
FROM builder AS installer
ARG INSTALL_PREFIX
RUN  make -C /panda/build install && \
    rm -r ${INSTALL_PREFIX}lib/panda/*/cosi \
        ${INSTALL_PREFIX}lib/panda/*/cosi_strace \
        ${INSTALL_PREFIX}lib/panda/*/gdb \
        ${INSTALL_PREFIX}lib/panda/*/snake_hook \
        ${INSTALL_PREFIX}lib/panda/*/rust_skeleton

# Install pypanda
RUN cd /panda/panda/python/core && \
    python3 create_panda_datatypes.py --install && \
    PRETEND_VERSION=$(cat /tmp/savedversion) pip install .
RUN python3 -m pip install --upgrade pip "setuptools<65.6.0" && \
    python3 -m pip install "pycparser<2.22" && \
    python3 -m pip install --force-reinstall --no-binary :all: cffi
# Build a whl too
RUN cd /panda/panda/python/core && \
    python3 create_panda_datatypes.py --install && \
    PRETEND_VERSION=$(cat /tmp/savedversion) pip install . && \
    PRETEND_VERSION=$(cat /tmp/savedversion) python3 -m build --wheel .

# BUG: PANDA sometimes fails to generate all the necessary files for PyPANDA. This is a temporary fix to detect and fail when this occurs
RUN ls -alt $(pip show pandare | grep Location: | awk '{print $2}')/pandare/autogen/
RUN bash -c "ls $(pip show pandare | grep Location: | awk '{print $2}')/pandare/autogen/panda_{aarch64_64,arm_32,mips64_64,mips_32,mipsel_32,ppc_32,ppc_64,x86_64_64,i386_32}.py"

# this layer is used to strip shared objects and change python data to be
# symlinks to the installed panda data directory
FROM installer AS cleanup
ARG INSTALL_PREFIX
RUN find ${INSTALL_PREFIX}lib/panda -name "*.so" -exec strip {} \;
RUN PKG=`pip show pandare | grep Location: | awk '{print $2}'`/pandare/data; \
    rm -rf $PKG/pc-bios && ln -s ${INSTALL_PREFIX}share/panda $PKG/pc-bios; \
    for arch in `find $PKG -name "*-softmmu" -type d -exec basename {} \;` ; do \
        ARCHP=$PKG/$arch; \
        SARCH=`echo $arch | cut -d'-' -f 1`; \
        rm $ARCHP/libpanda-$SARCH.so $ARCHP/llvm-helpers-$SARCH.bc; \
        ln -s ${INSTALL_PREFIX}share/panda/llvm-helpers-$SARCH.bc $ARCHP/llvm-helpers-$SARCH.bc1; \
        ln -s ${INSTALL_PREFIX}bin/libpanda-$SARCH.so $ARCHP/libpanda-$SARCH.so; \ 
        rm -rf $ARCHP/panda/plugins; \
        ln -s ${INSTALL_PREFIX}lib/panda/$SARCH/ $ARCHP/panda/plugins; \
    done

### Copy files for panda+pypanda from installer  - Stage 5
FROM base AS panda
ARG INSTALL_PREFIX
ARG TARGET_LIST

# Include dependency lists for packager
COPY --from=base /tmp/base_dep.txt /tmp
COPY --from=base /tmp/build_dep.txt /tmp

# Copy panda + libcapstone.so* + libosi libraries
COPY --from=cleanup ${INSTALL_PREFIX} ${INSTALL_PREFIX}
COPY --from=cleanup /usr/lib/libcapstone* /usr/lib/
# TODO: Once PR, https://github.com/panda-re/libosi/pull/17 is in, libosi installs to /usr/lib/x86_64-linux-gnu instead of /usr/lib
COPY --from=cleanup /usr/lib/libosi.so /usr/lib/libiohal.so /usr/lib/liboffset.so /usr/lib/x86_64-linux-gnu/

# Workaround issue #901 - ensure LD_LIBRARY_PATH contains the panda plugins directories
RUN LD_LIBRARY_PATH="" && \
    for arch in $(echo $TARGET_LIST | tr ',' ' '); do \
    if [ -z "$LD_LIBRARY_PATH" ]; then \
        LD_LIBRARY_PATH="${INSTALL_PREFIX}lib/python3.10/dist-packages/pandare/data/${arch}/panda/plugins/"; \
    else \
        LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${INSTALL_PREFIX}lib/python3.10/dist-packages/pandare/data/${arch}/panda/plugins/"; \
    fi \
    done && \
    echo "${LD_LIBRARY_PATH}" > /tmp/ld_library_path
ENV LD_LIBRARY_PATH $(cat /tmp/ld_library_path)

# PANDA_PATH is used by rust plugins
ENV PANDA_PATH ${INSTALL_PREFIX}lib/python3.10/dist-packages/pandare/data

# Ensure runtime dependencies are installed for our libpanda objects and panda plugins
RUN ldconfig && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 10 && \
    if (ldd ${INSTALL_PREFIX}lib/python*/dist-packages/pandare/data/*-softmmu/libpanda-*.so | grep 'not found'); then exit 1; fi && \
    if (ldd ${INSTALL_PREFIX}lib/python*/dist-packages/pandare/data/*-softmmu/panda/plugins/*.so | grep 'not found'); then exit 1; fi