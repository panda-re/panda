#syntax=docker/dockerfile:1.17-labs
ARG REGISTRY="docker.io"
ARG BASE_IMAGE="ubuntu:22.04"
ARG TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,aarch64-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu,mips64-softmmu,mips64el-softmmu"
ARG CAPSTONE_VERSION="5.0.5"
ARG PACKAGE_VERSION="3.1.0"

### BASE IMAGE
FROM ${REGISTRY}/$BASE_IMAGE AS base
ARG BASE_IMAGE
ARG CAPSTONE_VERSION

# Copy dependencies lists into container. We copy them all and then do a mv because
# we need to transform base_image into a windows compatible filename which we can't
# do in a COPY command.
COPY ./panda/dependencies/${BASE_IMAGE/:/_}_base.txt /tmp/base_dep.txt

# Base image just needs runtime dependencies
RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends curl jq $(cat /tmp/base_dep.txt | grep -o '^[^#]*') && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./panda/dependencies/${BASE_IMAGE/:/_}_build.txt /tmp/build_dep.txt

RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $(cat /tmp/build_dep.txt | grep -o '^[^#]*') && \
    apt-get clean && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal && \
    UBUNTU_VERSION=$(lsb_release -rs) && \
    if dpkg --compare-versions "$UBUNTU_VERSION" ge "23.04"; then \
        python3 -m pip install --upgrade --no-cache-dir "cffi>1.14.3" --break-system-packages && \
        python3 -m pip install --upgrade --no-cache-dir "capstone" --break-system-packages; \
        python3 -m pip install setuptools_scm --break-system-packages && \
        python3 -m pip install build --break-system-packages; \
    else \
        python3 -m pip install --upgrade --no-cache-dir pip && \
        python3 -m pip install --upgrade --no-cache-dir "cffi>1.14.3" && \
        python3 -m pip install --upgrade --no-cache-dir "capstone"; \
        python3 -m pip install setuptools_scm && \
        python3 -m pip install build; \
    fi

# Then install capstone debian package
RUN cd /tmp && \
    curl -LJO https://github.com/capstone-engine/capstone/releases/download/${CAPSTONE_VERSION}/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb && \
    dpkg -i /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb && \
    rm -rf /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb

ENV PATH="/root/.cargo/bin:${PATH}"

# install libosi
RUN cd /tmp && \
    BASE_IMAGE_VERSION=$(echo "$BASE_IMAGE" | awk -F':' '{print $2}') && \
    curl -LJO https://github.com/panda-re/libosi/releases/latest/download/libosi_${BASE_IMAGE_VERSION}.deb && \
    dpkg -i /tmp/libosi_${BASE_IMAGE_VERSION}.deb && \
    rm -rf /tmp/libosi_${BASE_IMAGE_VERSION}.deb

### BUILD IMAGE - STAGE 2
FROM base AS builder
ARG TARGET_LIST

# Build and install panda
# Copy repo root directory to /panda, note we explicitly copy in .git directory
# Note .dockerignore file keeps us from copying things we don't need
COPY --exclude=panda/debian \
    --exclude=panda/dependencies \
    --exclude=Dockerfile \
    --exclude=.github \
    --exclude=.gitignore \
    --exclude=build.sh \
    . /panda/
COPY .git /panda/

# Note we diable NUMA for docker builds because it causes make check to fail in docker
RUN git -C /panda submodule update --init dtc && \
    git -C /panda rev-parse HEAD > /usr/local/panda_commit_hash && \
    mkdir  /panda/build && cd /panda/build && \
    python3 -m setuptools_scm -r .. --strip-dev 2>/dev/null >/tmp/savedversion && \
    /panda/configure \
        --target-list="${TARGET_LIST}" \
        --prefix=/usr/local \
        --disable-numa \
        --extra-cflags=-Wno-error \
        --extra-cxxflags=-Wno-error \
        --enable-llvm && \
    rm -rf /panda/.git

RUN PRETEND_VERSION=$(cat /tmp/savedversion) make -C /panda/build -j "$(nproc)"

#### Develop setup: panda built + pypanda installed (in develop mode) - Stage 3
FROM builder AS developer
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
RUN  make -C /panda/build install && \
    rm -rf /usr/local/lib/panda/*/cosi \
        /usr/local/lib/panda/*/cosi_strace \
        /usr/local/lib/panda/*/gdb \
        /usr/local/lib/panda/*/snake_hook \
        /usr/local/lib/panda/*/rust_skeleton

# Build wheel and install pypanda
RUN cd /panda/panda/python/core && \
    python3 create_panda_datatypes.py --install && \
    PRETEND_VERSION=$(cat /tmp/savedversion) python3 -m build --wheel . && \
    UBUNTU_VERSION=$(lsb_release -rs) && \
    if dpkg --compare-versions "$UBUNTU_VERSION" ge "23.04"; then \
        python3 -m pip install dist/*.whl --break-system-packages; \
    else \
        python3 -m pip install dist/*.whl; \
    fi

# BUG: PANDA sometimes fails to generate all the necessary files for PyPANDA. This is a temporary fix to detect and fail when this occurs
RUN ls -alt $(pip show pandare | grep Location: | awk '{print $2}')/pandare/autogen/
RUN bash -c "ls $(pip show pandare | grep Location: | awk '{print $2}')/pandare/autogen/panda_{aarch64_64,arm_32,mips64_64,mips_32,mipsel_32,ppc_32,ppc_64,x86_64_64,i386_32}.py"

# this layer is used to strip shared objects and change python data to be
# symlinks to the installed panda data directory
FROM installer AS cleanup
RUN find /usr/local/lib/panda -name "*.so" -exec strip {} \;
RUN PKG=`pip show pandare | grep Location: | awk '{print $2}'`/pandare/data; \
    rm -rf $PKG/pc-bios && ln -s /usr/local/share/panda $PKG/pc-bios; \
    for arch in `find $PKG -name "*-softmmu" -type d -exec basename {} \;` ; do \
        ARCHP=$PKG/$arch; \
        SARCH=`echo $arch | cut -d'-' -f 1`; \
        rm $ARCHP/libpanda-$SARCH.so $ARCHP/llvm-helpers-$SARCH.bc; \
        ln -s /usr/local/share/panda/llvm-helpers-$SARCH.bc $ARCHP/llvm-helpers-$SARCH.bc1; \
        ln -s /usr/local/bin/libpanda-$SARCH.so $ARCHP/libpanda-$SARCH.so; \ 
        rm -rf $ARCHP/panda/plugins; \
        ln -s /usr/local/lib/panda/$SARCH/ $ARCHP/panda/plugins; \
    done

### Copy files for panda+pypanda from installer  - Stage 5
FROM base AS p

# Include dependency lists for packager
COPY --from=base /tmp/base_dep.txt /tmp
COPY --from=base /tmp/build_dep.txt /tmp

# Copy panda + libcapstone.so* + libosi libraries
COPY --from=cleanup /usr/local /usr/local
COPY --from=cleanup /usr/lib/x86_64-linux-gnu/libcapstone.so* /usr/lib/x86_64-linux-gnu/
COPY --from=cleanup /usr/lib/x86_64-linux-gnu/libosi.so /usr/lib/x86_64-linux-gnu/libiohal.so /usr/lib/x86_64-linux-gnu/liboffset.so /usr/lib/x86_64-linux-gnu/

# Workaround issue #901 - ensure LD_LIBRARY_PATH contains the panda plugins directories
#ARG TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu"
ENV LD_LIBRARY_PATH=/usr/local/lib/python3.8/dist-packages/pandare/data/x86_64-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/i386-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/arm-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/ppc-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/mips-softmmu/panda/plugins/:/usr/local/lib/python3.8/dist-packages/pandare/data/mipsel-softmmu/panda/plugins/
#PANDA_PATH is used by rust plugins
ENV PANDA_PATH=/usr/local/lib/python3.8/dist-packages/pandare/data

# Ensure runtime dependencies are installed for our libpanda objects and panda plugins
RUN ldconfig && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 10 && \
    if (ldd /usr/local/lib/python*/dist-packages/pandare/data/*-softmmu/libpanda-*.so | grep 'not found'); then exit 1; fi && \
    if (ldd /usr/local/lib/python*/dist-packages/pandare/data/*-softmmu/panda/plugins/*.so | grep 'not found'); then exit 1; fi


FROM base AS packager
ARG PACKAGE_VERSION

# Install necessary tools for packaging
RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
        fakeroot dpkg-dev

# Get dependencies list from base image
COPY --from=base /tmp/base_dep.txt /tmp
COPY --from=base /tmp/build_dep.txt /tmp

# Set up /package-root with files from panda we'll package
COPY --from=p /usr/local/bin/panda* /usr/local/bin/libpanda* /usr/local/bin/qemu-img /package-root/usr/local/bin/
COPY --from=p /usr/local/include/ /package-root/usr/include/
COPY --from=p /usr/local/etc/panda /package-root/usr/local/etc/panda
COPY --from=p /usr/local/lib/panda /package-root/usr/local/lib/panda
COPY --from=p /usr/local/share/panda /package-root/usr/local/share/panda

# Create DEBIAN directory and control file
COPY ./panda/debian/control /package-root/DEBIAN/control

# Add triggers script to run ldconfig after installation
COPY ./panda/debian/triggers /package-root/DEBIAN/triggers

# Generate MD5 checksums for all files and save to DEBIAN/md5sums
RUN cd /package-root && \
    find . -type f ! -path './DEBIAN/*' -exec md5sum {} + | sed 's| \./| |' > /package-root/DEBIAN/md5sums

# Update control file with the correct version, and place installed size
RUN INSTALLED_SIZE=$(du -sk /package-root | cut -f1) && \
    sed -i "s/^Installed-Size:.*/Installed-Size: ${INSTALLED_SIZE}/" /package-root/DEBIAN/control
RUN sed -i "s/^Version:.*/Version: ${PACKAGE_VERSION}/" /package-root/DEBIAN/control

# Update control file with dependencies
# Build time. We only select dependencies that are not commented out or blank
RUN dependencies=$(grep '^[a-zA-Z]' /tmp/build_dep.txt | tr '\n' ',' | sed 's/,,\+/,/g'| sed 's/,$//') && \
    sed -i "s/BUILD_DEPENDS_LIST/Build-Depends: $dependencies/" /package-root/DEBIAN/control

# Run time. Also includes ipxe-qemu so we can get pc-bios files
RUN dependencies=$(grep '^[a-zA-Z]' /tmp/base_dep.txt | tr '\n' ',' | sed 's/,,\+/,/g' | sed 's/,$//') && \
    sed -i "s/DEPENDS_LIST/Depends: ipxe-qemu,${dependencies}/" /package-root/DEBIAN/control

# Build the package
RUN fakeroot dpkg-deb --build /package-root /pandare.deb

# The user can now extract the .deb file from the container with something like
#docker run --rm -v $(pwd):/out packager bash -c "cp /pandare.deb /out"

FROM packager AS whlpackager

COPY --from=installer /panda/panda/python/core/dist/*.whl /


# last stage should be panda, but for the packager it needs to be earlier
FROM p AS panda
