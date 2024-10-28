ARG PACKAGE_VERSION=""

# First run the main Dockerfile to build the base image and name it panda. Then we run here
# to generate a debian package

FROM debian:bookworm-slim

# Install necessary tools for packaging
RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
        fakeroot dpkg-dev

# Get dependencies list from base image
COPY --from=panda /tmp/base_dep.txt /tmp
COPY --from=panda /tmp/build_dep.txt /tmp

# Set up /package-root with files from panda we'll package
COPY --from=panda /usr/local/bin/panda* /usr/bin/libpanda* /usr/bin/qemu-img /package-root/usr/bin/
COPY --from=panda /usr/local/etc/panda /package-root/etc/
COPY --from=panda /usr/local/lib/panda /package-root/usr/lib/
COPY --from=panda /usr/local/share/panda /package-root/usr/share/

# Copy documentation over, we should have a better Changelog if we go for official release?
COPY ./LICENSE /package-root/usr/share/doc/panda
COPY ./README.md /package-root/usr/share/doc/panda

# Create DEBIAN directory and control file
COPY control /package-root/DEBIAN/control

# Generate MD5 checksums for all files and save to DEBIAN/md5sums
RUN cd /package-root && \
    find . -type f ! -path './DEBIAN/*' -exec md5sum {} + | sed 's| \./| |' > /package-root/DEBIAN/md5sums

# Update control file with the correct version, and place installed size
ARG PACKAGE_VERSION
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
