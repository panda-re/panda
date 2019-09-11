FROM ubuntu
RUN echo "deb http://archive.ubuntu.com/ubuntu/ trusty universe multiverse" >> \
    /etc/apt/sources.list
RUN echo "deb-src http://archive.ubuntu.com/ubuntu/ trusty universe multiverse" >> \
    /etc/apt/sources.list
RUN sed -i "s/# deb-src /deb-src /g" /etc/apt/sources.list
RUN apt-get update
ENV PACKAGES flex bison \
    libusb-1.0-0-dev libiscsi-dev librados-dev libncurses5-dev \
    libseccomp-dev libgnutls28-dev libssh2-1-dev  libspice-server-dev \
    libspice-protocol-dev libnss3-dev libfdt-dev \
    libgtk-3-dev libvte-dev libsdl1.2-dev libpng-dev libpixman-1-dev \
    git make ccache python-yaml gcc clang sparse wget emacs genisoimage

RUN apt-get -y install $PACKAGES

RUN dpkg -l $PACKAGES | sort > /packages.txt
ENV FEATURES clang pyyaml

RUN mkdir /root/.panda
RUN wget -q http://panda.moyix.net/~moyix/wheezy_panda2.qcow2 -O /root/.panda/wheezy_panda2.qcow2

RUN git clone -b docker  https://github.com/panda-re/panda

ENV PANDA_DOCKER=1

RUN cd panda && ./panda/scripts/install_ubuntu.sh

#ENV PATH="/panda/build/x86_64-softmmu/:${PATH}"

