FROM amd64/ubuntu:18.04
RUN apt-get update

# packages for pahole
RUN apt-get -y install git cmake build-essential libtool autoconf pkg-config zlib1g zlib1g-dev flex gcc-6-multilib bison gawk

# use this so tzdata doesn't ask us things
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
# packages for pyenv 
RUN apt-get install -y --no-install-recommends make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

# clone git repos
# pahole requires elfutils
RUN git clone https://github.com/roolebo/elfutils
RUN git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git 
RUN git clone https://github.com/pyenv/pyenv.git ~/.pyenv

# install PYENV things
RUN echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
RUN echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
RUN echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init -)"\nfi' >> ~/.bashrc
#RUN exec "$SHELL" && source ~/.bashrc
RUN ~/.pyenv/bin/pyenv install 3.6.6

# elfutils install
WORKDIR /elfutils
RUN git checkout cff53f1784c9a4344604bedf41b7d499b3eb30d5
RUN autoreconf -i -f && ./configure --enable-maintainer-mode && make && make install

# pahole install
WORKDIR /pahole
RUN git checkout 529903571037b5f72e619e0a1921207a1ae880b9
WORKDIR /pahole/build
RUN cmake -D__LIB=lib ..
RUN make install

# install cffi in pyenv
RUN ~/.pyenv/versions/3.6.6/bin/python -m pip install 'cffi==1.14.0'

# install script
WORKDIR /
COPY ./run.py /run.py
COPY ./assumptions.h /assumptions.h
