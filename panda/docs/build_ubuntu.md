# Building on Ubuntu

Panda's build and runtime dependencies are listed in `panda/panda/dependencies/` for ubuntu 18, 19 and 20.

If you install all the packages listed there, clone panda, and run build.sh you should be able to build panda:

```sh
sudo apt-get update
sudo apt install --no-install-recommends [dependencies]

# clone and build PANDA
git clone https://github.com/panda-re/panda
cd panda
mkdir -p build && cd build
../build.sh

```

If you would like to use **PyPANDA** you'll need to also install it and its dependencies:

```sh
# Pypanda dependencies
pip3 install pycparser "protobuf==3.0.0" "https://foss.heptapod.net/pypy/cffi/-/archive/branch/default/cffi-branch-default.zip" colorama

# Install pypanda
cd panda/panda/python/core
python3 setup.py install
```
