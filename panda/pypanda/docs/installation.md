# Installing pypanda

Below are the directions to install PYPANDA. These are similar to PANDA.
```
git clone https://github.com/panda-re/panda.git
cd panda
pip install cffi colorama # make sure for Python 3
git checkout pypanda
git submodule update --init dtc
mkdir build
cd build
../build.sh
```

Required Libraries
- cffi
- colorama
