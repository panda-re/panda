#!/usr/bin/env python

from setuptools import setup, find_packages
from setuptools.command.install import install as install_orig
from setuptools.command.develop import develop as develop_orig
from setuptools.dist import Distribution
from subprocess import check_output
import shutil

import os
arches = ['arm', 'aarch64', 'i386', 'x86_64', 'ppc', 'mips', 'mipsel', 'mips64']

# Check for PANDA binaries in /usr/local/bin/ or in our build directory
#panda_binaries = ['/usr/local/bin/panda-system-{arch}' for arch in arches]
# Do we actually care at this point?

root_dir = os.path.join(*[os.path.dirname(__file__), "..", "..", ".."]) # panda-git/ root dir

pypi_build = False # Set to true if trying to minimize size for pypi package upload. Note this disables some architectures

lib_dir = os.path.join("pandare", "data")
def copy_objs():
    '''
    Run to copy objects into a (local and temporary) python module before installing to the system.
    Shouldn't be run if you're just installing in develop mode
    '''
    build_root = os.path.join(root_dir, "build")

    if os.path.isdir(lib_dir):
        shutil.rmtree(lib_dir)
    os.mkdir(lib_dir)

    # Copy pypanda's include directory (different than core panda's) into a datadir
    pypanda_inc = os.path.join(*[root_dir, "panda", "python", "core", "pandare", "include"])
    if not os.path.isdir(pypanda_inc):
        raise RuntimeError(f"Could not find pypanda include directory at {pypanda_inc}")
    pypanda_inc_dest = os.path.join(*["pandare", "data", "pypanda", "include"])
    if os.path.isdir(pypanda_inc_dest):
        shutil.rmtree(pypanda_inc_dest)
    shutil.copytree(pypanda_inc, pypanda_inc_dest)

    # For each arch, copy llvm-helpers
    # XXX Should these be in standard panda deb?
    # What actually uses these? Taint? Disabling for now
    '''
    # Check if we have llvm-support
    with open(os.path.join(*[build_root, 'config-host.mak']), 'r') as cfg:
        llvm_enabled = True if 'CONFIG_LLVM=y' in cfg.read() else False

    for arch in arches:
        libname = "libpanda-"+arch+".so"
        softmmu = arch+"-softmmu"
        path      = os.path.join(*[build_root, softmmu, libname])
        llvm1     = os.path.join(*[build_root, softmmu, "llvm-helpers.bc1"])
        llvm2     = os.path.join(*[build_root, softmmu, f"llvm-helpers-{arch}.bc"])

        if os.path.isfile(path) is False:
            print(("Missing file {} - did you run build.sh from panda/build directory?\n"
                   "Skipping building pypanda for {}").format(path, arch))
            continue

        os.mkdir(os.path.join(lib_dir, softmmu))
        if llvm_enabled:
            shutil.copy(    llvm1,      os.path.join(lib_dir, softmmu))
            shutil.copy(    llvm2,      os.path.join(lib_dir, softmmu))
    '''

from setuptools.command.install import install as install_orig
from setuptools.command.develop import develop as develop_orig
class custom_develop(develop_orig):
    '''
    Install as a local module (not to system) by
        1) Creating datatype files for local-use
        2) Running regular setup tools logic
    '''
    def run(self):
        from create_panda_datatypes import main as create_datatypes
        create_datatypes(install=False)
        super().run()

class custom_install(install_orig):
    '''
    We're going to install to the system. Two possible states to handle
    1) Running from within the panda repo with panda built - need to create_datatypes
    2) Running from a python sdist where all the files are already prepared
    '''
    def run(self):
        try:
            from create_panda_datatypes import main as create_datatypes
            # If we can do the import, we're in the panda repo
            create_datatypes(install=True)
            copy_objs()
            
        except ImportError:
            # Import failed, we're either in a python sdist or something has gone very wrong
            assert(os.path.isfile("pandare/include/panda_datatypes.h")), \
                            "panda_datatypes.h missing and can't be generated"
            assert(os.path.isfile("pandare/autogen/panda_datatypes.py")), \
                            "panda_datatypes.py missing and can't be generated"
        super().run()

# To build a package for pip:
# python setup.py install
# python setup.py sdist

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='pandare',
      version='0.1.2.0',
      description='Python Interface to PANDA',
      long_description=long_description,
      long_description_content_type="text/markdown",
      author='Andrew Fasano, Luke Craig, and Tim Leek',
      author_email='fasano@mit.edu',
      url='https://github.com/panda-re/panda/',
      packages=find_packages(),
      package_data = { 'pandare': [ \
          'data/*-softmmu/llvm-helpers*.bc*', # LLVM Helpers
          'data/pypanda/include/*.h',         # Includes files
          'data/pypanda/include/*.h',         # Includes files
          'qcows.json'                        # Generic Images
          ]},
      install_requires=[ 'cffi>=1.14.3', 'colorama', 'protobuf>=4.25.1'],
      python_requires='>=3.6',
      cmdclass={'install': custom_install, 'develop': custom_develop},
     )
