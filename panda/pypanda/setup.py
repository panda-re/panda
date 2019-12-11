#!/usr/bin/env python

from setuptools import setup
from setuptools.command.install import install as install_orig
from setuptools.command.develop import develop as develop_orig
import os
import shutil

##############################
# 1)  Populate panda/autogen #
##############################

from sys import path as sys_path
util_path = os.path.join(*[os.path.dirname(__file__), "utils"])
sys_path.append(util_path)
from create_panda_datatypes import main as create_datatypes
create_datatypes()

################################################
# 2) Copy panda object files: libpanda-XYZ.so, #
#    pc-bios/*, and all .so files for plugins  #
#    TODO: also copy includes directories      #
################################################

root_dir = os.path.join(*[os.path.dirname(__file__), "..", ".."])

# XXX - Can we toggle this depending on if we're run as 'setup.py develop' vs 'setup.py install'
# When we're run in develop mode, we shouldn't copy the prebuild binaries and instead should
# find them in ../../build/. Temporrary hack is to run setup.py develop then delete lib_dir (falls back to build)
lib_dir = os.path.join("panda", "data")
def copy_objs():
    build_root = os.path.join(root_dir, "build")

    if os.path.isdir(lib_dir):
        assert('panda' in lib_dir), "Refusing to rm -rf directory without 'panda' in it"
        shutil.rmtree(lib_dir)
    os.mkdir(lib_dir)

    # Copy bios directory
    biosdir = os.path.join(root_dir, "pc-bios")
    if not os.path.isdir(biosdir):
        raise RuntimeError(f"Could not find PC-bios directory at {lib_dir}")
    shutil.copytree(biosdir, lib_dir+"/pc-bios")

    # Copy pypanda includes - Now just copy in place instead of moving

    pypanda_inc = os.path.join(*[root_dir, "panda", "pypanda", "panda", "include"])
    if not os.path.isdir(pypanda_inc):
        raise RuntimeError(f"Could not find pypanda include directory at {pypanda_inc}")
    pypanda_inc_dest = os.path.join(*["panda", "data", "pypanda", "include"])
    if os.path.isdir(pypanda_inc_dest):
        shutil.rmtree(pypanda_inc_dest)
    shutil.copytree(pypanda_inc, pypanda_inc_dest)

    for arch in ['arm', 'i386', 'x86_64', 'ppc']:
        libname = "libpanda-"+arch+".so"
        softmmu = arch+"-softmmu"
        path      = os.path.join(*[build_root, softmmu, libname])
        plugindir = os.path.join(*[build_root, softmmu, "panda", "plugins"])
        plog      = os.path.join(*[build_root, softmmu, "plog_pb2.py"])
        os.mkdir(os.path.join(lib_dir, softmmu))

        new_plugindir = os.path.join(lib_dir, softmmu, "panda/plugins")
        os.mkdir(os.path.dirname(new_plugindir)) # When we copy the whole tree, it will make the plugins directory

        assert (os.path.isfile(path)), "Missing file {} - did you run build.sh from panda/build directory?".format(path)
        shutil.copy(    plog,       os.path.join(lib_dir, softmmu, "plog_pb2.py"))
        shutil.copy(    path,       os.path.join(lib_dir, softmmu))

        shutil.copytree(plugindir,  new_plugindir)

#########################
# 3)  Build the package #
#########################

from setuptools.command.install import install as install_orig
from setuptools.command.develop import develop as develop_orig
class custom_develop(develop_orig):
    def run(self):
        # Delete panda/data in the case of `setup.py develop`
        # Don't copy objects, use them in the current path
        if os.path.isdir(lib_dir):
            assert('panda' in lib_dir), "Refusing to rm -rf directory without 'panda' in it"
            shutil.rmtree(lib_dir)
        super().run()

class custom_install(install_orig):
    # Run copy_objs before we install in the case of `setup.py install`
    def run(self):
        copy_objs()
        super().run()


setup(name='panda',
      version='0.1',
      description='Python Interface to Panda',
      author='Andrew Fasano, Luke Craig, and Tim Leek',
      author_email='fasano@mit.edu',
      url='https://github.com/panda-re/panda/',
      packages=['panda', 'panda.taint', 'panda.autogen',
                'panda.images', 'panda.arm', 'panda.x86'],
      package_data = { 'panda': ['data/**/*', 'data/*/panda/plugins/*', 'data/*/panda/plugins/**/*', 'data/pypanda/include/*.h'] },
      install_requires=[ 'cffi', 'colorama', 'protobuf'],
      python_requires='>=3.5',
      cmdclass={'install': custom_install, 'develop': custom_develop}
     )
