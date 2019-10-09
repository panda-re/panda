#!/usr/bin/env python

from setuptools import setup

setup(name='panda',
      version='0.1',
      description='Python Interface to Panda',
      author='Andrew Fasano, Luke Craig, and Tim Leek',
      author_email='fasano@mit.edu',
      url='https://github.com/panda-re/panda/',
      packages=['panda', 'panda.taint', 'panda.autogen',
                'panda.arm', 'panda.x86'],
      install_requires=[ 'cffi', 'colorama', 'protobuf'],
      python_requires='>=3.5',
     )
