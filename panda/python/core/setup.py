#!/usr/bin/env python3

from setuptools import setup
import os


if "PRETEND_VERSION" in os.environ:
    version = os.environ["PRETEND_VERSION"]
else:
    from setuptools_scm import get_version
    version = get_version(root='../../..',
                          fallback_version="0.0.1",
                          version_scheme="guess-next-dev",
                          local_scheme="no-local-version")
    version = version.partition(".dev")[0]

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/panda-re/panda/',
    version=version
)
