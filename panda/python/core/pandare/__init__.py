"""
The PANDA python interface (sometimes called pypanda) is a python module built for interacting with the PANDA project.
The module enables driving an execution of a virtual machine while also introspecting on its execution using PANDA's callback
and plugin systems.

Most of the commonly used APIs are in `pandare.panda`.

Example plugins are available [on GitHub](https://github.com/panda-re/panda/tree/master/panda/python/examples).

.. include:: ../../docs/USAGE.md
"""

from .panda import Panda, blocking
from .ffi_importer import ffi
from .extras import *
from .plog_reader import PLogReader

__pdoc__ = {}

__pdoc__['volatility_cli_classes'] = False
__pdoc__['data'] = False
__pdoc__['autogen'] = False
__pdoc__['plog_pb2'] = False
