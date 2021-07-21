"""
`pandare` (also called PyPANDA) is a Python 3 module built for interacting with the PANDA project.
The module enables driving an execution of a virtual machine while also introspecting on its execution using PANDA's callback
and plugin systems.

Most of the commonly used APIs are in `pandare.panda`.

Example plugins are available in the [examples directory](https://github.com/panda-re/panda/tree/master/panda/python/examples).

.. include:: ../../docs/USAGE.md
"""

from .panda import Panda, blocking
from .ffi_importer import ffi
from .plog_reader import PLogReader

__pdoc__ = {}

__pdoc__['asyncthread'] = False
__pdoc__['autogen'] = False
__pdoc__['ffi_importer'] = False
__pdoc__['plog_pb2'] = False
__pdoc__['volatility_cli_classes'] = False
