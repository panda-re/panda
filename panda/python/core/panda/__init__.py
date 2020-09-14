"""
The panda python extension (pypanda) is a module built for interacting
with the PANDA project. The project enables interaction and callbacks
with a use-specified virtual machine. 

The primary interface for pypanda is in `panda.main`.

Check out our example plugins here: https://github.com/panda-re/panda/tree/master/panda/python/examples

.. include:: ../../docs/USAGE.md
"""

from .main import Panda, blocking
from .ffi_importer import ffi
from .extras import *

__pdoc__ = {}

__pdoc__['volatility_cli_classes'] = False
__pdoc__['data'] = False
__pdoc__['autogen'] = False
