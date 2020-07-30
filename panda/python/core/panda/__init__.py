"""
The panda python extension (pypanda) is a module built for interacting
with the PANDA project. The project enables interaction and callbacks
with a use-specified virtual machine. 

It's likely most of what you want is either in panda.main or its listed
ancestors.


Check out our example plugins here: https://github.com/panda-re/panda/tree/master/panda/python/examples
"""

from .main import Panda
from .decorators import blocking
from .ffi_importer import ffi
from .extras import *
