"""
Extras are a bit like python-based plugins. You can import them, instantiate them as classes, and use their functionality.

Note file names should NOT contain underscores, let's keep these in (upper)
CamelCase going forward (e.g., ModeFilter) so they match the class names.
"""
from .ModeFilter import ModeFilter

from .file_hook import FileHook
from .file_faker import FakeFile
from .ioctl_faker import IoctlFaker
from .proc_write_capture import ProcWriteCapture
