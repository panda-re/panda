# Test

The contents of this folder are for debugging and development of this plugin.

* [setup_dbg.py](./setup_dbg.py) - Bash script that downloads a file system, builds a test kernel, and prepares kernel VMI artifacts (OSI profile, DWARF JSON).
* [run_dbg.py](./run_dbg.py) - Python runner, boots the test kernel while logging syscall data to PANDALOG.
