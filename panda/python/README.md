pypanda: PANDA's Python Interface
========
What is PYPANDA
-
PYPANDA is a python interface to PANDA. With PYPANDA, you can quickly develop plugins
to analyze behavior of a running system, record a system and analyze replays, or do
nearly anything you can do using PANDA's C/C++ APIs.

### Technical details
See detailed installation, usage and example programs [here](./docs/USAGE.md).

## Here be Dragons
Pypanda is very new. We believe it is reasonably stable and should not break anything in PANDA's core logic,
but there are certainly many bugs yet-to-be-discovered in the library and/or Python interface.

A few notable known issues:
* On some machines, pypanda reliably crashes at the end of a script's execution due to a heap pointer being double-freed. This is tricky to debug as the heap object is passed between Python and C and both appear to be trying to clean it up. Observed on Ubuntu 16.04.6 but not 16.04.5. This crash happens on our Travis test image.
* Pip install does not currently work, you must run `setup.py install`.
* After installing pypanda in a venv or on your system, you cannot remove the PANDA build directory or the pypanda directory as some paths to includes/header files still point to the old location.
* When you return the wrong type from a callback, you get an error repeated many times combined with no useful traceback.

## Examples

The following examples demonstrate how easy PANDA plugin development can be when you use the Python interface.

#### [after_init.py](examples/after_init.py)

This sets up the callback for `after_machine_init`, hits it, and gives the user
a pdb trace.

#### [disable_callbacks.py](examples/disable_callbacks.py)

This example shows registering, enabling, and disabling of callbacks during 
runtime of a program. In particular, it enables `before_block_execute` and
`after_block_execute`. After 2 blocks hit it disables `after_block_execute`. 
After 2 additional blocks hit it enables `after_block_execute` again.
 
#### [multiple_cbs.py](examples/multiple_cbs.py)

This example shows the ability to set up multiple callbacks. The example sets up
`before_block_exec` as well as `after_block_exec`. There is a delay of 1 second 
every time each callback is called. 

#### [network_session_extraction.py](examples/network_session_extraction.py)

This example implements the networks same functionality as the network plugin in
panda. It registers `replay_handle_packet` callback, converts the buffer, and
writes the buffer out to a pcap.

#### [record_then_replay.py](examples/record_then_replay.py)

This example takes a recording, then replays it under analysis.

#### [dump_regs.py](examples/dump_regs.py)

This example prints the CPU state of an x86 guest after every basic block.
