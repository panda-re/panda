pypanda
========
What is PYPANDA
-
PYPANDA is an interface to PANDA that allows for Python3 to control PANDA and to register
functions that run on various PANDA callbacks.

### Installation
See installation instructions in [here](./docs/installation.md).

### Usage
See installation instructions in [here](./docs/USAGE.md).

## Example plugins

#### [example_after_init.py](example_after_init.py)

This sets up the callback for `after_machine_init`, hits it, and gives the user
a pdb trace.

Run this with `python3 example_after_init.py`

#### [example_coverage.py](example_coverage.py)

This example demonstrates dynamic loading and unloading of the coverage plugin.
It does so by registering the `before_block_execute` callback.

#### [example_disable_callbacks.py](example_disable_callbacks.py)

This example shows registering, enabling, and disabling of callbacks during 
runtime of a program. In particular, it enables `before_block_execute` and
`after_block_execute`. After 2 blocks hit it disables `after_block_execute`. 
After 2 additional blocks hit it enables `after_block_execute` again.
 
Run with: `python3 example_disable_callbacks.py`

#### [example_multiple_callbacks.py](example_multiple_callbacks.py)

This example shows the ability to set up multiple callbacks. The example sets up
`before_block_exec` as well as `after_block_exec`. There is a delay of 1 second 
every time each callback is called. 

Run this with `python3 example_multiple_callbacks.py`

#### [example_network.py](example_network.py)

This example implements the networks same functionality as the network plugin in
panda. It registers `replay_handle_packet` callback, converts the buffer, and
writes the buffer out to a pcap.

Run with: `python3 example_network.py i386 out.pcap /path/to/recording`

#### [example_osi_linux_test.py](example_osi_linux_test.py)

This exampls shows off the functionality of `osi_linux` in pypanda. Modeled
after the original `osi_linux` panda plugin.

Runs with `python3 example_osi_linux_test.py i386 /path/to/recording`

#### [example_plugin.py](example_plugin.py)

This is the simplest of plugins. It registers a callback for `before_block_exec`
and gives the user a pdb trace each time it is hit.

Run this with `python3 example_plugin.py`

#### [example_print_regs.py](example_print_regs.py)

This example displays the register state of the cpu in x86 at each 
`before_block_exec`.

Run this with `python3 example_print_regs.py`

#### [example_record_replay.py](example_record_replay.py)

This example registers asid_changed and runs a replay from a file specified.

Run with: `python3 example_record_replay.py i386 /path/to/recording`

#### [example_virt_mem_read_callback.py](example_virt_mem_read_callback.py)

This plugin registers the `virt_mem_after_write` callback and attempts to find
strings in the buffers.

Run with: `python3 example_virt_mem_read_callback.py`

#### [example_watch_program.py](example_watch_program.py)

This example allows us to debug a specific program by name. It registers 
`asid_changed` and waits for the osi process name to match the name of the
program set by the user.

Run with: `python3 example_watch_program.py`
