# PyPANDA
PyPANDA is a python interface to PANDA. With PyPANDA, you can quickly develop plugins
to analyze behavior of a running system, record a system and analyze replays, or do
nearly anything you can do using PANDA's C/C++ APIs.

## Installation
1. Follow instructions to build PANDA using build.sh with the `--python` flag or run `scripts/panda/install_ubuntu.sh`.

## Example program
This program counts the number of basic blocks executed while running `uname -a` inside a 32-bit guest.
```py
from pandare import Panda, blocking
panda = Panda(generic='i386') # Create an instance of panda

# Counter of the number of basic blocks
blocks = 0

# Register a callback to run before_block_exec and increment blocks
@panda.cb_before_block_exec
def before_block_execute(cpustate, transblock):
    global blocks
    blocks += 1

# This 'blocking' function runs in a seperate thread from the main CPU loop
# which allows for it to wait for the guest to complete commands
@blocking
def run_cmd():
    # First revert to the qcow's root snapshot (synchronously)
    panda.revert_sync("root")
    # Then type a command via the serial port and print its results
    print(panda.run_serial_cmd("uname -a"))
    # When the command finishes, terminate the panda.run() call
    panda.end_analysis()

# Queue up the run_cmd function to drive the guest once it's running
panda.queue_async(run_cmd)

# Start the guest
panda.run()
print("Finished. Saw a total of {} basic blocks during execution".format(blocks))
```

# Usage
## Create an instance of Panda
The `Panda` class takes many arguments, but the only crucial argument is a
specificed qcow image. If you wish to get started quickly you may use the `panda.images` module
to download a default image and run it.

For example: `panda = Panda(generic='i386')`

## Register a callback
```py
@panda.cb_before_block_exec
def my_before_block_fn(cpustate, translation_block):
  pc = panda.current_pc(env)
  print("About to run the block at 0x{:x}".format(pc))
```

The panda object creates decorators named `cb_[CALLBACK_NAME]` for each panda callback.
The decorated functions must take the same number of arguments, and return the same type
as expected by the original C callback, see [Callback List](https://github.com/panda-re/panda/tree/master/panda/docs/manual.md#appendix-a-callback-list)
for more information.
The decorated functions are called at the appropriate times, similarly to how a panda plugin written
in C behaves.

## Enable and disable callbacks
Python callbacks can be enabled and disabled using their names.
By default, a callback is named after the function that is decorated. For example, the callback describe in
```py
@panda.cb_before_block_exec
def my_before_block_fn(cpustate, translation_block):
  ...
```
is named `my_before_block_fn` and can be disabled with `panda.disable_callback('my_before_block_fn')` and later
enabled with `panda.enable_callback('my_before_block_fn')`.

Callbacks can be given custom names and disabled at initialization by passing arguments to their decorators:
```py
@panda.cb_before_block_exec(name='my_callback', enabled=False)
def my_before_block_fn(cpustate, translation_block):
  ...
panda.enable_callback('my_callback')
```

If a callback is decorated with a `procname` argument, it will only be enabled when that process is running.
To permanently disable such a callback, you can use `panda.disable_callback('name', forever=True)`.

## Replaying Recordings
```py
panda = Panda(...)
# Register functions to run on callbacks here
panda.begin_replay("/file/path/here")
panda.run() # Actually run the replay
```

## Load and unload a C plugin
A C plugin can be loaded from pypanda easily: `panda.load_plugin("stringsearch")`

C plugins can be passed named arguments using a dictionary: `panda.load_plugin("stringsearch", {"name": "jpeg"})`

Or unnamed arguments using a list: `panda.load_plugin("my_plugin", ["arg1", "arg2"])`

## Asynchronous Activity
When a callback is executing, the guest is suspended until the callback finishes. However, we often want to interact
with guests during our analyses. In these situations, we run code asynchronously to send data into and wait for results
from the guest.

Pypanda provides two tools to help with this common usecase, the *@blocking* decorator, and the *queue_async()* function.

Consider if you with to run the commands `uname -a`, then `whoami` in a guest. If your guest exposes a console over a serial port
(as all the 'generic' qcows we use do), you could run these commands by simply typing them and waiting for a response. But if you were
to do this in a callback, the guest would have no chance to respond to your commands and you'd end up in a deadlock where your callback
code never terminates until the guest executes your command, and the guest will never execute commands until your callback terminates.

Instead, in a callback (or at any time), you can queue up blocking functions to run asynchronously as follows:

```py
# (panda object initialization not shown)

@blocking
def first_cmd():
    print(panda.run_serial_cmd("uname -a"))

@blocking
def second_cmd():
    print(panda.run_serial_cmd("whoami"))
    panda.end_analysis()

@panda.cb_before_block_exec
def before_block_execute(cpustate, transblock):
    pc = panda.current_pc(cpustate)
    if pc > 0x41414141:
        # Queue up the run_cmd function to drive the guest if the PC is a made up value
        panda.queue_async(run_cmd)
        panda.queue_async(second_cmd)
        panda.disable_callback('before_block_execute') # Don't repeatedly queue up commands

panda.run()
```

## Recordings
See [take_recording.py](https://github.com/panda-re/panda/tree/master/panda/python/examples/take_recording.py)

A replay can be taken with the function `panda.record_cmd('cmd_to_run', recording_name='replay_name')` which will revert the guest to a `root` snapshot, type a command, begin a recording, press enter, wait for the command to finish, and then end the replay.
Once a replay is created on disk, it can be analyzed by using `panda.run_replay('replay_name')`.

Alternatively, you can begin/end the recording through the monitor with `panda.run_monitor_cmd('begin_record myname')`
and `panda.run_monitor_cmd('end_record')` and drive the guest using `panda.run_serial_cmd` in the middle.

# Typical Use Patterns

## Live system
Example: [osi_procnames.py](https://github.com/panda-re/panda/tree/master/panda/python/examples/osi_procnames.py).

1. Initialize a panda object based off a generic machine or a qcow you have.
2. Register functions to run at various PANDA callbacks.
3. Register an `@blocking` function to revert the guest to a snapshot, run commands with `panda.run_serial_cmd()`, and stop the execution with `panda.end_analysis()`
4. Queue the blocking function to run with `panda.queue_async()`
5. Start the execution with `panda.run()`

## Record/Replay
Example: [record_then_replay.py](https://github.com/panda-re/panda/tree/master/panda/python/examples/record_then_replay.py).

1. Initialize a panda object based off a generic machine or a qcow you have.
2. Register `@blocking` functions to drive guest execution while recording or with `panda.record_cmd` then call `panda.end_analysis()`
3. Register functions to run at various PANDA callbacks.
5. Analyze the replay with `panda.run_replay(filename)`

# Here Be Dragons
* You can't have multiple instances of panda running at the same time. Once you've created a panda object for a given architecture, you can never create another. Hoewver, you can modify the machine after it's created to run a new analysis as long as you don't change the machine type.
* You cannot read from stdin in a pypanda callback (i.e., you can't use `input()` or interactive debuggers)
* PyPANDA is slower than traditional panda. To improve performance try disabling callbacks whenever possible and only enabling them when they are needed.

# Extending PyPANDA
PyPANDA currently supports interactions (e.g., ppp callbacks) with numerous PANDA plugins such as `taint2` and `osi`. If you wish to extend PyPANDA to support an new plugin, its header file
must be cleaned up such that it can be parsed by CFFI. See [create_panda_datatypes.py](https://github.com/panda-re/panda/tree/master/panda/python/utils/create_panda_datatypes.py)
and the magic `BEGIN_PYPANDA_NEEDS_THIS` strings it searches for.
