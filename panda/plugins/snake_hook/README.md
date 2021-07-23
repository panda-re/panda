# snake_hook

A plugin for running pypanda scripts in a plugin-style architecture. Unlike traditional pypanda usage, this allows PANDA to drive python, rather than python driving PANDA. This allows for a higher level of uncoordinated composability than is possible from using pypanda itself.

### Usage:

```
panda-system-x86_64 -panda snake_hook:files=print_pcs.py:print_strings.py -nographic
```

### Arguments

* `files` - a colon-separated list of python files to load

### Example Script

```py
def init(panda):
    blocks = 0

    @panda.cb_before_block_exec
    def before_block_execute(cpustate, transblock):
        nonlocal blocks
        blocks += 1
        print(f"Blocks run: {}", blocks)
```

The anatomy of a pypanda plugin in its current form (note: this is subject to change) is rather simple: all that is required is declaring an `init` function that takes an `panda` object, which is of type [pandare.Panda](https://docs.panda.re/panda.html#pandare.panda.Panda).

From there, you can add hooks and declare initial state for your plugin. However it is worth noting (such as in the above example) that any variables declared outside of your callback will need to be marked as [`nonlocal`](https://docs.python.org/3/reference/simple_stmts.html#nonlocal) (or, if desired, [`global`](https://docs.python.org/3/reference/simple_stmts.html#global)). This will ensure the variable within the callback is recognized as being a reference to the variable in a higher scope.
