# Simple guide to extending pypanda
## Adding callbacks to pypanda
### Working with include files

You must adjust the enum `panda_cb_type` and union `panda_cb` which are located
in the [panda_datatypes.h](include/panda_datatypes.h) file. These 
structures should reflect the datastructures included in `plugin.h`.

### Adding a callback in panda_datypes.py

The rest of these edits will be done in the
[panda_dataypes.py](./panda_datatypes.py) file.

#### Add a field in PandaCB

In [panda_datatypes.py](./panda_datatypes.py) look for a structure resembling
the following:

```
PandaCB = namedtuple("PandaCB", "init \
before_block_exec_invalidate_opt \
...
...
after_machine_init \
top_loop");
```

Add your callback as a line in the `namedtuple` in the form:

```
my_callback_name \
```

in the same order as the union `panda_cb`.

Note: The ordering is not a requirement, but keeps things organized.

#### Add callback arguments in pcb

In [panda_datatypes.py](./panda_datatypes.py) look for a structure resembling
the following:

```
pcb = PandaCB(init = pyp.callback("bool(void*)"),
before_block_exec_invalidate_opt = pyp.callback("bool(CPUState*,
TranslationBlock*)"),
...
...
after_machine_init = pyp.callback("void(CPUState*)"),
top_loop = pyp.callback("void(CPUState*)"))
```

Add your callback on a new line in the PandaCB initializer in the form:
```
callback_name = pyp.callback("ret_type(arg1type,arg2type,arg3type...)"),
```
in the same order as PandaCB, which is hte same order as the union `panda_cb`.

#### Add callback to callback_diectionary

In [panda_datatypes.py](./panda_datatypes.py) look for a structure resembling
the following:
```
callback_dictionary = {
pcb.init : pandacbtype("init", -1),
...
pcb.top_loop : pandacbtype("top_loop", C.PANDA_CB_TOP_LOOP)}
```

Add your callback on a new line in dictionary the form:

```
pcb.your_callback_name : pandacbtype("your_callback_name",
C.PANDA_CB_YOUR_CALLBACK_NAME),
```
This `C.PANDA_CB_YOUR_CALLBACK_NAME` should properly resolve the enum
`panda_cb_type` assuming you populated that enum with your callback name in both
PANDA and the pypanda include files.

## Adding C functions to pypanda

All you must do to add a C function to pypanda is add its description in a file 
in the [include](./include) directory. Most of the time this will be the
[panda_datatypes.h](include/panda_datatypes.h) file.

The [panda_datatypes.h](include/panda_datatypes.h) file is a mashup of most of
the include files from panda and is likely where you would want to add your
definition. Try to place your function definition close to other functions in
the same include file in panda.

Once our description is added to [panda_datatypes.h](include/panda_datatypes.h)
it will be automatically populated within our libpanda object in the panda
class. We *can* add call it through `panda.libpanda.our_function`, but we
_should_ add it as a method to the panda class. See the example below for
details.


### Example: Adding `panda_current_pc` to the panda object.

First, we want CFFI to understand return type and arguments of the
`panda_current_pc` method. To do this we add the following line to
[panda_datatypes.h](include/panda_datatypes.h):

```
int panda_current_pc(CPUState *cpu);
```

`cffi` will automatically parse and add this function to a list of functions
available to the `libpanda` object, the object representation of the
`libpanda-ARCH.so` file. 

We can at this point call `panda.libpanda.panda_current_pc(cpu)` and get our
results, however, it is recommended to add a method to the panda object that
properly translates arguments from users and calls the underlying method.

In the case of `current_pc` this is fairly simple:

```
def current_pc(self,cpustate):
	return self.libpanda.panda_current_pc(cpustate)
```

and requires no "translation" of arguments from python to C. However, some will
require this. In this case it can be helpful to review the `cffi`
[documentation](https://cffi.readthedocs.io/en/latest/).

