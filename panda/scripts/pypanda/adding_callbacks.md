# Adding callbacks to pypanda
## Working with include files

You must adjust the enum `panda_cb_type` and union `panda_cb` which are located
in the [panda_datypes.h](include/panda_datatypes.h) file. These 
structures should reflect the datastructures included in `plugin.h`.

## Adding a callback in panda_datypes.py

The rest of these edits will be done in the
[panda_dataypes.py](./panda_datatypes.py) file.

### Add a field in PandaCB

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

Add your callback name as a line with a "\" at the end. Do this in the same
order as the union `panda_cb` (not required to work, but makes things easier).

### Add callback arguments in pcb

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

Add your callback on a new line in the form:
```
callback_name = pyp.callback("ret_type(arg1type,arg2type,arg3type...)"),
```
in the same order as PandaCB, which is hte same order as the union `panda_cb`.

### Add callback to callback_diectionary

In [panda_datatypes.py](./panda_datatypes.py) look for a structure resembling
the following:
```
callback_dictionary = {
pcb.init : pandacbtype("init", -1),
...
pcb.top_loop : pandacbtype("top_loop", C.PANDA_CB_TOP_LOOP)}
```

Add your callback on a new line in the form:

```
pcb.your_callback_name : pandacbtype("your_callback_name",
C.PANDA_CB_YOUR_CALLBACK_NAME),
```
This `C.PANDA_CB_YOUR_CALLBACK_NAME` should properly resolve the enum
`panda_cb_type` assuming you populated that enum with your callback name in both
PANDA and the pypanda include files.



