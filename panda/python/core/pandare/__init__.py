"""
`pandare` (also called PyPANDA) is a Python 3 module built for interacting with the PANDA project.
The module enables driving an execution of a virtual machine while also introspecting on its execution using PANDA's callback
and plugin systems.

Most of the commonly used APIs are in `pandare.panda`.

Example plugins are available in the [examples directory](https://github.com/panda-re/panda/tree/master/panda/python/examples).

.. include:: ../../docs/USAGE.md
"""

from .panda import Panda, blocking
from .plog_reader import PLogReader
from .pyplugin import PyPlugin

__all__ = ['Panda', 'PLogReader', 'Callbacks', 'PyPlugin']

__pdoc__ = {}

__pdoc__['asyncthread'] = False
__pdoc__['autogen'] = False
__pdoc__['ffi_importer'] = False
__pdoc__['plog_pb2'] = False
__pdoc__['volatility_cli_classes'] = False

# The following code is soley here to allow pdoc to document callbacks
from .autogen.panda_datatypes import get_cb_docs
class Callbacks:
    '''
    The core callbacks provided by PANDA. Note this is a fake class that only exists for
    documentation.
    Importantly: the arguments listed are the arguments **your callback function will receive** and
    the return value is what **your callback must return**.

    These decorators should be accessed through a handle to a panda object, for example:

        panda = Panda(generic='x86_64')

        @panda.cb_before_block_exec
        def my_bbe_callback(cpu, tb):
            print("Before block exec!")
        ...
    '''

    def __init__(self):
        raise RuntimeError("The callbacks class is only used for documentation. Callback " \
                           "decorators should be accessed through @panda.cb_[calback_name] " \
                           "where panda is the name of your pandare.Panda() object")

cb_docs = get_cb_docs()
for cb_name, (rv, args, docstring) in cb_docs._asdict().items():
    # Add fake functions to our callbacks class with dynamic docstrings

    if cb_name == "init":
        continue
    fakename = "@panda.cb_" + cb_name

    # Add no-op function to the class
    setattr(Callbacks, fakename, lambda Your_Function: None)

    # Build argument list and reformat for pdoc from function signature
    args = args.replace(" *", "* ") # CPUState *env -> CPUState* env
    arglist = []
    for arg in args.split(","):
        arg = arg.strip()
        if " " in arg:
            typ = arg.split(" ")[0]
            name = arg[len(typ)+1:]
            arglist.append((typ, name))
        else:
            arglist.append((arg, ""))

    # Try to build argument descriptions too from text by finding lines like "argname: something\n"
    arg_desc = {}
    rv_desc = ""
    next_rv = False

    type_signature = f"{rv} (*" # To identify when we're done with useful docs

    for line in docstring.split("\n"):
        # Get arg descriptions
        for (arg_type, arg_name) in arglist:
            if f"{arg_name}:" in line:
                arg_desc[arg_name] = line.split(f"{arg_name}:")[1].strip()

        # Get return value description
        if line.startswith("Return value:"):
            next_rv = True
        elif next_rv and ":" in line or type_signature in line:
            # End when we hit something like "Notes: " or "void (*this_callback)..."
            next_rv = False
        elif next_rv:
            rv_desc += line.strip() + " "

    argnames = "\n        ".join(f"{argtype}: {argname}: {arg_desc[argname] if argname in arg_desc else ''}" for (argtype, argname) in arglist)

    # Build docstring
    full_ds = ""

    # Now we want to add the comments from the C header, but we have to avoid
    # including "Arguments:" or pdoc will stop special-formatting our above
    # arguments we worked so hard to get.
    # For now let's just grab from [name]: up until a line ending with Arguments
    # and also Notes:

    record = False
    for line in docstring.split("\n"):
        if line.strip().replace(":", "").endswith("Arguments"):
            record = False

        if 'Notes:' in line: # Include Notes: in our ouptut
            record = True
            #full_ds += "\n\n"

        if cb_name+":" in line:
            start = line.split(cb_name+":")[1]
            if len(start):
                start+= " "
            full_ds += start
            record = True
            continue

        if type_signature in line:
            record = False

        if record:
            full_ds += line + " "

    # Now add args and retval
    full_ds += f"""
    Args:
        {argnames}

    Returns:
        {rv}: {rv_desc if len(rv_desc) else 'the type your callback must return'}

    """

    __pdoc__[f"Callbacks.{fakename}"] = full_ds
