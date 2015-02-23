  
Panda Plugin-Plugin Interaction  
===============================  
  
Introduction  
------------  
  
There are at least three ways in which we can imagine wanting to have
plugins interact with one another.
    
__Way 1__: Plugin A turns Plugin B on and off.  
This is useful if B is expensive to run, computationally, and A knows
best when B should run and when not.

__Way 2__: Plugin A hands Plugin B a function to be run in B.  
In other words, A registers a callback function with B which B will
run at a some specific place.  This allows a plugin's functionality to
be abstracted away and used by other plugins to accomplish more
complex tasks with less code.

__Way 3__: Plugin A calls functions in B's API.  
These API functions might allow plugin A to change B's analysis, or
they might permit A to obtain intermediate results from B.  So, the
idea here is that A wants to control or communicate with B.

Note that Way 1 is already well supported by the functions
`panda_load_plugin` / `panda_unload_plugin` and `panda_enable_plugin` / `panda_disable_plugin`
(the former completely load or unload plugins while the latter allow to temporarily enable or
disable callbacks registered by a given plugin).  See `panda_plugin.h` for more details.

The interactions described in Ways 2 and 3, however, are tricky
because panda plugins are dynamically loaded.  Thus, even if Plugin A
has a function intended to be called by another plugin, it is painful
to obtain access to that function from Plugin B (hint: dlsym is
involved).  Further, the code necessary to iterate over a sequence of
callbacks is annoying and formulaic.  Software engineering to the
rescue!  `panda_plugin_plugin.h` provides a number of convenient
macros that simplify arranging for these two types of plugin
interaction.  Here is how to use them.


Macros to Support Plugin Callbacks. 
--------------------------------------------

There are two halves to this: creating the pluggable place in Plugin
A, and registering a callback implemented in Plugin B with Plugin A.

In order to create the pluggable place in Plugin A, you have to do
the following.

1. Determine at precisely what line in A you want callbacks to run.
Also, decide what arguments the callback functions will take.  Also
also, choose a name for the callback, e.g., `foo`.

2. Create a type for the callback function.  Put this in the .h file
for Plugin A.  If the callback's name is `foo`, then this type has to
be called `foo_t`.

3. Use the macro `PPP_RUN_CB` at the line chosen in 1.  This macro
takes all the arguments you want the callback to get, so it will look
like a function call.  But it will expand into code that runs all
callbacks registered to run there, handing each all those args.

4. In the same file you edited in 3, use the macro
`PPP_CB_BOILERPLATE` somewhere above the line decided in 1, just not
inside of a function.  This macro takes a single argument, the
callback name, and expands into a bunch of necessary code: a global
array of function pointers, an integer keeping track of how many
functions have been registered, and a pair of functions that can be
used from outside Plugin A to register callbacks.

5. In the same file you edited in 3, in the `extern "C" {` portion 
near the top of the file, add `PPP_PROT_REG_CB(foo);`. For more 
information on this, see `panda_plugin_plugin.h`.

6. Remember to `#include "panda_plugin_plugin.h"` at the top of the
edited source file.

In order to register a callback with Plugin A that is defined in
Plugin B, all you need to do is use the `PPP_REG_CB` macro in Plugin
B's init_plugin function and include Plugin A's .h file where the 
type for the callback is defined (see #2).  This macro takes three 
arguments. The first is the name of plugin A (as in, its name in the
Makefile). The second is the callback name.  The third is the function
in B that is to be registered with A.

A good example of how all this fits together can be seen in the
interaction between the `stringsearch` and `tstringsearch` plugins.
`stringsearch` is plugin A.  It has one pluggable site: when a string
match occurs.  The name of that callback is `on_ssm` for "on
stringsearch match".  Look in `stringsearch.h` to see the type
definition for the callback functions `on_ssm_t`.  Look in
`stringsearch.cpp` for the macro invocations of `PPP_RUN_CB` and
`PPP_CB_BOILERPLATE`.  `tstringsearch` is plugin B.  It contains a
function `tstringsearch_match` which it registers with `stringsearch`
via the `PPP_REG_CB` macro in order to apply taint labels to any
string match. Their powers combined, these two plugins allow us to
perform a complicated task (content-based taint labeling).


Macros to support Plugin APIs
-----------------------------

To export an API, list each function's prototype in `<plugin>_int.h` in the plugin's directory.
The apigen.py script (which is run by build.sh) will automatically find all the plugins
with those files, and generate a `<plugin>_ext.h` file for each one, in the plugin's directory.

A user simply needs to `#include "panda_plugins/<plugin>/<plugin>_ext.h"` and then
in the user's plugin's init function, call `init_<plugin>_api()`, and ensure the return value is true.

For example, to use the functions exported by the sample plugin, `#include "panda_plugins/sample/sample_ext.h"`
and call `init_sample_api()` in the calling plugin's `init_plugin()` function. The calling plugin can then call
`sample_function()` and `other_sample_function()` as if they had been linked into the calling plugin.
