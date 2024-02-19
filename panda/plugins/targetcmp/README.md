Plugin: TargetCmp
===========

Summary
-------

At every function call, check the first two potential arguments to identify if it's a string pointer to a specified value. If so, examine the other pointer. If that's a string, record it's value.

The goal here is to dynamically identify values that are compared against a known string.

**WARNING**: this plugin may have a sizable impact on emulation speed. In limited testing, CLI interfaces were still usable, but were noticably slower than normal.

Arguments
---------

`output_dir`: Optional, directory to store results in. File will be created named targetcmp.txt in this directory. Current directory if unset.
`target_str`: String to search for.

Dependencies
------------

* `callstack_instr`
* `callwitharg`

APIs and Callbacks
------------------

To use `targetcmp` programatically you can use the following API functions.

```
bool add_string(const char* arg)
```
Add `arg` to the list of strings that `targetcmp` is watching for. Returns true if your string was successfully added to the list. Also returns true if your string was already in the search list.


```
bool remove_strings(const char* arg)
```
Remove `arg` from the list of strings that `targetcmp` is watching for. Returns true if your string was successfully found and removed from the list.

```
void reset_strings()
```
Remove all strings that targetcmp is watching for.


`targetcmp` provides a single callback that can be used by other plugins to take actions when a string match is found:

Name: **on_tcm**
Signature:
```C
typedef void (* on_ssm_t)(CPUState *env, char* specified_value, char* compared_value);
```

Example
-------
When tab-completing a command, linux will search the path for a given prefix. If we set our search target to whoami, we'll see when the whoami string is compared against a prefix of `wh`.

```
$(python3 -m pandare.qcows x86_64) -panda callstack_isntr -panda callwitharg -panda targetcmp:target_strings=whoami,verbose=True

root@guest# echo wh[PRESS TAB TWICE]
[TargetCMP of whoami] wh
```
