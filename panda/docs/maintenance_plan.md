#PANDA maintenance plan PROPOSAL

## Versions
Staring with version 3.0.0, PANDA will provide stable releases of the core analysis platform which follow semantic versioning (see semver.org for details) with major, minor and patch versions. Across major versions, the PANDA API will change in a backwards-incompatible way. 

Across PANDA minor and patch versions, all API changes will be backwards-compatible, though plugins may need to be recompiled (i.e., names in an ENUM will not change, but their values may).

## Branches
We will maintain two primary branches of PANDA: `stable` and `development`.

1. `stable` branch with semantic versioning. This is probably the one you want if you are using PANDA. Updates to this branch are tagged with *major*, *minor*, and *patch* version upon check-in. If you don’t know what these mean: 
- major breaks PANDA’s API somehow (see below for what that means)
- minor adds functionality but no change to API
- patch fixes something but no change to API

Notes about the `stable` branch.
- Every version compiles  
- Every version passes all of the PANDA and qemu regression tests
- Last commit to each major version will be tagged in the git repo as `stable-major.minor.patch` 

2. `development` branch with no versioning.  The head of this branch will always be a (possibly unstable) version of the current head of the `stable` branch, perhaps several commits ahead.  

Notes about the `development` branch.
- Every version compiles

There are obviously going to be other branches.  But we make no guarantees about any of them.

## The PANDA API

These are the parts of PANDA to which users will be sensitive to changes.  For intsance, a user will care if the record/replay system changes such that old recordings will no longer replay.  But she will likely not care if the `callstack_instr` plugin is changed to use a cuckoo-hashed linear array instead of a C++ map to keep track of call/ret basic blocks.

Here are the parts of PANDA we consider to be part of the API and which should only change when the major number of the `stable` release increases.
Note that when we mention a function, here, we mean the prototype to that function as well as its operation (semantics) should remain stable within a major release.

### Record / Replay
All functions and types in panda/include/panda_api_rr.h 
* Function to determine where in a replay one is, e.g., rr_get_guest_instr_count and rr_prog_point
* Functions to control record and replay, e.g., rr_do_begin_record, rr_do_end_record,  rr_do_begin_replay, and rr_do_end_replay

Notes:
* An additional, top-level, constraint here is that recordings created with any version within a major release should all replay with any version on the major release.
* Recordings MAY be compatable across major versions but this will not always be the case.

### Qemu
All functions and types in panda/include/panda/api/qemu.h
* Functions that influence qemu operation such as `panda_do_flush_tb` and `panda_break_main_loop`
* Functions that access qemu data such as `panda_current_pc` and `panda_current_asid`

### Plugins
All functions and types in panda/include/panda/api/plugins.h
* Functions used to load, unload, enable and disable plugins
* Functions to access and manipulate plugin arguments
* Functions for parsing arguments to plugins
* Functions for registering or using Plugin-to-Plugin (PPP) interfaces
* plugin.h, plugin-plugin.h

### Callbacks
All functions and types in panda/include/panda/api/callbacks.h
* The callbacks available
* The function signatures of PANDA callbacks and names in the panda_cb_type ENUM (include/panda/callbacks/cb-defs.h)
* The utility functions used to register and unregister callbacks from within plugins
* Note *when* a callback fires may be changed according to our versioning scheme (e.g., a bugfix in when a callback fires would require new patch version)

### LLVM
All functions and types in panda/include/panda/api/llvm.h
[ I think this means it just includes tcg-llvm.h?)

Notes:
* The version of LLVM PANDA uses for taint and other intermediate language analyses will remain constant within a major release number

### Pandalog
All functions and types in panda/include/panda/api/plog.h
* Plog metadata (header and chunk structures)
* The functions available for reading/writing/seeking through plogs
* Relevant files: plog-cc.hpp, plog-cc-bridge.h

Notes:
* The Pandalog is based upon Google's protocol buffers.  Critical low-level details about protocol buffers will remain constant within a major version of Panda, including
** The version of protocol buffers used (2 vs 3)
** Slot numbering for messages or message fields

### Python interface
* All the functions exposed by PyPANDA in the pandare.panda class are part of the PANDA API. These functions are already documented at panda-re.github.io/panda.html.

Notes:
    PyPANDA could perhaps have its own versioning or be in its own repo?

### Docker 
* The Dockerfile will not move locations without a major version change. 
* The Ubuntu version the dockerfile is based on will not change without a minor version change.

### Scripts
Do we consider anything in panda/scripts to be part of the API?

## Restructure and Splitting of Existing PANDA Repository

PANDA will be split into three repositories.  One contains PANDA itself and the API detailed above, another contains core plugins, and a third contains more experimental plugins.

Plugins are consumers of the APIs provided by the core of PANDA. The APIs provided by plugins are *not* described by the core PANDA version number.
To ensure plugin properly function with core PANDA, they will be able to specify which version(s) (minimum, maximum or exact) of PANDA they are known to be compatible with.

In addition to consuming the core PANDA APIs, plugins also provide APIs through PPP.
Plugins will optionally be versioned and in the future, we may support versioning requirements on plugin-to-plugin interactions (e.g., syscalls_logger depends on syscalls > v0.1).

Plugins will be split into two new repositories, `pandare/core-plugins`, and `pandare/plugins`.
The plugins committed to `core-plugins` will each follow semantic versioning and have CI testing. These are plugins that we want to provide reasonability stability guarantees for (Taint2, syscalls2, etc).
The plugins committed to the general `plugins` repository will have no such requirements but commits to the main branch will be tested with CI to ensure they compile.


