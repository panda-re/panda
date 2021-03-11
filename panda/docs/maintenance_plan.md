# PANDA maintenance plan PROPOSAL

## Versions
Staring with version 3.0.0, PANDA will provide releases of the core analysis platform which follow semantic versioning (see [semver.org](http://semver.org) for details) with major, minor and patch versions.

Across major versions, the PANDA API may change in a backwards-incompatible way.

Across PANDA minor and patch versions, all API changes will be backwards-compatible, though plugins may need to be recompiled (i.e., names in an ENUM will not change, but their values may).

New minor versions may introduce new features.  Patches will fix bugs.

## Branches
We will maintain two primary branches of PANDA: `main` and `stable`. These branches will use semantic versioning.

1. `main`
	- Reaching this branch should be the goal of all feature development.
	- Code should reach `main` by pull requests from feature branches.
		- Scrutiny should be applied to pull request into main to ensure the changes are understood and that the pull request does not contain spurious changes.
		- At a minimum, code merged into main should build on supported operating systems and pass any existing CI tests.
	- Feature developers likely want to fork this branch to begin their work.
	- Regular releases will be sourced from this branch.
1. `stable`
	- This branch exists to support longer term development efforts
	- Periodically (currently every 12 months) a new `stable` release will be created.
		- Stable releases can always be found by the tag `panda-stable-{VERSION}`
		- The `stable` branch will always point to the most recent stable release.
	- Code in `stable` must not be updated except for the following reasons:
		- Patches that fix severe issues, like fixes for CVEs.
		- Patches that fix regressions.
	- Stable releases will be sourced from this branch.
1. Other branches
	- Most development work for PANDA will occur on feature or development branches.
	- No assumptions should be made about the state of such branches. They may not build, may break every API, etc...
	- When a developer feels their feature or update is ready, the developer may make a pull request to have it merged into `main` (or `stable` if it meats the criteria).
		- Developers are encouraged to reach out before their feature/update is ready to merge for assistance/guidance especially if the update is large or contains breaking changes.

## Schedule

We will tag a new regular release of PANDA at least every 3 months (possibly faster depending on feature accumulation). We will select a new stable release every 12 months. Support for the prior stable release will end once a new stable branch is selected. These periods may change as we experiment with our new release process. Upstream qemu tags a new stable release around every 12 months, so if we ever manage to get in sync with upstream, our stable release could slightly lag theirs (we are currently on upstream qemu version 2.9.1).

As we move to semantic versioning and better change tracking, care will be taken to avoid breaking changes where possible.

A changelog will accompany each release indicating all in the API that has been changed, both in a backwards-compatible and in a backwards-breaking manner.

## Supported Operating Systems
Each PANDA major version will have a published set of supported operating systems with versions. Removing a supported operating system will require updating the major version. Additional operating systems can be added at any time.

## The PANDA API

These are the parts of PANDA to which users will be sensitive to changes.  For intsance, a user will care if the record/replay system changes such that old recordings will no longer replay.  But she will likely not care if the `callstack_instr` plugin is changed to use a cuckoo-hashed linear array instead of a C++ map to keep track of call/ret basic blocks.

Here are the parts of PANDA we consider to be part of the API and which should only change when the major number of the `stable` release increases.
Note that when we mention a function, here, we mean the prototype to that function as well as its operation (semantics) should remain stable within a major release.

### Record / Replay
All functions and types in panda/include/panda/api/rr.h 
* Functions to determine where in a replay one is, e.g., rr_get_guest_instr_count and rr_prog_point
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

### Callbacks
All functions and types in panda/include/panda/api/callbacks.h
* The callbacks available
* The function signatures of PANDA callbacks and names in the panda_cb_type ENUM 
* Functions used to register and unregister callbacks from within plugins

Notes:
* *When* a callback fires may be changed according to our versioning scheme (e.g., a bugfix in when a callback fires would require new patch version)

### LLVM
All functions and types in panda/include/panda/api/llvm.h
[ I think this means it just includes tcg-llvm.h?)

Notes:
* The version of LLVM PANDA uses for taint and other intermediate language analyses will remain constant within a major release number

### Pandalog
All functions and types in panda/include/panda/api/plog.h
* Plog metadata (header and chunk structures)
* Functions for reading/writing/seeking through plogs

Notes:
* The Pandalog is based upon Google's protocol buffers.  Critical low-level details about protocol buffers will remain constant within a major version of Panda, including
** The version of protocol buffers used (2 vs 3)
** Slot numbering for messages or message fields
* Pandalog is chunked and encrypted.  These details will be not change except across a major revision.
* A minor revision number change may add features, and thus may add new pandalog message types.  Thus it is possible that a pandalog can only be generated and consumed by code *after* a particular minor revision number.

### Python interface
* All the functions exposed by PyPANDA in the pandare.panda class are part of the PANDA API. These functions are already documented at panda-re.github.io/panda.html.

Notes:
* PyPANDA could perhaps have its own versioning or be in its own repo

### Docker 
* The Dockerfile will not move locations without a major version change. 
* The Ubuntu version the dockerfile is based on will not change without a minor version change.

### Scripts
[Do we consider anything in panda/scripts to be part of the API?]

## Restructure and Splitting of Existing PANDA Repository

PANDA will be split into three repositories.  One contains PANDA itself and the API detailed above, another contains core plugins, and a third contains more experimental plugins.

Plugins are consumers of the APIs provided by the core of PANDA. The APIs provided by plugins are *not* described by the core PANDA version number.
To ensure plugin properly function with core PANDA, they will be able to specify which version(s) (minimum, maximum or exact) of PANDA they are known to be compatible with.

In addition to consuming the core PANDA APIs, plugins also provide APIs through PPP.
Plugins will optionally be versioned and in the future, we may support versioning requirements on plugin-to-plugin interactions (e.g., syscalls_logger depends on syscalls > v0.1).

Plugins will be split into two new repositories, `pandare/core-plugins`, and `pandare/plugins`.
The plugins committed to `core-plugins` will each follow semantic versioning and have CI testing. These are plugins that we want to provide reasonability stability guarantees for (Taint2, syscalls2, etc).
The plugins committed to the general `plugins` repository will have no such requirements but commits to the main branch will be tested with CI to ensure they compile.


