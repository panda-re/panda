Plugin: fdtracker
===========

Summary
-------

`fdtracker` watches system calls and their return values to track what file descriptors map to what filenames.

**WARNING**: This plugin depends on the `syscalls` plugin, which is deprecated in favor of `syscalls2`. It needs to be updated to work with `syscalls2`, but this hasn't happened yet because support for out parameters in `syscalls2` for Linux is broken. It also relies on the deprecated `taint` plugin, 

Arguments
---------

* `taint`: boolean that controls whether fdtracker will log extra information about file operations that deal with tainted data

Dependencies
------------

Uses `syscalls` to track the various system calls that work with file descriptors (Linux-only), and the `linux_vmi` plugin to get Linux-specific VMI information (used for tracking file descriptors across calls to `clone()` and `fork()`.

APIs and Callbacks
------------------

`fdtracker` provides the following API:
    
    // Gets the filename corresponding to a given taint label
    const char *fdtracker_get_fd_name(uint32_t taint_label);

Example
-------

FIXME
