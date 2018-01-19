Plugin: unigrams
===========

Summary
-------

The `unigrams` plugin is the better-named successor to the `textfinder` plugin. It collects unigram byte statistics (i.e., a histogram of byte values seen) for each tap point encountered in a replay, for both memory reads and writes.

The histograms for each tap point for memory reads and writes are saved to `unigram_mem_read_report.bin` and `unigram_mem_write_report.bin`, respectively. The files can be parsed with the Python code found in `scripts/unigram_hist.py`.

Arguments
---------

None.

Dependencies
------------

The `callstack_instr` plugin is used to group memory accesses into tap points.

APIs and Callbacks
------------------

None.

Example
-------

To collect unigram statistics during a replay:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr -panda unigrams

For another example of using `unigrams`, and what you can do by computing simple statistics based on the histograms it gives you, you can see the blog post [Breaking Spotify DRM with PANDA](http://moyix.blogspot.com/2014/07/breaking-spotify-drm-with-panda.html).
