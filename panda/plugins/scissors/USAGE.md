Plugin: scissors
===========

Summary
-------

The `scissors` plugin takes a long replay and extracts out a subset of it between some starting and ending instruction count. This is very useful if you've made a replay that is very long but has some interesting portion that you want to analyze in detail.

For example, if you're doing a heavyweight analysis like taint tracking, and you know that the data you want to track isn't introduced until halfway through the replay, you can use `scissors` to snip out the latter half of the replay.

If you don't know what starting and ending instruction count contains your region of interest, you can use QEMU's debug output to determine it. Running a replay with `-d in_asm,rr` will print the rr instruction counts of each guest instruction. 

Arguments
---------

* `name`: string, defaults to "scissors". The base name of the output replay log files. E.g., using `foo` will create `foo-rr-snp` and `foo-rr-nondet.log`.
* `start`: uint64, defaults to 0. The count of the first instruction that we want included in our new replay.
* `end`: uint64, defaults to the end of the replay. The count of the last instruction that we want included in our new replay.

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

Snipping from instruction 12345 to 8675309 into `foo_reduced`:

```sh
$PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
    -panda scissors:name=foo_reduced,start=12345,end=8675309
```

Bugs
----

Sometimes scissors will produce a replay file that can't be successfully replayed. As a workaround, try adjusting the start and end values and running scissors again.
