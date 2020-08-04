Plugin: signal

===========

Summary
-------

Linux process-to-process signal interception:

* Log the 5 tuple (`sig_num`, `suppressed_bool`, `src_proc_name`, `dst_proc_name`, `src_pid`, `dst_pid`) to PANDALOG (serialized binary format).
* Optionally suppress signals globally (by number) or for a specific process (by number and process name)

Arguments
---------

None

Dependencies
------------

* `syscalls2`
* `osi_linux`

APIs and Callbacks
------------------

Block a signal for all processes:
```C
void block_sig(int32_t sig);
```

Block a signal only for a named process
```C
void block_sig_by_proc(int32_t sig, char* proc_name);
```

Python Example
-------

```python
# Block SIGSEGV for one process
proc_name = 'my_proc_name'.encode('ascii')
panda.plugins['signal'].block_sig_by_proc(11, proc_name)

# Block SIGABRT for the entire system
panda.plugins['signal'].block_sig(6)
```

See [`test/run.py`](./test/run.py) for full, runnable test.