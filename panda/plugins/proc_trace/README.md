Plugin: `proc_trace`
===========

Summary
-------

The `proc_trace` plugin uses OSI to determine whenever the guest has switched to a new process. With this information, two modes are available:

1) Dump data about the now-running process to a pandalog (through the C++ plugin in this directory)
2) Generate a visual representation of which processes ran over time (through the graph.py script in this directory).

To use the plugin in the first mode, you'll load it as a standard panda plugin: `-panda proc_trace`.
To load the plugin in  the second mode, you'll just load the `graph.py` script using snake_hook: `-panda snake_hook:files=/path/to/graph.py`

Arguments
---------

* None

Dependencies
------------

Depends on the **osi** plugin to provide OS introspection information.

APIs and Callbacks
------------------

None. This plugin simply uses OSI's `on_task_change` callback.

Example
-------

To run the `proc_trace` C++ plugin on an Ubuntu x64 recording:

```
panda-system-x86_64 -m 1G \
  -os linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr \
  -pandalog out.plog -replay trace_test -panda proc_trace
```

To generate a graph of which processes ran over time, use the `snake_hook` plugin to load graph.py:

```
panda-system-x86_64 -m 1G \
  -os linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr \
  -replay trace_test -panda snake_hook:files=graph.py
```


This will generate output like:
```
 Ins.Count PID   TID  First       Last     Names
   8244033 7     7    39191    -> 8283224  ksoftirqd/0
   8227419 884   884  112851   -> 8340270  bash
   8060353 8     8    282458   -> 8342811  rcu_sched
   7189204 1355  1355 993885   -> 8183089  bash, find
   6588162 1356  1356 1489188  -> 8077350  bash, md5sum
   4577872 350   350  124967   -> 4702839  systemd-journal
   4448539 558   571  2120743  -> 6569282  gmain
   2341708 924   924  167161   -> 2508869  systemd-resolve
   1637794 551   582  70060    -> 1707854  in:imklog
   1478152 551   583  927915   -> 2406067  rs:main Q:Reg
   1166624 151   151  2416041  -> 3582665  kworker/0:1H
    827710 506   506  197924   -> 1025634  systemd-network
    369644 279   279  3210725  -> 3580369  jbd2/sda1-8
    145075 31    31   83641    -> 228716   kworker/0:1
     83991 155   155  162163   -> 246154   kworker/0:2
     55199 2     2    142724   -> 197923   kthreadd
     52686 1353  1353 211354   -> 264040   kthreadd, kwatchdog
     52116 1354  1354 237598   -> 289714   kthreadd, kworker/0:0
      6328 5     5    77312    -> 83640    kworker/u2:0
      5833 10    10   231764   -> 237597   migration/0
PID  TID  | --------------------------------------------------------HISTORY--------------------------------------------------------| NAMES
2    2    | ▂▂                                                                                                                     | kthreadd
5    5    | ▂                                                                                                                      | kworker/u2:0
7    7    |▄  ▂                                                                                                                    | ksoftirqd/0
8    8    |    ▅        ▂▄     ▂▂▆▆▅▇▇▇▆▃         ▃▇▇▇▇ ▃▆▂       ▂▇▇▇▇▇▇▇▇▇▇▃▂          ▆▇▇▇▇▇▇▇▇▇▇▇▇▇▅▄▇▇▇▇▇▇▇▆▇▇▇▇▅▇▇▇▇▅   ▂▄▆▅ | rcu_sched
10   10   |                                                                                                                        | migration/0
31   31   | ▂▂                                                                                                                     | kworker/0:1
151  151  |                                  ▂         ▇▄  ▅▆▂                                                                     | kworker/0:1H
155  155  |                                                                                                                        | kworker/0:2
279  279  |                                               ▃▃ ▃                                                                     | jbd2/sda1-8
350  350  | ▂ ▂   ▃▂▂   ▃  ▆                 ▃    ▂           ▃▅▃▂▆                                                                | systemd-journal
506  506  |  ▃     ▂ ▃                                                                                                             | systemd-network
551  583  |             ▂▂▇        ▃    ▄  ▆▂                                                                                      | rs:main Q:Reg
551  582  |▄    ▆▇▃ ▂ ▆▇▂                                                                                                          | in:imklog
558  571  |                              ▆▇   ▂▇▇▇▂           ▃                                         ▂                          | gmain
884  884  | ▃     ▄▄▃▃▂ ▂   ▃                                                                                             ▃▇▇▇▆▄   | bash
924  924  |         ▂▃   ▂  ▂▇▇▆            ▆▂▄                                                                                    | systemd-resolve
1353 1353 |  ▂▂                                                                                                                    | kthreadd, kwatchdog
1354 1354 |   ▂                                                                                                                    | kthreadd, kworker/0:0
1355 1355 |                ▂▃   ▆▂     ▂   ▂ ▂    ▃       ▃    ▃▃                ▆▇▅                   ▂▂       ▂    ▂             | bash, find
1356 1356 |                              ▂    ▂           ▂ ▂▄▃ ▂▆           ▄▆▇▇▂ ▃▇▇▇▇▇▂                           ▂             | bash, md5sum
```
