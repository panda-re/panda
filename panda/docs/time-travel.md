# Time-travel debugging

Time-travel debugging requires the [`checkpoint`](../plugins/checkpoint) plugin to be enabled.

To enable checkpoints and time-travel debugging, and halt the replay until a GDB client attaches,
```sh
$PANDA_PATH/build/x86_64-softmmu/qemu-system-x86_64 -replay foo -S -s -panda checkpoint
```

To attach the GDB client and load PANDA commands, run
```
gdb -x ~/panda/panda/scripts/gdbinit -ex 'target remote localhost:1234'
```

## Reverse execution
You can use `reverse-stepi` and `reverse-continue` commands, which are analogous to `step` and `continue`, to debug the guest.

Watchpoints and breakpoints should work as normal.

```
Remote debugging using localhost:1234
0xffffffff81030c64 in ?? ()
Breakpoint 1 at 0xffffffff810422d6
Continuing.

Breakpoint 1, 0xffffffff810422d6 in ?? ()
(gdb) rsi 10 <----- step back 10 instructions
0xffffffff81063e59 in ?? ()
(gdb) si 10
Breakpoint 1, 0xffffffff810422d6 in ?? ()
(gdb) b *0xffffffff81063e59
Breakpoint 2 at 0xffffffff81063e59
(gdb) rc <----- step back until breakpoint
Continuing.

Breakpoint 2, 0xffffffff81063e59 in ?? ()
(gdb)
```

## GDB commands

PANDA supports several commands inspired by Mozilla's rr project.

* `when`
During replay, `when` displays the guest instruction count
* `rrbreakpoint <instr>`
Sets a breakpoint on a guest instruction count
* `rrdelete <instr>`
Deletes a breakpoint on a guest instruction count
* `rrlist`
Lists all guest instruction count breakpoints

```
(gdb) when
2000
(gdb) rrb 3000
Added breakpoints at instructions 3000
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0xffffffff810135d2 in ?? ()
(gdb) when
3000
```

Support for more commands coming soon!
