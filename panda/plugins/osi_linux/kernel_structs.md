# Kernel structs quick notes

Sketch of some of the structures used for Linux OS introspection. Only relevant fields appear in the sketch. Exact offsets have to be extracted for each kernel variant using the [kernelinfo](utils/kernelinfo) module.

<big><pre style="line-height: 90%; font-size: 13px;">struct task\_struct {        /\* [sched.h][task_struct] \*/
    void \*stack;            /\* pointer to process task \*/
    struct mm\_struct \*mm {{ /\* memory descriptor: [mm_types.h][mm_struct], pp353 \*/
        pgd_t \*pgd;                     /\* page directory \*/
        struct vm\_area\_struct \*mmap {{  /\* memory regions list: [mm_types.h][vm_area_struct] \*/
            struct mm\_struct \*vm\_mm;    /\* address space we belong to (not used for OSI) \*/
            struct vm_area_struct \*vm\_next, \*vm\_prev; /\* list of VM areas, sorted by address \*/
            unsigned long vm\_start;     /\* start address within vm_mm \*/
            unsigned long vm\_end;       /\* first byte after our end within vm_mm \*/
            unsigned long vm\_flags;     /\* RWXS flags \*/
            struct file \*vm\_file {{     /\* file we map to (can be NULL): [fs.h][file], pp471 \*/
                struct path f\_path {{   /\* not pointer!: [path.h][path] \*/
                    struct vfsmount \*mnt {{    /\* mounted fs containing file: [mount.h][vfsmount], pp486 \*/
                        struct vfsmount \*mnt_parent;
                        struct dentry \*mnt_mountpoint; /\* dentry of mountpoint: [dcache.h][dentry], pp475 \*/
                        struct dentry \*mnt_root; /\* root of the mounted tree: [dcache.h][dentry], pp475 \*/
                    }};
                    struct dentry \*dentry {{    /\* where file is located on fs: [dcache.h][dentry], pp475 \*/
                        struct qstr d\_name {{   /\* not pointer!: [dcache.h][qstr] \*/
                        	unsigned int len;
                            const unsigned char \*name;
                        }};
                        unsigned char d\_iname[DNAME\_INLINE\_LEN]; /\* should not be used directly! when the name is small enough, d_name->name will point here. \*/  
                    }}; /\* dentry \*/
                }}; /\* path /*
            }}; /\* file \*/
        }}; /\* vm\_area\_struct \*/
    }}; /\* mm\_struct \*/
    struct files\_struct \*files {{ /\* open files information: [fdtable.h][files_struct], ppXXX \*/
        struct fdtable *fdt {{   /\* ??? this may point to fdtab -- VERIFY : [fdtable.h][fdtable] \*/
            struct file **fd {{  /\* current fd array: [XXX][XXX] \*/
            }};
        }};
        struct fdtable fdtab {{   /\* not pointer!: [fdtable.h][fdtable] \*/
            struct file **fd {{  /\* current fd array: [XXX][XXX] \*/
            }};
        }};
    }}; /\* files\_struct \*/
} /\* task\_struct \*/
</pre></big>

<!-- fdt seems to point to fdtab in general. for a few tasks it doesn't.
see

print the tasks where fdt does not point to fdtab:
grep lul f  | grep '0$' | awk '{print $3}' | sort | uniq -c

see if for any of these tasks, fdt points to fdtab at some point:
for t in $(grep lul f  | grep '0$' | awk '{print $3}' | sort | uniq); do grep  "lul.*$t.*1$" f; done

-->

[task_struct]: https://github.com/torvalds/linux/blob/v3.2/include/linux/sched.h#L1220
[mm_struct]: https://github.com/torvalds/linux/blob/v3.2/include/linux/mm_types.h#L289
[vm_area_struct]: https://github.com/torvalds/linux/blob/v3.2/include/linux/mm_types.h#L201
[file]: https://github.com/torvalds/linux/blob/v3.2/include/linux/fs.h#L964
[path]: https://github.com/torvalds/linux/blob/v3.2/include/linux/path.h#L7
[vfsmount]: https://github.com/torvalds/linux/blob/v3.2/include/linux/mount.h#L55
[dentry]: https://github.com/torvalds/linux/blob/v3.2/include/linux/dcache.h#L116
[qstr]: https://github.com/torvalds/linux/blob/v3.2/include/linux/dcache.h#L35
[files_struct]: https://github.com/torvalds/linux/blob/v3.2/include/linux/fdtable.h#XXX
[fdtable]: https://github.com/torvalds/linux/blob/v3.2/include/linux/fdtable.h#XXX


# The kernel task list

The kernel task list can be obtained in two ways:

1. Using `next_task_struct` which uses the global symbol for `init_task` as the starting point.
1. Using the `current_task_struct` structure. This is slightly more complicated, as the starting point (as returned from our `get_task_struct()` function can belong to either a process or a thread. In either case, it is guaranteed that the next pointer in `task_struct` will point to a process (either the next process `task_struct` or the `init_task`.

Following, is an illustration of the how the process/thread list really works. There are two fields of interest in each `task_struct`:

1. The `next` pointer that points to the next `task_struct`.
1. The `thread_group` field, which is of type struct `list_head { list_head* next, prev; }`. This means `task_struct.thread_group` will automatically give you access to the value of `next`. The tricky thing is `next` is the address of the `thread_group` field of the next `task_struct` in the same thread group. See the figure below.

For this example, lets assume that we have two running processes, 30 and 31. 31 is single threaded and 30 is multi-threaded with two additional threads 32 and 33. Given that we always have `init_task`, we should have a total of 5 `task_structs`, 1 for `init` 2 for the processes and 2 for the threads. The process list for this example would look like this:

```
,--------------------------------------------------------------------,
|     _____________          _____________          _____________    |
|---> | pid = 0   |    ,---> | pid = 30  |    ,---> | pid = 31  |    |
|     | tgid = 0  |    |     | tgid = 30 |    |     | tgid = 31 |    |
|     | next      | ---'     | next      | ---|     | next      | ---'
| ,-> | t_group   | -,   ,-> | t_group   | -, | ,-> | t_group   | --,
| |   |___________|  |  /    |___________|  | | |   |___________|   |
| '------------------' /                    | | '-------------------'
|                     / ,-------------------' |
|                    |  |    _____________    |
|                    |  |    | pid = 32  |    |
|                    |  |    | tgid = 30 |    |
|                    |  |    | next      | ---' (points to real next)
|                    |  '--> | t_group   | --,
|                    |       |___________|   |
|                    |  ,--------------------'
|                    |  |    _____________
|                    |  |    | pid = 33  |
|                    |  |    | tgid = 30 |
|                    |  |    | next      | ----, (points to init_task)
|                    |  '--> | t_group   | --, |
|                    |       |___________|   | |
|                    '-----------------------' |
'----------------------------------------------'
```

To sum up:

1. `thread_group.next` (represented by `t_group`) points to the next `thread_group` field.
1. The `next` field of a `task_struct` is guaranteed to point either to:
  * to the `task_struct` of the next process in the list.
  * the `task_struct` of the `init_task`.
1. `pid`s are always unique. This is why in the figure the `pid`s of the three threads of the multi-threaded process are 30 (the main thread), 32 and 33 (the other two threads).
1. The `tgid` field is shared between the threads of multi-threaded process, and shows the real `pid` of the process.

Note that the above example does not include the `thread_info` structure. Each `task_struct` is associated with its own `thread_info` structure which is pointed to by the `stack` field. The process stack pointer is stored in the `cpu_context` field of the `thread_info` struct. More info on the `cpu_context` and `copy_thread()` (called from `copy_process()` called from `do_fork()`) can be found in [arch/ARCH/kernel/process.c][process_c].

[process_c]: https://github.com/torvalds/linux/blob/v3.2/arch/x86/kernel/process.c
