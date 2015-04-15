PANDA-Volatility interface
===
A set of interfaces that allows PANDA to use Volatility, and also to allow Volatility
to access memory of the VM while live or during a replay.

Volatility interface
---
Provides an interface that allows plugins to programmatically use and retrieve output
from Volatility.

QemuMemoryAccess Volatility address space
---
This address space allows volatility to read a VM's memory while it is running.

It uses the request structure format defined in
[memory-access.c](../qemu/memory-access.c),
and communicates through a UNIX socket.

Installation
---
Copy or symlink [pmemaddressspace.py](pmemaddressspace.py) into `$VOLATILITY/volatility/plugins/addrspaces`

Copy or symlink panda_vol_int_pb2.py, once it is built, into `$VOLATILITY/volatility/plugins`

Usage
---
*Volatility interface*

Include [volatility_interface.h](../qemu/volatility_interface.h).

Then call `vol_run_cmd(command, unix_socket, profile)`. 
This will return a list of protobuf data output by volatility. You can iterate over 
this list and have protobuf-c unpack the data for you.

Example for linux_pslist:

*Ensure that `render_protobuf` is available to linux_pslist in volatility*
```
time_t start_time;
VolatilityRender__LinuxPslistTask *task = NULL;
// Run volatility
vol_ll_node *list_ptr =
    vol_run_cmd("linux_pslist", "/tmp/pmem", "Linuxdebian-2_6_32-5-amd64x64");
// Print header
fprintf(stdout, "%-19s%-21s%-16s%-16s%-7s%-19s%s\n", "offset", "name","pid", "uid", "gid",
        "dtb", "start time");
// Print process info
while (list_ptr != NULL) {
    // Unpack protobuf data to a struct
    task = volatility_render__linux_pslist_task__unpack(NULL, list_ptr->data_size,
                                                        list_ptr->data_ptr);
    start_time = task->start_time;
    fprintf(stdout, "0x%016"PRIx64" %-21s%-16u%-16u%-7u",
            task->offset, task->name, task->pid, task->uid, task->gid);
    if (task->dtb == -1)
        fprintf(stdout, "%s", "------------------");
    else
        fprintf(stdout, "0x%016"PRIx64, task->dtb);
    fprintf(stdout, " %s", asctime(localtime(&start_time)));
    // Get next entry in list
    list_ptr = list_ptr->next_ptr;
}

```

*Volatility stand-alone*

Run qemu as you normally would, and send `pmemaccess /path/to/socket` to the
qemu monitor. This will start the memory-access server and create the UNIX socket 
for use by volatility.

Then run volatility:
`
python vol.py [plugin] -f [/path/to/socket] --profile=[profile]
`

Support for more commands
---
To add support for new commands, define a format in
[panda_vol_int.proto](panda_vol_int.proto) and add a `render_protobuf` function
to the commond in volatility.

Example for linux_pslist:

Protobuf format:
```
message linux_pslist_task {
  optional uint64 offset = 1;
  optional string name = 2;
  optional uint32 pid = 3;
  optional uint32 uid = 4;
  optional uint32 gid = 5;
  optional uint64 dtb = 6;
  optional uint64 start_time = 7;
}
```

Volatility render function:
```
def render_protobuf(self, outfd, data):
    uint64 = 0xffffffffffffffff
    uint32 = 0xffffffff
    for task in data:
        if task.mm.pgd == None:
            dtb = task.mm.pgd
        else:
            dtb = self.addr_space.vtop(task.mm.pgd) or task.mm.pgd
        ptask = linux_pslist_task()
        ptask.offset = int(task.obj_offset) & uint64
        ptask.name = str(task.comm)
        ptask.pid = int(task.pid) & uint32
        ptask.uid = int(task.uid) & uint32
        ptask.gid = int(task.gid) & uint64
        ptask.dtb = int(Address(dtb)) & uint64
        ptask.start_time = int(task.get_task_start_time()) & uint6
        tmp = ptask.SerializeToString()
        try:
            outfd.write(struct.pack("<I", len(tmp))+tmp)
        except:
            pass
```
