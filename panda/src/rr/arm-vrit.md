# What works
A basic busybox system runs with the addition of rring timers.
This was done by creating .accessfn functions for gvirt_timer ctl values. Then inserting the correct rr macro into that function.
# What is still broken
All of virtio. 
Most importantly virtio-blk and virtio-net.
virtio-blk causes a MEM_UNMAP skipped call. 
the skipped calls functions that have a record and replay macro in them. This kind of recursive call is problematic and was fixed with adding a global variable that controls if you are currently in the call stack of skipped calls. Further information is needed to know if (the offending macro)[https://github.com/panda-re/panda/blob/381301411f110b9a4df3335526f52d78f6702413/exec.c#L2908-L2947] is needed though it seems likely it is not.

# Infortmation to continue work
Most of virt-blk seems to be handle by the existing memrw skipped calls. A core funtionality breaks upon virtqueue_push which calls virtqueue_fill which calls an unmap function producing the MEM_UNMAP skipped calls. virtqueue_flush is what actually writes the divergent value. A lot of the accesses to this data is handled by MACRO glue functions. Given the large number of structures that virtqueue_push and the called functions rely on it might be easier to focus on the virtio ecosystem at the macro level.