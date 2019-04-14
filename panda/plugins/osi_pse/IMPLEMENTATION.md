# Implementation notes for Process Events plugin

Hide intrinsics of process creation/destruction.
+++ ascii from asidstory +++

Allow other plugins to use either asid or taskd mappings.


## Generic Version
A naive approach for identifying the creation/destruction of processes
is register a `PANDA\_CB\_ASID\_CHANGED` callback that retrieves the
full process listing. Comparing the current process list with the list
retrieved in the previous invocation of the callback will yield the
processes that were created and destructed in the meantime.

+++ add diff symbols +++

This is a generic approach that will work independently of the
introspected operating system. But it has a couple of drawbacks:

 * It is computationally intensive. Even if we only retrieve
   `OsiProcHandle` instead of full `OsiProc` structs, calculating
   the difference of the previous and current process lists
   requires linear time. More important, this cost is paid on
   every time there is an asid change, even if no process has
   been created or destructed since the last time.
 * It is only OS-agnostic on the surface. Process descriptors (e.g.
   Linux `struct task_struct`) may be present in the process list
   before the process is ready to run. This means that `osi\_pse`
   may invoke the `on\_process\_start` callbacks prematurely,
   offloading to the plugin that uses it the responsibility to
   track when the process information becomes valid. This is
   clearly undesirable.

## Linux Version

The linux kernel is **preemptible**.

#if 0
Kernel weirdness:
    (a) Checking for new processes at the start/end of clone/vfork is
        not enough. At the start of the calls, the new process/thread
        has not been setup yet. At the return of the calls, the new
        process/thread may have already been scheduled. The latter is
        not the norm, but it is something we have already observed in
        traces.

        --> Process information should be created in a lazy fashion
        (i.e. when the process is first scheduled) rather than waiting
        for a system-call to return to update the plugin state.

Assumptions and Invariants:
    (a) Processes are tracked via `OsiProcHandle` structs.
    (b) The `procs` and `procflags` maps are indexed by the `taskd` value
        of the structs. This member is a bit more stable than `asid`, 
        which takes longer to update during process creation/destruction.
        Also, it should make easier to track threads in the future.
    (c) At all times, for each existing task there is an entry in `procflags`.
    (d) As soon as process starts exiting, it is removed from `procs` and
        the `PROCFLAGS_EXIT` flag is set.
    (e) While a process is exiting, it can still be scheduled if it has
        multiple threads. (asid?)
    (f) When the `asid` of a process is updated, we consider that the 
        process ends and a new one starts.
#endif

Some code may appear redundant. Most times this is to make explicit some
non-obvious or counter-intuitive facts and make future debugging easier.

eg LPTracker::AddNewByPPID()
The fact that a process may invoke clone() a second or even a third time
before the first created process has the opportunity to execute is 
counter-intuitive. We prefer to make this explicit by including a separate
case for LPFSM::State::INIT.


if (p.fsm.state == LPFSM::State::END) {
    // do stuff
} else if (p.fsm.state == LPFSM::State::INIT) {
    // created by recent clone() by the same parent - ignore
    continue;
} else {
    // running process with the same parent - ignore
    continue;
}

asid mapping are expected to be removed when not in use.

reset checks for invalid state by default - this helps avoiding redundant checks


### `sys_vfork`
The return handling for `sys_vfork`
`sys_vfork` 
{
// PANDA trigers the return event for sys_vfork in the
// child process context. This is the opposite of PANDA's
// behaviour for sys_clone.
//
// When sys_vfork is invoked, parent and child processes
// share the same asid. This has an important side effect:
// Since there is no need to overwrite the ASID register
// (CR3 in x86), we can't rely on PANDA_CB_ASID_CHANGED
// to detect context switches.
//
// While the child is executing, the
// parent process is expected to remain idle.
// We use aliases pchild and pparent in this context.


asid sanity checks
~ 196                     // Return of sys_vfork.
~ 197                     // Unlike with other syscalls, PANDA will not trigger
~ 198                     // this callback in the context of the calling process,
~ 199                     // but in the context of the created process. Moreover,
~ 200                     // calling (parent) process and created (child) process
~ 201                     // will be sharing their asid for a while. This means
~ 202                     // that there may be a context switch between the two
~ 203                     // without triggering PANDA_CB_ASID_CHANGED.
~_204                     // See IMPLEMENTATION.md for details.
  205                     LOG_DEBUG("VFORK");
  206                     process_info_t &pchild = p;
  207
_ 208                     // Reset process info for child process.
  209                     if (pexists) {
+ 210                         assert(pchild.fsm.state == LPFSM::State::END);
  211                         // again - can't do any sanity checks on asid mappings here
  212                         // asid may have been reused while task remains in struct
  213                         //if (lpt.asids.find(pchild.handle.asid) != lpt.asids.end()) {
  214                             //LOG_DEBUG(TARGET_PTR_FMT "->" TARGET_PTR_FMT, pchild.handle.asi
  215                             //LOG_DEBUG(TARGET_PTR_FMT ":" TARGET_PTR_FMT, h->asid, h->taskd)
  216                         //}
  217                         //assert(!lpt.asids.erase(pchild.handle.asid));
  218                         pchild.reset(cpu, h, true);
  219                         //rick pchild.vdump(cpu);
  220                     }
  221
