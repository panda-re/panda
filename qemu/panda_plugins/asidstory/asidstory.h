#ifndef __ASIDSTORY_H_
#define __ASIDSTORY_H_

// the type for the ppp callback for when asidstory decides a process has changed
// and we have decent OsiProc.
typedef void (* on_proc_change_t)(CPUState *env, target_ulong asid, OsiProc *proc);


#endif 
