#ifndef __LINUX_VMI_INT_FNS_H__
#define __LINUX_VMI_INT_FNS_H__

// get all the typedefs (including stucts)
//#include "linux_vmi_types.h"

// Caller doesn't own the result
ProcessInfo* findProcessByPID(gpid_t pid);
// Caller doesn't own the result
ProcessInfo* findProcessByPGD(target_asid_t pgd);

#endif
