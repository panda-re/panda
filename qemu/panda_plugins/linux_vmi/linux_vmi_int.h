#ifndef __LINUX_VMI_INT_H
#define __LINUX_VMI_INT_H

// get all the typedefs (including stucts)
#include "linux_vmi_types.h"

// Caller doesn't own the result
ProcessInfo* findProcessByPID(gpid_t pid);
// Caller doesn't own the result
ProcessInfo* findProcessByPGD(target_asid_t pgd);

#endif
