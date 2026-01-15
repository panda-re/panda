/*!
 * @file taint2_hypercalls.h
 * @brief Support for hypercalls from the PANDA guest to the taint2 plugin.
 *
 * @note This is currently only used by LAVA. Make sure you keep this file
 * in sync between the PANDA and LAVA repositories.
 * Check the panda/include/panda/lava_hypercall_struct.h file for the struct implementation
 *
 * @author
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#pragma once

#include "qemu/osdep.h"

#ifdef __cplusplus
extern "C" {
#endif
bool guest_hypercall_callback(CPUState *cpu);
bool guest_hypercall_warning_callback(CPUState *cpu);
#ifdef __cplusplus
}
#endif
