/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
#ifndef __PANDA_PLUGIN_H__
#define __PANDA_PLUGIN_H__

#include "panda/debug.h"
#include "panda/cheaders.h"

#ifndef CONFIG_SOFTMMU
#include "linux-user/qemu-types.h"
#include "thunk.h"
#endif


#ifdef __cplusplus
extern "C" {
#endif

// typedef enum of callback numbers
// list union that contains all the prototypes
// trying to keep this in one place
#include "panda_callback_list.h"

// plugin and callback mgmt stuff 
// fns and efs from panda/src/callabcks.c
#include "panda_plugin_mgmt.h"

// stuff to do with panda arg parsing
#include "panda_args.h"

// panda api includes things like enabling precise pc and llvm
#include "panda_api.h"

// some externed things for dealing with os
#include "panda_os.h"

#include "panda_common.h"

#ifdef __cplusplus
}
#endif

#include "panda/plugin_plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "panda/rr/rr_log.h"
#include "panda/plog.h"
#include "panda/addr.h"

#ifdef __cplusplus
}
#endif


#endif
