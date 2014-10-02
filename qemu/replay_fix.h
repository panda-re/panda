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

#ifndef __REPLAY_FIX_H
#define __REPLAY_FIX_H

#include <stdint.h>
#include <stdbool.h>

void fix_replay_stuff(void);

struct _replay_issues {
    uint64_t ram_size;
    char* ram_name;
    bool fatal_error;    
};

extern struct _replay_issues replay_issues;

#endif //__REPLAY_FIX_H
