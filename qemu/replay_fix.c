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

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "replay_fix.h"
#include "hw/boards.h"

#include "cpu.h"

struct _replay_issues replay_issues;

void fix_replay_stuff(void)
{
    if(replay_issues.fatal_error){
        assert(0);
    }
    if(0 != replay_issues.ram_size){
#if defined(TARGET_ARM) && defined(CONFIG_ANDROID)
        const char const * machinename_arm = "android_arm";
        if (0 == strncmp(current_machine->name, machinename_arm, strlen(machinename_arm) +1)){
            android_arm_resize_ram(replay_issues.ram_size);
        }
#else
        if(0){}
#endif
        else { // default
            printf("ERROR: could not reinitialize replay with %ld bytes of RAM in device %s\n",
                   replay_issues.ram_size, replay_issues.ram_name);
            assert(0);
        }
    }
}
