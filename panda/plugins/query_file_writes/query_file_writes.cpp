



#define __STDC_FORMAT_MACROS

#include <string>

#include "panda/plugin.h"
#include "taint2/taint2.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "osi_linux/osi_linux_ext.h"

#include "taint2/taint2_ext.h"

extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
}

#include <iostream>
#include<set>

using namespace std;



static string target_filename = "";

// used to collect labels via iterator
set<TaintLabel> all_labels;

// taint2_labelset_ram_iter  helper 
int collect_labels(TaintLabel l, void *stuff) {
    all_labels.insert(l);
    return 0;
}



void before_write(CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count) {

    static uint8_t read_buf[128];
    if (!taint2_enabled()) return;

    OsiProc *proc = get_current_process(cpu);

    cout << "Write from process " << proc->name << " of " << count << " bytes\n";

    if (0 != strcmp(proc->name,"python3")) return;


/*
    // The filename in Linux should always be absolute.
    char *filename = osi_linux_fd_to_filename(cpu, proc, fd);
    if (filename != NULL) {
        // unable to figure out filename -- can't query taint
        return;
    }

    cout << "write. filename=" << filename << " count=" << count << "\n";
    
    // make sure its the right fileanme
    string sfilename = string(filename);
    if ( string::npos == sfilename.find(target_filename))
        return;
*/
    
    if (count != 38) return;
    
    cout << "** MATCH\n";
            
    int count128max = (count > 128) ? (128) : count;

    panda_virtual_memory_read(cpu, buf, read_buf, count128max);
    cout << "first part of write: [";
    for (int i=0; i<count128max; i++) {
        if (isprint(read_buf[i])) 
            cout << read_buf[i];
        else 
            cout << ".";
    }   

    cout << "Querying buf @ " << hex << buf << "\n";
    int num_tainted = 0;
    for (int i=0; i<count; i++) {
        hwaddr shadow_addr = panda_virt_to_phys(cpu, buf + i);
        if (shadow_addr == (hwaddr)(-1)) {
            // can't query 
        }
        else {
            if (taint2_query_ram(shadow_addr)) {
                num_tainted ++;
                // collect labels for this read 
                cout << "labels on byte " << i << " : ";
                all_labels.clear();
                taint2_labelset_ram_iter(shadow_addr, collect_labels, NULL);
                for (auto l : all_labels) 
                    cout << l << " ";
                cout << "\n";
            }
        }
    }
    cout << "** " << num_tainted << " tainted\n";
            



}


bool init_plugin(void *self)
{
    panda_require("osi");
    assert(init_osi_api());

    // Parse arguments for file_taint
    panda_arg_list *args = panda_get_args("query_file_writes");
    target_filename =
        panda_parse_string_req(args, "filename", "name of file for which we will query writest");
    
    
    // Setup dependencies

    panda_require("syscalls2");
    assert(init_syscalls2_api());

    panda_require("taint2");
    assert(init_taint2_api());

    // OS specific setup
    switch (panda_os_familyno) {
    case OS_WINDOWS: {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
        cout << "No support for windows file write querying\n";
        return false;        
#endif
    } break;
    case OS_LINUX: {
#if defined(TARGET_X86_64)
        PPP_REG_CB("syscalls2", on_sys_write_enter, before_write);
#endif
    } break;
    default: {
        cout << "No support for OS\n";
        return false;
    }
    }        

    return true;
}


void uninit_plugin(void *self) {
}
