#define __STDC_FORMAT_MACROS

#include "../taint2/taint2.h"

extern "C" {

#include "rr_log.h"    
#include "qemu-common.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "pandalog.h"
#include "panda_common.h"
#include "../syscalls2/gen_syscalls_ext_typedefs_linux_x86.h"
#include "../taint/taint_ext.h"
#include "../taint2/taint2_ext.h"
#include "panda_plugin_plugin.h" 
    
    bool init_plugin(void *);
    void uninit_plugin(void *);
    
    int get_loglevel() ;
    void set_loglevel(int new_loglevel);

}

#include <vector>
#include <map>
 
double prob_label_u32 = 0;
const char *taint_filename = 0;
bool positional_labels = true;
bool use_taint2 = true;
bool no_taint = true;

#define MAX_FILENAME 256
bool saw_open = false;
uint32_t the_asid = 0;
uint32_t the_fd;

uint32_t max_num_labels = 1000000;

uint64_t first_instr = 0;

uint32_t taint_label_number_start = 0;

float pdice(float m) {
    float x = ((float)(rand())) / RAND_MAX;
    return (x<m);
}
    

std::map< std::pair<uint32_t, uint32_t>, char *> asidfd_to_filename;



void label_byte(CPUState *env, target_ulong virt_addr, uint32_t label_num) {
    printf ("label_num = %d\n");
#if 0
    if ( ! 
         ((label_num >=8 && label_num <= 15) 
          || (label_num >= 140 && label_num <= 160)) ) {
        printf (" discarding\n");
        return;
    }
    printf ("keeping\n");
#endif
    target_phys_addr_t pa = panda_virt_to_phys(env, virt_addr);
    if (pandalog) {
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.has_taint_label_virtual_addr = 1;
        ple.has_taint_label_physical_addr = 1;
        ple.has_taint_label_number = 1;
        ple.taint_label_virtual_addr = virt_addr;
        ple.taint_label_physical_addr = pa;
        if (positional_labels) {
            ple.taint_label_number = label_num;
        }
        else {
            ple.taint_label_number = 1;
        }
        pandalog_write_entry(&ple);           
    }
    if (!no_taint) {
        if (positional_labels) {
            if (use_taint2) 
                taint2_label_ram(pa, label_num);
            else 
                taint_label_ram(pa, label_num);
        }
        else {
            if (use_taint2) 
                taint2_label_ram(pa, 1);
            else 
                taint_label_ram(pa, 1);
        }
    }
}



char *last_open_filename;
uint32_t last_open_asid;

#ifdef TARGET_I386
// 5 long sys_open(const char __user *filename,int flags, int mode);
// typedef void (*on_sys_open_enter_t)(CPUState* env,target_ulong pc,target_ulong filename,int32_t flags,int32_t mode);

void open_enter(CPUState* env,target_ulong pc,target_ulong filename,int32_t flags,int32_t mode) {
    uint32_t i;
    char the_filename[MAX_FILENAME];
    the_filename[0] = 0;
    for (i=0; i<MAX_FILENAME; i++) {
        uint8_t c;
        panda_virtual_memory_rw(env, filename+i, &c, 1, 0);
        the_filename[i] = c;
        if (c==0) {            
            break;
        }
    }
    the_filename[MAX_FILENAME-1] = 0;
    if (i != 0 ) {
        printf ("saw open of [%s]\n", the_filename);
    }
    if (i == strlen(taint_filename)) {
        if (strncmp(the_filename, taint_filename, strlen(the_filename)) == 0) {
            saw_open = true;
            printf ("saw open of file we want to taint: [%s]\n", taint_filename);
            the_asid = panda_current_asid(env);
        }
    }
}


void open_return(CPUState* env,target_ulong pc,target_ulong filename,int32_t flags,int32_t mode) {
    //    printf ("returning from open\n");
    if (saw_open && the_asid == panda_current_asid(env)) {
        saw_open = false;
        // get return value, which is the file descriptor for this file
        the_asid = panda_current_asid(env);
        the_fd = EAX;
        printf ("saw return from open of [%s]: asid=0x%x  fd=%d\n", taint_filename, the_asid, the_fd);
    }
            
}
   

uint32_t the_buf;
uint32_t the_count;
bool saw_read = false;

uint32_t last_read_fd;
uint32_t last_read_count;
uint32_t last_read_buf;

void read_enter(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) { 
    uint32_t asid = panda_current_asid(env);
    char *filename = 0;
    if (asidfd_to_filename.count(std::make_pair(asid, fd)) != 0) {
        filename = asidfd_to_filename[std::make_pair(asid, fd)];
    }
    if (filename !=0) {
        printf ("filename = [%s]\n", filename);
    }
    else {
        printf ("filename is not known\n");
    }

    // these things are only known at enter of read call
    last_read_fd = fd;
    last_read_count = count;
    last_read_buf = buf;

    if (asid == the_asid && fd == the_fd) {
        printf ("saw read of %d bytes in file we want to taint\n", count);
        saw_read = true;
    }
}




uint32_t bytes_labeled = 0;

// 3 long sys_read(unsigned int fd, char __user *buf, size_t count);
// typedef void (*on_sys_read_return_t)(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count);
void read_return(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) { 
    if (saw_read && panda_current_asid(env) == the_asid) {
        count = EAX;
        printf ("count=%d\n", count);
        
        printf ("returning from read of [%s] count=%d\n", taint_filename, count);    
        printf ("*** applying %s taint labels %d..%d to buffer\n",
                positional_labels ? "positional" : "uniform",
                taint_label_number_start, taint_label_number_start + count - 1);
        if (prob_label_u32 == 0 && bytes_labeled < max_num_labels) {
            for (uint32_t i=0; i<count; i++) {
                label_byte(env, last_read_buf+i, taint_label_number_start + i);
                bytes_labeled ++;
                if (bytes_labeled > max_num_labels) {
                    printf ("reached max_num_labels bytes labeled\n");
                    break;
                }
            }
        }
        else {
            // iterate over uint32 blobs
            for (uint32_t i=0; i<count/4; i++) {
                if (pdice(prob_label_u32)) {
                    uint32_t label_num = taint_label_number_start + i*4;
                    printf ("labeling uint32 %d..%d\n", i*4, i*4+3);
                    // we will label this uint32
                    for (uint32_t j=0; j<4; j++) {
                        uint32_t offset = i*4 + j;
                        label_byte(env, last_read_buf + offset, label_num);
                    }
                }
            }
        }
        taint_label_number_start += count;
        printf (" ... done applying labels\n");
        saw_read = false;
    }


}
#endif

extern uint64_t replay_get_guest_instr_count(void);
bool taint_is_enabled = false;

int file_taint_enable(CPUState *env, target_ulong pc) {
    if (!no_taint && !taint_is_enabled) {
        uint64_t ins = replay_get_guest_instr_count();
        //        printf ("ins= %" PRId64 "  first_ins = %" PRId64" %d\n",
        //                ins, first_instr, (ins > first_instr) );

        if (ins > first_instr) {
            
            taint_is_enabled = true;
            if (use_taint2) {
                printf ("enabling taint2");
                taint2_enable_taint();
            }
            else {
                taint_enable_taint();
                printf ("enabling taint");
            }
            printf (" @ ins  %" PRId64 "\n", ins); 
        }
    }
    return 0;
}

bool init_plugin(void *self) {

    printf("Initializing plugin file_taint\n");

    panda_arg_list *args;
    args = panda_get_args("file_taint");
    taint_filename = panda_parse_string(args, "filename", "abc123");
    positional_labels = panda_parse_bool(args, "pos");
    use_taint2 = !panda_parse_bool(args, "taint1");
    // used to just find the names of files that get 
    no_taint = panda_parse_bool(args, "notaint");
    prob_label_u32 = panda_parse_double(args, "prob_label_u32", 0.0);
    max_num_labels = panda_parse_ulong(args, "max_num_labels", 1000000);
    first_instr = panda_parse_uint64(args, "first_instr", 0);

    printf ("taint_filename = [%s]\n", taint_filename);
    printf ("positional_labels = %d\n", positional_labels);
    printf ("use_taint2 = %d\n", use_taint2);
    printf ("no_taint = %d\n", no_taint);
    printf ("prob_label_u32 = %.3f\n", prob_label_u32);
    printf ("max_num_labels = %d\n", max_num_labels);
    printf ("first_instr = %" PRId64 " \n", first_instr);

    panda_require("syscalls2");

    // this sets up the taint api fn ptrs so we have access
    if (!no_taint) {
        if (use_taint2) {
            panda_require("taint2");
            assert(init_taint2_api());
            if (first_instr == 0) {
                taint2_enable_taint();
            }
        } else {
            panda_require("taint");
            assert(init_taint_api());
            if (first_instr == 0) {
                taint_enable_taint();
            }
        }
    }
    
    panda_cb pcb;        

    if (first_instr > 0) {
        // only need this callback if we are turning on taint late
        pcb.before_block_translate = file_taint_enable;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
    }

#if defined(TARGET_I386)
            
    PPP_REG_CB("syscalls2", on_sys_open_enter, open_enter);
    PPP_REG_CB("syscalls2", on_sys_open_return, open_return);
    
    PPP_REG_CB("syscalls2", on_sys_read_enter, read_enter);
    PPP_REG_CB("syscalls2", on_sys_read_return, read_return);

#endif
    return true;
}



void uninit_plugin(void *self) {
}

