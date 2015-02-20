
// cd panda/qemu
// g++ -g -o pandalog_reader pandalog_reader.c pandalog.c pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c -I .. -lz -D PANDALOG_READER

#define __STDC_FORMAT_MACROS


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "pandalog.h"


void print_process(Panda__Process *p) {
    printf ("(%d, %s)", p->pid, p->name);
}

void print_process_file(Panda__ProcessFile *pf) {
    print_process(pf->proc);
    printf (" filename=[%s]", pf->filename);
}

        
void print_process_key(Panda__ProcessKey *pk) {
    print_process(pk->proc);
    printf (" key=[%s] ", pk->keyname);
}


void print_process_key_value(Panda__ProcessKeyValue *pkv) {
    print_process_key(pkv->pk);
    printf (" value = [%s] ", pkv->value_name);            
}


void print_process_key_index(Panda__ProcessKeyIndex *pki) {
    print_process_key(pki->pk);
    printf (" index = [%u] ", pki->index);            
}



int main (int argc, char **argv) {
    pandalog_open(argv[1], "r");
    Panda__LogEntry *ple;
    while (1) {
        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        printf ("instr=%lld  pc=0x%x : ", ple->instr, ple->pc);

        // from asidstory / osi
        if (ple->has_asid) {
            printf (" asid=%x", ple->asid);
        }

        if (ple->has_process_id != 0) {
            printf (" pid=%d", ple->process_id);
        }
        if (ple->process_name != 0) {
            printf (" process=[%s]", ple->process_name);
        }

        // from file_taint
        if (ple->has_taint_label_number) {
            printf (" tl=%d", ple->taint_label_number);
        }
        if (ple->has_taint_label_virtual_addr) {
            printf (" va=0x%llx", ple->taint_label_virtual_addr);
        }
        if (ple->has_taint_label_physical_addr) {
            printf (" pa=0x%llx", ple->taint_label_physical_addr);
        }

        // from tainted_branch
        if (ple->n_tainted_branch_label > 0) {
            printf (" tb=(%d,[", ple->n_tainted_branch_label);
            uint32_t i;
            for (i=0; i<ple->n_tainted_branch_label; i++) {
                printf (" %d", ple->tainted_branch_label[i]);
                if (i+1 < ple->n_tainted_branch_label) {
                    printf (",");
                }
            }
            printf ("])");
        }
        if (ple->n_callstack > 0) {
            printf (" cs=(%d,[",ple->n_callstack);
            uint32_t i;
            for (i=0; i<ple->n_callstack; i++) {
                printf (" 0x%llx", ple->callstack[i]);
                if (i+1 < ple->n_callstack) {
                    printf (",");
                }
            }
            printf ("])");
        }

        // win7proc
        if (ple->new_pid) { 
            printf (" new_pid ");
            print_process(ple->new_pid);
        }
        else if (ple->nt_create_user_process) {
            printf (" nt_create_user_process ");
            printf (" [ cur " ); 
            print_process(ple->nt_create_user_process->cur_p); 
            printf (" ]");
            printf (" [ new " ); 
            print_process(ple->nt_create_user_process->new_p); 
            printf (" ]");
            printf (" name=[%s] ", 
                    ple->nt_create_user_process->new_long_name);
        }
        else if (ple->nt_terminate_process) {
            printf (" nt_terminate_process ");
            printf (" [ cur " ); 
            print_process(ple->nt_terminate_process->cur_p);
            printf (" ]");
            printf (" [ term " ); 
            print_process(ple->nt_terminate_process->term_p);
            printf (" ]");
        }

        else if (ple->nt_create_file) {
            printf (" nt_create_file ");
            print_process_file(ple->nt_create_file);
        }

        else if (ple->nt_read_file) {
            printf (" nt_read_file ");
            print_process_file(ple->nt_read_file);
        }
        else if (ple->nt_delete_file) {
            printf (" nt_delete_file ");
            print_process_file(ple->nt_delete_file);
        }
        else if (ple->nt_write_file) {
            printf ("nt_write_file ");
            print_process_file(ple->nt_write_file);
        }
        else if (ple->nt_create_key) {
            printf (" nt_create_key ");
            print_process_key(ple->nt_create_key);
        }
        else if (ple->nt_create_key_transacted) {
            printf (" nt_create_key_transacted ");
            print_process_key(ple->nt_create_key_transacted);
        }
        else if (ple->nt_open_key) {
            printf (" nt_open_key ");
            print_process_key(ple->nt_open_key);
        }
        else if (ple->nt_open_key_ex) {
            printf (" nt_open_key_ex ");
            print_process_key(ple->nt_open_key_ex);
        }
        else if (ple->nt_open_key_transacted) {
            printf (" nt_open_key_transacted ");
            print_process_key(ple->nt_open_key_transacted);
        }
        else if (ple->nt_open_key_transacted_ex) {
            printf (" nt_open_key_transacted_ex ");
            print_process_key(ple->nt_open_key_transacted_ex);
        }
        else if (ple->nt_delete_key) {
            printf (" nt_delete_key ");
            print_process_key(ple->nt_delete_key);
        }
        else if (ple->nt_query_key) {
            printf (" nt_query_key ");
            print_process_key(ple->nt_query_key);
        }
        else if (ple->nt_query_value_key) {
            printf (" nt_query_value_key ");
            print_process_key_value(ple->nt_query_value_key);
        }
        else if (ple->nt_delete_value_key) {
            printf (" nt_delete_value_key ");
            print_process_key_value(ple->nt_delete_value_key);
        }
        else if (ple->nt_set_value_key) {
            printf (" nt_set_value_key ");
            print_process_key_value(ple->nt_set_value_key);
        }
        else if (ple->nt_enumerate_key) {
            printf (" nt_enumerate_key ");
            print_process_key_index(ple->nt_enumerate_key);
        }
        else if (ple->nt_enumerate_value_key) {
            printf (" nt_enumerate_value_key ");
            print_process_key_index(ple->nt_enumerate_value_key);
        }
        else {
            printf ("unrecognized!\n");
        }

        printf ("\n");
        panda__log_entry__free_unpacked(ple, NULL);
    }
}
