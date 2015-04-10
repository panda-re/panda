
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
        if (ple->instr == -1) {
            printf ("[after replay end] : ");
        } 
        else {
            printf ("instr=%" PRIu64 " pc=0x%" PRIx64 " :", ple->instr, ple->pc);
        }

        // from asidstory / osi
        if (ple->has_asid) {
            printf (" asid=%" PRIx64, ple->asid);
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
            printf (" va=0x%" PRIx64, ple->taint_label_virtual_addr);
        }
        if (ple->has_taint_label_physical_addr) {
            printf (" pa=0x%" PRIx64 , ple->taint_label_physical_addr);
        }

        if (ple->n_callstack > 0) {
            printf (" callstack=(%u,[", (uint32_t) ple->n_callstack);
            uint32_t i;
            for (i=0; i<ple->n_callstack; i++) {
                printf (" 0x%" PRIx64 , ple->callstack[i]);
                if (i+1 < ple->n_callstack) {
                    printf (",");
                }
            }
            printf ("])");
        }

        if (ple->attack_point) {
            Panda__AttackPoint *ap = ple->attack_point;
            printf (" attack point: info=[%s]", ap->info);
        }

        if (ple->src_info) {
            Panda__SrcInfo *si = ple->src_info;
            printf (" src info filename=[%s] astnode=[%s] linenum=%d",
                    si->filename, si->astnodename, si->linenum);
        }

        if (ple->has_tainted_branch && ple->tainted_branch) {
            printf (" tainted branch");
        }
        if (ple->taint_query_hypercall) {
            Panda__TaintQueryHypercall *tqh = ple->taint_query_hypercall;
            printf (" taint query hypercall(buf=0x%" PRIx64 ",len=%u,num_tainted=%u)", tqh->buf, tqh->len, tqh->num_tainted);
        }
        if (ple->has_tainted_instr && ple->tainted_instr) {
            printf (" tainted instr");
        }

        // dead data
        if (ple->n_dead_data > 0) {
            printf ("\n");
            uint32_t i;
            for (i=0; i<ple->n_dead_data; i++) {
                printf (" dead_data(label=%d,deadness=%.2f\n", i, ple->dead_data[i]);
            }
        }

        // taint queries
        if (ple->taint_query_unique_label_set) {
            printf (" taint query unqiue label set: ptr=%" PRIx64" labels: ", ple->taint_query_unique_label_set->ptr);
            uint32_t i;
            for (i=0; i<ple->taint_query_unique_label_set->n_label; i++) {
                printf ("%d ", ple->taint_query_unique_label_set->label[i]);
            }
        }
        
        if (ple->taint_query) {
            Panda__TaintQuery *tq = ple->taint_query;
            printf (" taint query: labels ptr %" PRIx64" tcn=%d ", tq->ptr, tq->tcn);
        }

        // win7proc
        if (ple->new_pid) { 
            printf (" new_pid ");
            print_process(ple->new_pid);
        }
        if (ple->nt_create_user_process) {
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
        if (ple->nt_terminate_process) {
            printf (" nt_terminate_process ");
            printf (" [ cur " ); 
            print_process(ple->nt_terminate_process->cur_p);
            printf (" ]");
            printf (" [ term " ); 
            print_process(ple->nt_terminate_process->term_p);
            printf (" ]");
        }

        if (ple->nt_create_file) {
            printf (" nt_create_file ");
            print_process_file(ple->nt_create_file);
        }

        if (ple->nt_read_file) {
            printf (" nt_read_file ");
            print_process_file(ple->nt_read_file);
        }
        if (ple->nt_delete_file) {
            printf (" nt_delete_file ");
            print_process_file(ple->nt_delete_file);
        }
        if (ple->nt_write_file) {
            printf ("nt_write_file ");
            print_process_file(ple->nt_write_file);
        }
        if (ple->nt_create_key) {
            printf (" nt_create_key ");
            print_process_key(ple->nt_create_key);
        }
        if (ple->nt_create_key_transacted) {
            printf (" nt_create_key_transacted ");
            print_process_key(ple->nt_create_key_transacted);
        }
        if (ple->nt_open_key) {
            printf (" nt_open_key ");
            print_process_key(ple->nt_open_key);
        }
        if (ple->nt_open_key_ex) {
            printf (" nt_open_key_ex ");
            print_process_key(ple->nt_open_key_ex);
        }
        if (ple->nt_open_key_transacted) {
            printf (" nt_open_key_transacted ");
            print_process_key(ple->nt_open_key_transacted);
        }
        if (ple->nt_open_key_transacted_ex) {
            printf (" nt_open_key_transacted_ex ");
            print_process_key(ple->nt_open_key_transacted_ex);
        }
        if (ple->nt_delete_key) {
            printf (" nt_delete_key ");
            print_process_key(ple->nt_delete_key);
        }
        if (ple->nt_query_key) {
            printf (" nt_query_key ");
            print_process_key(ple->nt_query_key);
        }
        if (ple->nt_query_value_key) {
            printf (" nt_query_value_key ");
            print_process_key_value(ple->nt_query_value_key);
        }
        if (ple->nt_delete_value_key) {
            printf (" nt_delete_value_key ");
            print_process_key_value(ple->nt_delete_value_key);
        }
        if (ple->nt_set_value_key) {
            printf (" nt_set_value_key ");
            print_process_key_value(ple->nt_set_value_key);
        }
        if (ple->nt_enumerate_key) {
            printf (" nt_enumerate_key ");
            print_process_key_index(ple->nt_enumerate_key);
        }
        if (ple->nt_enumerate_value_key) {
            printf (" nt_enumerate_value_key ");
            print_process_key_index(ple->nt_enumerate_value_key);
        }

        printf ("\n");
        panda__log_entry__free_unpacked(ple, NULL);
    }
}
