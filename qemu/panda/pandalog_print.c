
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "pandalog.h"
#include "pandalog_print.h"


#ifdef LAVA_PANDALOG_PRINT
#include "../../../lava/src_clang/lavaDB.h"

std::map<std::string,uint32_t> str2ind;
std::map<uint32_t,std::string> ind2str;

char *gstr(uint32_t ind) {
    return (char *) (ind2str[ind].c_str());
}
#endif

void pprint_process(const char *label, Panda__Process *p) {
    printf ("(process, %s, %d, %s)", label, p->pid, p->name);
}

void pprint_process_file(Panda__ProcessFile *pf) {
    pprint_process("",pf->proc);
    printf ("(filename,%s)", pf->filename);
}

        
void pprint_process_key(Panda__ProcessKey *pk) {
    pprint_process("",pk->proc);
    printf ("(process_key,%s)", pk->keyname);
}


void pprint_process_key_value(Panda__ProcessKeyValue *pkv) {
    pprint_process_key(pkv->pk);
    printf ("(process_key_value,%s)", pkv->value_name);            
}


void pprint_process_key_index(Panda__ProcessKeyIndex *pki) {
    pprint_process_key(pki->pk);
    printf ("(process_key_index,%u)", pki->index);            
}

void pprint_section(Panda__Section *section) {
    pprint_process("",section->proc);
    printf("(section,(id,%x),", section->section_id);
    if (section->name != NULL) {
        printf("(name,%s),", section->name);
    }
    if (section->file_name != NULL) {
        printf("(file_name,%s)", section->file_name);
    }
    printf (")");
}

void pprint_panda_vm (Panda__VirtualMemory *pvm) {
    pprint_process("proc", pvm->proc);
    pprint_process("target",pvm->target);
}

void pprint_local_port(Panda__LocalPort *port) {
    printf("(local_port,");
    if (port->server) {
        pprint_process("server", port->server);
    }
    if (port->client) {
        pprint_process("client", port->client);
    }
    /*
    if ((port->server == NULL) && (port->client == NULL)){
        printf(" empty");
    }
    */
    printf(")");
}


void pprint_call_stack(Panda__CallStack *cs) {
    if (cs->n_addr > 0) {
        printf ("(callstack,%u,(", (uint32_t) cs->n_addr);
        uint32_t i;
        for (i=0; i<cs->n_addr; i++) {
            printf ("0x%" PRIx64 , cs->addr[i]);
            if (i+1 < cs->n_addr) {
                printf (",");
            }
        }
        printf ("))");
    }
}



#ifdef LAVA_PANDALOG_PRINT

void pprint_attack_point(Panda__AttackPoint *ap) {        
    printf ("(attack_point,(%s,", gstr(ap->info));
    pprint_call_stack(ap->call_stack);
    printf (",");
    pprint_src_info(ap->src_info);
    printf (")");
}


void pprint_src_info(Panda__SrcInfo *si) {
    printf ("(src_info,%s,%s,%d,%d)",gstr(si->filename),gstr(si->astnodename),
            si->linenum, si->insertionpoint);
}

#endif

void pprint_taint_query_unique_label_set(Panda__TaintQueryUniqueLabelSet *tquls) {
    printf("(unique_label_set,0x%" PRIx64 ",", tquls->ptr);
    int i;
    for (i=0; i<tquls->n_label; i++) {
        printf ("%d,", tquls->label[i]);
    }
    printf (")");
}

void pprint_taint_query(Panda__TaintQuery *tq) {
    printf ("(taint_query,0x%" PRIx64 ",%d,%d,",
            tq->ptr, tq->tcn, tq->offset);
    if (tq->unique_label_set) {
        pprint_taint_query_unique_label_set(tq->unique_label_set);
    }
    else
        printf ("None");
    printf (")");
}
        

void pprint_taint_query_hypercall(Panda__TaintQueryHypercall *tqh) {
    printf ("(taint_query_hypercall,0x%" PRIx64 ",%d,",
            tqh->buf, tqh->len);
    if (tqh->n_data > 0) {
        printf ("(");
        int i;
        for (i=0; i<tqh->n_data; i++) {
            printf("%x,", tqh->data[i]);
        }
        printf ("),");
    }
    printf ("%d,", tqh->num_tainted);
    pprint_call_stack(tqh->call_stack);
    printf (",");
#ifdef LAVA_PANDALOG_PRINT
    pprint_src_info(tqh->src_info);
    printf (",");
#endif
    int i;
    for (i=0; i<tqh->n_taint_query; i++) {
        pprint_taint_query(tqh->taint_query[i]);
        printf (",");
    }    
    printf (")");
}

       
void pprint_tainted_branch(Panda__TaintedBranch *tb) {
    printf ("(tainted_branch,");
    pprint_call_stack(tb->call_stack);
    printf (",");
    int i;
    for (i=0; i<tb->n_taint_query; i++) {
        pprint_taint_query(tb->taint_query[i]);
    }
    printf (")");
}
  
void pprint_tainted_instr(Panda__TaintedInstr *ti) {
    printf ("(tainted_instr,");
    pprint_call_stack(ti->call_stack);
    printf (",");
    int i;
    for (i=0; i<ti->n_taint_query; i++) {
        pprint_taint_query(ti->taint_query[i]);
    }
    printf (")");
}

void pprint_tainted_instr_summary(Panda__TaintedInstrSummary *tis) {
    printf ("(tainted_instr_summary,");
    printf ("%" PRIx64 ",%" PRIx64 ")", tis->asid, tis->pc);
}
    


int started = 0;

void pprint_ple(Panda__LogEntry *ple) {
    if (!started) {
#ifdef LAVA_PANDALOG_PRINT
        str2ind = LoadDB(std::string("/tmp/lavadb"));
        ind2str = InvertDB(str2ind);
#endif
        started = 1;
    }
    if (ple == NULL){
        printf("Null Panda Log Entry!\n");
        return;
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

    if (ple->call_stack) {
        pprint_call_stack(ple->call_stack);
    }

#ifdef LAVA_PANDALOG_PRINT
    if (ple->attack_point) {
        pprint_attack_point(ple->attack_point);
    }
#endif
    if (ple->tainted_branch) {
        pprint_tainted_branch(ple->tainted_branch);
    }

    
    if (ple->taint_query_hypercall) {
        pprint_taint_query_hypercall(ple->taint_query_hypercall);
    }

    if (ple->tainted_instr) {
        pprint_tainted_instr(ple->tainted_instr);
    }

    if (ple->tainted_instr_summary) {
        pprint_tainted_instr_summary(ple->tainted_instr_summary);
    }

    // win7proc
    if (ple->new_pid) { 
    pprint_process("new_pid", ple->new_pid);
    }
    if (ple->nt_create_user_process) {
        printf (" nt_create_user_process ");
        printf (" [ " ); 
        pprint_process("cur",ple->nt_create_user_process->cur_p); 
        printf (" ]");
        printf (" [ " ); 
        pprint_process("new",ple->nt_create_user_process->new_p); 
        printf (" ]");
        printf (" name=[%s] ", 
                ple->nt_create_user_process->new_long_name);
    }
    if (ple->nt_terminate_process) {
        printf (" nt_terminate_process ");
        printf (" [ " ); 
        pprint_process("cur",ple->nt_terminate_process->cur_p);
        printf (" ]");
        printf (" [ " ); 
        pprint_process("term",ple->nt_terminate_process->term_p);
        printf (" ]");
    }
    
    if (ple->nt_create_file) {
        printf (" nt_create_file ");
        pprint_process_file(ple->nt_create_file);
    }
    
    if (ple->nt_read_file) {
        printf (" nt_read_file ");
        pprint_process_file(ple->nt_read_file);
    }
    if (ple->nt_delete_file) {
        printf (" nt_delete_file ");
        pprint_process_file(ple->nt_delete_file);
    }
    if (ple->nt_write_file) {
        printf ("nt_write_file ");
        pprint_process_file(ple->nt_write_file);
    }
    if (ple->nt_create_key) {
        printf (" nt_create_key ");
        pprint_process_key(ple->nt_create_key);
    }
    if (ple->nt_create_key_transacted) {
        printf (" nt_create_key_transacted ");
        pprint_process_key(ple->nt_create_key_transacted);
    }
    if (ple->nt_open_key) {
        printf (" nt_open_key ");
        pprint_process_key(ple->nt_open_key);
    }
    if (ple->nt_open_key_ex) {
        printf (" nt_open_key_ex ");
        pprint_process_key(ple->nt_open_key_ex);
    }
    if (ple->nt_open_key_transacted) {
        printf (" nt_open_key_transacted ");
        pprint_process_key(ple->nt_open_key_transacted);
    }
    if (ple->nt_open_key_transacted_ex) {
        printf (" nt_open_key_transacted_ex ");
        pprint_process_key(ple->nt_open_key_transacted_ex);
    }
    if (ple->nt_delete_key) {
        printf (" nt_delete_key ");
        pprint_process_key(ple->nt_delete_key);
    }
    if (ple->nt_query_key) {
        printf (" nt_query_key ");
        pprint_process_key(ple->nt_query_key);
    }
    if (ple->nt_query_value_key) {
        printf (" nt_query_value_key ");
        pprint_process_key_value(ple->nt_query_value_key);
    }
    if (ple->nt_delete_value_key) {
        printf (" nt_delete_value_key ");
        pprint_process_key_value(ple->nt_delete_value_key);
    }
    if (ple->nt_set_value_key) {
        printf (" nt_set_value_key ");
        pprint_process_key_value(ple->nt_set_value_key);
    }
    if (ple->nt_enumerate_key) {
        printf (" nt_enumerate_key ");
        pprint_process_key_index(ple->nt_enumerate_key);
    }
    if (ple->nt_enumerate_value_key) {
        printf (" nt_enumerate_value_key ");
        pprint_process_key_index(ple->nt_enumerate_value_key);
    }
    if (ple->nt_create_section) {
        printf (" nt_create_section ");
        pprint_section(ple->nt_create_section);
    }
    if (ple->nt_open_section) {
        printf (" nt_open_section ");
        pprint_section(ple->nt_open_section);
    }
    if (ple->nt_map_view_of_section) {
        printf (" nt_map_view_of_section ");
        pprint_process("target", ple->nt_map_view_of_section->target);
        pprint_section(ple->nt_map_view_of_section->section);
    }
    if (ple->nt_create_port) {
        printf(" nt_create_port ");
        printf("name = %s ", ple->nt_create_port->port_name);
        pprint_local_port(ple->nt_create_port->port);
    }
    if (ple->nt_connect_port) {
        printf(" nt_connect_port ");
        printf("name = %s ", ple->nt_connect_port->port_name);
        pprint_local_port(ple->nt_connect_port->port);
    }
    if (ple->nt_listen_port) {
        printf(" nt_listen_port ");
        pprint_local_port(ple->nt_listen_port);
    }
    if (ple->nt_accept_connect_port) {
        printf(" nt_accept_connect_port ");
        pprint_local_port(ple->nt_accept_connect_port);
    }
    if (ple->nt_complete_connect_port) {
        printf(" nt_complete_connect_port ");
        pprint_local_port(ple->nt_complete_connect_port);
    }
    if (ple->nt_request_port) {
        printf(" nt_request_port ");
        pprint_local_port(ple->nt_request_port);
    }
    if (ple->nt_request_wait_reply_port) {
        printf(" nt_request_wait_reply_port ");
        pprint_local_port(ple->nt_request_wait_reply_port);
    }
    if (ple->nt_reply_port) {
        printf(" nt_reply_port ");
        pprint_local_port(ple->nt_reply_port);
    }
    if (ple->nt_reply_wait_reply_port) {
        printf(" nt_reply_wait_reply_port ");
        pprint_local_port(ple->nt_reply_wait_reply_port);
    }
    if (ple->nt_reply_wait_receive_port) {
        printf(" nt_reply_wait_receive_port ");
        pprint_local_port(ple->nt_reply_wait_receive_port);
    }
    if (ple->nt_impersonate_client_of_port) {
        printf(" nt_impersonate_client_of_port ");
        pprint_local_port(ple->nt_impersonate_client_of_port);
    }
    if (ple->nt_read_virtual_memory) {
        printf(" nt_read_virtual_memory ");
        pprint_panda_vm(ple->nt_read_virtual_memory);
    }
    if (ple->nt_write_virtual_memory) {
        printf(" nt_write_virtual_memory ");
        pprint_panda_vm(ple->nt_write_virtual_memory);
    }
    printf ("\n");
}
