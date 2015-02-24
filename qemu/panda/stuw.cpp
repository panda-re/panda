
// cd panda/qemu
// g++ -g -o stuw stuw.cpp pandalog.c pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c -I .. -lz -D PANDALOG_READER  -std=c++11

#define __STDC_FORMAT_MACROS

extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
}



#include <tuple>
#include <vector>

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





typedef struct process_struct {
    uint32_t pid;
    char *name;
} Process;


bool processes_equal(Process &p1, Process &p2) {
    if (p1.pid != p2.pid) {
        return false;
    }
    if (0 != strcmp(p1.name, p2.name)) {
        return false;
    }
    return true;
}

enum StoreType {File, RegKeyVal};

typedef struct file_data_struct {
    char *filename;
} FileData;

typedef struct reg_key_val_data_struct {
    char *keyname;
    char *valname;
    uint32_t index;
} RegKeyValData;


typedef struct store_struct {
    StoreType type;
    union {
        FileData fd;
        RegKeyValData kvd;
    } val;
} Store;

bool stores_equal(Store &s1, Store &s2) {
    if (s1.type != s2.type) return false;
    switch (s1.type) {
    case File:
        if (0 == strcmp(s1.val.fd.filename, s2.val.fd.filename))
            return true;
        else 
            return false;
        break;
    case RegKeyVal:
        if ((0 == strcmp(s1.val.kvd.keyname, s2.val.kvd.keyname))
            && (0 == strcmp(s1.val.kvd.valname, s2.val.kvd.valname)))
            return true;
        else
            return false;
        break;
    default:
        break;
    }
    return false;
}


void print_store(Store &s) {
    switch (s.type) {
    case File:
        printf ("file(%s)", s.val.fd.filename);
        break;
    case RegKeyVal:
        printf ("reg(key=%s,val=%s,i=%d)", s.val.kvd.keyname, s.val.kvd.valname, s.val.kvd.index);
        break;
    default:
        break;
    }
}

void print_process(Process &p) {
    printf ("proc(%d,%s)", p.pid, p.name);
}


                

// instruction count
typedef uint64_t Instr;
// program counter
typedef uint64_t Pc;






enum Direction {In=0, Out=1};

const char * dirname[] = {"in", "out"};


typedef struct flow_struct {
    Instr instr;
    Pc pc;
    Direction dir;
    Process process;
    Store store;
} Flow;

    
void print_flow(Flow &flow) {
    printf("instr=%lld  pc=0x%x ", flow.instr, flow.pc);
    if (flow.dir == In) {
        print_store(flow.store);
        printf (" -> ");
        print_process(flow.process);
    }
    if (flow.dir == Out) {
        print_process(flow.process);
        printf (" -> ");
        print_store(flow.store);
    }
}

    


// flows leaving a process
std::vector < Flow > ins;

// flows entering a process
std::vector < Flow > outs;


void flow_match() {
    for ( auto &outflow : outs ) {
        for ( auto &inflow : ins ) {            
            if (stores_equal(outflow.store, inflow.store)) {
                printf ("\ninflow matches outflow\n");
                print_flow(outflow); printf ("\n");
                print_flow(inflow); printf ("\n");
                if (processes_equal(outflow.process, inflow.process)) {
                    printf (" -- processes same \n");
                }
                else {
                    printf (" -- processes differ\n");
                }
            }
        }
    }
}



int main (int argc, char **argv) {
    pandalog_open(argv[1], "r");
    Panda__LogEntry *ple;
    while (1) {
        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        //        printf ("instr=%lld  pc=0x%x : ", ple->instr, ple->pc);
        if (ple->new_pid) { 
            //            printf (" new_pid ");
            //            print_process(ple->new_pid);
        }

#if 0
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
#endif

#if 0
        else if (ple->nt_create_file) {
            printf (" nt_create_file ");
            print_process_file(ple->nt_create_file);
        }
#endif 
        else if (ple->nt_read_file) {
            Flow inflow;
            inflow.instr = ple->instr;
            inflow.pc = ple->pc;
            inflow.dir = In;
            inflow.process = {ple->nt_read_file->proc->pid, strdup(ple->nt_read_file->proc->name)};
            inflow.store.type = File;
            inflow.store.val.fd.filename = strdup(ple->nt_read_file->filename);
            ins.push_back(inflow);
            flow_match();
        }
        else if (ple->nt_delete_file) {
            printf (" nt_delete_file ");
            print_process_file(ple->nt_delete_file);
        }
        else if (ple->nt_write_file) {
            Flow outflow;
            outflow.instr = ple->instr;
            outflow.pc = ple->pc;
            outflow.dir = Out;
            outflow.process = {ple->nt_write_file->proc->pid, strdup(ple->nt_write_file->proc->name)};
            outflow.store.type = File;
            outflow.store.val.fd.filename = strdup(ple->nt_write_file->filename);
            outs.push_back(outflow);
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
