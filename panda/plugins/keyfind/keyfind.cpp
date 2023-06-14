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
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

#include <iostream>
#include <vector>
#include <algorithm>
#include <math.h>
#include <stdio.h>



    
// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

typedef struct Memchunk {
    target_ptr_t start;
    target_ptr_t end;
    target_ulong size;
    uint8_t buf[48];
} Memchunk;


// Globals

Memchunk last_write;

std::vector<std::pair<Memchunk, double> > memory_segments;

//uint16_t ciphersuite_id = 0;
uint8_t keysize = 0;
double entropy_threshold = 0.0;


//helper function for sorting by buffer value
bool buffer_compare(std::pair<Memchunk, double> &a, std::pair<Memchunk, double> &b) {
    return (memcmp(a.first.buf, b.first.buf, keysize) < 0);
}

//helper function for sorting by highest entropy
bool entropy_compare(std::pair<Memchunk, double> &a, std::pair<Memchunk, double> &b) {
    return a.second > b.second;
}

//heper function for checking equality of memchunks by buffer value
bool memchunk_compare(std::pair<Memchunk, double> &a, std::pair<Memchunk, double> &b) {
    return (memcmp(a.first.buf, b.first.buf, keysize) == 0);
}


double shannon_entropy(uint8_t* buf, size_t size) {
    uint8_t frequencies[256] = {0};
    double entropy = 0.0;
    for(int i = 0; i < size; i++) {
        frequencies[buf[i]] += 1;
    }

    for (int i = 0; i < 256; i++) {
        double px = (double) frequencies[i] / size;
        if (px > 0.0) {
            entropy += (px*-1) * log2(px);
        }
    }

    return entropy;
}



// after mem write, that is
void mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       size_t size, uint8_t *buf) {


    //check if the write is happening right after the end of the last write
    //if it's not, reset the last_write
    if(addr != last_write.end){
        //if the next write isn't adjacent to the last AND the last write buffer had KEYSIZE bytes written to it, add it to the vec, then reset last_write

        if(last_write.size == keysize) {
            //store in vec, reset last_write
            double e = shannon_entropy(last_write.buf, keysize);

            if(e >= entropy_threshold) {
                memory_segments.push_back(std::make_pair(last_write, e));
            } 
        }


        last_write.start = addr;
        last_write.end = addr + size;
        memset(last_write.buf, 0, keysize);
        memcpy(last_write.buf, buf, size);
        last_write.size = size;

    //if it is, add it to the last_write chunk
    } else if (addr == last_write.end) { 
        last_write.end += size;

        //no need to keep track of anything written if the amount of data exceeds keysize bytes
        if (last_write.size + size <= keysize) {
            memcpy(&last_write.buf[last_write.size], buf, size);
        }

        last_write.size += size;
    }
}




bool init_plugin(void *self) {
    // General PANDA stuff
    panda_cb pcb;

    printf("Initializing plugin keyfind\n");

    // Enable our callbacks
    panda_enable_memcb();
    panda_enable_precise_pc();

    printf("enabling mem write callback\n");
    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);


    //get the pcap name
    panda_arg_list *args = panda_get_args("keyfind");
//    const char* pcap_file = panda_parse_string_req(args, "pcap", "required: path to pcap file");

    //get_ciphersuite_id(pcap_file);

    const uint32_t ciphersuite_id = panda_parse_uint32_opt(args, "ciphersuite_id", 0, "The id of the ciphersuite used. See readme for instructions on how to obtain");
    const char* ciphersuite_name = panda_parse_string_opt(args, "ciphersuite_name", "\0", "One of TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384, or TLS_AES_128_GCM_SHA256");


    //if it's AES_256_GCM_SHA384 (1302)
    if (ciphersuite_id == 0x1302 || strcmp(ciphersuite_name, "TLS_AES_256_GCM_SHA384") == 0) {                     
        keysize = 48;
        entropy_threshold = 5.0044;
    }

    //if it's AES_128_GCM_SHA256 (1301) or CHACHA20_POLY1305_SHA256 (1303)
    else if (ciphersuite_id == 0x1301 || strcmp(ciphersuite_name, "TLS_AES_128_GCM_SHA256") == 0 ||
                ciphersuite_id == 0x1303 || strcmp(ciphersuite_name, "TLS_CHACHA20_POLY1305_SHA256") == 0) {

        keysize = 32;
        entropy_threshold = 4.394;
    }

    if (keysize == 0 || entropy_threshold == 0.0) {
        printf("Ciphersuite has not been specified. Start keyfind and specify either ciphersuite_id or ciphersuite_name as parameters. See the README for example usage.\n");
        exit(1);
    }



    return true;
}

void uninit_plugin(void *self) {

    printf("collected %ld memory_segments:\n", memory_segments.size());

    printf("deduplicating the memory segments...\n");

    //use of std::unique requires that the segments are sorted by value
    std::sort(memory_segments.begin(), memory_segments.end(), buffer_compare);
    memory_segments.erase(std::unique(memory_segments.begin(), memory_segments.end(), memchunk_compare), memory_segments.end());
    printf("there are %ld memory segments after deduplication\n", memory_segments.size());


    printf("sorting memory segments by entropy...\n");
    std::sort(memory_segments.begin(), memory_segments.end(), entropy_compare);
    

    printf("writing memory segments to key_candidates.txt\n");
    FILE *fptr;
    fptr = fopen("key_candidates.txt", "w");
    for(int i = 0; i < memory_segments.size(); i++) {
        for(int j = 0; j < keysize; j++) {
            fprintf(fptr, "%02x", memory_segments[i].first.buf[j]);
        }
        fprintf(fptr, "\n");
    }
    fclose(fptr);
}


