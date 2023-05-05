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

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "keyfind.h"


#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include <iostream>
#include <unordered_set>
#include <vector>
#include <set>
#include <map>
#include <utility>
#include <algorithm>
#include <time.h>
#include <glib.h>
#include <math.h>
#include <stdio.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>


    
// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

//int count = 0;
//time_t start, current;

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

//bool in_openssl;


//int keysize = 48;

typedef struct Memchunk {
    target_ptr_t start;
    target_ptr_t end;
    target_ulong size;
    uint8_t buf[48];
} Memchunk;


std::vector<std::pair<Memchunk, double> > heap_segments;

std::vector<std::pair<Memchunk, double> > deduplicated_heap;

Memchunk last_write;
//typedef struct cand_prog_point_struct {


// Utility functions
//unsigned char hexchar_to_int(int c)
//{
//    if (c >= 0x30 && c < 0x40) return c - 0x30;
//    else if (c >= 0x41 && c < 0x5B) return c - 0x37;
//    else return 0;
//}

//void read_hex_string(std::string in, unsigned char *out)
//{
//    unsigned char *ptr = out;
//    for(unsigned int i = 0; i < in.length(); i += 2) {
//        int high = toupper(in[i]);
//        int low = toupper(in[i+1]);
//        *ptr++ = (hexchar_to_int(high) << 4) | hexchar_to_int(low);
//    }
//}

// Globals
StringInfo g_keydata;
StringInfo g_master_secret;
StringInfo g_out;
StringInfo g_client_random;
StringInfo g_server_random;
StringInfo g_version;
StringInfo g_content_type;
StringInfo g_enc_msg;
const EVP_CIPHER *g_ciph = NULL;
const EVP_MD *g_md = NULL;

bool have_candidates = true;
bool seen_first_byte = false;
int count = 0;
int writes_interval = 0;

uint16_t ciphersuite_id = 0;
uint8_t keysize = 0;
double entropy_threshold = 0.0;

typedef std::tuple<target_ulong, target_ulong, target_ulong> candidate_prog_point;
std::set <candidate_prog_point> candidates;

// Optimization
//std::unordered_set <target_ulong> asids;
//std::vector <target_ulong> eips;


typedef std::tuple <target_ulong, target_ulong, std::string> match;
std::set<match> matches;
//std::map<prog_point,key_buf> key_tracker;

int handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    const struct iphdr* ip;
    u_int length = pkthdr->len;
    u_int ip_hlen;

    int ether_hlen = sizeof(struct ether_header);

    /* jump past the ethernet header */
    ip = (struct iphdr*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct iphdr))
    {
        printf("truncated ip %d",length);
        return 0;
    }

    ip_hlen    =  ip->ihl * 4; /* header length */

    if(ip->protocol != 6) { //end early if it's not a tcp packet
        return 0;
    }

    const struct tcphdr* tcp;
    tcp = (struct tcphdr*) (packet + ether_hlen + ip_hlen);

    if (ntohs(tcp->th_sport) != 443) {      //only consider packets sent from the server
        return 0;
    }

    int tcp_hlen = tcp->th_off * 4;
    int tls_start_idx = ether_hlen + ip_hlen + tcp_hlen;

    //parse tls record
    //byte 0    : record type   - we want handshake records (22)
    //bytes 1-2 : ssl version
    //bytes 3-4 : data length

    if (packet[tls_start_idx] == 22) {
        int record_data_idx = tls_start_idx + 5;

        if (packet[record_data_idx] == 2) {

            int ciphersuite_idx = record_data_idx + 71;
            //printf("%02x\n", packet[ciphersuite_idx]);
            uint16_t ciphersuite_id = ntohs(*((uint16_t*) &packet[ciphersuite_idx]));
            printf("ciphersuite id: %x\n", ciphersuite_id);
            return ciphersuite_id;
        }
    }

    else {
    //TODO check if there are more records
    }


    return 0;
}


u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    struct ether_header *eptr;  /* net/ethernet.h */

    eptr = (struct ether_header *) packet;

    /* check to see if we have an ip packet, disregard everything else */
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)   //ETHERTYPE_IP == 8
    {
        return eptr->ether_type;
    }

    return 0;
}

void packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    uint16_t result;

    //printf("HANDLING PACKET!\n");
    u_int16_t type = handle_ethernet(NULL,pkthdr,packet);

    if(type == 8) {     /* handle IP packet */
        result = handle_IP(NULL, pkthdr, packet);       

        if (result != 0) {
            ciphersuite_id = result;
        }
    }
}

uint16_t get_ciphersuite_id(const char* pcap_file) {
    pcap_t* pcapHandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file
    pcapHandle = pcap_open_offline(pcap_file, errbuf);
    if (pcapHandle == NULL) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    // Set a packet callback function
    pcap_loop(pcapHandle, 0, packetHandler, NULL);

    // Close the pcap file
    pcap_close(pcapHandle);

    return 0;
}

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

//void print_memchunk(Memchunk* m) {
//    printf("\tstart: " TARGET_PTR_FMT "\n", m->start);
//    printf("\tend  : " TARGET_PTR_FMT "\n", m->end);
//    printf("\tsize : " TARGET_FMT_ld "\n", m->size);
//    printf("\tbuf  : ");
//
//    for(int i = 0; i < keysize; i++) {
//        printf("%02x", m->buf[i]);
//    }
//    printf("\n");
//}


void get_heap_bounds(CPUState* env, target_ptr_t* start, target_ptr_t* end) {
    OsiProc *current;
    current = get_current_process(env);

    GArray *ms = NULL;
    ms = get_mappings(env, current);
    if (ms != NULL) {
        for (uint32_t j = 0; j < ms->len; j++) {
            OsiModule *m = &g_array_index(ms, OsiModule, j);
            if(strcmp(m->name, "[heap]") == 0) {
                *start = m->base;
                *end = m->base + m->size;
                //printf("\t" TARGET_PTR_FMT " " TARGET_PTR_FMT "  %s:%s\n", m->base, m->base + m->size, m->name, m->file);
            }
        }
        g_array_free(ms, true);
    }

   
}


// after mem write, that is
void mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       size_t size, uint8_t *buf) {


//    OsiProc *current;
//    current = get_current_process(env);

//    if(strcmp(current->name, "openssl") != 0) {
//        return;
//    }

    //check if the write is happening right after the end of the last write
    //if it's not, reset the last_write
    if(addr != last_write.end){
        //if the next write isn't adjacent to the last AND the last write buffer had KEYSIZE bytes written to it, add it to the vec, then reset last_write

        if(last_write.size == keysize) {
            //store in vec, reset last_write
            double e = shannon_entropy(last_write.buf, keysize);
            target_ptr_t heap_start;
            target_ptr_t heap_end;
            get_heap_bounds(env, &heap_start, &heap_end);

            //if(e >= ENTROPY_THRESHOLD_48 && last_write.start < 0x0000000000c22000 && last_write.start >= 0x0000000000b95000) {
            if(e >= entropy_threshold /*&& last_write.start < heap_end && last_write.start >= heap_start*/) {
            //if(e >= 5.0 && last_write.start < (target_ptr_t) 0x00007ffffffff000 && last_write.start >= (target_ptr_t) 0x00007ffffffde000) {
                heap_segments.push_back(std::make_pair(last_write, e));
            } else if (e >= entropy_threshold) {
                //non_heap_segments.push_back(std::make_pair(last_write, e));
            }

        }


        last_write.start = addr;
        last_write.end = addr + size;
        memset(last_write.buf, 0, keysize);
        memcpy(last_write.buf, buf, size);
        last_write.size = size;

    //if it is, add it to the last_write chunk
    } else if (addr == last_write.end /*&& last_write.size < keysize*/) { 
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

    panda_require("osi");

    // this sets up OS introspection API
    assert(init_osi_api());



    printf("Initializing plugin keyfind\n");

    //in_openssl = true;

    // Enable our callbacks
    panda_enable_memcb();
    panda_enable_precise_pc();
    //enabled_memcb = true;

    printf("enabling mem write callback\n");
    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);


//    pcb.asid_changed = asid_changed_cb;
//    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    //get the pcap name
    panda_arg_list *args = panda_get_args("keyfind");
    const char* pcap_file = panda_parse_string_req(args, "pcap", "required: path to pcap file");

    get_ciphersuite_id(pcap_file);

    if (ciphersuite_id == 0) {
        printf("unable to find the ciphersuite id\n");
        exit(1);
    }

    //if it's AES_256_GCM_SHA384
    if (ciphersuite_id == 0x1302) {                     
        keysize = 48;
        entropy_threshold = 5.0044;

    //if it's CHACHA20_POLY1305_SHA256 or AES_128_GCM_SHA256
    } else if (ciphersuite_id == 0x1301 || ciphersuite_id == 0x1303) {
        keysize = 32;
        entropy_threshold = 4.394;
    }


    return true;
}

void uninit_plugin(void *self) {

    printf("collected %ld heap_segments:\n", heap_segments.size());

    printf("deduplicating the heap segments...\n");
    std::sort(heap_segments.begin(), heap_segments.end(), buffer_compare);
    heap_segments.erase(std::unique(heap_segments.begin(), heap_segments.end(), memchunk_compare), heap_segments.end());
    printf("there are %ld heap segments after deduplication\n", heap_segments.size());


    printf("sorting heap_segments by entropy...\n");
    std::sort(heap_segments.begin(), heap_segments.end(), entropy_compare);
    

    printf("writing heap writes to key_candidates.txt\n");
    FILE *fptr;
    fptr = fopen("key_candidates.txt", "w");
    for(int i = 0; i < heap_segments.size(); i++) {
        for(int j = 0; j < keysize; j++) {
            fprintf(fptr, "%02x", heap_segments[i].first.buf[j]);
        }
        fprintf(fptr, "\n");
    }
    fclose(fptr);
}


