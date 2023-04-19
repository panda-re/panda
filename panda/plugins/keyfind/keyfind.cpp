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

#define NPAGES(n) ((uint32_t)((n) >> 12))

//#include "../common/prog_point.h"
//#include "pandalog.h"
//#include "../callstack_instr/callstack_instr_ext.h"
    
// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

//int count = 0;
//time_t start, current;

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
//int before_block_translate_cb(CPUState *env, target_ulong pc);
//int after_block_translate_cb(CPUState *env, TranslationBlock *tb);

}

bool in_openssl;

#define KEYSIZE 48
#define ENTROPY_THRESHOLD_48 5.0044
#define ENTROPY_THRESHOLD_32 4.394

//int keysize = 48;

typedef struct Memchunk {
    target_ptr_t start;
    target_ptr_t end;
    target_ulong size;
    uint8_t buf[KEYSIZE];
} Memchunk;


std::vector<std::pair<Memchunk, double> > heap_segments;
std::vector<std::pair<Memchunk, double> > non_heap_segments;

std::vector<std::pair<Memchunk, double> > deduplicated_heap;
std::vector<std::pair<Memchunk, double> > deduplicated_non_heap;

std::vector<std::pair<Memchunk, Memchunk> > heap_pairs;
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

typedef std::tuple<target_ulong, target_ulong, target_ulong> candidate_prog_point;
std::set <candidate_prog_point> candidates;

// Optimization
std::unordered_set <target_ulong> asids;
std::vector <target_ulong> eips;

// Ringbuf-like structure
//struct key_buf {
//    uint8_t key[MASTER_SECRET_SIZE];
//    int start;
//    bool filled;
//};


typedef std::tuple <target_ulong, target_ulong, std::string> match;
std::set<match> matches;
//std::map<prog_point,key_buf> key_tracker;

bool check_key(StringInfo *master_secret, StringInfo *client_random, StringInfo *server_random,
               StringInfo *enc_msg, StringInfo *version, StringInfo *content_type,
               const EVP_MD *md, const EVP_CIPHER *ciph)
{

    printf("CHECKING KEY\n");
    return false;


}

//helper function for sorting by buffer value
bool buffer_compare(std::pair<Memchunk, double> &a, std::pair<Memchunk, double> &b) {
    return (memcmp(a.first.buf, b.first.buf, KEYSIZE) < 0);
}

//helper function for sorting by highest entropy
bool entropy_compare(std::pair<Memchunk, double> &a, std::pair<Memchunk, double> &b) {
    return a.second > b.second;
}


//heper function for checking equality of memchunks by buffer value
bool memchunk_compare(std::pair<Memchunk, double> &a, std::pair<Memchunk, double> &b) {
    return (memcmp(a.first.buf, b.first.buf, KEYSIZE) == 0);
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

void print_memchunk(Memchunk* m) {
    printf("\tstart: " TARGET_PTR_FMT "\n", m->start);
    printf("\tend  : " TARGET_PTR_FMT "\n", m->end);
    printf("\tsize : " TARGET_FMT_ld "\n", m->size);
    printf("\tbuf  : ");

    for(int i = 0; i < KEYSIZE; i++) {
        printf("%02x", m->buf[i]);
    }
    printf("\n");
}

void print_heap_segments() {
    printf("%ld heap_segments stored\n", heap_segments.size());
//    for(int i = 0; i < heap_segments.size(); i++) {
//        print_memchunk(&heap_segments[i]);
//    }
}

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
                printf("\t" TARGET_PTR_FMT " " TARGET_PTR_FMT "  %s:%s\n", m->base, m->base + m->size, m->name, m->file);
            }
        }
        g_array_free(ms, true);
    }

   
}

//server handshake traffic key: c6b78b42 10befbe5 a38e7cca646d214d2ae64174e194a18ad722b18429821635885b747cb98f4372 4e9b46a9 3690e6ed
//client traffic secret 0     : a8d81721 039568bc 96e69589117a9e200cfc45b841495cf21ec3b20bd46206f24f66c283b6fc59fb b05c0638 de87e0cf

// after mem write, that is.
void mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       size_t size, uint8_t *buf) {

    uint8_t first_8[8] = {0xc6, 0xb7, 0x8b, 0x42, 0x10, 0xbe, 0xfb, 0xe5};
    //uint8_t last_8[8] = {0xa8, 0xd8, 0x17, 0x21, 0x03, 0x95, 0x68, 0xbc};

    OsiProc *current;
    current = get_current_process(env);

    if(strcmp(current->name, "openssl") != 0) {
        return;
    }

    if(in_openssl) {

        if(seen_first_byte && count < 12) {
            printf("writing %ld bytes to " TARGET_PTR_FMT " --> ", size, addr);
            for(int i = 0; i < size; i++) {
                printf("%02x", buf[i]);
            }
            printf("\n");
            count++;
            uint8_t out[64] = {0};
            int res = panda_virtual_memory_read(env, last_write.start, out, 64);

            printf(TARGET_PTR_FMT " --> ", addr);
            if(res != -1) {
                for(int i = 0; i < 64; i++) {
                    printf("%02x", out[i]);
                }
                printf("\n");
            }

        }
        if(!seen_first_byte && memcmp(first_8, buf, 8) == 0) {
            printf("THERE ARE %ld heap_segments\n", heap_segments.size());
            printf("matches first_8!\n");
            printf("writing %ld bytes to " TARGET_PTR_FMT " --> ", size, addr);
            for(int i = 0; i < size; i++) {
                printf("%02x", buf[i]);
            }
            printf("\n");
            count = 0;
            if(addr == (target_ulong) 0x0000000000c1dd90) {
                seen_first_byte = true;
                uint8_t out[64] = {0};
                int res = panda_virtual_memory_read(env, addr, out, 64);

                printf(TARGET_PTR_FMT " --> ", addr);
                if(res != -1) {
                    for(int i = 0; i < 64; i++) {
                        printf("%02x", out[i]);
                    }
                    printf("\n");
                }
            }
            GArray *ms = NULL;
            ms = get_mappings(env, current);
            if (ms != NULL) {
                for (uint32_t j = 0; j < ms->len; j++) {
                    OsiModule *m = &g_array_index(ms, OsiModule, j);
                    printf("\t" TARGET_PTR_FMT " " TARGET_PTR_FMT "  %s:%s\n", m->base, m->base + m->size, m->name, m->file);
                }
                g_array_free(ms, true);
            }




        }

        //check if the write is happening right after the end of the last write
        //if it's not, reset the last_write
        if(addr != last_write.end){
            //if the next write isn't adjacent to the last AND the last write buffer had KEYSIZE bytes written to it, add it to the vec, then reset last_write

            if(last_write.size == KEYSIZE) {
                //store in vec, reset last_write
                double e = shannon_entropy(last_write.buf, KEYSIZE);
                target_ptr_t heap_start;
                target_ptr_t heap_end;
                get_heap_bounds(env, &heap_start, &heap_end);

                //if(e >= ENTROPY_THRESHOLD_48 && last_write.start < 0x0000000000c22000 && last_write.start >= 0x0000000000b95000) {
                if(e >= ENTROPY_THRESHOLD_48 && last_write.start < heap_end && last_write.start >= heap_start) {
                //if(e >= 5.0 && last_write.start < (target_ptr_t) 0x00007ffffffff000 && last_write.start >= (target_ptr_t) 0x00007ffffffde000) {
                    heap_segments.push_back(std::make_pair(last_write, e));
                } else if (e >= ENTROPY_THRESHOLD_48) {
                    non_heap_segments.push_back(std::make_pair(last_write, e));
                }
 
            }


            last_write.start = addr;
            last_write.end = addr + size;
            memset(last_write.buf, 0, KEYSIZE);
            memcpy(last_write.buf, buf, size);
            last_write.size = size;

        //if it is, add it to the last_write chunk
        } else if (addr == last_write.end && last_write.size < KEYSIZE) { 
            last_write.end += size;
            memcpy(&last_write.buf[last_write.size], buf, size);
            last_write.size += size;

            //if the last_write chunk reaches the keysize, store it in the vec, and then reset the last_write

            //if(last_write.size == KEYSIZE) {
            //    //store in vec, reset last_write
            //    double e = shannon_entropy(last_write.buf, KEYSIZE);

            //    if(e >= 5.0 && last_write.start < 0x0000000000c22000 && last_write.start >= 0x0000000000b95000) {
            //    //if(e >= 5.0 && last_write.start < (target_ptr_t) 0x00007ffffffff000 && last_write.start >= (target_ptr_t) 0x00007ffffffde000) {
            //        heap_segments.push_back(std::make_pair(last_write, e));
            //    } else if (e >= 5.0) {
            //        non_heap_segments.push_back(std::make_pair(last_write, e));
            //    }
            //    
            //}
        }

        if(seen_first_byte && count < 12) {
            print_memchunk(&last_write);
            print_heap_segments();
        }
    }

//    Memchunk *segment_ptr = find_segment_for_addr(addr);
//
//    if(segment == NULL) {
//        Memchunk new_chunk;
//        new_chunk.start = addr;
//        new_chunk.end = addr - size;
//        new_chunk.size = size;
//        memcpy(new_chunk.buf, buf, size);
//        heap_segments.push_back(new_chunk);
//    }
//
//    return;




//    count++;
//    double seconds;
//    time(&current);
//    seconds = difftime(current, start);
//    int hours, minutes, secs;
//
//    if (count % 100000 == 0) {
//        hours = (int)seconds / 3600;
//        minutes = ((int)seconds % 3600) / 60;
//        secs = ((int)seconds % 3600) % 60;
//        printf("%02d:%02d:%02d - got %d mem write callbacks\n", hours, minutes, secs, count);
//    }
}

#define ASSUMED_TB_SIZE 256

bool enabled_memcb = false;
int instrumented, total;




//void before_block_translate_cb(CPUState *env, target_ulong pc) {
//    // Don't bother with any of this if we don't have any canidates;
//    // in this case precise pc and memcb will always be on.
//    if (!have_candidates) 
//        return;
//    
//    target_ulong cr3 = panda_current_asid(env);
//
//    if (asids.find(cr3) == asids.end()) 
//        return;
//
//    // Slightly tricky: we ask for the lower bound of the TB start and
//    // the lower bound of the (assumed) TB end in our sorted list of tap
//    // EIPs. If that interval is nonempty then at least one of our taps
//    // is in the upcoming TB, so we need to instrument it.
//    std::vector<target_ulong>::iterator beg, end, it;
//    beg = std::lower_bound(eips.begin(), eips.end(), pc);
//    end = std::lower_bound(eips.begin(), eips.end(), pc+ASSUMED_TB_SIZE);
//
//    if (std::distance(beg, end) != 0) {
//        panda_enable_memcb();
//        panda_enable_precise_pc();
//        enabled_memcb = true;
//        //printf("Enabling callbacks for TB " TARGET_FMT_lx " Interval:(%ld,%ld)\n", pc, beg-eips.begin(), end-eips.begin());
//        //printf("Encompassed EIPs:");
//        //for (it = beg; it != end; it++) {
//        //    printf(" " TARGET_FMT_lx, *it);
//        //}
//        //printf("\n");
//        instrumented++;
//    }
//    total++;
//
//    return;
//}

bool asid_changed_cb(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    printf("got asid changed callback!\n");
    
    OsiProc *current;
    current = get_current_process(env);

    if(strcmp(current->name, "openssl") == 0) {
        in_openssl = true;
    } else {
        in_openssl = true;
    }


//    GArray *ms = NULL;
//    ms = get_mappings(env, current);
//    if (ms != NULL) {
//        for (uint32_t j = 0; j < ms->len; j++) {
//            OsiModule *m = &g_array_index(ms, OsiModule, j);
//            printf("\t" TARGET_PTR_FMT " " TARGET_PTR_FMT "  %s:%s\n", m->base, m->base + m->size, m->name, m->file);
//        }
//        g_array_free(ms, true);
//    }


    return false;
}

void  after_block_translate_cb(CPUState *env, TranslationBlock *tb) {
    if (!have_candidates) return;

    if (enabled_memcb) {
        // Check our assumption
        if (tb->size > ASSUMED_TB_SIZE) {
            printf("WARN: TB " TARGET_FMT_lx " is larger than we thought (%d bytes)\n", tb->pc, tb->size);
        }
        panda_disable_memcb();
        panda_disable_precise_pc();
        enabled_memcb = false;
        //printf("Disabling callbacks for TB " TARGET_FMT_lx "\n", tb->pc);
    }
    return;
}

bool init_plugin(void *self) {
    // General PANDA stuff
    panda_cb pcb;

    panda_require("osi");

    // this sets up OS introspection API
    assert(init_osi_api());


    //time(&start);

    printf("Initializing plugin keyfind\n");

    //if(!init_callstack_instr_api()) return false;

    // SSL stuff
    // Init list of ciphers & digests
    //OpenSSL_add_all_algorithms();

    // Read and parse list of candidate taps
//    std::ifstream taps("keyfind_candidates.txt");
//    if (!taps) {
//        printf("Couldn't open keyfind_candidates.txt; no key tap candidates defined.\n");
//        printf("We will proceed, but it may be SLOW.\n");
//        have_candidates = false;
//    }
//    else {
//        std::unordered_set <target_ulong> eipset;
//        target_ulong caller, pc, asid;
//        while (taps >> std::hex >> caller) {
//            taps >> std::hex >> pc;
//            taps >> std::hex >> asid;
//
//            eipset.insert(pc);
//            asids.insert(asid);
//
//            //printf("Adding tap point (" TARGET_FMT_lx "," TARGET_FMT_lx "," TARGET_FMT_lx ")\n",
//            //       p.caller, p.pc, p.cr3);
//            auto candidate = std::make_tuple(caller, pc, asid);
//            candidates.insert(candidate);
//        }
//        printf("keyfind: Will check for keys on %ld taps.\n", candidates.size());
//        taps.close();
//
//        // Sort EIPs
//        for(auto ii : eipset) {
//            eips.push_back(ii);
//        }
//        std::sort(eips.begin(), eips.end());
//    }

    in_openssl = true;

    // Enable our callbacks
    panda_enable_memcb();
    panda_enable_precise_pc();
    enabled_memcb = true;

    printf("enabling mem write callback\n");
    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);


    pcb.asid_changed = asid_changed_cb;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);


//    pcb.before_block_translate = before_block_translate_cb;
//    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
//    pcb.after_block_translate = after_block_translate_cb;
//    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    return true;
}

void uninit_plugin(void *self) {

    printf("collected %ld heap_segments:\n", heap_segments.size());
    printf("collected %ld non_heap_segments:\n", non_heap_segments.size());

    int num_pairs = 0;
    for(int i = 0; i < heap_segments.size(); i++) {
        for(int j = 0; j < heap_segments.size(); j++) {
            if(j != i && ((heap_segments[i].first.start - heap_segments[j].first.start) == 64 || (heap_segments[j].first.start - heap_segments[i].first.start) == 64)) {
//                printf("found pair:\n");
//                printf("\t" TARGET_PTR_FMT ": ", heap_segments[i].first.start);
//                for(int k = 0; k < KEYSIZE; k++) {
//                    printf("%02x", heap_segments[i].first.buf[k]);
//                }
//                printf("\n");
//                printf("\t" TARGET_PTR_FMT ": ", heap_segments[j].first.start);
//                for(int k = 0; k < KEYSIZE; k++) {
//                    printf("%02x", heap_segments[j].first.buf[k]);
//                }
//                printf("\n");
                if(heap_segments[i].first.start < heap_segments[j].first.start) {
                    heap_pairs.push_back(std::make_pair(heap_segments[i].first, heap_segments[j].first));
                } else {
                    heap_pairs.push_back(std::make_pair(heap_segments[j].first, heap_segments[i].first));
                }
                num_pairs++;
            }
        }
    }
    printf("found %ld pairs in the heap\n", heap_pairs.size());


    printf("deduplicating the heap segments...\n");
    std::sort(heap_segments.begin(), heap_segments.end(), buffer_compare);
    heap_segments.erase(std::unique(heap_segments.begin(), heap_segments.end(), memchunk_compare), heap_segments.end());
    printf("there are %ld heap segments after deduplication\n", heap_segments.size());


    printf("deduplicating the non-heap segments...\n");
    std::sort(non_heap_segments.begin(), non_heap_segments.end(), buffer_compare);
    non_heap_segments.erase(std::unique(non_heap_segments.begin(), non_heap_segments.end(), memchunk_compare), non_heap_segments.end());
    printf("there are %ld non-heap segments after deduplication\n", non_heap_segments.size());


    printf("sorting heap_segments and non_heap_segments by entropy...\n");
    std::sort(heap_segments.begin(), heap_segments.end(), entropy_compare);
    std::sort(non_heap_segments.begin(), non_heap_segments.end(), entropy_compare);

    printf("writing heap pairs to file heap_pairs.txt\n");
    FILE *fptr;

    fptr = fopen("heap_pairs.txt", "w");
    for(int i = 0; i < heap_pairs.size(); i++) {
        for(int j = 0; j < KEYSIZE; j++) {
            fprintf(fptr, "%02x", heap_pairs[i].first.buf[j]);           
        }
        fprintf(fptr, ":");
        for(int j = 0; j < KEYSIZE; j++) {
            fprintf(fptr, "%02x", heap_pairs[i].second.buf[j]);
        }
        fprintf(fptr, "\n");
    }
    fclose(fptr);
    
    printf("writing heap writes to heap_writes.txt\n");
    fptr = fopen("heap_writes.txt", "w");
    for(int i = 0; i < heap_segments.size(); i++) {
        for(int j = 0; j < KEYSIZE; j++) {
            fprintf(fptr, "%02x", heap_segments[i].first.buf[j]);
        }
        fprintf(fptr, "\n");
    }
    fclose(fptr);

    printf("writing deduplicated non-heap writes to non_heap_writes.txt\n");
    fptr = fopen("non_heap_writes.txt", "w");
    for(int i = 0; i < non_heap_segments.size(); i++) {
        for(int j = 0; j < KEYSIZE; j++) {
            fprintf(fptr, "%02x", non_heap_segments[i].first.buf[j]);
        }
        fprintf(fptr, "\n");
    }
    fclose(fptr);
}



//server handshake: 0000000000c1dd90
//server traffic  : 0000000000c00c4c
//client traffic  : 0000000000c00c0c