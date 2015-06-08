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

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"

#include "panda_plugin.h"

}

#include "keyfind.h"
#include <unordered_set>
#include <vector>
#include <set>
#include <map>

#include "../common/prog_point.h"
#include "pandalog.h"
#include "../callstack_instr/callstack_instr_ext.h"
    
// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int before_block_translate_cb(CPUState *env, target_ulong pc);
int after_block_translate_cb(CPUState *env, TranslationBlock *tb);

}

// Utility functions
#define CHECK(var,label) \
    if (!var) { fprintf(stderr, label ": failed. Exiting.\n"); return false; }
#define MASTER_SECRET_SIZE 48

unsigned char hexchar_to_int(int c)
{
    if (c >= 0x30 && c < 0x40) return c - 0x30;
    else if (c >= 0x41 && c < 0x5B) return c - 0x37;
    else return 0;
}

void read_hex_string(std::string in, unsigned char *out)
{
    unsigned char *ptr = out;
    for(unsigned int i = 0; i < in.length(); i += 2) {
        int high = toupper(in[i]);
        int low = toupper(in[i+1]);
        *ptr++ = (hexchar_to_int(high) << 4) | hexchar_to_int(low);
    }
}

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
std::unordered_set <prog_point, hash_prog_point > candidates;

// Optimization
std::unordered_set <target_ulong> cr3s;
std::vector <target_ulong> eips;

// Ringbuf-like structure
struct key_buf {
    uint8_t key[MASTER_SECRET_SIZE];
    int start;
    bool filled;
};

std::set<prog_point> matches;
std::map<prog_point,key_buf> key_tracker;

bool check_key(StringInfo *master_secret, StringInfo *client_random, StringInfo *server_random,
               StringInfo *enc_msg, StringInfo *version, StringInfo *content_type,
               const EVP_MD *md, const EVP_CIPHER *ciph)
{
    // Generate the session keys
    if (version->data[0] == 0x03 && version->data[1] == 0x03) {
        tls12_prf(EVP_sha256(), master_secret, "key expansion", server_random, client_random, &g_keydata);
    } else {
        tls_prf(master_secret, "key expansion", server_random, client_random, &g_keydata);
    }
    
    // Divvy up the key block
    unsigned char *client_mac_key;
    //unsigned char *server_mac_key;
    unsigned char *client_enc_key;
    //unsigned char *server_enc_key;
    unsigned char *client_enc_iv;
    //unsigned char *server_enc_iv;

    unsigned char *keyblock_ptr = g_keydata.data;
    // Client MAC
    client_mac_key = keyblock_ptr;
    keyblock_ptr += EVP_MD_size(md);
    // Server MAC
    //server_mac_key = keyblock_ptr;
    keyblock_ptr += EVP_MD_size(md);
    // Client enc
    client_enc_key = keyblock_ptr;
    keyblock_ptr += EVP_CIPHER_key_length(ciph);
    // Server enc
    //server_enc_key = keyblock_ptr;
    keyblock_ptr += EVP_CIPHER_key_length(ciph);
    // Client IV
    client_enc_iv = keyblock_ptr;
    keyblock_ptr += EVP_CIPHER_iv_length(ciph);
    // Server IV
    //server_enc_iv = keyblock_ptr;
    
    // Do the decryption
    int res = 0;
    int dec_data_len = 0;
    int tmp_len = enc_msg->data_len;

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CIPHER_CTX_set_padding(&ctx, 1);
    res = EVP_DecryptInit_ex(&ctx, ciph, NULL, client_enc_key, client_enc_iv);
    CHECK(res, "EVP_DecryptInit");
    res = EVP_DecryptUpdate(&ctx, g_out.data, &tmp_len, enc_msg->data, enc_msg->data_len);
    CHECK(res, "EVP_DecryptUpdate");
    dec_data_len += tmp_len;
    tmp_len = enc_msg->data_len - dec_data_len;
    EVP_DecryptFinal_ex(&ctx, g_out.data+dec_data_len, &tmp_len); 
    CHECK(res, "EVP_DecryptFinal");
    dec_data_len += tmp_len;
    EVP_CIPHER_CTX_cleanup(&ctx);

    // For some reason there's always one byte of extra padding?
    // This only applies to block ciphers, of course.
    if (EVP_CIPHER_block_size(ciph) != 1) dec_data_len--;
    g_out.data_len = dec_data_len;
    ssl_print_string("decrypted data", &g_out);
    
    unsigned short msg_len = dec_data_len - EVP_MD_size(md);
    unsigned char *msg = g_out.data;
    unsigned char *mac = g_out.data + msg_len;

    // TLS 1.1 and 1.2 provide an IV in the decrypted data. Skip it.
    if (version->data[0] == 0x03 && version->data[1] > 0x01) {
        msg += EVP_CIPHER_iv_length(ciph);
        msg_len -= EVP_CIPHER_iv_length(ciph);
    }

    // Verify the MAC
    // We assume sequence number 0 here
    const unsigned char seq_num_s[] = {0,0,0,0,0,0,0,0};
    uint16_t data_len = htons(msg_len);
    unsigned int maclen = EVP_MD_size(md);
    unsigned char calc_mac[maclen];

    HMAC_CTX hctx;
    HMAC_CTX_init(&hctx);
    HMAC_Init_ex(&hctx, client_mac_key, EVP_MD_size(md), md, NULL);
    HMAC_Update(&hctx, seq_num_s, sizeof(seq_num_s));
    HMAC_Update(&hctx, content_type->data, content_type->data_len);
    HMAC_Update(&hctx, version->data, version->data_len);
    HMAC_Update(&hctx, (unsigned char *)&data_len, sizeof(data_len));
    HMAC_Update(&hctx, msg, msg_len);
    HMAC_Final(&hctx, calc_mac, &maclen);
    HMAC_cleanup(&hctx);

    ssl_print_data("MAC (message)", mac, maclen);
    ssl_print_data("MAC (calculated)", calc_mac, maclen);

    if (memcmp(mac, calc_mac, maclen) == 0)
        return true;
    else
        return false;
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    prog_point p = {};
    get_prog_point(env, &p);

    // Only use candidates found in config (pre-filtered for key-ness)
    if (have_candidates && candidates.find(p) == candidates.end()) {
        //printf("Skipping " TARGET_FMT_lx "\n", p.pc);
        return 1;
    }

    // XXX DEBUG: Just check the one we KNOW is correct
    //if(p.caller != 0x0000000074ce9788 || p.pc != 0x0000000074ce82ef || p.cr3 != 0x000000003f9650e0) return 1;

    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        key_buf *k = &key_tracker[p];
        k->key[k->start++] = val;
        if (k->start == sizeof(k->key)) {
            k->start = 0;
            if (unlikely(!k->filled)) {
                k->filled = true;
            }
        }
        if (likely(k->filled)) {
            // Copy it out of the ring buffer
            int key_bytes_left = sizeof(k->key) - k->start;
            int key_bytes_right = k->start;
            memcpy(g_master_secret.data, k->key+k->start, key_bytes_left);
            if(key_bytes_right) {
                memcpy(g_master_secret.data+key_bytes_left, k->key, key_bytes_right);
            }

            bool match = check_key(&g_master_secret, &g_client_random, &g_server_random,
                           &g_enc_msg, &g_version, &g_content_type, g_md, g_ciph);

            if (unlikely(match)) {
                fprintf(stderr, "MAC match found at " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
                    p.caller, p.pc, p.cr3);
                fprintf(stderr, "Key: ");
                for(int j = 0; j < MASTER_SECRET_SIZE; j++)
                    fprintf(stderr, "%02x", g_master_secret.data[j]);
                fprintf(stderr, "\n");
                matches.insert(p);
            }
        }
    }
 
    return 1;
}

#define ASSUMED_TB_SIZE 256

bool enabled_memcb = false;
int instrumented, total;
int before_block_translate_cb(CPUState *env, target_ulong pc) {
    // Don't bother with any of this if we don't have any canidates;
    // in this case precise pc and memcb will always be on.
    if (!have_candidates) return 1;
    
    target_ulong tb_cr3 = 0;
#if defined(TARGET_I386)
    if ((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
       tb_cr3 = env->cr[3];
#elif defined(TARGET_ARM)
    if ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC) {
        if (pc & env->cp15.c2_mask)
            tb_cr3 = env->cp15.c2_base1 & 0xffffc000;
        else
            tb_cr3 = env->cp15.c2_base0 & env->cp15.c2_base_mask;
    }
#endif

    if (cr3s.find(tb_cr3) == cr3s.end()) return 1;

    // Slightly tricky: we ask for the lower bound of the TB start and
    // the lower bound of the (assumed) TB end in our sorted list of tap
    // EIPs. If that interval is nonempty then at least one of our taps
    // is in the upcoming TB, so we need to instrument it.
    std::vector<target_ulong>::iterator beg, end, it;
    beg = std::lower_bound(eips.begin(), eips.end(), pc);
    end = std::lower_bound(eips.begin(), eips.end(), pc+ASSUMED_TB_SIZE);

    if (std::distance(beg, end) != 0) {
        panda_enable_memcb();
        panda_enable_precise_pc();
        enabled_memcb = true;
        //printf("Enabling callbacks for TB " TARGET_FMT_lx " Interval:(%ld,%ld)\n", pc, beg-eips.begin(), end-eips.begin());
        //printf("Encompassed EIPs:");
        //for (it = beg; it != end; it++) {
        //    printf(" " TARGET_FMT_lx, *it);
        //}
        //printf("\n");
        instrumented++;
    }
    total++;

    return 1;
}

int after_block_translate_cb(CPUState *env, TranslationBlock *tb) {
    if (!have_candidates) return 1;

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
    return 1;
}

bool init_plugin(void *self) {
    // General PANDA stuff
    panda_cb pcb;

    printf("Initializing plugin keyfind\n");

    if(!init_callstack_instr_api()) return false;

    // SSL stuff
    // Init list of ciphers & digests
    OpenSSL_add_all_algorithms();

    // Read and parse list of candidate taps
    std::ifstream taps("keyfind_candidates.txt");
    if (!taps) {
        printf("Couldn't open keyfind_candidates.txt; no key tap candidates defined.\n");
        printf("We will proceed, but it may be SLOW.\n");
        have_candidates = false;
    }
    else {
        std::unordered_set <target_ulong> eipset;
        prog_point p = {};
        while (taps >> std::hex >> p.caller) {
            taps >> std::hex >> p.pc;
            taps >> std::hex >> p.cr3;

            eipset.insert(p.pc);
            cr3s.insert(p.cr3);

            //printf("Adding tap point (" TARGET_FMT_lx "," TARGET_FMT_lx "," TARGET_FMT_lx ")\n",
            //       p.caller, p.pc, p.cr3);
            candidates.insert(p);
        }
        printf("keyfind: Will check for keys on %ld taps.\n", candidates.size());
        taps.close();

        // Sort EIPs
        for(auto ii : eipset) {
            eips.push_back(ii);
        }
        std::sort(eips.begin(), eips.end());
    }

    // Read and parse the configuration file
    std::ifstream config("keyfind_config.txt");
    if (!config) {
        printf("Couldn't open keyfind_config.txt. Aborting.\n");
        return false;
    }

    bool found_client_random = false,
         found_server_random = false,
         found_enc_msg = false,
         found_version = false,
         found_content_type = false,
         found_cipher = false,
         found_mac = false;

    std::string line;
    while(std::getline(config, line)) {
        trim(line);

        // Skip comment lines
        if (line[0] == '#') continue;

        // Get Key: Value pairs
        std::istringstream iss(line);
        std::string key, value;
        std::getline(iss, key, ':');
        std::getline(iss, value, ':');
        trim(key); trim(value);

        if (key == "Client-Random") {
            if (value.length() != 32*2) {
                fprintf(stderr, "Client-Random length incorrect.\n");
                return false;
            }
            ssl_data_alloc(&g_client_random, 32);
            read_hex_string(value, g_client_random.data);
            found_client_random = true;
        }
        else if (key == "Server-Random") {
            if (value.length() != 32*2) {
                fprintf(stderr, "Server-Random length incorrect.\n");
                return false;
            }
            ssl_data_alloc(&g_server_random, 32);
            read_hex_string(value, g_server_random.data);
            found_server_random = true;
        }
        else if (key == "Enc-Msg") {
            ssl_data_alloc(&g_enc_msg, value.length()/2);
            read_hex_string(value, g_enc_msg.data);
            found_enc_msg = true;
        }
        else if (key == "Content-Type") {
            if (value.length() != 1*2) {
                fprintf(stderr, "Content-Type length incorrect.\n");
                return false;
            }
            ssl_data_alloc(&g_content_type, 1);
            read_hex_string(value, g_content_type.data);
            found_content_type = true;
        }
        else if (key == "Version") {
            if (value.length() != 2*2) {
                fprintf(stderr, "Version length incorrect.\n");
                return false;
            }
            ssl_data_alloc(&g_version, 2);
            read_hex_string(value, g_version.data);
            found_version = true;
        }
        else if (key == "Cipher") {
            g_ciph = EVP_get_cipherbyname(value.c_str());
            if (!g_ciph) {
                fprintf(stderr, "Unknown cipher name: %s\n", value.c_str());
                return false;
            }
            found_cipher = true;
        }
        else if (key == "MAC") {
            g_md = EVP_get_digestbyname(value.c_str());
            if (!g_md) {
                fprintf(stderr, "Unknown digest name: %s\n", value.c_str());
                return false;
            }
            found_mac = true;
        }
        else {
            printf("Unknown key: %s\n", key.c_str());
        }
    }

    // Make sure we have everything we need
    if (!found_client_random) { fprintf(stderr, "Client-Random not found in config file, aborting.\n"); return false; }
    if (!found_server_random) { fprintf(stderr, "Server-Random not found in config file, aborting.\n"); return false; }
    if (!found_enc_msg) { fprintf(stderr, "Enc-Msg not found in config file, aborting.\n"); return false; }
    if (!found_version) { fprintf(stderr, "Version not found in config file, aborting.\n"); return false; }
    if (!found_content_type) { fprintf(stderr, "Content-Type not found in config file, aborting.\n"); return false; }
    if (!found_cipher) { fprintf(stderr, "Cipher not found in config file, aborting.\n"); return false; }
    if (!found_mac) { fprintf(stderr, "MAC not found in config file, aborting.\n"); return false; }

    // Global data. Init it once here so we don't have to
    // re-alloc each time.
    ssl_data_alloc(&g_master_secret, MASTER_SECRET_SIZE);
    int needed = 0;
    needed = EVP_MD_size(g_md)*2 + \
             EVP_CIPHER_key_length(g_ciph)*2 + \
             EVP_CIPHER_iv_length(g_ciph)*2;
    ssl_data_alloc(&g_keydata, needed);
    ssl_data_alloc(&g_out, g_enc_msg.data_len);

    if (!have_candidates) {
        panda_enable_memcb();
        panda_enable_precise_pc();
        enabled_memcb = true;
    }

    // Enable our callbacks
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.before_block_translate = before_block_translate_cb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
    pcb.after_block_translate = after_block_translate_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    printf("%d / %d blocks instrumented.\n", instrumented, total);
    FILE *mem_report = fopen("key_matches.txt", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }
    std::set<prog_point>::iterator it;
    for(it = matches.begin(); it != matches.end(); it++) {
        // Print prog point
        fprintf(mem_report, TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
            it->caller, it->pc, it->cr3);
        // Print strings that matched and how many times
    }
    fclose(mem_report);
}
