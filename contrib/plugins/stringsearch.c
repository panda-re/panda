#include <glib.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <qemu-plugin.h>
#include <plugin-qpp.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "stringsearch";

#include "stringsearch.h"

qemu_plugin_id_t plugin_id;

bool verbose = true;

#define MAX_STRINGS 100
#define MAX_CALLERS 128
#define MAX_STRLEN  1024

typedef struct {
    int32_t val[MAX_STRINGS];
} match_strings;

typedef struct {
    uint32_t val[MAX_STRINGS];
} string_pos;

GHashTable *matches = NULL;

/* table of recent reads that contained a substring of a match */
GHashTable *read_text_tracker = NULL;

/* table of recent writes that contained a substring of a match */
GHashTable *write_text_tracker = NULL;

/* list of strings to search for */
char tofind[MAX_STRINGS][MAX_STRLEN];

/* how long each string in tofind is */
uint32_t strlens[MAX_STRINGS];

/* number of strings in tofind */
size_t num_strings = 0;

static guint u64_hash(gconstpointer key)
{
    uint64_t k = (uint64_t)key;

    return ((guint)k) ^ ((guint)(k >> 32));
}

static int u64_equality(gconstpointer left, gconstpointer right)
{
    uint64_t l = (uint64_t)left;
    uint64_t r = (uint64_t)right;

    return l == r;
}

static void mem_callback(uint64_t pc, uint64_t addr, size_t size, bool is_write,
                  GHashTable *text_tracker)
{
    static char *big_buf = NULL;
    static uint32_t big_buf_len = 0;
    char buf[16] = { 0 };

    if (big_buf == NULL) {
        big_buf = (char *) g_malloc0(big_buf_len);
        big_buf_len = 128;
    }

    uint64_t p = pc;
    string_pos *sp = g_hash_table_lookup(text_tracker, (gconstpointer)p);
    if(sp == NULL) {
        sp = (string_pos*)g_malloc0(sizeof(string_pos));
        g_hash_table_insert(text_tracker, (gpointer)p, (gpointer)sp);
    }

    assert (size < 16);

    qemu_plugin_read_guest_virt_mem(addr, buf, size);

    for (size_t i = 0; i < size; i++) {
        char val = ((char *)buf)[i];
        for(size_t str_idx = 0; str_idx < num_strings; str_idx++) {
            if (tofind[str_idx][sp->val[str_idx]] == val) {
                sp->val[str_idx]++;
            } else {
                sp->val[str_idx] = 0;
            }

            if (sp->val[str_idx] == strlens[str_idx]) {
                /* Victory! */
                if (verbose) {
                    /* Log the discovery of a match */
                    size_t output_len = snprintf(NULL, 0, "%s Match of str %li at pc=0x%lx\n", is_write ? "WRITE" : "READ", str_idx, pc);
                    char *output = (char*)g_malloc0(output_len + 1);

                    snprintf(output, output_len, "%s Match of str %li at pc=0x%lx\n", is_write ? "WRITE" : "READ", str_idx, pc);
                    qemu_plugin_outs(output);

                    g_free((gpointer)output);
                }

                /* Keep track of what matches have been found and where */
                match_strings *match = (match_strings*)g_hash_table_lookup(matches, (gconstpointer)p);
                if(match == NULL) {
                    match = g_malloc0(sizeof(match_strings));
                    g_hash_table_insert(matches, (gpointer)p, match);
                }
                match->val[str_idx]++;
                sp->val[str_idx] = 0;

                /* Check if the full string is in memory. */
                uint32_t sl = strlens[str_idx];

                if (big_buf_len < sl) {
                    big_buf_len = sl * 2;
                    big_buf = (char *) g_realloc(big_buf, big_buf_len);
                }

                uint64_t match_addr = (addr + i) - (sl - 1);

                /* Check if the entire string is currently present in memory */
                qemu_plugin_read_guest_virt_mem(match_addr, big_buf, sl);

                if (memcmp(big_buf, tofind[str_idx], sl) == 0) {
                    /* Run the callback only if the entire string is present */
                    qemu_plugin_run_callback(plugin_id, "on_string_found", &match_addr, NULL);
                    qemu_plugin_outs("... its in memory\n");
                } else {
                    qemu_plugin_outs("... its not in memory\n");
                }
            }
        }
    }
 
    return;
}


/* Add a string to the list of strings we're searching for. */
QEMU_PLUGIN_EXPORT bool stringsearch_add_string(const char* arg_str)
{
  size_t arg_len = strlen(arg_str);
  if (arg_len <= 0) {
      qemu_plugin_outs("WARNING [stringsearch]: not adding empty string\n");
      return false;
  }

  if (arg_len >= MAX_STRLEN-1) {
      qemu_plugin_outs("WARNING [stringsearch]: string too long\n");
      return false;
  }

  /* If string already present it's okay */
  for (size_t str_idx = 0; str_idx < num_strings; str_idx++) {
      if (strncmp(arg_str, (char*)tofind[str_idx], strlens[str_idx]) == 0) {
        return true;
      }
  }

  if (num_strings >= MAX_STRINGS-1) {
    qemu_plugin_outs("Warning [stringsearch]: out of string slots\n");
    return false;
  }

  memcpy(tofind[num_strings], arg_str, arg_len);
  strlens[num_strings] = arg_len;
  num_strings++;

  if (verbose) {
      size_t output_len = snprintf(NULL, 0, "[stringsearch] Adding string %s\n\n", arg_str);
      char *output = (char*)g_malloc0(output_len + 1);

      snprintf(output, output_len, "[stringsearch] Adding string %s\n\n", arg_str);
      qemu_plugin_outs(output);

      g_free((gpointer)output);
  }

  return true;
}

/* Remove the first match from our list */
QEMU_PLUGIN_EXPORT bool stringsearch_remove_string(const char* arg_str)
{
    for (size_t str_idx = 0; str_idx < num_strings; str_idx++) {
        if (strncmp(arg_str, (char*)tofind[str_idx], strlens[str_idx]) == 0) {
            memmove( &tofind[str_idx],  &(tofind[str_idx+1]), (sizeof(uint8_t ) * (num_strings - str_idx)));
            memmove(&strlens[str_idx], &(strlens[str_idx+1]), (sizeof(uint32_t) * (num_strings - str_idx)));
            num_strings--;

            return true;
        }
    }

    return false;
}

/* Remove all strings from search list */
QEMU_PLUGIN_EXPORT void stringsearch_reset_strings(void)
{
    num_strings = 0;
}

static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata)
{
    size_t sz = pow(2, qemu_plugin_mem_size_shift(info));
    uint64_t pc = qemu_plugin_get_pc();

    if (qemu_plugin_mem_is_store(info)) {
        mem_callback(pc, vaddr, sz, /*is_write=*/true, read_text_tracker);
    } else {
        mem_callback(pc, vaddr, sz, /*is_write=*/false, write_text_tracker);
    }
}


static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;
    size_t n = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < n; i++) {
        insn = qemu_plugin_tb_get_insn(tb, i);

        /* Register callback on memory read or write */
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, NULL);        
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    plugin_id = id;

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_create_callback(id, "on_string_found");

    matches = g_hash_table_new_full(u64_hash, u64_equality, NULL, g_free);
    read_text_tracker = g_hash_table_new_full(u64_hash, u64_equality, NULL, g_free);
    write_text_tracker = g_hash_table_new_full(u64_hash, u64_equality, NULL, g_free);
    
    /* parse arguments for passing strings to look for */
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_autofree char **tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "str") == 0) {
            stringsearch_add_string(tokens[1]);
        }
    }

    return 0;
}

