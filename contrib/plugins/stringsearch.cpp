#include <glib.h>
#include <assert.h>
#include <math.h>
#include <string.h>

#include <map>
#include <string>

extern "C" {
#include <qemu-plugin.h>
}

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "stringsearch";

bool verbose = true;

#define MAX_STRINGS 100
#define MAX_CALLERS 128
#define MAX_STRLEN  1024

using match_strings = std::array<int, MAX_STRINGS>;
using string_pos = std::array<uint32_t, MAX_STRINGS>;

std::map<uint64_t, match_strings> matches;
std::map<uint64_t, string_pos> read_text_tracker;
std::map<uint64_t, string_pos> write_text_tracker;
char tofind[MAX_STRINGS][MAX_STRLEN];
uint32_t strlens[MAX_STRINGS];
size_t num_strings = 0;

void mem_callback(uint64_t pc, uint64_t addr, size_t size, bool is_write,
                  std::map<uint64_t, string_pos> &text_tracker)
{
    static char *big_buf = NULL;
    static uint32_t big_buf_len = 0;
    char buf[16] = { 0 };

    if (big_buf == NULL) {
        big_buf = (char *) g_malloc0(big_buf_len);
        big_buf_len = 128;
    }

    uint64_t p = pc;
    string_pos &sp = text_tracker[p];

    assert (size < 16);

    qemu_plugin_read_guest_virt_mem(addr, buf, size);

    for (size_t i = 0; i < size; i++) {
        char val = ((char *)buf)[i];
        for(size_t str_idx = 0; str_idx < num_strings; str_idx++) {
            if (tofind[str_idx][sp[str_idx]] == val) {
                sp[str_idx]++;
            } else {
                sp[str_idx] = 0;
            }

            if (sp[str_idx] == strlens[str_idx]) {
                /* Victory! */
                if (verbose) {
                    printf("%s Match of str %li at pc=0x%lx\n", is_write ? "WRITE" : "READ", str_idx, pc);
                }

                matches[p][str_idx]++;
                sp[str_idx] = 0;

                /* Check if the full string is in memory. */
                uint32_t sl = strlens[str_idx];

                if (big_buf_len < sl) {
                    big_buf_len = sl * 2;
                    big_buf = (char *) g_realloc(big_buf, big_buf_len);
                }

                uint64_t match_addr = (addr + i) - (sl - 1);
                qemu_plugin_read_guest_virt_mem(match_addr, big_buf, sl);

                if (memcmp(big_buf, tofind[str_idx], sl) == 0) {
                    qemu_plugin_run_callback(id, "my_string_found", &called, NULL);
                    printf("... its in memory\n");
                } else {
                    printf("... its not in memory\n");
                }
            }
        }
    }
 
    return;
}


/* Add a string to the list of strings we're searching for. */
bool add_string(const char* arg_str)
{
  size_t arg_len = strlen(arg_str);
  if (arg_len <= 0) {
      printf("WARNING [stringsearch]: not adding empty string\n");
      return false;
  }

  if (arg_len >= MAX_STRLEN-1) {
      printf("WARNING [stringsearch]: string too long (max %d)\n", MAX_STRLEN-1);
      return false;
  }

  /* If string already present it's okay */
  for (size_t str_idx = 0; str_idx < num_strings; str_idx++) {
      if (strncmp(arg_str, (char*)tofind[str_idx], strlens[str_idx]) == 0) {
        return true;
      }
  }

  if (num_strings >= MAX_STRINGS-1) {
    printf("Warning [stringsearch]: out of string slots (using %ld)\n", num_strings);
    return false;
  }

  memcpy(tofind[num_strings], arg_str, arg_len);
  strlens[num_strings] = arg_len;
  num_strings++;

  if (verbose) {
      printf("[stringsearch] Adding string %s\n", arg_str);
  }

  return true;
}

/* Remove the first match from our list */
bool remove_string(const char* arg_str)
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

void reset_strings()
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
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_create_callback(id, "my_on_string_found");
    
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_autofree char **tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "str") == 0) {
            add_string(tokens[1]);
        }
    }

    return 0;
}

