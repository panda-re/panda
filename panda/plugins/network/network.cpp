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

#define COMMENT_BUF_LEN 1024

#include "panda/plugin.h"

#include <wireshark/config.h>
#include <wiretap/wtap.h>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

    bool init_plugin(void *);
    void uninit_plugin(void *);

    int handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t direction,
                uint64_t old_buf_addr);

    extern uint64_t rr_get_guest_instr_count(void);
}

panda_arg_list *args;
wtap_dumper *plugin_log;

bool init_plugin(void *self) {
    panda_cb pcb;

    int i;
    char *tblog_filename = NULL;
    args = panda_get_args("network");
    if (args != NULL) {
        for (i = 0; i < args->nargs; i++) {
            // Format is sample:file=<file>
            if (0 == strncmp(args->list[i].key, "file", 4)) {
                tblog_filename = args->list[i].value;
            }
        }
    }

    if (!tblog_filename) {
        fprintf(stderr, "Plugin 'network' needs argument: -panda-arg network:file=<file>\n");
        return false;
    }

#if VERSION_MAJOR == 2 && VERSION_MINOR == 2 && VERSION_MICRO >= 4
    wtap_init();
#endif

    int err;
    plugin_log = wtap_dump_open_ng(
            /*filename*/tblog_filename,
            /*file_type_subtype*/WTAP_FILE_TYPE_SUBTYPE_PCAPNG,
            /*encap*/WTAP_ENCAP_ETHERNET,
            /*snaplen*/65535,
            /*compressed*/1,
            /*shb_hdrs*/NULL,
            /*idb_inf*/NULL,
#if VERSION_MAJOR >= 2 && VERSION_MINOR >= 0 && VERSION_MICRO >= 0
            /*nrb_hdrs*/NULL,
#endif
            /*err*/&err);
    if(!plugin_log) {
        fprintf(stderr, "Plugin 'network': failed wtap_dump_open_ng() with error %d\n", err);
        return false;
    }

    pcb.replay_handle_packet = handle_packet;
    panda_register_callback(self, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);

    return true;
}

void uninit_plugin(void *self) {
    printf("Unloading network plugin.\n");
    panda_free_args(args);
    int err;
    gboolean ret = wtap_dump_close(plugin_log, &err);
    if (!ret) {
        fprintf(stderr, "Plugin 'network': failed wtap_dump_close() with error %d\n", err);
    }
}

int handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t direction,
                uint64_t old_buf_addr) {
    int err;
    struct wtap_pkthdr header;
    struct timeval now_tv;
    char comment_buf[COMMENT_BUF_LEN];
#if VERSION_MAJOR >= 2 && VERSION_MINOR >= 0 && VERSION_MICRO >= 0
    char *err_info;
    wtap_phdr_init(&header);
#endif
    gettimeofday(&now_tv, NULL);
    header.ts.secs = now_tv.tv_sec;
    header.ts.nsecs = now_tv.tv_usec * 1000;
    header.caplen = size;
    header.len = size;
    header.opt_comment = comment_buf;
    snprintf(comment_buf, COMMENT_BUF_LEN, "Guest instruction count: %" PRIu64, rr_get_guest_instr_count());
    gboolean ret = wtap_dump(
        /*wtap_dumper*/plugin_log,
        /*wtap_pkthdr*/&header,
        /*buf*/buf,
        /*err*/&err
#if VERSION_MAJOR >= 2 && VERSION_MINOR >= 0 && VERSION_MICRO >= 0
        ,
        /*err_info*/&err_info
#endif
        );
    if (!ret) {
      fprintf(stderr, "Plugin 'network': failed wtap_dump() with error %d", err);
#if VERSION_MAJOR >= 2 && VERSION_MINOR >= 0 && VERSION_MICRO >= 0
      fprintf(stderr, " and error_info %s", err_info);
#endif
      fprintf(stderr, "\n");
    }
#if VERSION_MAJOR >= 2 && VERSION_MINOR >= 0 && VERSION_MICRO >= 0
    wtap_phdr_cleanup(&header);
#endif

    return 0;
}
