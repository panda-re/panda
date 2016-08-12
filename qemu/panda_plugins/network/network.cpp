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

#define __STDC_FORMAT_MACROS

#define COMMENT_BUF_LEN 1024

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda/network.h"

}

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <wiretap/wtap.h>

extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

int handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t direction,
    uint64_t old_buf_addr);

extern uint64_t replay_get_guest_instr_count(void);

}

panda_arg_list *args;
wtap_dumper *plugin_log;

// RW Yanked from net.c
static void hex_dump(FILE *f, const uint8_t *buf, int size)
{
    int len, i, j, c;

    for(i=0;i<size;i+=16) {
        len = size - i;
        if (len > 16)
            len = 16;
        fprintf(f, "%08x ", i);
        for(j=0;j<16;j++) {
            if (j < len)
                fprintf(f, " %02x", buf[i+j]);
            else
                fprintf(f, "   ");
        }
        fprintf(f, " ");
        for(j=0;j<len;j++) {
            c = buf[i+j];
            if (c < ' ' || c > '~')
                c = '.';
            fprintf(f, "%c", c);
        }
        fprintf(f, "\n");
    }
}

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

    int err;
    plugin_log = wtap_dump_open_ng(tblog_filename, WTAP_FILE_TYPE_SUBTYPE_PCAPNG, WTAP_ENCAP_ETHERNET, 65535, 1, NULL, NULL, NULL, &err);
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
        uint64_t old_buf_addr){
//    switch (direction){
//        case PANDA_NET_RX:
//            fprintf(plugin_log, "RX:\n");
//            break;
//        case PANDA_NET_TX:
//            fprintf(plugin_log, "TX:\n");
//            break;
//        default:
//            assert(0);
//            break;
//    }
//    hex_dump(plugin_log, buf, size);
//    fprintf(plugin_log, "\n");

    int err;
    char *err_info;
    struct wtap_pkthdr header;
    struct timeval now_tv;
    char comment_buf[COMMENT_BUF_LEN];

    wtap_phdr_init(&header);
    gettimeofday(&now_tv, NULL);
    header.ts.secs = now_tv.tv_sec;
    header.ts.nsecs = now_tv.tv_usec * 1000;
    header.caplen = size;
    header.len = size;
    header.opt_comment = comment_buf;
    snprintf(comment_buf, COMMENT_BUF_LEN, "Guest instruction count: %" PRIu64, replay_get_guest_instr_count());
    gboolean ret = wtap_dump(plugin_log, &header, buf, &err, &err_info);
    if (!ret) {
      fprintf(stderr, "Plugin 'network': failed wtap_dump() with error %d and error_info %s\n", err, err_info);
    }
    wtap_phdr_cleanup(&header);

    return 0;
}

