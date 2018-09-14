/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Laura L. Mann
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <iostream>

#include "panda/plugin.h"
#include "panda/network.h"
#include "taint2/taint2.h"

extern "C" {
#include "qemu/cutils.h"
#include "taint2/taint2_ext.h"
}

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
int on_replay_handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t
    direction, uint64_t old_buf_addr);
}

// buffer for getting labels on transmitted packets
uint32_t *taint_labels = NULL;
size_t cur_max_labels = 10;

// Configuration
bool label_incoming_network_traffic = false;
bool query_outgoing_network_traffic = false;
bool positional_tainting = false;
const char *tx_filename = NULL;

bool firstOpen = true;


// a packet has come in over the network, or is about to go out over the network
int on_replay_handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t
    direction, uint64_t old_buf_addr) {

    if (PANDA_NET_RX == direction)
    {
        if (label_incoming_network_traffic)
        {
            if (!taint2_enabled())
            {
                std::cerr << PANDA_MSG "Label operation detected (network)" <<
                  std::endl;
                std::cerr << PANDA_MSG "Enabling taint processing" << std::endl;
                taint2_enable_taint();
            }
            fprintf(stderr, PANDA_MSG "Applying labels to %d IO items starting at 0x%lx\n",
                size, old_buf_addr);
            for (int i = 0; i < size; i++)
            {
                if (positional_tainting)
                {
                    taint2_label_io((old_buf_addr + i), i);
                }
                else
                {
                    taint2_label_io((old_buf_addr + i), 100);
                }
            }
        }
    }
    else if (PANDA_NET_TX == direction)
    {
        if (query_outgoing_network_traffic && taint2_enabled())
        {
            // the output can be rather voluminous, so send it to a file
            // just keep appending data to same file - the column headers will
            // separate the packets
            FILE *taintlogF = NULL;
            if (firstOpen)
            {
                taintlogF = fopen(tx_filename, "w+");
                firstOpen = false;
            }
            else
            {
               taintlogF = fopen(tx_filename, "a+");
            }
            fprintf(taintlogF, "\"Address\",\"Datum\",\"Labels\"\n");

            uint32_t numLabels = 0;
            uint64_t curAddr = 0;
            for (int i = 0; i < size; i++)
            {
                curAddr = old_buf_addr + i;
                numLabels = taint2_query_io(curAddr);
                if (numLabels > 0)
                {
                    // is my label buffer big enough?
                    if (numLabels > cur_max_labels)
                    {
                        taint_labels = (uint32_t *)realloc(taint_labels,
                            numLabels * sizeof(uint32_t));
                        cur_max_labels = numLabels;
                    }
                   
                    // fetch the labels on curAddr into taint_labels
                    taint2_query_set_io(curAddr, taint_labels);
                   
                    // print out info for this datum, using . for unprintable
                    // characters
                    if (isprint(buf[i]))
                    {
                        fprintf(taintlogF, "%ld,%c,", curAddr, buf[i]);
                    }
                    else
                    {
                        fprintf(taintlogF, "%ld,.,", curAddr);
                    }
                    for (int j = 0; j < numLabels; j++)
                    {
                        fprintf(taintlogF, " %d", taint_labels[j]);
                    }
                    fprintf(taintlogF, "\n");
                } // end of item-in-TX-buffer-has-label(s)
                else
                {
                    if (isprint(buf[i]))
                    {
                        fprintf(taintlogF, "%ld,%c, NULL\n", curAddr, buf[i]);
                    }
                    else
                    {
                        fprintf(taintlogF, "%ld,., NULL\n", curAddr);
                    }
                }
            } // end of loop through items in TX buffer
            
            qemu_fdatasync(fileno(taintlogF));  // ensure ALL data gets flushed
            int status = fclose(taintlogF);
            if (status != 0)
            {
                fprintf(stderr, "ERROR closing %s\n", tx_filename);
            }
        } // end of care-about-outgoing-taint
    }
    else
    {
        fprintf(stderr, "Unrecognized network packet direction (%d)\n",
            direction);
    }
    
    return 1;
}


bool init_plugin(void *self) {
    panda_cb pcb;
#ifdef CONFIG_SOFTMMU
    
    // fetch the plugin arguments
    panda_arg_list *args = panda_get_args("tainted_net");
    
    label_incoming_network_traffic = panda_parse_bool_opt(args,
        "label_incoming_network",
        "apply taint labels to incoming network traffic");
    std::cerr << PANDA_MSG "label incoming network traffic " <<
      PANDA_FLAG_STATUS(label_incoming_network_traffic) << std::endl;
    
    query_outgoing_network_traffic = panda_parse_bool_opt(args,
        "query_outgoing_network", "display taint on outgoing network traffic");
    std::cerr << PANDA_MSG "query outgoing network traffic " <<
      PANDA_FLAG_STATUS(query_outgoing_network_traffic) << std::endl;
    
    if (!(label_incoming_network_traffic || query_outgoing_network_traffic))
    {
        std::cerr <<
          PANDA_MSG "tainted_net needs at least one of label_incoming_network or query_outgoing_network enabled" <<
          std::endl;
        return false;
    }
    
    // for incoming packets, does each byte get same label, or different
    // (positional) labels?
    if (label_incoming_network_traffic)
    {
        positional_tainting = panda_parse_bool_opt(args, "pos",
            "positional taint");
        std::cerr << PANDA_MSG "apply positional taint labels " <<
          PANDA_FLAG_STATUS(positional_tainting) << std::endl;
    }
    
    // need a file name if watching for outgoing taint
    if (query_outgoing_network_traffic)
    {
        tx_filename = panda_parse_string_opt(args, "file",
            "tainted_net_query.csv",
            "name of file for taint information on outgoing network packets");
        std::cerr << PANDA_MSG "outgoing network traffic taint file " <<
            tx_filename << std::endl;
            
        // need some initialize room in the buffer for taint labels too
        taint_labels = (uint32_t *)malloc(cur_max_labels * sizeof(uint32_t));
    }
    
    panda_require("taint2");
    
    pcb.replay_handle_packet = on_replay_handle_packet;
    panda_register_callback(self, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);
    
    assert(init_taint2_api());
    
    return true;
#else
    std::cerr << PANDA_MSG "tainted_net does not support user mode" <<
      std::endl;
    return false;
#endif
}

void uninit_plugin(void *self)
{
    if (query_outgoing_network_traffic)
    {
        free(taint_labels);
    }
}
