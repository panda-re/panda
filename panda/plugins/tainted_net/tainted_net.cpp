/* PANDABEGINCOMMENT
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <iostream>
#include <set>
#include <cstring>
#include <stdint.h>

#include "panda/plugin.h"
#include "panda/network.h"
#include "taint2/taint2.h"

// Number of bits in a taint label
constexpr uint32_t LABEL_BITS = 32;

// Unsigned, 32-bit, 1
constexpr uint32_t ONE = 1;

extern "C"
{
#include "qemu/cutils.h"
#include "taint2/taint2_ext.h"
#include "ida_taint2/ida_taint2_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
bool init_plugin(void *self);
void uninit_plugin(void *self);
int on_replay_handle_packet(CPUState *env, uint8_t *buf, int packet_size,
    uint8_t direction, uint64_t old_buf_addr);
}

const std::string PLUGIN_NM = std::string("tainted_net");

// Delimiter for options that specify sets of integer ranges
const std::string DELIM = std::string(":");

// Default value for options that specify sets of integer ranges
const std::string DEFAULT_ALL = std::string("all");

// IPV4/Ethernet constants

constexpr uint16_t MAC_HEADER_SIZE = 14;
constexpr uint16_t ETHERTYPE_OCTET = 12;
constexpr uint16_t IPV4_HEADER_MIN_SIZE = 19;
constexpr uint16_t IPV4_VERSION_OCTET = (MAC_HEADER_SIZE+0);
constexpr uint16_t IPV4_VERSION_MASK = (1 << 6);
constexpr uint16_t IPV4_PROTOCOL_OCTET = (MAC_HEADER_SIZE+9);
constexpr uint16_t IPV4_SOURCE_IP_OCTET = (MAC_HEADER_SIZE+12);
constexpr uint16_t IPV4_DEST_IP_OCTET = (MAC_HEADER_SIZE+16);

// Constants for implementing max packet size option
constexpr uint16_t PACKET_SIZE_16 = ((1<<16)-1);
constexpr uint16_t PACKET_SIZE_15 = ((1<<15)-1);
constexpr uint16_t PACKET_SIZE_14 = ((1<<14)-1);
constexpr uint16_t PACKET_SIZE_13 = ((1<<13)-1);
constexpr uint16_t PACKET_SIZE_12 = ((1<<12)-1);
constexpr uint16_t PACKET_SIZE_11 = ((1<<11)-1);

// buffer for getting labels on transmitted packets
uint32_t *taint_labels = NULL;
size_t cur_max_labels = 10;

// Configuration
bool label_incoming_network_traffic = false;
bool query_outgoing_network_traffic = false;
bool semantic_labels = false;
bool positional_labels = false;
const char *tx_filename = NULL;

bool firstOpen = true;

// File that semantic label data is written to.
FILE *semantic_labels_file = NULL;

// Counter for each incoming network packet.  Allows for tainting only specific
// packet numbers.
uint32_t packet_count = 0;

// Label counter.  Used when semantic labeling is enabled.
uint32_t label_count = 0;

// Only used for positional tainting.  The number of bits to reserve in the
// taint label for the TCP packet_size.
uint32_t packet_size_bits = 0;

// Set of packet numbers that will be tainted.
std::set<uint32_t> packets_to_taint;

// Set of IPV4 protocol numbers to taint.  Only packets with protocol numbers
// in this set will be tainted.
std::set<uint32_t> protocols_to_taint;

// Set of byte offsets in packets to taint.
std::set<uint32_t> bytes_to_taint;

// If non-zero, only taint packets that arrive from this source ip.
uint32_t source_ip=0;

// If non-zero, only taint packets with this destination ip.
uint32_t dest_ip=0;

// If non-zero, only taint packets with this ethertype protocol number.
uint16_t ethertype=0;

static void output_message(const std::string &message)
{
    std::cerr << PANDA_MSG << message << std::endl;
}

// Called when a packet received passes all filtering criteria.
// Data within the packet should be tainted.
// User-specified options may limit the data that is tainted (e.g. only taint
// bytes 56-60.)

void taint_network_data(int packet_size, target_ptr_t old_buf_addr)
{
    // Counts number of labels applied to this packet.
    uint32_t num_labels_applied = 0;

    // Default label value is 100.  This will be overwritten if semantic or positional labeling is enabled.
    uint32_t label_value = 100;

    if (0 == taint2_enabled())
    {
        output_message("Label operation detected (network)");
        output_message("Enabling taint processing");
        taint2_enable_taint();
    }

    // Loop through each byte in the packet
    for (uint32_t byte_offset = 0; byte_offset < packet_size; byte_offset++)
    {
        // If only specific bytes are to be tainted, check to see if this byte should be tainted
        if(bytes_to_taint.empty() || (bytes_to_taint.find(byte_offset)!=bytes_to_taint.end()))
        {
            // Label is to be applied, increment the counter.
            num_labels_applied++;

            if (semantic_labels)
            {
                // With semantic labels, increment the counter and write out the packet count and byte offset.
                // The IDA taint plugin will read this data so semantic labels can be displayed in IDA.
                label_value=++label_count;
                assert(fprintf(semantic_labels_file, "%u,%u-%u\n", label_value, packet_count, byte_offset) > 0);
            }
            else if (positional_labels)
            {
                // Compute taint label.
                // Set the high order bits to be the packet number.
                // Set the low order bits to be the byte offset.
                label_value = (packet_count << packet_size_bits) |
                    (byte_offset & ((ONE << packet_size_bits) - ONE));
            }

            // Apply taint label
            taint2_label_io(old_buf_addr + byte_offset, label_value);
        }
    }

    // Notify user that data is being tainted.
    fprintf(stderr, PANDA_MSG "Applying labels to %d of %d IO items "
            "starting at 0x" TARGET_PTR_FMT ", packet #%u\n",
             num_labels_applied, packet_size, old_buf_addr, packet_count);
}

// if filtering on specific ipv4 protocols, determine if this packet matches one of the target protocols
static bool validate_protocol(uint8_t *buf, bool is_ipv4)
{
    return protocols_to_taint.empty() || 
        (is_ipv4 && protocols_to_taint.find(buf[IPV4_PROTOCOL_OCTET])!=protocols_to_taint.end());
}

// if filtering on specific packet numbers, determine if this packet matches one of the target packet numbers
static bool validate_packet_number(void)
{
    return packets_to_taint.empty() || (packets_to_taint.find(packet_count)!=packets_to_taint.end());
}

// if filtering on specific source ip, determine if this packet matches
static bool validate_source_ip(uint8_t *buf, bool is_ipv4)
{
    return (0 == source_ip) || (is_ipv4 && (0 == memcmp(buf+IPV4_SOURCE_IP_OCTET, &source_ip, sizeof(source_ip))));
}

// if filtering on specific destination ip, determine if this packet matches
static bool validate_dest_ip(uint8_t *buf, bool is_ipv4)
{
    return (0 == dest_ip) || (is_ipv4 && (0 == memcmp(buf+IPV4_DEST_IP_OCTET, &dest_ip, sizeof(dest_ip))));
}

// if filtering on specific protocol encapsulated within an ethernet packet, determine if this packet matches
static bool validate_ethertype(uint8_t *buf, int packet_size)
{
    return (0 == ethertype) || 
        ((packet_size > MAC_HEADER_SIZE) && (0 == memcmp(buf+ETHERTYPE_OCTET, &ethertype, sizeof(ethertype))));
}


static void on_replay_handle_incoming_packet(CPUState *env, uint8_t *buf, int packet_size, uint64_t _old_buf_addr)
{
    // The interface always used uint64_t, irrespective of the guest address space.
    // Downcast the address.
    target_ptr_t old_buf_addr = (target_ptr_t)_old_buf_addr;
    assert(packet_size > 0);
    assert(buf);
    assert(old_buf_addr);

    // determine if this is an IPV4 packet
    bool is_ipv4 = (packet_size > (MAC_HEADER_SIZE + IPV4_HEADER_MIN_SIZE)) &&
        ((buf[IPV4_VERSION_OCTET] & IPV4_VERSION_MASK) == IPV4_VERSION_MASK);

    if(validate_protocol(buf, is_ipv4) &&
        validate_packet_number() &&
        validate_source_ip(buf, is_ipv4) &&
        validate_dest_ip(buf, is_ipv4) &&
        validate_ethertype(buf, packet_size))
    {
        // if we get here, packet has matched all filter criteria.  start tainting.
        taint_network_data(packet_size, old_buf_addr);
    }
}

static void on_replay_handle_outgoing_packet(CPUState *env, uint8_t *buf, int packet_size, target_ptr_t old_buf_addr)
{
    if (0 != taint2_enabled())
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
        target_ptr_t curAddr = 0;
        for (int i = 0; i < packet_size; i++)
        {
            curAddr = old_buf_addr + i;
            numLabels = taint2_query_io(curAddr);
            if (numLabels > 0)
            {
                // is my label buffer big enough?
                if (numLabels > cur_max_labels)
                {
                    taint_labels = static_cast<uint32_t *>(realloc(taint_labels,
                        numLabels * sizeof(uint32_t)));
                    cur_max_labels = numLabels;
                }

                // fetch the labels on curAddr into taint_labels
                taint2_query_set_io(curAddr, taint_labels);

                // print out info for this datum, using . for unprintable
                // characters
                if (isprint(buf[i]))
                {
                    fprintf(taintlogF, TARGET_PTR_FMT ",%c,", curAddr, buf[i]);
                }
                else
                {
                    fprintf(taintlogF, TARGET_PTR_FMT ",.,", curAddr);
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
                    fprintf(taintlogF, TARGET_PTR_FMT ",%c, NULL\n", curAddr, buf[i]);
                }
                else
                {
                    fprintf(taintlogF, TARGET_PTR_FMT ",., NULL\n", curAddr);
                }
            }
        } // end of loop through items in TX buffer

        qemu_fdatasync(fileno(taintlogF));  // ensure ALL data gets flushed
        int status = fclose(taintlogF);
        if (status != 0)
        {
            output_message(std::string("ERROR closing ") + tx_filename);
        }
    } // end of care-about-outgoing-taint
}

// a packet has come in over the network, or is about to go out over the network
int on_replay_handle_packet(CPUState *env, uint8_t *buf, int packet_size, 
        uint8_t direction, target_ptr_t old_buf_addr)
{
    // Increment packet counter.  This count should agree with the count in the
    // wireshark file that is produced by the network plugin.
    ++packet_count;

    if (PANDA_NET_RX == direction)
    {
        if (label_incoming_network_traffic)
        {
            on_replay_handle_incoming_packet(env, buf, packet_size,
                old_buf_addr);
        }
    }
    else if (PANDA_NET_TX == direction)
    {
        if (query_outgoing_network_traffic)
        {
            on_replay_handle_outgoing_packet(env, buf, packet_size,
                old_buf_addr);
        }
    }
    else
    {
        output_message("Unrecognized network packet direction (" +
            std::to_string(direction) + ")");
    }

    return 1;
}

// Parse a string containing a set of integers and/or ranges and return a set containing all
// specified values.
// Example valid inputs:
// 1
// 1:2
// 1:2:3
// 1-3 (identical to 1:2:3)
// 1-3:5
// 1-3:5:6:7
// 1-3:5-7
std::set<uint32_t> parse_int_ranges(panda_arg_list *args, const char *arg_name,
        const char *help_text)
{
    std::set<uint32_t> int_set;

    const char *arg_value = panda_parse_string_opt(args, arg_name, DEFAULT_ALL.c_str(),
        help_text);

    if(0 != std::strcmp(arg_value, DEFAULT_ALL.c_str()))
    {
        char *tmp = new char[std::strlen(arg_value)+1];
        std::strncpy(tmp, arg_value, std::strlen(arg_value)+1);

        char *savptr;

        for(char *s=strtok_r(tmp,DELIM.c_str(),&savptr); s; s=strtok_r(NULL,DELIM.c_str(),&savptr))
        {
            char *t=std::strchr(s, '-');
            unsigned long first;
            unsigned long last;
            if(t != NULL)
            {
                *(t++)='\0';
                first=std::strtoul(s,NULL,0);
                last=std::strtoul(t,NULL,0);
            }
            else
            {
                first=(last=std::strtoul(s,NULL,0));
            }
            assert(first!=0);
            assert(last!=0);
            assert(first!=ULONG_MAX);
            assert(last!=ULONG_MAX);
            assert(last<=UINT32_MAX);
            assert(first<=last);
            for(uint32_t i=first; i<=last; i++)
            {
                int_set.insert(i);
            }
        }
        delete[] tmp;
    }

    return int_set;
}

// convert a command line argument value to a uint16_t
uint16_t parse_uint16_t(panda_arg_list *args, const char *arg_name,
        const char *default_value, const char *help_text)
{

    uint16_t num = 0;

    const char *arg_value = panda_parse_string_opt(args, arg_name,
        default_value, help_text);

    assert(arg_value);

    if(*arg_value != '\0')
    {
        unsigned long n=std::strtoul(arg_value,NULL,0);
        assert(n!=ULONG_MAX);
        assert(n<=UINT16_MAX);
        num = static_cast<uint16_t>(n);
    }

    return num;
}

// convert a command line argument value to a binary ipv4 address
uint32_t parse_ip(panda_arg_list *args, const char *arg_name,
        const char *help_text)
{

    uint32_t ip = 0;

    const char *arg_value = panda_parse_string_opt(args, arg_name, "", help_text);

    assert(arg_value);

    if(*arg_value != '\0')
    {
        assert(1 == inet_pton(AF_INET, arg_value, &ip));
    }

    return ip;
}

// Get values in set as a std::string
std::string get_set_as_string(std::set<uint32_t> const &set)
{
    std::string s=std::string();
    for(auto it = set.begin(); it!=set.end(); ++it)
    {
        s+=std::to_string(*it) + " ";
    }
    return s;
}

bool init_plugin(void *self)
{
    panda_cb pcb;
#ifdef CONFIG_SOFTMMU

    // fetch the plugin arguments
    panda_arg_list *args = panda_get_args(PLUGIN_NM.c_str());

    label_incoming_network_traffic = panda_parse_bool_opt(args,
        "label_incoming_network",
        "apply taint labels to incoming network traffic");
    output_message(std::string("label incoming network traffic ") +
      PANDA_FLAG_STATUS(label_incoming_network_traffic));

    query_outgoing_network_traffic = panda_parse_bool_opt(args,
        "query_outgoing_network", "display taint on outgoing network traffic");
    output_message(std::string("query outgoing network traffic ") +
      PANDA_FLAG_STATUS(query_outgoing_network_traffic));

    if (!(label_incoming_network_traffic || query_outgoing_network_traffic))
    {
        output_message(PLUGIN_NM + " needs at least one of label_incoming_network or query_outgoing_network enabled");
        return false;
    }

    if (label_incoming_network_traffic)
    {
        positional_labels = panda_parse_bool_opt(args, "pos",
            "positional labels");
        output_message(std::string("apply positional taint labels ") +
          PANDA_FLAG_STATUS(positional_labels));

        if(positional_labels) {
            uint16_t max_packet_size = parse_uint16_t(args, "max_packet_size",
                "65535", "Maximum size of TCP packets");
            switch(max_packet_size) {
                case PACKET_SIZE_16:
                    packet_size_bits = 16;
                    break;
                case PACKET_SIZE_15:
                    packet_size_bits = 15;
                    break;
                case PACKET_SIZE_14:
                    packet_size_bits = 14;
                    break;
                case PACKET_SIZE_13:
                    packet_size_bits = 13;
                    break;
                case PACKET_SIZE_12:
                    packet_size_bits = 12;
                    break;
                case PACKET_SIZE_11:
                    packet_size_bits = 11;
                    break;
                default:
                    output_message("Invalid value for maximum_packet_size. "
                        "Must be one of " + std::to_string(PACKET_SIZE_16) +
                        ", " + std::to_string(PACKET_SIZE_15) +
                        ", " + std::to_string(PACKET_SIZE_14) +
                        ", " + std::to_string(PACKET_SIZE_13) +
                        ", " + std::to_string(PACKET_SIZE_12) +
                        ", or " + std::to_string(PACKET_SIZE_11) + ".");
                    return false;
            }

            output_message("Maximum packet size to ensure "
                "unique taint labels is " + std::to_string(
                (1<<packet_size_bits)-1) + " bytes.");

            output_message("Maximum number of packets to ensure "
                "unique taint labels is " +
                std::to_string((1<<(LABEL_BITS-packet_size_bits))-1) + ".");
        }

        semantic_labels = panda_parse_bool_opt(args, "semantic",
            "semantic labels");
        output_message(std::string("apply semantic taint labels ") +
          PANDA_FLAG_STATUS(semantic_labels));

        packets_to_taint = parse_int_ranges(args, "packets",
            ("list of packet numbers or ranges to taint: example: 22" + DELIM + "33-40").c_str());
        if(!packets_to_taint.empty())
        {
            output_message("packets to taint " + get_set_as_string(packets_to_taint));
        }

        protocols_to_taint = parse_int_ranges(args, "ip_proto",
            "list of protocol numbers or ranges to taint");
        if(!protocols_to_taint.empty())
        {
            output_message("only tainting IPV4 protocols " + get_set_as_string(protocols_to_taint));
        }

        bytes_to_taint = parse_int_ranges(args, "bytes",
            "list of byte offsets or ranges to taint");
        if(!bytes_to_taint.empty())
        {
            output_message("only tainting packet bytes offsets " + get_set_as_string(bytes_to_taint));
        }

        source_ip = parse_ip(args, "ip_src",
            "only taint packets originating from specific ip address");
        if(source_ip != 0)
        {
            output_message("only tainting packets with IPV4 source addr " + std::to_string(source_ip));
        }

        dest_ip = parse_ip(args, "ip_dst",
            "only taint packets sent to a specific ip address");
        if(dest_ip != 0)
        {
            output_message("only tainting packets with IPV4 dest addr " + std::to_string(dest_ip));
        }

        ethertype = parse_uint16_t(args, "eth_type", "",
            "protocol number of packet encapsulated in ethernet");
        if(ethertype != 0)
        {
            output_message("only tainting packets with ethertype " + std::to_string(ethertype));
            ethertype=htons(ethertype);
        }

        if(semantic_labels)
        {
            if(positional_labels)
            {
                output_message(PLUGIN_NM + " only one of positional labels or semantic labels can be enabled");
                return false;
            }
            panda_require("ida_taint2");
            assert(init_ida_taint2_api());
            const char *taint2_filename = ida_taint2_get_filename();
            assert(taint2_filename);
            assert(*taint2_filename);
            const char *filename_suffix = ".semantic_labels";

            std::string semantic_labels_filename=std::string(taint2_filename);
            semantic_labels_filename.append(filename_suffix);

            semantic_labels_file=fopen(semantic_labels_filename.c_str(), "w");
            assert(semantic_labels_file);
        }
    }

    // need a file name if watching for outgoing taint
    if (query_outgoing_network_traffic)
    {
        tx_filename = panda_parse_string_opt(args, "file",
            (PLUGIN_NM + "_query.csv").c_str(),
            "name of file for taint information on outgoing network packets");
        output_message(std::string("outgoing network traffic taint file ") + tx_filename);

        // need some initialize room in the buffer for taint labels too
        taint_labels = static_cast<uint32_t *>(malloc(cur_max_labels * sizeof(uint32_t)));
    }

    panda_require("taint2");

    pcb.replay_handle_packet = on_replay_handle_packet;
    panda_register_callback(self, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);

    assert(init_taint2_api());

    return true;
#else
    output_message(PLUGIN_NM + " does not support user mode");
    return false;
#endif
}

void uninit_plugin(void *self)
{
    if (taint_labels != NULL)
    {
        free(taint_labels);
        taint_labels = NULL;
    }

    if(semantic_labels_file != NULL)
    {
        fclose(semantic_labels_file);
        semantic_labels_file = NULL;
    }
}
