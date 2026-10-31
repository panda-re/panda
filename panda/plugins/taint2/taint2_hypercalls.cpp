/*!
 * @file taint2_hypercalls.cpp
 * @brief Support for hypercalls from the PANDA guest to the taint2 plugin.
 *
 * @author
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <iostream>
#include <cstdio>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include "panda/lava_hypercall_struct.h"
#include "taint2_hypercalls.h"
#include "taint_api.h"
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#ifdef TARGET_I386
// shorcuts for accesing the values of x86 registers
#define EAX ((CPUArchState*)cpu->env_ptr)->regs[R_EAX]
#define EBX ((CPUArchState*)cpu->env_ptr)->regs[R_EBX]
#define ECX ((CPUArchState*)cpu->env_ptr)->regs[R_ECX]
#define EDX ((CPUArchState*)cpu->env_ptr)->regs[R_EDX]
#define EDI ((CPUArchState*)cpu->env_ptr)->regs[R_EDI]
#endif // defined(TARGET_I386)

#ifdef TARGET_X86_64
// shorcuts for accesing the values of x86 registers
#define EAX ((CPUArchState*)cpu->env_ptr)->regs[R_EAX]
#define EBX ((CPUArchState*)cpu->env_ptr)->regs[R_EBX]
#define ECX ((CPUArchState*)cpu->env_ptr)->regs[R_ECX]
#define EDX ((CPUArchState*)cpu->env_ptr)->regs[R_EDX]
#define EDI ((CPUArchState*)cpu->env_ptr)->regs[R_EDI]
#endif // defined(TARGET_X86_64)

#ifdef TARGET_ARM
// shortcuts for accessing the vlues of arm registers
#define R0 env->regs[0]
#define R1 env->regs[1]
#define R2 env->regs[2]
#define R3 env->regs[3]
#define R4 env->regs[4]
#endif // defined(TARGET_ARM)

// max length of strnlen or taint query
#define QUERY_HYPERCALL_MAX_LEN 32

static const int ENABLE_TAINT = 6;
static const int LABEL_BUFFER = 7;
static const int LABEL_BUFFER_POS = 8;
static const int QUERY_BUFFER = 9;
static const int LABEL_REGISTER = 10;
static const int QUERY_REGISTER = 11;
static const int LOG = 12;

extern bool taintEnabled;
extern void *taint2_plugin;

// for writing output to text file, for testing purposes
char taint2_log_msg[256];
FILE *taint2_log_file;

char hypercall_msg[256];

std::map<target_ulong,std::string> addressMap;
target_ulong nextAddressCounter = 0;

const std::string addressString = "ADDRESS";

void map_address(target_ulong addr) {
    if(addressMap.count(addr) == 0) {
	addressMap[addr] = addressString + std::to_string(nextAddressCounter);
        nextAddressCounter += 1;
    }
}

std::string address_to_string(target_ulong addr) {
    if(addressMap.count(addr) == 0) {
        return "ADDRESS_NOT_LABELED_EXPLICTTLY";
    }
    else {
        return addressMap[addr];
    }
}

#if defined(TARGET_I386) || defined(TARGET_X86_64) || defined(TARGET_ARM)
static void write_taint_log(const std::string &msg)
{
    if (NULL == taint2_log_file) {
        return;
    }

    fprintf(taint2_log_file, "%s", msg.c_str());
}
#endif

bool guest_hypercall_callback(CPUState *cpu) {
    bool ret = false;
#if defined(TARGET_I386) || defined(TARGET_X86_64) || defined(TARGET_ARM)
    // "CPUID" is hypercall for I386/X86_64 guests
    // "MCR P7" is hypercall for ARM guests
    // uses EAX through EDI for Intel, R0 through R4 for ARM
    // EAX is command for Intel, R0 is command for ARM
    // EBX, ECX, EDX, EDI are arguments to command for Intel
    // R1, R2, R3, R4 are arguments to command for ARM
#if defined(TARGET_I386) || defined(TARGET_X86_64)
#define REG_CMD EAX
#define REG_ARG0 EBX
#define REG_ARG1 ECX
#define REG_ARG2 EDX
#define REG_ARG3 EDI
#define REG_ARG4 ESI
#endif // defined(TARGET_I386) || defined(TARGET_X86_64)
#if defined(TARGET_ARM)
#define REG_CMD R0
#define REG_ARG0 R1
#define REG_ARG1 R2
#define REG_ARG2 R3
#define REG_ARG3 R4
#define REG_ARG4 R5
#endif // defined(TARGET_ARM)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    if (REG_CMD == ENABLE_TAINT) {
        if (!taintEnabled) {
            printf("taint2: enabling taint processing\n");
            taint2_enable_taint();
            taint2_log_file = fopen("taint2_log", "a");
	}
    }
    if (taintEnabled) {
        if (REG_CMD == LABEL_BUFFER ||
            REG_CMD == LABEL_BUFFER_POS ||
            REG_CMD == QUERY_BUFFER ||
            REG_CMD == LABEL_REGISTER ||
            REG_CMD == QUERY_REGISTER ||
            REG_CMD == LOG) {
            if (REG_CMD == LABEL_BUFFER) {
                // Standard buffer label
                target_ulong buf_start = REG_ARG0;
                target_ulong buf_len = REG_ARG1;
                uint32_t label = REG_ARG3;
		size_t label_index=0;
                for (label_index=0;label_index<buf_len;label_index++) {
		    map_address(buf_start+label_index);
                }
                sprintf(taint2_log_msg,
                        "apply_single_label(addr: %s, len: %d, label: %08X)\n",
                        address_to_string(buf_start).c_str(), (int)buf_len,
                        label);
                std::stringstream head;
                head << PANDA_MSG << std::string(taint2_log_msg) << std::endl;
                write_taint_log(head.str());
                taint2_add_taint_ram_single_label(cpu, (uint64_t)buf_start,
                                                  (int)buf_len, label);
            }
            else if (REG_CMD == LABEL_BUFFER_POS) {
                // Positional buffer label
                target_ulong buf_start = REG_ARG0;
                target_ulong buf_len = REG_ARG1;
                uint32_t label = REG_ARG3;
		map_address(buf_start);
                sprintf(taint2_log_msg,
                        "apply_positional_label(addr: %s, off: %d, label: %08X)\n",
                        address_to_string(buf_start).c_str(), (int)buf_len,
                        label);
                std::stringstream head;
                head << PANDA_MSG << std::string(taint2_log_msg) << std::endl;
                write_taint_log(head.str());
                taint2_add_taint_ram_pos(cpu, (uint64_t)buf_start, (int)buf_len, label);
            }
            else if (REG_CMD == QUERY_BUFFER) {
                // Query taint for label on byte (assert existence of label on byte)
                std::stringstream head;
                target_ulong buf_start = REG_ARG0;
                target_ulong buf_off = REG_ARG1;
                uint32_t label = REG_ARG3;
		uint32_t positive = REG_ARG2;
		// buffer address + buffer offset
                target_ulong va = buf_start + buf_off;
		// physical address based on va above
                target_ulong pa =  panda_virt_to_phys(cpu, va);
                if ((int) pa != -1) {
                    // make an Addr from the physical address for taint query
                    Addr a = make_maddr(pa);
                    // find out how many labels are associated with the address
                    uint32_t num_labels = taint2_query(a);
                    bool label_found = false;
                    // if at least one label exists
		    // and storage is allocated for labels
                    if (num_labels > 0) {
                        // allocate memory for num_labels taint labels
                        uint32_t *labels = (uint32_t *)malloc(sizeof(uint32_t) * num_labels);
                        uint32_t **labelsptr = &labels;
			// query for the entire set of taint labels present on address
                        // and store them in "labels"
                        taint2_query_set_a(a, labelsptr, &num_labels);
			// once per present label
                        for (size_t label_num = 0; label_num < num_labels; label_num++) {
                            if (label == labels[label_num]) {
                                label_found = true;
                                break;
                            }
                        }
                        free(labels);
		    }
                    if (positive) {
                        if (label_found) {
                            sprintf(taint2_log_msg,
                             "pass: label %08X found for addr %s\n",
                            label, address_to_string(va).c_str());
                       }
                        else {
                            sprintf(taint2_log_msg,
                            "fail: label %08X not found for addr %s\n",
                            label, address_to_string(va).c_str());
                        }
                    }
                    else {
                        if (!label_found) {
                            sprintf(taint2_log_msg,
                            "pass: label %08X not found for addr %s\n",
                            label, address_to_string(va).c_str());
                        }
                        else {
                            sprintf(taint2_log_msg,
                            "fail: label %08X found for addr %s\n",
                            label, address_to_string(va).c_str());
                        }
                    }
                    head << PANDA_MSG << std::string(taint2_log_msg) << std::endl;
                    write_taint_log(head.str());
                }
                else {
                    // bad address
                    sprintf(taint2_log_msg,
                            "fail: panda_virt_to_phys failed for addr 0x%" PRIXPTR "\n",
                            (uintptr_t)va);
                    head << PANDA_MSG << std::string(taint2_log_msg) << std::endl;
                    write_taint_log(head.str());
                }
            }
            else if (REG_CMD == LABEL_REGISTER) {
                // positional register label
                target_ulong reg_num = REG_ARG0;
                target_ulong reg_off = REG_ARG1;
		uint32_t label = REG_ARG3;
		sprintf(taint2_log_msg,
                        "apply_register_label(reg: %08X, off: %d, label: %08X)\n",
                        (uint32_t)reg_num, (int)reg_off,
                        label);
                std::stringstream head;
                head << PANDA_MSG << std::string(taint2_log_msg) << std::endl;
                write_taint_log(head.str());
                taint2_label_reg(reg_num, reg_off, label);
            }
            else if (REG_CMD == QUERY_REGISTER) {
                // query taint for label on register
                std::stringstream head;
                target_ulong reg_num = REG_ARG0;
                target_ulong reg_off = REG_ARG1;
		uint32_t label = REG_ARG3;
		uint32_t positive = REG_ARG2;
		Addr reg_as_addr = make_greg(reg_num,reg_off);
		uint32_t num_labels = taint2_query(reg_as_addr);
		bool label_found = false;
                if (num_labels > 0) {
                    // allocate memory for num_labels taint labels
                    uint32_t *labels = (uint32_t *)malloc(sizeof(uint32_t) * num_labels);
                    uint32_t **labelsptr = &labels;
                    // query for the entire set of taint labels present on address and store them in "labels"
                    taint2_query_set_a(reg_as_addr, labelsptr, &num_labels);
                    // once per present label
                    for (size_t label_num = 0; label_num < num_labels; label_num++) {
                        if (label == labels[label_num]) {
                            label_found = true;
                            break;
                        }
                    }
                    free(labels);
                }
                if (positive) {
                    if (label_found) {
                        sprintf(taint2_log_msg,
                                "pass: label %08X found for reg,off %08X,%d\n",
                                label, (uint32_t)reg_num, (int)reg_off);
                    }
                    else {
                        sprintf(taint2_log_msg,
                                "fail: label %08X not found for reg,off %08X,%d\n",
                                label, (uint32_t)reg_num, (int)reg_off);
                    }
                }
                else {
                    if (!label_found) {
                        sprintf(taint2_log_msg,
                                "pass: label %08X not found for reg,off %08X,%d\n",
                                label, (uint32_t)reg_num, (int)reg_off);
                    }
                    else {
                        sprintf(taint2_log_msg,
                                "fail: label %08X found for reg,off %08X,%d\n",
                                label, (uint32_t)reg_num, (int)reg_off);
                    }

                }
                head << PANDA_MSG << std::string(taint2_log_msg) << std::endl;
                write_taint_log(head.str());
            }
            else if (REG_CMD == LOG) {
                // print a string located in guest memory to taint2 log
                target_ulong string_len = REG_ARG0;
                target_ulong string_addr = REG_ARG1;
                if(string_len > 256) {
                    string_len = 256;
                }
                panda_virtual_memory_rw(cpu, string_addr, (uint8_t *)hypercall_msg, string_len-1, false);
                hypercall_msg[string_len-1] = 0;
                std::stringstream head;
                head << PANDA_MSG << std::string(hypercall_msg) << std::endl;
                write_taint_log(head.str());
            }
            fflush(taint2_log_file);
            ret = true;
        }
    }
#endif // defined(TARGET_I386) || defined(TARGET_X86_64) || defined(TARGET_ARM)
    return ret;
}

// Print a warning if taint2 hypercall received while taint2 hypercall
// callback processing is not enabled.
bool guest_hypercall_warning_callback(CPUState *cpu) {
    bool ret = false;

#if defined(TARGET_I386) || defined(TARGET_X86_64) || defined(TARGET_ARM)

    // Look for taint2 hypercall (mirrors logic in guest_hypercall_callback)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    if (!taintEnabled) {
        ret = REG_CMD == ENABLE_TAINT;
    } else {
        ret = REG_CMD == LABEL_BUFFER ||
            REG_CMD == LABEL_BUFFER_POS ||
            REG_CMD == QUERY_BUFFER ||
            REG_CMD == LABEL_REGISTER ||
            REG_CMD == QUERY_REGISTER ||
            REG_CMD == LOG;
    }

    if(ret) {
        printf("taint2: WARNING: ignoring taint2 hypercalls - set taint2 "
            "parameter enable_hypercalls to true to enable taint2 "
            "hypercall processing\n");
        panda_cb pcb;
        pcb.guest_hypercall = guest_hypercall_warning_callback;
        panda_disable_callback(taint2_plugin, PANDA_CB_GUEST_HYPERCALL, pcb);
    }
#endif // defined(TARGET_I386) || defined(TARGET_X86_64) || defined(TARGET_ARM)
    return ret;
}
