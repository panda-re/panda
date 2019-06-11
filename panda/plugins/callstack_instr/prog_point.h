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
#ifndef __PROG_POINT_H
#define __PROG_POINT_H

// different ways to segregate the stacks
enum stack_type {
    STACK_ASID = 0,
    STACK_HEURISTIC,
    STACK_THREADED
};

struct prog_point {
    target_ulong caller;
    target_ulong pc;
    target_ulong sidFirst;
    target_ulong sidSecond;
    stack_type stackKind;
#ifdef __cplusplus
    bool operator <(const prog_point &p) const {
        return (this->pc < p.pc) || \
               ((this->pc == p.pc) && (this->caller < p.caller)) || \
               ((this->pc == p.pc) && (this->caller == p.caller) && \
                       (this->sidFirst < p.sidFirst)) || \
               ((this->pc == p.pc) && (this->caller == p.caller) && \
                       (this->sidFirst == p.sidFirst) && \
                       (this->sidSecond < p.sidSecond)) || \
               ((this->pc == p.pc) && (this->caller == p.caller) && \
                       (this->sidFirst == p.sidFirst) && \
                       (this->sidSecond == p.sidSecond) && \
                       (this->stackKind < p.stackKind));
    }
    bool operator ==(const prog_point &p) const {
        bool sids_match = true;
        if ((this->sidFirst != p.sidFirst) ||
                (this->sidSecond != p.sidSecond) ||
                (this->stackKind != p.stackKind)) {
            sids_match = false;
        }
        return ((this->pc == p.pc) && (this->caller == p.caller) && sids_match);
    }
#endif
};

#ifdef __GXX_EXPERIMENTAL_CXX0X__

struct hash_prog_point{
    size_t operator()(const prog_point &p) const
    {
        size_t h1 = std::hash<target_ulong>()(p.caller);
        size_t h2 = std::hash<target_ulong>()(p.pc);
        size_t h3 = std::hash<target_ulong>()(p.sidFirst);
        size_t h4 = std::hash<target_ulong>()(p.sidSecond);
        size_t h5 = std::hash<target_ulong>()(p.stackKind);
        return h1 ^ h2 ^ h3 ^ h4 ^ h5;
    }
};


#endif

// Get stack ID from the program point as a string
// Caller must use g_free to free the returned object when done with it
static inline char *get_stackid_string(prog_point p) {
    // this function is intentionally not callstack_instr plugin API so that it
    // can be called after callstack_instr has been unloaded
    char *sid_string;
    if (STACK_HEURISTIC == p.stackKind) {
        sid_string = g_strdup_printf("(asid=0x" TARGET_FMT_lx ", sp=0x" TARGET_FMT_lx ")",
                p.sidFirst, p.sidSecond);
    } else if (STACK_THREADED == p.stackKind) {
        sid_string = g_strdup_printf("(processID=0x" TARGET_FMT_lx ", threadID=0x" TARGET_FMT_lx ")",
                p.sidFirst, p.sidSecond);
    } else {
        // STACK_ASID
        sid_string = g_strdup_printf("(asid=0x" TARGET_FMT_lx ")", p.sidFirst);
    }

    assert(sid_string);
    return sid_string;
}

#endif
