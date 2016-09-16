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
struct prog_point {
    target_ulong caller;
    target_ulong pc;
    target_ulong cr3;
#ifdef __cplusplus
    bool operator <(const prog_point &p) const {
        return (this->pc < p.pc) || \
               (this->pc == p.pc && this->caller < p.caller) || \
               (this->pc == p.pc && this->caller == p.caller && this->cr3 < p.cr3);
    }
    bool operator ==(const prog_point &p) const {
        return (this->pc == p.pc && this->caller == p.caller && this->cr3 == p.cr3);
    }
#endif
};

#ifdef __GXX_EXPERIMENTAL_CXX0X__

#include <functional>
struct hash_prog_point{
    size_t operator()(const prog_point &p) const
    {
        size_t h1 = std::hash<target_ulong>()(p.caller);
        size_t h2 = std::hash<target_ulong>()(p.pc);
        size_t h3 = std::hash<target_ulong>()(p.cr3);
        return h1 ^ h2 ^ h3;
    }
};


#endif
