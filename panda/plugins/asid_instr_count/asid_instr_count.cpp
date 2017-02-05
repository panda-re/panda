/*
  This plugin provides a per-asid instruction count.
  
  For each asid, keep track of the total number of instructions previously
  executed by all other asids.  This allows us to 'correct' the instruction
  count for an asid by subtraction.  Which means we can now take two instructions
  counts obtained via calls to asid_instr_count(asid) and subtract them to know
  how many instructions were executed between the two.  Without this accounting,
  we'd be including execution by other asids.

  This plugin just exposes an api of one function which returns the corrected
  instruction count for the asid. 

  Instr instr_count_asid(target_ulong asid);  
*/

#define __STDC_FORMAT_MACROS

#include <iostream>
#include <set>
#include <map>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"


extern "C" {
#include "panda/rr/rr_log.h"

//#include "cpu.h"

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include "asid_instr_count.h"
extern "C" {
#include "asid_instr_count_int_fns.h"
}

using namespace std;

// instruction count at start of bb before which asid changed
Instr ac_instr_start=0;

target_ulong current_asid=0;

// asid_instr_intervals[asid] is a *set* of instr intervals for
typedef std::pair<Instr,Instr> InstrRange;
typedef std::set<InstrRange> InstrRangeSet;
// map from asid to instruction intervalus
std::map<target_ulong,InstrRangeSet> asid_instr_intervals;

// asid_rr_sub_factor[asid] is how much to subtract from rr instr count for asid
// to get instr-count just for that asid
std::map<target_ulong, Instr> asid_rr_sub_factor;

// just saw last instr in interval for old_asid.
// update the number we use to correct rr instr count by asid (a subtraction factor)
void update_asid_rr_sub_factor(target_ulong old_asid, InstrRange rri) {
    // ok, yes, we aren't actually using this information for anything
    // but wouldn't it be cool? 
    asid_instr_intervals[old_asid].insert(rri);
    Instr rri_len = rri.second - rri.first;
    // update subtract factor for all other asids
    for (auto kvp : asid_rr_sub_factor) {
        auto asid = kvp.first;
        if (asid != old_asid) asid_rr_sub_factor[asid] += rri_len;
    }
    if (asid_rr_sub_factor.count(old_asid) == 0) {
        // first time seeing this asid.  
        // its subtraction factor is just current instr count
        asid_rr_sub_factor[old_asid] = rr_get_guest_instr_count();
    }
}

/*
  called whenever asid changes
  update info about what instruction intervals belong to each asid
  which is, in turn, used to be able to know instruction count by asid
*/
int asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    // XXX I wonder why this is in here?
    if (new_asid < 10) return 0;
    Instr instr = rr_get_guest_instr_count();
    if (old_asid != new_asid) {
        auto rri = std::make_pair(ac_instr_start, instr-1);
        update_asid_rr_sub_factor(old_asid, rri);
    }
    ac_instr_start = rr_get_guest_instr_count();        
    current_asid = new_asid;
    return 0;
}

/*
  returns instruction count for current asid (subtracting out instructions for other asids)
  NOTE: this means this isnt the actual instr count within the replay, but it is now
  safe, e.g., to subtract two instruction counts
*/
Instr get_instr_count_current_asid() {
    return (rr_get_guest_instr_count() - asid_rr_sub_factor[current_asid]);
}

Instr get_instr_count_by_asid(target_ulong asid) {
    return (rr_get_guest_instr_count() - asid_rr_sub_factor[asid]);
}

bool init_plugin(void *self) {
    panda_cb pcb;
    pcb.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    return true;
}

