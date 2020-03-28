

/*
  Collect all code executed during this run (live or replay).

  Using a callback registered to run after each bb is translated,
  we collect a set of bb of code, i.e., the binary blob of each.
  
*/

#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

extern "C" {   
#include <assert.h>
#include <stdint.h>
#include "panda/plog.h"
}

#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>
#include <set>

using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);

#include <string.h>
}

#ifdef CONFIG_SOFTMMU



struct Bblock {
	target_ulong asid;
	target_ulong pc;
	uint16_t size;
	uint8_t *code;

	bool operator<(const Bblock &other) const {
		if (asid < other.asid) return true;
		if (asid > other.asid) return false;
		if (pc < other.pc) return true;
		if (pc > other.pc) return false;
		if (size < other.size) return true;
		if (size > other.size) return false;
		int r = memcmp(code, other.code, size);
		if (r<0) return true;
		else return false;
	}

	bool operator==(const Bblock &other) const {
		if (asid != other.asid) return false;
		if (pc != other.pc) return false;
		if (size != other.size) return false;
		return(memcmp(code, other.code, size) == 0);
	}

	
	string str() {
		stringstream ss;
		ss << "[asid=" << setfill('0') << setw(2) << hex << asid 
		   << ",pc=" << pc 
		   << ",size=" << dec << size
		   << ",code=";
		for (int i=0; i<size; i++) 		   
			ss << setfill('0') << setw(2) << hex << (uint16_t) code[i];
		ss << "]";
		return ss.str();
	}
}; 




// asid * pc * bblock_set
map<target_ulong, map<target_ulong, set<Bblock>>> pc2bb;

uint64_t num_unique_bb = 0;

Panda__BasicBlock pbb;

void after_bb_translate(CPUState *env, TranslationBlock *tb) {
	Bblock bb;
	target_ulong pc = tb->pc;    

	bb.asid = panda_current_asid(env);
	bb.pc = pc;
	bb.size = tb->size;
	bb.code = (uint8_t *) malloc(bb.size);
	panda_virtual_memory_read(env, pc, bb.code, bb.size);

	pc2bb[bb.asid][pc].insert(bb);

	// create and write plog entry
	pbb = PANDA__BASIC_BLOCK__INIT;
	pbb.has_asid = pbb.has_size = pbb.has_code = 1;
	pbb.asid = bb.asid;
	pbb.size = bb.size;
	pbb.code.data = bb.code;	
	pbb.code.len = bb.size;
	Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
	ple.basic_block = &pbb;
	pandalog_write_entry(&ple);

    // NB: code to see if we have more than one bb for asid/pc
    // This seems to happen often but always corresponds to 
    // getting ejected from middle of a basic block in the middle
    // and thus ending up with 1/2 a block
/*
	if (pc2bb[bb.asid][pc].size() > 1) {
		cout << "Hmm for asid=" << hex << bb.asid << " pc=" << pc << dec << " -> " << (pc2bb[bb.asid][pc].size()) << " bb found\n"; 
        for (auto bb2 : pc2bb[bb.asid][pc]) {
            cout << bb2.str() << "\n";
        }
	}
*/

	num_unique_bb += 1;
	if ((num_unique_bb % 1000) == 0) 
		cout << "num_unique_bb " << num_unique_bb << "\n";

}


#endif

bool init_plugin(void *self) {

#ifdef CONFIG_SOFTMMU

  if (!pandalog) {
    fprintf(stderr, "ERROR: collect_code requiers a pandalog. Set with -pandalog [filename]\n");
    return  false;
  }

	panda_cb pcb;
	pcb.after_block_translate = after_bb_translate;
	panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

	// gives us instr count
	panda_enable_precise_pc();

	return true;

#else
	return false;
#endif
}


void uninit_plugin(void *self) {
	
    for (auto kvp : pc2bb) {
        auto asid = kvp.first;
        cout << "collect_code: asid=" << hex << asid << " num pc (bbs): " << dec << (kvp.second.size()) << " \n";
    }
	
}
