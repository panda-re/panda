#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "osi_linux/osi_linux_ext.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
}

using namespace std;

#include<map>
#include<iostream>
#include<fstream>
#include<string>

map<target_ulong,map<target_ulong,uint32_t>> scount;
map<target_ulong,string> sname;

void count_syscalls(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *rp) {
  scount[rp->asid][call->no] ++;
  sname[call->no] = string(call->name);
}

bool init_plugin(void *self) {
  // Setup dependencies
  panda_require("syscalls2");
  assert(init_syscalls2_api());  
  PPP_REG_CB("syscalls2", on_all_sys_enter2, count_syscalls);  
  return 1;
}

void uninit_plugin(void *) {
  ofstream outf;
  outf.open ("syshist");
  outf << "asid\tord\tcount\n";
  for (auto kvp: scount) {
    auto asid = kvp.first;
    for (auto kvp2 : kvp.second) {
      auto ord = kvp2.first;
      auto count = kvp2.second;
      outf << hex << asid << dec << " " << sname[ord] << " " << count << "\n";
    }
  }
  outf.close();
}

