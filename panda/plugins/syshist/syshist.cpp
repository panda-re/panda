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
#include<ostream>

map<target_ulong,map<target_ulong,uint32_t>> scount;

void count_syscalls(CPUState *env, target_ulong pc, target_ulong callno) {
  target_ulong asid = panda_current_asid(env);
  scount[asid][callno] ++;
}

bool init_plugin(void *self) {
  // Setup dependencies
  panda_require("syscalls2");
  assert(init_syscalls2_api());  
  PPP_REG_CB("syscalls2", on_all_sys_enter, count_syscalls);  
  return 1;
}

void uninit_plugin(void *) {
  printf ("syshist:\n");
  printf ("asid\tord\tcount\n");
  for (auto kvp: scount) {
    auto asid = kvp.first;
    for (auto kvp2 : kvp.second) {
      auto ord = kvp2.first;
      auto count = kvp2.second;
      printf ("%llx\t%u\t%u\n", (long long unsigned) asid, (unsigned int) ord, (unsigned int) count);
    }
  }
}

