/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Luke Craig                  luke.craig@ll.mit.edu
 *  Andrew Fasano               andrew.fasano@ll.mit.edu
 *  Nick Gregory                ngregory@nyu.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "mem_hooks_int_fns.h"
#include <iostream>
#include <unordered_map>
#include <vector>
#include <csignal>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
void enable_mem_hooking(void);
void disable_mem_hooking(void);
void phys_mem_before_write(CPUState *cpu, target_ptr_t pc, target_ulong addr, size_t size, uint8_t *buf);
void phys_mem_before_read(CPUState *cpu, target_ptr_t pc, target_ulong addr, size_t size, uint8_t *buf);
void phys_mem_after_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
void phys_mem_after_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
struct memory_hooks_region* add_mem_hook(struct memory_hooks_region* a);
void cool_other_function(void);
}


std::vector<struct memory_hooks_region> hooks;

// Callback objects
panda_cb c_callback_before_read;
panda_cb c_callback_before_write;
panda_cb c_callback_after_read;
panda_cb c_callback_after_write;

// Handle to self
void* self = NULL;

// Enable and disable callbacks
void enable_mem_hooking(void) {
  assert(self != NULL);
  panda_enable_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, c_callback_before_read);
  panda_enable_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, c_callback_before_write);
  panda_enable_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, c_callback_after_read);
  panda_enable_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, c_callback_after_write);
}
void disable_mem_hooking(void) {
  assert(self != NULL);
  panda_disable_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, c_callback_before_read);
  panda_disable_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, c_callback_before_write);
  panda_disable_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, c_callback_after_read);
  panda_disable_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, c_callback_after_write);
}

// nah
//void update_hook(hook_func_t hook, target_ulong value){
//  //Given hook function, move it to fire on a different address
//  for (auto it = hooks.begin(); it != hooks.end(); ++it){
//		if (it->first == value) continue;
//        std::vector<hook_func_t> hook_pile = it->second;
//        auto i = hook_pile.begin();
//        while (i != hook_pile.end()){
//            if (hook == *i){
//                i = hook_pile.erase(i);
//            }else{
//                ++i;
//            }
//
//        }
//       it->second = hook_pile;
//    }
//	hooks[value].push_back(hook);
//#if DEBUG
//  printf("Updated hook to fire at %p\n", &hook);
//#endif
//}

struct memory_hooks_region* add_mem_hook(struct memory_hooks_region* m) {
  if (!panda_is_callback_enabled(self, PANDA_CB_PHYS_MEM_BEFORE_READ, c_callback_before_read)) enable_mem_hooking(); // Ensure our panda callback is enabled when we add a hook
	// check for existing hook
  hooks.push_back(*m);
  return &hooks[hooks.size() - 1];
}

void check_phys_mem_change(CPUState *cpu, target_ptr_t pc, target_ulong addr, size_t size, uint8_t *buf, bool is_write, bool is_before){
  bool is_read = !is_write;
  bool is_after = !is_before;
  for (auto& it: hooks){
    if (it.enabled){
      if ((addr >= it.start_address && addr <= it.stop_address) ||
          (addr + size >= it.start_address && addr + size <= it.stop_address) || (addr >= it.start_address && addr + size <= it.stop_address)){
        // needs to be more complicated
        if ((is_write && it.on_write && is_before && it.on_before) ||
           (is_read && it.on_read && is_before && it.on_before) ||
           (is_write && it.on_write && is_after && it.on_after) ||
           (is_read && it.on_read && is_after && it.on_after)){
             (*(it.cb))(cpu, pc, addr, size, buf, is_write, is_before);
        }
      }else{
      }
    }else{
      printf("here but not enabled\n");
    }
  }
}

void phys_mem_before_write(CPUState *cpu, target_ptr_t pc, target_ulong addr, size_t size, uint8_t *buf){
  check_phys_mem_change(cpu, pc, addr, size, buf, true, true);
}
void phys_mem_before_read(CPUState *cpu, target_ptr_t pc, target_ulong addr, size_t size){
  check_phys_mem_change(cpu, pc, addr, size, (uint8_t*) NULL, false, true);
}

void phys_mem_after_write(CPUState *cpu, target_ulong pc, target_ulong addr, size_t size, uint8_t *buf){
  check_phys_mem_change(cpu, pc, addr, size, buf, true, false);
}
void phys_mem_after_read(CPUState *cpu, target_ulong pc, target_ulong addr, size_t size, uint8_t *buf){
  check_phys_mem_change(cpu, pc, addr, size, buf, false, false);
}

bool init_plugin(void *_self) {
    // On init, register a callback but don't enable it
    self = _self;

    c_callback_before_read.phys_mem_before_read = phys_mem_before_read;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, c_callback_before_read);
    c_callback_before_write.phys_mem_before_write = phys_mem_before_write;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, c_callback_before_write);
    c_callback_after_read.phys_mem_after_read = phys_mem_after_read;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, c_callback_after_read);
    c_callback_after_write.phys_mem_after_write = phys_mem_after_write;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, c_callback_after_write);

    panda_enable_memcb();

    return true;
}

void uninit_plugin(void *self) {}
