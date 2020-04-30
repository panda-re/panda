#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

extern "C" {

  bool init_plugin(void *);
  void uninit_plugin(void *);

#include <stdint.h>

}

/*

  track_intexc plugin keeps track of when cpu is executing various
  kinds of code for Linux.

  User:      user code 
  Kernel:    kernel code
  Interrupt: interrupt service routine (should be both top and bottom half)
  Exception: exception handling code

  Four callbacks are registered: 

  before handle exception -- to note possible transition and record pc
                             and exception index
  before handle interrupt -- ditto for interrupt number
  insn translate --          for when we translate an iret
  insn execute --            this should only execute on iret (given previous) 
                             and figures out a bunch of state transitions as
                             well as maintaining iret stack
  before block exec --       more of the that decides when state transitions
                             occur and to update iret stack

  Plugin works as follows. The current state is initialized to
  Unknown. When first we see ourselves in user code, transition to
  User. Then, when we handle excp or int, we move into MaybeException
  or MaybeInterrupt. These transitions are confirmed if we see pc
  changed as a result of the maybe int / exc.  We manage a stack per
  asid for irets to help figure out what is going on.

  *** TL/DR ***
  What's all this good for?  If you are writing a plugin and want to
  exclude from your analysis any code corresponding to interrupt or
  exception handling, you can use the api presented:

  check_in_interrupt()   will return true if CPU is in the middle of 
                         handling an interrupt
  check_in_exception()   similar but for an exception

*/


#include<fstream>
#include<iostream>
#include<map>
#include<vector>
#include <string>   

using namespace std;


typedef enum {
  Unknown, 
  User, 
  Kernel, 
  MaybeInterrupt, 
  Interrupt,
  MaybeException, 
  Exception,
  EndOfIEState
} IEState;

string state_name[] = {
  "unknown", 
  "user", 
  "kernel", 
  "maybe_interrupt",
  "interrupt", 
  "maybe_exception", 
  "exception"
};

struct IntExc {
  target_ulong old_pc;
  IEState state;
  bool is_int;
};

// used to keep track of current state of CPU
// are we in user code? 
// Kernel code?  
// Interrupt service routine?
// Exception handling code?
IEState current_state = Unknown;
IEState state_before_maybe_state = Unknown;

// just some stats
uint64_t state_count[8];

// keeps track of stack of entering exc/int
// pc to which we should return,
// state from which we entered the exc/int
// and if we were entering an exc or int
map<target_ulong, vector<IntExc>> iret_stack;

bool debug = false;
target_ulong last_bb_start = 0;
bool maybe_in_exception = false;
target_ulong pc_at_exception;
int32_t exception_index;
bool maybe_in_interrupt = false;
target_ulong pc_at_interrupt;
int32_t interrupt_request;


bool last_bb_was_kernel;


#if defined(TARGET_I386) || defined(TARGET_X86_64)    

// API -- used to determine if in exception or interrupt handling code

extern "C" bool check_in_interrupt() {
    return (current_state == Interrupt);
}

extern "C" bool check_in_exception() {
  return (current_state == Exception);
}

    
#define ESP ((CPUArchState*)cpu->env_ptr)->regs[R_ESP]


// Implementation

// for debugging
void check_transition(IEState old_state, IEState new_state) {

  if (old_state == new_state) return;

  if (debug) {
    cout << "instr = " << dec << rr_get_guest_instr_count() << hex
	 << " Transition from " 
	 << state_name[old_state] << " -> " 
	 << state_name[new_state] << "\n";
    
    if ((old_state == User || old_state == Kernel)
	&& (new_state == Interrupt || new_state == Exception)) 
      cout << " ** entering exc / int code\n";
    
    if ((old_state == Interrupt || old_state == Exception) 
	&& (new_state == User || new_state == Kernel)) 
      cout << " ** leaving exc / int code \n";
  }
}


// also for debugging
void spit_stacks() {
  for (auto kvp : iret_stack) {
    auto asid = kvp.first;
    cout << "stack " << hex << asid << " : ";
    for (auto el : kvp.second) 
      cout << "(" << hex << el.old_pc << "," << el.is_int << ") ";
    cout << "\n";
  }
}  



// called when we 
// note exception start (maybe)
int32_t note_exception(CPUState *cpu, int32_t ei) {
  if (current_state == Unknown) return ei;
  state_before_maybe_state = current_state;
  current_state = MaybeException;
  exception_index = ei;
  pc_at_exception = panda_current_pc(cpu);
  check_transition(state_before_maybe_state, current_state);
  return ei;
}

int32_t note_interrupt(CPUState *cpu, int32_t ir) {
  if (current_state == Unknown) return ir;
  state_before_maybe_state = current_state;
  current_state = MaybeInterrupt;
  interrupt_request = ir;
  pc_at_interrupt = panda_current_pc(cpu);
  check_transition(state_before_maybe_state, current_state);
  return ir;
}


void before_block_exec(CPUState *cpu, TranslationBlock *tb) {

  target_ulong pc = panda_current_pc(cpu);
  bool in_kernel = panda_in_kernel(cpu);
  IEState old_state = current_state;
  target_ulong asid = panda_current_asid(cpu);
  
  // keep track of stats
  state_count[current_state] += 1;
  
  // manage trans from unknown and between user and kernel
  if (!in_kernel) current_state = User;
  else {
    if (current_state == User && in_kernel) 
      current_state = Kernel;
    if (current_state == Kernel && !in_kernel)
      current_state = User;
  }
  
  if (current_state == MaybeInterrupt || current_state == MaybeException) {
    IntExc ie;
    // we hit interrupt handling / exception handling code in qemu 
    target_ulong pc_check;
    bool is_int = (current_state == MaybeInterrupt);
    pc_check = (is_int) ? pc_at_interrupt : pc_at_exception;
    if (pc != pc_check) {
      // and pc got changed so int/exc really happened
      // change state
      current_state = (is_int) ? Interrupt : Exception;
      if (debug)
	printf ("entering %s . instr=%" PRId64 " old_pc=%" PRIx64 " new_pc=%" PRIx64" number=%x\n",
		((is_int) ? "interrupt" : "exception"),
		rr_get_guest_instr_count(),
		(uint64_t) pc_check, (uint64_t) pc,
		(is_int) ? interrupt_request : exception_index);
      // pc and state for return site (also remember if this was int/exc)
      ie = {pc_check, state_before_maybe_state, is_int};
      // update the appropriate stack
      if (last_bb_was_kernel) 
	iret_stack[0].push_back(ie);
      else {
	iret_stack[asid].push_back(ie);
      }
      if (debug) spit_stacks();
    }                
    else 
      // that maybe_interrupt / maybe_exception didn't pan out
      current_state = state_before_maybe_state;        
  }
  
  if (debug) {
    cout << "pc = " << hex << pc << " ASID = " << hex << asid << " ESP = " << ESP;
    cout << " in_kernel = " << in_kernel;
    if (old_state == current_state) 
      cout << " state = " << state_name[current_state];
    else 
      cout << " old_state,current_state = " << state_name[old_state] << "," << state_name[current_state];
    cout << "\n";
  }
  
  last_bb_was_kernel = in_kernel;
  check_transition(old_state, current_state);
}


// arrange for insn_exec callback on all irets
bool translate_callback(CPUState* cpu, target_ulong pc){
  unsigned char byte[2];
  int res = panda_virtual_memory_read(cpu, pc, (uint8_t *) &byte, 2);
  if (res == -1) // really should not happen
    return false;
#if defined(TARGET_I386) 
#if defined(TARGET_X86_64)
  // rex.w prefix is 0x48
  if (byte[0] == 0x48 && byte[1] == 0xcf) 
    return true;    
#else
  if (byte[0] == 0xcf) 
    return true;
#endif
#endif
  return false; // dont add callback
}


uint64_t num_irets = 0;
uint64_t num_irets_resolved = 0;

// this will be called *before* the instruction in question
// i.e. just before iret since that's the only one we instrument
int insn_exec_callback(CPUState *cpu, target_ulong pc) {

  uint64_t retto;
  
  panda_virtual_memory_read(cpu, ESP, (uint8_t *) &retto, 8);
  
  if (debug) 
    cout << "iret cr3 = " << hex << panda_current_asid(cpu) << " ESP = " << ESP << " retto = " << retto << "\n";
  
  IEState old_state = current_state;
  bool iret_resolved = false;
  if (iret_stack.size() == 0) {
    if (debug) cout << "iret_stack is empty\n";
  }
  else {
    // check the kernel and current asid stack
    if (iret_stack[0].size() == 0) {
      if (debug) cout << "iret_stack for kernel stack is empty\n";
    }
    else {
      auto ie = iret_stack[0].back();
      if (retto == ie.old_pc) {
	if (debug) 
	  printf ("exiting %s. instr=%" PRId64 " pc=%" PRIx64 
		  " -- top of kernel stack matches retto \n",
		  (ie.is_int) ? "interrupt" : "exception",
		  rr_get_guest_instr_count(), (uint64_t) pc);
	// restore state to site of int/exc
	current_state = ie.state;
	iret_stack[0].pop_back();
	iret_resolved = true;
      }
    }
    target_ulong asid = panda_current_asid(cpu);
    if (iret_stack[asid].size() == 0) {
      if (debug) cout << "iret_stack for asid=" << hex << asid << " is empty\n";
    }
    else {
      auto ie = iret_stack[asid].back();
      if (retto == ie.old_pc) {
	if (debug) cout << "Top of asid=" << hex << asid << " stack matches retto is_int = " << ie.is_int << "\n";
	// restore state to site of int/exc
	current_state = ie.state;
	iret_stack[asid].pop_back();
	iret_resolved = true;
      }
    }            
  }
  if (iret_resolved) 
    num_irets_resolved ++;    
  else 
    if (debug) cout << "iret NOT resolved\n";
  
  num_irets ++;
  if (debug) cout << dec << num_irets_resolved << " irets resolved out of " << num_irets << "\n";
  
  if (debug) spit_stacks();
  check_transition(old_state, current_state);
  
  return 0;    
}
#endif
    

bool init_plugin(void *self) {
#if defined(TARGET_I386) || defined(TARGET_X86_64)    
  panda_cb pcb;
    
  memset(&state_count, 0, 8 * 8);
  
  panda_arg_list *args = panda_get_args("track_intexc");
  debug = panda_parse_bool_opt(args, "debug", "turn on debug output");
  
  pcb.before_handle_exception = note_exception;
  panda_register_callback(self, PANDA_CB_BEFORE_HANDLE_EXCEPTION, pcb);
  pcb.before_handle_interrupt = note_interrupt;
  panda_register_callback(self, PANDA_CB_BEFORE_HANDLE_INTERRUPT, pcb);
  
  pcb.insn_translate = translate_callback;
  panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
  pcb.insn_exec = insn_exec_callback;
  panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
  pcb.before_block_exec = before_block_exec;
  panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
#else
  std::cerr << PANDA_MSG "ERROR track_intexc plugin not implemented for anything other than i386 and x86_64" << std::endl;
  return false;
#endif
  return true;
}


void uninit_plugin(void *) {
  // dump stats at the end
  for (int i=0; i<EndOfIEState; i++) {
    cout << "count(" << state_name[i] << ") = " << dec << state_count[i] << "\n";
  }
}
