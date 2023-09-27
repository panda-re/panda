#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
#include <filesystem>
#include <sys/types.h>
#include <set>

#include "callstack_instr/callstack_instr.h"
#include "callwitharg/callwitharg.h" // Unnecessary?

extern "C" {
#include "callwitharg/callwitharg_ext.h"
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

size_t target_str_len;
char *target_str;
std::ofstream outfile;

// We track the last QUEUE_SIZE addresses we've checked to avoid rereading guest pointers
#define QUEUE_SIZE 100
std::atomic<size_t> queue_idx(0);
std::atomic<target_ulong> queue[QUEUE_SIZE];
// Now we'll define a function to add to the queue
void add_to_queue(target_ulong addr) {
  size_t idx = queue_idx.fetch_add(1);
  queue[idx % QUEUE_SIZE] = addr;
}
// And a function to check if an address is in the queue
bool in_queue(target_ulong addr) {
  for (size_t i = 0; i < QUEUE_SIZE; i++) {
    if (queue[i] == addr) return true;
  }
  return false;
}

// C++ set for storing unique string matches
std::set<std::string> matches;

void record_match(char *str) {
  if (strlen(str) == 0) return;

  for (int i = 0; i < strlen(str); i++) {
    if (!isprint(str[i])) {
      return;
    }
  }

  std::string s(str);
  if (matches.find(s) == matches.end()) {
    //printf("TargetCMP finds %s with length %u\n", s.c_str(), s.length());
    outfile << s << std::endl;
    matches.insert(s);
  }
}

void on_match(CPUState* cpu, target_ulong func_addr, target_ulong *args, char* value, uint matching_idx, uint args_read) {
  // We expect 2 args, if matching_idx is 0, arg1 is our target pointer, otherwise arg0
  assert(args_read >= 2);

  //printf("Match in arg %d with arg1=" TARGET_FMT_lx " and arg2=" TARGET_FMT_lx "\n", matching_idx, args[0], args[1]);

  target_ulong target_ptr = args[matching_idx == 0 ? 1 : 0]; // If we matched arg0, we want arg1 and vice versa

  // If it's in the queue, we've already checked it - bail
  if (in_queue(target_ptr)) {
    return;
  }
  // Otherwise add it to the queue
  add_to_queue(target_ptr);

  size_t short_len = strlen(value);
  size_t full_len = 4*short_len;
  char* other_arg = (char*)malloc(full_len + 1);

  // Try to read the target string from memory
  if (panda_virtual_memory_read(cpu, target_ptr, (uint8_t*)other_arg, full_len) == 0) {
    other_arg[target_str_len] = '\0'; // Ensure null termination
  } else if (panda_virtual_memory_read(cpu, target_ptr, (uint8_t*)other_arg, short_len) == 0) {
    // Recovered short string - move null terminator early
    other_arg[short_len] = '\0'; // Ensure null termination
  } else {
    // Failed to read even the short string - bail
    free(other_arg);
    return;
  }
  record_match(other_arg);
  free(other_arg);
}

// logfile default is cwd/targetcmp.txt
std::filesystem::path logfile = std::filesystem::current_path() / "targetcmp.txt";

bool init_plugin(void *self) {
  if (!init_callwitharg_api()) {
    printf("[targetcmp] Fatal error: unable to initialize callwitharg - is it loaded?\n");
    return false;
  }

  std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(
    panda_get_args("targetcmp"), panda_free_args);

  const char* logfile_arg = panda_parse_string_opt(args.get(), "output_file",
      NULL, "Output file to record compared values into");
  if (logfile_arg) logfile = std::string(logfile_arg);

  target_str = strdup(panda_parse_string_req(args.get(), "target_str", "String to match"));
  target_str_len = strlen(target_str);

  if (target_str_len <= 0) {
    printf("targetcmp error: invalid target_str argument\n");
    return false;
  }

  // On every function call, use our callback to check an argument is the target_str, if so store the other arg
#if defined(TARGET_ARM) || defined(TARGET_MIPS) || defined(TARGET_X86_64)
  // Create empty file - Just so we see that something's happening
  // Open file for writing, delete anything there.
  outfile.open(logfile.string(), std::ios_base::out | std::ios_base::trunc);

  // Call callwitharg's add_target_string function
  add_target_string(target_str);

  // Register on_call_match with callwitharg's on_call_match_str PPP callback
  PPP_REG_CB("callwitharg", on_call_match_str, on_match);
	return true;
#endif
  printf("ERROR: Unsupported architecture for targetcmp\n");
  return false;
}

void uninit_plugin(void *self) {
  if (outfile.is_open()) {
    outfile.close();
  }
  free((void*)target_str);
}
